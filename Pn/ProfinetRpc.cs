using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace EthernetTools.Pn;

/// <summary>A Profinet device's I&amp;M0: who made it, what it is (order number), its serial number and revisions.</summary>
public sealed record Im0(ushort VendorId, string OrderId, string SerialNumber, ushort HardwareRevision, string SoftwareRevision, ushort RevisionCounter);

/// <summary>One port of a Profinet device as its own records tell (PDPortDataReal): its id and who is on the other end.</summary>
public sealed record PnPort(ushort Subslot, string PortId, IReadOnlyList<PnPeer> Peers);

/// <summary>The neighbour on a port: its port id ("port-001.station" or a switch's), chassis id (name of station, or a
/// switch's chassis) and the MAC of its port.</summary>
public sealed record PnPeer(string PortId, string ChassisId, byte[] Mac);

/// <summary>
/// Reads Profinet devices' own records over PNIO-CM (connectionless DCE/RPC on UDP 34964), the way PRONETA does when a
/// device does not answer SNMP: a Read Implicit (no application relation) of PDPortDataReal (index 0x802A) for each
/// port subslot of slot 0 (0x8001, 0x8002 ...). Read-only.
/// </summary>
public static class ProfinetRpc
{
    public const int UdpPort = 34964;
    public const ushort IndexPdPortDataReal = 0x802A, BlockPdPortDataReal = 0x020F;
    public const ushort IndexIm0 = 0xAFF0, BlockIm0 = 0x0020;
    public const ushort BlockReadReqHeader = 0x0009, BlockReadResHeader = 0x8009;
    public const ushort OpReadImplicit = 5;

    /// <summary>The PNIO device interface's UUID.</summary>
    public static readonly Guid DeviceInterface = new("DEA00001-6C97-11D1-8271-00A02442DF7D");

    /// <summary>A device's object UUID: DEA00000-6C97-11D1-8271-{instance}{device id}{vendor id}.</summary>
    public static Guid ObjectUuid(ushort vendorId, ushort deviceId, ushort instance = 1) =>
        new(0xDEA00000, 0x6C97, 0x11D1, 0x82, 0x71,
            (byte)(instance >> 8), (byte)instance, (byte)(deviceId >> 8), (byte)deviceId, (byte)(vendorId >> 8), (byte)vendorId);

    /// <summary>
    /// A Read Implicit request: the 80-byte RPC header (little-endian), the NDR arguments, and the IODReadReqHeader
    /// block (big-endian) for <paramref name="index"/> of API 0, <paramref name="slot"/>/<paramref name="subslot"/>.
    /// </summary>
    public static byte[] BuildReadImplicit(Guid objectUuid, Guid activity, uint sequence, ushort slot, ushort subslot, ushort index,
        int maxRecord = 4068)
    {
        // IODReadReqHeader: block header, seq, AR UUID (nil: implicit), API, slot, subslot, padding, index,
        // record data length, then 24 bytes (target AR UUID + padding, or RW padding: zero either way)
        var block = new byte[64];
        BinaryPrimitives.WriteUInt16BigEndian(block, BlockReadReqHeader);
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(2), 60);
        block[4] = 1; block[5] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(6), (ushort)sequence);
        BinaryPrimitives.WriteUInt32BigEndian(block.AsSpan(24), 0); // API
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(28), slot);
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(30), subslot);
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(34), index);
        BinaryPrimitives.WriteUInt32BigEndian(block.AsSpan(36), (uint)maxRecord);

        // NDR (little-endian): args maximum, args length, then the array: maximum count, offset, actual count
        var body = new byte[20 + block.Length];
        int argsMax = maxRecord + 64;
        BinaryPrimitives.WriteUInt32LittleEndian(body, (uint)argsMax);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(4), (uint)block.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(8), (uint)argsMax);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(12), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(16), (uint)block.Length);
        block.CopyTo(body, 20);

        var packet = new byte[80 + body.Length];
        packet[0] = 4;          // RPC version
        packet[1] = 0;          // request
        packet[2] = 0x20;       // idempotent
        packet[4] = 0x10;       // little-endian, ASCII, IEEE float
        objectUuid.TryWriteBytes(packet.AsSpan(8));
        DeviceInterface.TryWriteBytes(packet.AsSpan(24));
        activity.TryWriteBytes(packet.AsSpan(40));
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(56), 0);        // server boot time
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(60), 1);        // interface version
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(64), sequence);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(68), OpReadImplicit);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(70), 0xFFFF);   // interface hint
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(72), 0xFFFF);   // activity hint
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(74), (ushort)body.Length);
        body.CopyTo(packet, 80);
        return packet;
    }

    /// <summary>
    /// The record a Read Implicit answer carries, or null when <paramref name="packet"/> is not the answer to
    /// <paramref name="activity"/>. <paramref name="status"/>: the PNIO status (0: read; else the device's error).
    /// </summary>
    public static byte[]? ReadResponse(ReadOnlySpan<byte> packet, Guid activity, out uint status)
    {
        status = 0;
        if (packet.Length < 84 || packet[0] != 4 || packet[1] != 2) return null; // an RPC response
        bool little = (packet[4] & 0x10) != 0;
        Guid act = little ? new Guid(packet.Slice(40, 16)) : new Guid(packet.Slice(40, 16), bigEndian: true);
        if (act != activity) return null;
        var body = packet[80..];
        status = BinaryPrimitives.ReadUInt32BigEndian(body);
        if (status != 0 || body.Length < 20) return [];
        int argsLength = (int)(little ? BinaryPrimitives.ReadUInt32LittleEndian(body[4..]) : BinaryPrimitives.ReadUInt32BigEndian(body[4..]));
        var data = body.Slice(20, Math.Min(argsLength, body.Length - 20));
        if (data.Length < 64 || BinaryPrimitives.ReadUInt16BigEndian(data) != BlockReadResHeader) return [];
        int recordLength = (int)BinaryPrimitives.ReadUInt32BigEndian(data[36..]);
        return data.Slice(64, Math.Min(recordLength, data.Length - 64)).ToArray();
    }

    /// <summary>A PDPortDataReal block: the port's own id and its peers (port id, chassis id, MAC).</summary>
    public static PnPort? ReadPortDataReal(ReadOnlySpan<byte> block)
    {
        if (block.Length < 14 || BinaryPrimitives.ReadUInt16BigEndian(block) != BlockPdPortDataReal) return null;
        ushort subslot = BinaryPrimitives.ReadUInt16BigEndian(block[10..]);
        int at = 12;
        string ownPort = Text(block, ref at);
        if (at >= block.Length) return null;
        int peerCount = block[at++];
        at = Align4(at);
        var peers = new List<PnPeer>();
        for (int i = 0; i < peerCount && at < block.Length; i++)
        {
            string first = Text(block, ref at);
            string second = Text(block, ref at);
            at = Align4(at);
            if (at + 10 > block.Length) break;
            at += 4; // line delay
            byte[] mac = block.Slice(at, 6).ToArray();
            at = Align4(at + 6);
            // PeerPortID then PeerChassisID; a device that writes them the other way round is read by the port's shape
            bool swapped = !IsPortId(first) && IsPortId(second);
            peers.Add(swapped ? new PnPeer(second, first, mac) : new PnPeer(first, second, mac));
        }
        return new PnPort(subslot, ShortPort(ownPort), peers);

        static string Text(ReadOnlySpan<byte> b, ref int at)
        {
            if (at >= b.Length) return "";
            int length = b[at++];
            if (at + length > b.Length) { at = b.Length; return ""; }
            string s = Encoding.ASCII.GetString(b.Slice(at, length)).TrimEnd('\0');
            at += length;
            return s;
        }
        static int Align4(int at) => (at + 3) & ~3;
        static bool IsPortId(string s) => s.StartsWith("port-", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// An I&amp;M0 block (Identification &amp; Maintenance 0): vendor id, order id (20 characters), serial number (16),
    /// hardware revision, software revision (prefix V/R/P/U/T and three numbers: "V2.9.4"), revision counter.
    /// </summary>
    public static Im0? ReadIm0(ReadOnlySpan<byte> block)
    {
        if (block.Length < 52 || BinaryPrimitives.ReadUInt16BigEndian(block) != BlockIm0) return null;
        char prefix = (char)block[46];
        return new Im0(
            BinaryPrimitives.ReadUInt16BigEndian(block[6..]),
            Encoding.ASCII.GetString(block.Slice(8, 20)).TrimEnd('\0', ' '),
            Encoding.ASCII.GetString(block.Slice(28, 16)).TrimEnd('\0', ' '),
            BinaryPrimitives.ReadUInt16BigEndian(block[44..]),
            $"{(char.IsLetter(prefix) ? prefix : 'V')}{block[47]}.{block[48]}.{block[49]}",
            BinaryPrimitives.ReadUInt16BigEndian(block[50..]));
    }

    /// <summary>
    /// A device's I&amp;M0: Read Implicit of 0xAFF0 at slot 0, subslot 1 (the head module), else 0x8000 (the interface).
    /// Null when it does not answer or refuses.
    /// </summary>
    public static async Task<Im0?> ReadIm0Async(IPAddress ip, ushort vendorId, ushort deviceId, TimeSpan timeout, CancellationToken ct, int port = UdpPort)
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Connect(ip, port);
        uint sequence = 0;
        foreach (ushort instance in new ushort[] { 1, 0 })
        {
            var obj = ObjectUuid(vendorId, deviceId, instance);
            bool answered = false;
            foreach (ushort subslot in new ushort[] { 0x0001, 0x8000 })
            {
                var record = await ReadRecordAsync(udp, obj, sequence++, 0, subslot, IndexIm0, timeout, ct).ConfigureAwait(false);
                if (record is null) break; // no answer: try the other object UUID
                answered = true;
                if (ReadIm0(record) is { } im) return im;
            }
            if (answered) return null;
        }
        return null;
    }

    /// <summary>
    /// One Read Implicit: the record, an empty array when the device refuses (a PNIO error), null when it does not
    /// answer (twice). <paramref name="udp"/> is connected to the device.
    /// </summary>
    private static async Task<byte[]?> ReadRecordAsync(UdpClient udp, Guid obj, uint sequence, ushort slot, ushort subslot, ushort index,
        TimeSpan timeout, CancellationToken ct)
    {
        var activity = Guid.NewGuid();
        byte[] request = BuildReadImplicit(obj, activity, sequence, slot, subslot, index);
        for (int attempt = 0; attempt < 2; attempt++)
        {
            await udp.SendAsync(request, ct).ConfigureAwait(false);
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
            wait.CancelAfter(timeout);
            try
            {
                while (true)
                {
                    var received = await udp.ReceiveAsync(wait.Token).ConfigureAwait(false);
                    if (ReadResponse(received.Buffer, activity, out _) is { } record) return record;
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            catch (SocketException) { return null; } // nothing listens on 34964
        }
        return null;
    }

    /// <summary>"port-001.station" as "port-001".</summary>
    public static string ShortPort(string portId) =>
        portId.StartsWith("port-", StringComparison.OrdinalIgnoreCase) && portId.IndexOf('.') is > 0 and var dot ? portId[..dot] : portId;

    /// <summary>
    /// A device's ports, as its records tell: PDPortDataReal of subslots 0x8001, 0x8002 ... until one is refused or
    /// not answered. Empty when the device does not answer (or not to these object UUIDs).
    /// </summary>
    public static async Task<List<PnPort>> ReadPortsAsync(IPAddress ip, ushort vendorId, ushort deviceId, TimeSpan timeout,
        CancellationToken ct, int port = UdpPort, int maxPorts = 8)
    {
        var ports = new List<PnPort>();
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Connect(ip, port);
        uint sequence = 0;
        foreach (ushort instance in new ushort[] { 1, 0 })
        {
            var obj = ObjectUuid(vendorId, deviceId, instance);
            for (ushort subslot = 0x8001; subslot < 0x8001 + maxPorts; subslot++)
            {
                var activity = Guid.NewGuid();
                byte[] request = BuildReadImplicit(obj, activity, sequence++, 0, subslot, IndexPdPortDataReal);
                byte[]? record = null;
                for (int attempt = 0; attempt < 2 && record is null; attempt++)
                {
                    await udp.SendAsync(request, ct).ConfigureAwait(false);
                    using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    wait.CancelAfter(timeout);
                    try
                    {
                        while (record is null)
                        {
                            var received = await udp.ReceiveAsync(wait.Token).ConfigureAwait(false);
                            record = ReadResponse(received.Buffer, activity, out _);
                        }
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
                    catch (SocketException) { return ports; } // nothing listens on 34964
                }
                if (record is null) break;                              // no answer
                if (ReadPortDataReal(record) is not { } p) break;      // refused: no such port
                ports.Add(p);
            }
            if (ports.Count > 0) break;
        }
        return ports;
    }

    /// <summary>What a device's records tell, as the map reads an SNMP agent: its ports and their neighbours.</summary>
    public static SnmpAgentData ToAgent(NetDevice device, IReadOnlyList<PnPort> ports)
    {
        string station = device.NameOfStation ?? "";
        var agent = new SnmpAgentData
        {
            Ip = device.IPAddress!,
            SysName = station,
            LocalChassis = station.Length > 0 ? new LldpId(7, Encoding.ASCII.GetBytes(station)) : null,
            FromProfinet = true,
        };
        foreach (var p in ports)
        {
            int number = p.Subslot - 0x8000;
            agent.LocalPorts[number] = p.PortId.Length > 0 ? p.PortId : $"port-{number:000}";
            foreach (var peer in p.Peers)
            {
                var chassis = MacText(peer.ChassisId) is { } mac
                    ? new LldpId(4, mac)
                    : new LldpId(7, Encoding.ASCII.GetBytes(peer.ChassisId));
                var portId = new LldpId(7, Encoding.ASCII.GetBytes(peer.PortId));
                agent.Neighbors.Add((number, new LldpNeighbor(chassis, portId, "",
                    chassis.IsChassisMac ? "" : peer.ChassisId, "", LldpCapabilities.None, null, peer.Mac)));
            }
        }
        return agent;

        static byte[]? MacText(string s)
        {
            string hex = s.Replace(":", "").Replace("-", "");
            return s.Length == 17 && hex.Length == 12 && hex.All(Uri.IsHexDigit) ? Convert.FromHexString(hex) : null;
        }
    }
}
