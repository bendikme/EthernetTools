using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace EthernetTools.Pn;

/// <summary>
/// What switches say on every port without being asked, read as the neighbour the adapter is plugged into: LLDP,
/// Cisco's CDP, and spanning tree (STP/RSTP/MSTP BPDUs, Cisco PVST+). A network card whose firmware keeps LLDP to
/// itself (Intel X710 ...) still passes CDP and BPDUs. None is ever forwarded by a switch: each names the switch port
/// This PC is on.
/// </summary>
public static class L2Hello
{
    /// <summary>The capture filter for all three (LLDP also behind an 802.1Q tag).</summary>
    public const string Filter = "ether proto 0x88cc or (vlan and ether proto 0x88cc) or ether dst 01:80:c2:00:00:00 " +
                                 "or ether dst 01:00:0c:cc:cc:cc or ether dst 01:00:0c:cc:cc:cd";

    /// <summary>The neighbour a frame describes (LLDP, CDP or a BPDU), or null.</summary>
    public static LldpNeighbor? Read(ReadOnlySpan<byte> frame) => Lldp.Read(frame) ?? Cdp.Read(frame) ?? Stp.Read(frame);

    /// <summary>Which of the three is the better source of a port's name: LLDP, then CDP, then spanning tree.</summary>
    public static int Rank(LldpNeighbor n) => n.Protocol switch { "LLDP" => 0, "CDP" => 1, _ => 2 };
}

/// <summary>
/// Spanning-tree BPDUs (IEEE 802.1D/w/s on 01:80:C2:00:00:00 behind LLC 42-42-03, Cisco PVST+ on 01:00:0C:CC:CC:CD
/// behind SNAP 00-00-0C-01-0B): the sending bridge, the port it was sent from, the root bridge and the cost to it.
/// </summary>
public static class Stp
{
    /// <summary>
    /// A configuration or RST/MST BPDU as the neighbour that sent it: chassis = the bridge's MAC, port = "port N" (the
    /// port id's number), a bridge; with the root bridge and the sender's root path cost. Null for anything else
    /// (a topology-change notice carries no ids).
    /// </summary>
    public static LldpNeighbor? Read(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 14) return null;
        int at;
        if (frame[..6].SequenceEqual(new byte[] { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x00 })
            && frame.Length >= 17 && frame[14] == 0x42 && frame[15] == 0x42 && frame[16] == 0x03) at = 17;
        else if (frame[..6].SequenceEqual(new byte[] { 0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCD })
            && frame.Length >= 22 && frame.Slice(14, 8).SequenceEqual(new byte[] { 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x01, 0x0B })) at = 22;
        else return null;
        if (frame.Length < at + 35 || BinaryPrimitives.ReadUInt16BigEndian(frame[at..]) != 0) return null; // protocol id 0
        byte type = frame[at + 3];
        if (type is not (0x00 or 0x02)) return null; // a TCN BPDU (0x80) names no bridge
        byte[] root = frame.Slice(at + 7, 6).ToArray();
        uint cost = BinaryPrimitives.ReadUInt32BigEndian(frame[(at + 13)..]);
        byte[] bridge = frame.Slice(at + 19, 6).ToArray();
        int port = BinaryPrimitives.ReadUInt16BigEndian(frame[(at + 25)..]) & 0x0FFF;
        return new LldpNeighbor(new LldpId(4, bridge), new LldpId(7, Encoding.ASCII.GetBytes($"port {port}")),
            "", "", "", LldpCapabilities.Bridge, null, frame.Slice(6, 6).ToArray())
        {
            Protocol = "STP",
            RootBridge = root,
            RootPathCost = cost,
        };
    }

    /// <summary>
    /// A root path cost that is exactly one link's cost (802.1D-2004: 10 Gbit/s 2000, 1 Gbit/s 20000, 100 Mbit/s
    /// 200000 ...; the older short costs 2, 4, 19, 100): the sender is most likely cabled straight to the root.
    /// </summary>
    public static bool IsOneLink(uint cost) => cost is 2 or 4 or 19 or 100 or 200 or 2000 or 20000 or 200000 or 2000000 or 20000000;
}

/// <summary>Cisco Discovery Protocol (01:00:0C:CC:CC:CC behind SNAP 00-00-0C-20-00): device id, port, platform, addresses.</summary>
public static class Cdp
{
    public static LldpNeighbor? Read(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 26 || !frame[..6].SequenceEqual(new byte[] { 0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC })
            || !frame.Slice(14, 8).SequenceEqual(new byte[] { 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00 })) return null;
        int at = 26; // version, ttl, checksum
        string device = "", port = "", platform = "";
        uint caps = 0;
        IPAddress? address = null;
        while (at + 4 <= frame.Length)
        {
            int type = BinaryPrimitives.ReadUInt16BigEndian(frame[at..]), length = BinaryPrimitives.ReadUInt16BigEndian(frame[(at + 2)..]);
            if (length < 4 || at + length > frame.Length) break;
            var value = frame.Slice(at + 4, length - 4);
            switch (type)
            {
                case 1: device = Text(value); break;
                case 3: port = Text(value); break;
                case 6: platform = Text(value); break;
                case 4 when value.Length >= 4: caps = BinaryPrimitives.ReadUInt32BigEndian(value); break;
                case 2 when value.Length >= 4 && address is null:
                    // count, then each: protocol type, protocol length, protocol (0xCC = IP), address length, address
                    int a = 4;
                    for (uint i = BinaryPrimitives.ReadUInt32BigEndian(value); i > 0 && a + 2 <= value.Length; i--)
                    {
                        int pl = value[a + 1];
                        if (a + 2 + pl + 2 > value.Length) break;
                        bool ip = pl == 1 && value[a + 2] == 0xCC;
                        int al = BinaryPrimitives.ReadUInt16BigEndian(value[(a + 2 + pl)..]);
                        int addr = a + 4 + pl;
                        if (addr + al > value.Length) break;
                        if (ip && al == 4) { address = new IPAddress(value.Slice(addr, 4)); break; }
                        a = addr + al;
                    }
                    break;
            }
            at += length;
        }
        if (device.Length == 0 || port.Length == 0) return null;
        // a device id that is a MAC (Cisco small-business switches send their chassis MAC as 04eb40e0c222) is one
        string hex = device.Replace(":", "").Replace("-", "").Replace(".", "");
        var chassis = hex.Length == 12 && hex.All(Uri.IsHexDigit) ? new LldpId(4, Convert.FromHexString(hex)) : new LldpId(7, Encoding.ASCII.GetBytes(device));
        var capabilities = ((caps & 0x08) != 0 || (caps & 0x02) != 0 ? LldpCapabilities.Bridge : 0) | ((caps & 0x01) != 0 ? LldpCapabilities.Router : 0);
        return new LldpNeighbor(chassis, new LldpId(5, Encoding.ASCII.GetBytes(port)), "", chassis.IsChassisMac ? "" : device, platform,
            capabilities, address, frame.Slice(6, 6).ToArray()) { Protocol = "CDP" };

        static string Text(ReadOnlySpan<byte> v) => Encoding.ASCII.GetString(v).TrimEnd('\0').Trim();
    }
}
