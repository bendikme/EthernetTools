using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;

namespace EthernetTools.Pn;

/// <summary>
/// ARP frame builder + parser. Used to actively probe every host in the local IPv4
/// subnet (so Windows PCs / printers / cameras with no Profinet show up too).
/// </summary>
public static class ArpProtocol
{
    public const ushort EtherTypeArp = 0x0806;
    private const ushort HwTypeEthernet = 0x0001;
    private const ushort ProtoTypeIPv4 = 0x0800;
    private const ushort OpRequest = 1;
    private const ushort OpReply = 2;

    private static readonly PhysicalAddress Broadcast =
        new(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
    private static readonly PhysicalAddress Zero =
        new(new byte[] { 0, 0, 0, 0, 0, 0 });

    /// <summary>Build an ARP "who-has targetIp tell senderIp" broadcast frame.</summary>
    public static byte[] BuildRequest(
        PhysicalAddress senderMac,
        IPAddress senderIp,
        IPAddress targetIp)
    {
        // Ethernet (14) + ARP (28) = 42, pad to 60.
        var buf = new byte[60];
        Broadcast.GetAddressBytes().CopyTo(buf, 0);
        senderMac.GetAddressBytes().CopyTo(buf, 6);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(12, 2), EtherTypeArp);

        var a = buf.AsSpan(14);
        BinaryPrimitives.WriteUInt16BigEndian(a[..2], HwTypeEthernet);
        BinaryPrimitives.WriteUInt16BigEndian(a.Slice(2, 2), ProtoTypeIPv4);
        a[4] = 6; // hw size
        a[5] = 4; // proto size
        BinaryPrimitives.WriteUInt16BigEndian(a.Slice(6, 2), OpRequest);
        senderMac.GetAddressBytes().CopyTo(buf, 14 + 8);
        senderIp.GetAddressBytes().CopyTo(buf, 14 + 14);
        Zero.GetAddressBytes().CopyTo(buf, 14 + 18);
        targetIp.GetAddressBytes().CopyTo(buf, 14 + 24);
        return buf;
    }

    /// <summary>
    /// Parse an Ethernet frame as ARP. Returns true and populates <paramref name="mac"/>
    /// and <paramref name="ip"/> with the *sender* hardware/protocol address from the
    /// ARP packet (works for both replies and gratuitous requests).
    /// </summary>
    public static bool TryParse(
        ReadOnlySpan<byte> frame,
        out PhysicalAddress mac,
        out IPAddress ip,
        out bool isReply)
    {
        mac = PhysicalAddress.None;
        ip = IPAddress.None;
        isReply = false;

        if (frame.Length < 14 + 28) return false;
        ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(12, 2));
        if (etherType != EtherTypeArp) return false;

        var a = frame[14..];
        if (BinaryPrimitives.ReadUInt16BigEndian(a[..2]) != HwTypeEthernet) return false;
        if (BinaryPrimitives.ReadUInt16BigEndian(a.Slice(2, 2)) != ProtoTypeIPv4) return false;
        if (a[4] != 6 || a[5] != 4) return false;

        ushort op = BinaryPrimitives.ReadUInt16BigEndian(a.Slice(6, 2));
        isReply = (op == OpReply);

        mac = new PhysicalAddress(a.Slice(8, 6).ToArray());
        ip = new IPAddress(a.Slice(14, 4).ToArray());
        return true;
    }

    /// <summary>Enumerate all *host* IPv4 addresses inside an IPv4 subnet (skips network &amp; broadcast).</summary>
    public static IEnumerable<IPAddress> EnumerateSubnetHosts(IPAddress ip, IPAddress mask)
    {
        uint ipU = BinaryPrimitives.ReadUInt32BigEndian(ip.GetAddressBytes());
        uint maskU = BinaryPrimitives.ReadUInt32BigEndian(mask.GetAddressBytes());
        if (maskU == 0) yield break;

        uint network = ipU & maskU;
        uint broadcast = network | ~maskU;

        for (uint host = network + 1; host < broadcast; host++)
        {
            var bytes = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(bytes, host);
            yield return new IPAddress(bytes);
        }
    }

    public static int CountSubnetHosts(IPAddress mask)
    {
        uint maskU = BinaryPrimitives.ReadUInt32BigEndian(mask.GetAddressBytes());
        if (maskU == 0) return 0;
        long size = (long)(~maskU) - 1;
        return size < 0 ? 0 : (int)Math.Min(size, int.MaxValue);
    }
}
