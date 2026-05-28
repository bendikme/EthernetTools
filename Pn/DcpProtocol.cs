using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace EthernetTools.Pn;

/// <summary>
/// Profinet DCP (Discovery and Configuration Protocol) frame builder + parser.
/// Operates at Layer 2 (EtherType 0x8892), discovering devices regardless of IP subnet.
/// I/O is performed by <see cref="NetworkScanner"/>.
/// </summary>
public static class DcpProtocol
{
    // Profinet DCP "Identify" multicast destination MAC.
    public static readonly PhysicalAddress IdentifyMulticast =
        new(new byte[] { 0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00 });

    public const ushort EtherTypeProfinet = 0x8892;
    public const ushort FrameIdIdentifyRequest = 0xFEFE;
    public const ushort FrameIdIdentifyResponse = 0xFEFF;

    private const byte ServiceIdIdentify = 0x05;
    private const byte ServiceIdSet = 0x04;
    private const byte ServiceTypeRequest = 0x00;
    private const byte ServiceTypeResponse = 0x01;

    /// <summary>
    /// Build a DCP Identify-All Ethernet frame.
    /// </summary>
    public static byte[] BuildIdentifyAllRequest(PhysicalAddress srcMac, uint xid)
    {
        // Ethernet (14) + DCP header (10) + AllSelector block (4) = 28 bytes.
        // Pad to 60 bytes minimum Ethernet payload.
        const int frameLen = 60;
        var buf = new byte[frameLen];

        IdentifyMulticast.GetAddressBytes().CopyTo(buf, 0);
        srcMac.GetAddressBytes().CopyTo(buf, 6);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(12, 2), EtherTypeProfinet);

        var pn = buf.AsSpan(14);
        BinaryPrimitives.WriteUInt16BigEndian(pn[..2], FrameIdIdentifyRequest);
        pn[2] = ServiceIdIdentify;
        pn[3] = ServiceTypeRequest;
        BinaryPrimitives.WriteUInt32BigEndian(pn.Slice(4, 4), xid);
        BinaryPrimitives.WriteUInt16BigEndian(pn.Slice(8, 2), 0x0080); // ~1.28 s response window
        BinaryPrimitives.WriteUInt16BigEndian(pn.Slice(10, 2), 4);     // DCPDataLength

        // AllSelector block: Option=0xFF, Suboption=0xFF, BlockLength=0x0000
        pn[12] = 0xFF;
        pn[13] = 0xFF;
        pn[14] = 0x00;
        pn[15] = 0x00;
        return buf;
    }

    /// <summary>
    /// Build a DCP "Set Signal" (Flash LED) request frame addressed to a specific
    /// Profinet device by MAC. Causes the device to blink its diagnostic LED for
    /// ~3 seconds.
    /// </summary>
    public static byte[] BuildFlashRequest(PhysicalAddress srcMac, PhysicalAddress dstMac, uint xid)
    {
        // Ethernet (14) + DCP header (10) + Signal block (4 + 4) = 32, pad to 60.
        var buf = new byte[60];
        dstMac.GetAddressBytes().CopyTo(buf, 0);
        srcMac.GetAddressBytes().CopyTo(buf, 6);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(12, 2), EtherTypeProfinet);

        var pn = buf.AsSpan(14);
        // Set service uses unicast Get/Set FrameID 0xFEFD.
        BinaryPrimitives.WriteUInt16BigEndian(pn[..2], 0xFEFD);
        pn[2] = ServiceIdSet;
        pn[3] = ServiceTypeRequest;
        BinaryPrimitives.WriteUInt32BigEndian(pn.Slice(4, 4), xid);
        BinaryPrimitives.WriteUInt16BigEndian(pn.Slice(8, 2), 0x0000); // ResponseDelay (unicast)
        BinaryPrimitives.WriteUInt16BigEndian(pn.Slice(10, 2), 8);     // DCPDataLength

        // Signal block: Option=0x05, Suboption=0x03, BlockLength=4
        pn[12] = 0x05;
        pn[13] = 0x03;
        BinaryPrimitives.WriteUInt16BigEndian(pn.Slice(14, 2), 4);
        // BlockQualifier=0x0000 + SignalValue 0x0100 (= flash once)
        BinaryPrimitives.WriteUInt16BigEndian(pn.Slice(16, 2), 0x0000);
        BinaryPrimitives.WriteUInt16BigEndian(pn.Slice(18, 2), 0x0100);
        return buf;
    }

    /// <summary>
    /// Try to parse an Ethernet frame as a DCP Identify response and apply the data
    /// to <paramref name="dev"/>. Returns true if it was a matching DCP Identify response
    /// for the given <paramref name="expectedXid"/>.
    /// </summary>
    public static bool TryParseIdentifyResponse(
        ReadOnlySpan<byte> ethernetFrame,
        uint expectedXid,
        NetDevice dev)
    {
        if (ethernetFrame.Length < 14 + 12) return false;

        ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(ethernetFrame.Slice(12, 2));
        if (etherType != EtherTypeProfinet) return false;

        var pn = ethernetFrame[14..];
        ushort frameId = BinaryPrimitives.ReadUInt16BigEndian(pn[..2]);
        if (frameId != FrameIdIdentifyResponse) return false;

        if (pn[2] != ServiceIdIdentify || pn[3] != ServiceTypeResponse) return false;

        uint rxXid = BinaryPrimitives.ReadUInt32BigEndian(pn.Slice(4, 4));
        if (rxXid != expectedXid) return false;

        ushort dataLen = BinaryPrimitives.ReadUInt16BigEndian(pn.Slice(10, 2));
        if (12 + dataLen > pn.Length) dataLen = (ushort)(pn.Length - 12);

        ParseBlocks(pn.Slice(12, dataLen), dev);
        return true;
    }

    private static void ParseBlocks(ReadOnlySpan<byte> blocks, NetDevice dev)
    {
        int o = 0;
        while (o + 4 <= blocks.Length)
        {
            byte option = blocks[o];
            byte suboption = blocks[o + 1];
            ushort len = BinaryPrimitives.ReadUInt16BigEndian(blocks.Slice(o + 2, 2));
            int payloadStart = o + 4;
            if (payloadStart + len > blocks.Length) break;

            var payload = blocks.Slice(payloadStart, len);

            switch ((option, suboption))
            {
                case (0x01, 0x02) when payload.Length >= 14: // IP parameter
                    dev.IPAddress = new IPAddress(payload.Slice(2, 4).ToArray());
                    dev.SubnetMask = new IPAddress(payload.Slice(6, 4).ToArray());
                    dev.Gateway = new IPAddress(payload.Slice(10, 4).ToArray());
                    break;

                case (0x02, 0x01) when payload.Length > 2: // TypeOfStation (vendor)
                    dev.VendorName = TrimAscii(payload[2..]);
                    break;

                case (0x02, 0x02) when payload.Length > 2: // NameOfStation
                    dev.NameOfStation = TrimAscii(payload[2..]);
                    break;

                case (0x02, 0x03) when payload.Length >= 6: // VendorID + DeviceID
                    dev.VendorId = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
                    dev.DeviceId = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
                    break;

                case (0x02, 0x04) when payload.Length >= 3: // Device Role
                    dev.DeviceRole = payload[2];
                    break;
            }

            int next = payloadStart + len;
            if ((len & 1) == 1) next++; // pad to even
            o = next;
        }
    }

    private static string TrimAscii(ReadOnlySpan<byte> s)
    {
        int n = s.Length;
        while (n > 0 && s[n - 1] == 0) n--;
        return Encoding.ASCII.GetString(s[..n]);
    }
}
