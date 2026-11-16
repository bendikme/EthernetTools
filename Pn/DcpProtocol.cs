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
    public const ushort EtherTypeVlan = 0x8100;
    public const ushort FrameIdGetSet = 0xFEFD;
    public const ushort FrameIdIdentifyRequest = 0xFEFE;
    public const ushort FrameIdIdentifyResponse = 0xFEFF;

    private const byte ServiceIdIdentify = 0x05;
    private const byte ServiceIdSet = 0x04;
    private const byte ServiceTypeRequest = 0x00;
    private const byte ServiceTypeResponse = 0x01;

    private const byte OptionDevice = 0x02;
    private const byte OptionControl = 0x05;
    private const byte SubNameOfStation = 0x02;
    private const byte SubControlSignal = 0x03;
    private const byte SubControlResponse = 0x04;

    /// <summary>BlockQualifier of a Set: keep the value after a power cycle (0 would be until the next one).</summary>
    private const ushort QualifierPermanent = 0x0001;

    /// <summary>
    /// Where the Profinet payload (FrameID onwards) starts in <paramref name="frame"/>: 14, or 18 behind an 802.1Q tag
    /// (Profinet devices often send their answers priority-tagged). -1 when the frame is not Profinet.
    /// </summary>
    public static int ProfinetOffset(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 14) return -1;
        ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(12, 2));
        if (etherType == EtherTypeProfinet) return 14;
        if (etherType == EtherTypeVlan && frame.Length >= 18
            && BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(16, 2)) == EtherTypeProfinet) return 18;
        return -1;
    }

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
        // Control ▸ Signal, BlockQualifier 0x0000, SignalValue 0x0100 (= flash once).
        return BuildSetRequest(srcMac, dstMac, xid, OptionControl, SubControlSignal, 0x0000, [0x01, 0x00]);
    }

    /// <summary>
    /// Build a DCP "Set NameOfStation" request frame addressed to a specific device by MAC: the device keeps
    /// <paramref name="name"/> as its name of station, also after a power cycle. The name must pass
    /// <see cref="StationName.Problem"/> (ASCII only).
    /// </summary>
    public static byte[] BuildSetNameRequest(PhysicalAddress srcMac, PhysicalAddress dstMac, uint xid, string name)
    {
        return BuildSetRequest(srcMac, dstMac, xid, OptionDevice, SubNameOfStation, QualifierPermanent, Encoding.ASCII.GetBytes(name));
    }

    /// <summary>
    /// A unicast DCP Set request (FrameID 0xFEFD) carrying one block: option, suboption, BlockLength
    /// (2 + the value), BlockQualifier and the value, padded to an even length. The DCPDataLength counts the padding;
    /// the frame is padded to the 60-byte Ethernet minimum (the adapter adds the FCS).
    /// </summary>
    private static byte[] BuildSetRequest(PhysicalAddress srcMac, PhysicalAddress dstMac, uint xid,
        byte option, byte suboption, ushort qualifier, ReadOnlySpan<byte> value)
    {
        int blockLength = 2 + value.Length;
        int dataLength = 4 + blockLength + (blockLength % 2);
        var buf = new byte[Math.Max(14 + 12 + dataLength, 60)];
        dstMac.GetAddressBytes().CopyTo(buf, 0);
        srcMac.GetAddressBytes().CopyTo(buf, 6);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(12, 2), EtherTypeProfinet);

        var pn = buf.AsSpan(14);
        BinaryPrimitives.WriteUInt16BigEndian(pn[..2], FrameIdGetSet);
        pn[2] = ServiceIdSet;
        pn[3] = ServiceTypeRequest;
        BinaryPrimitives.WriteUInt32BigEndian(pn.Slice(4, 4), xid);
        BinaryPrimitives.WriteUInt16BigEndian(pn.Slice(8, 2), 0x0000); // reserved (no response delay: unicast)
        BinaryPrimitives.WriteUInt16BigEndian(pn.Slice(10, 2), (ushort)dataLength);

        pn[12] = option;
        pn[13] = suboption;
        BinaryPrimitives.WriteUInt16BigEndian(pn.Slice(14, 2), (ushort)blockLength);
        BinaryPrimitives.WriteUInt16BigEndian(pn.Slice(16, 2), qualifier);
        value.CopyTo(pn[18..]);
        return buf;
    }

    /// <summary>
    /// Try to read <paramref name="ethernetFrame"/> as <paramref name="device"/>'s answer to the Set request
    /// <paramref name="expectedXid"/>. <paramref name="blockError"/> is 0 when the device did it, otherwise why it did
    /// not (<see cref="SetErrorText"/>).
    /// </summary>
    public static bool TryReadSetResponse(ReadOnlySpan<byte> ethernetFrame, uint expectedXid, PhysicalAddress device, out byte blockError)
    {
        blockError = 0;
        int at = ProfinetOffset(ethernetFrame);
        if (at < 0 || ethernetFrame.Length < at + 12) return false;
        if (!ethernetFrame.Slice(6, 6).SequenceEqual(device.GetAddressBytes())) return false;

        var pn = ethernetFrame[at..];
        if (BinaryPrimitives.ReadUInt16BigEndian(pn[..2]) != FrameIdGetSet || pn[2] != ServiceIdSet) return false;
        if ((pn[3] & 0x01) == 0) return false; // a request, not an answer
        if (BinaryPrimitives.ReadUInt32BigEndian(pn.Slice(4, 4)) != expectedXid) return false;

        // ServiceType "response, not supported" (0x05): the device does not take this Set at all.
        if (pn[3] != ServiceTypeResponse)
        {
            blockError = 1;
            return true;
        }

        int dataLen = Math.Min(BinaryPrimitives.ReadUInt16BigEndian(pn.Slice(10, 2)), pn.Length - 12);
        var blocks = pn.Slice(12, Math.Max(0, dataLen));
        int o = 0;
        while (o + 4 <= blocks.Length)
        {
            byte option = blocks[o], suboption = blocks[o + 1];
            int len = BinaryPrimitives.ReadUInt16BigEndian(blocks.Slice(o + 2, 2));
            if (o + 4 + len > blocks.Length) break;
            // Control ▸ Response: the option and suboption answered, then the block error.
            if (option == OptionControl && suboption == SubControlResponse && len >= 3)
            {
                blockError = blocks[o + 4 + 2];
                return true;
            }
            o += 4 + len + (len & 1);
        }
        return true;
    }

    /// <summary>What a DCP block error means (IEC 61158-6-10, BlockError).</summary>
    public static string SetErrorText(byte error) => error switch
    {
        0 => "done",
        1 => "the device does not support this option",
        2 => "the device does not support this suboption",
        3 => "the device did not set it",
        4 => "the device has no resources for it now",
        5 => "the device refuses it for a reason of its own",
        6 => "the device is in operation (connected to its controller) and refuses it",
        _ => $"the device answered error {error}",
    };

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
        int at = ProfinetOffset(ethernetFrame);
        if (at < 0 || ethernetFrame.Length < at + 12) return false;

        var pn = ethernetFrame[at..];
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
