using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace EthernetTools.Pn;

/// <summary>
/// An LLDP chassis or port id: its subtype (IEEE 802.1AB) and value. MAC subtypes read as aa:bb:.., network
/// addresses as an IP, the rest as text.
/// </summary>
public readonly record struct LldpId(byte Subtype, byte[] Value)
{
    // Chassis id subtypes 4 (MAC address) and 5 (network address); port id subtypes 3 (MAC) and 4 (network address).
    public bool IsChassisMac => Subtype == 4 && Value.Length == 6;

    public string ChassisText => Text(Subtype == 4, Subtype == 5);
    public string PortText => Text(Subtype == 3, Subtype == 4);

    private string Text(bool mac, bool address)
    {
        if (mac && Value.Length == 6) return string.Join(":", Value.Select(b => b.ToString("X2")));
        if (address && Value.Length == 5 && Value[0] == 1) return new IPAddress(Value.AsSpan(1)).ToString();
        return Encoding.UTF8.GetString(Value).TrimEnd('\0').Trim();
    }

    public bool Equals(LldpId other) => Subtype == other.Subtype && Value.AsSpan().SequenceEqual(other.Value);
    public override int GetHashCode() => HashCode.Combine(Subtype, Convert.ToHexString(Value));
}

/// <summary>LLDP system capabilities (the frame's bit order: bit 0 Other ... bit 7 Station only).</summary>
[Flags]
public enum LldpCapabilities : ushort
{
    None = 0, Other = 1, Repeater = 2, Bridge = 4, WlanAccessPoint = 8, Router = 16, Telephone = 32, Docsis = 64, Station = 128,
}

/// <summary>What one device announces about itself and the port it sent from.</summary>
public sealed record LldpNeighbor(
    LldpId Chassis,
    LldpId Port,
    string PortDescription,
    string SystemName,
    string SystemDescription,
    LldpCapabilities Capabilities,
    IPAddress? ManagementAddress,
    byte[] SourceMac);

/// <summary>LLDP (IEEE 802.1AB, EtherType 0x88CC): reading the frames a neighbour sends.</summary>
public static class Lldp
{
    public const ushort EtherType = 0x88CC;

    /// <summary>The neighbour an LLDP frame describes, or null when the frame is not LLDP.</summary>
    public static LldpNeighbor? Read(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 14) return null;
        int at = 12;
        ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(frame[at..]);
        if (etherType == DcpProtocol.EtherTypeVlan && frame.Length >= 18)
        {
            at += 4;
            etherType = BinaryPrimitives.ReadUInt16BigEndian(frame[at..]);
        }
        if (etherType != EtherType) return null;
        at += 2;

        LldpId? chassis = null, port = null;
        string portDesc = "", sysName = "", sysDesc = "";
        var caps = LldpCapabilities.None;
        IPAddress? management = null;
        while (at + 2 <= frame.Length)
        {
            ushort header = BinaryPrimitives.ReadUInt16BigEndian(frame[at..]);
            int type = header >> 9, length = header & 0x1FF;
            at += 2;
            if (type == 0 || at + length > frame.Length) break; // End of LLDPDU
            ReadOnlySpan<byte> value = frame.Slice(at, length);
            at += length;
            switch (type)
            {
                case 1 when length >= 2: chassis = new LldpId(value[0], value[1..].ToArray()); break;
                case 2 when length >= 2: port = new LldpId(value[0], value[1..].ToArray()); break;
                case 4: portDesc = Text(value); break;
                case 5: sysName = Text(value); break;
                case 6: sysDesc = Text(value); break;
                case 7 when length >= 4:
                    // system capabilities, then the enabled ones: the enabled are what the device is now
                    caps = (LldpCapabilities)BinaryPrimitives.ReadUInt16BigEndian(value[2..]);
                    break;
                case 8 when length >= 6 && management is null:
                    // management address: string length (subtype + address), subtype (1 = IPv4), address, ...
                    if (value[0] == 5 && value[1] == 1) management = new IPAddress(value.Slice(2, 4));
                    break;
            }
        }
        if (chassis is null || port is null) return null;
        return new LldpNeighbor(chassis.Value, port.Value, portDesc, sysName, sysDesc, caps, management, frame.Slice(6, 6).ToArray());
    }

    /// <summary>SNMP BITS (LLDP-MIB lldpRemSysCapEnabled: bit 0 is the first byte's high bit) as capabilities.</summary>
    public static LldpCapabilities FromSnmpBits(ReadOnlySpan<byte> bits)
    {
        // Some agents (HPE OfficeConnect) send the two octets swapped: 00 20 for a bridge. Bits 8-15 name no
        // capability a device has without one of 0-7, so an empty first octet with a full second is read swapped.
        if (bits.Length == 2 && bits[0] == 0 && bits[1] != 0) bits = new byte[] { bits[1], 0 };
        int result = 0;
        for (int i = 0; i < 16 && i / 8 < bits.Length; i++)
            if ((bits[i / 8] & (0x80 >> (i % 8))) != 0) result |= 1 << i;
        return (LldpCapabilities)result;
    }

    private static string Text(ReadOnlySpan<byte> value) => Encoding.UTF8.GetString(value).TrimEnd('\0').Trim();
}
