using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
using EthernetTools.Pn;

namespace EthernetTools;

/// <summary>
/// <c>EthernetTools.exe --selftest</c>: what can be checked without a network or a device -
/// the Profinet DCP frames byte by byte (Identify, Signal, Set NameOfStation), the reading of the devices' answers
/// (with and without an 802.1Q tag), the station-name rules on ProfinetTools' cases (Test/station-names.json,
/// embedded) and the Set Name dialog. One line per check on standard output (UTF-8); exit code 0 when every check
/// passes. Test\SmokeTest.ps1 runs it, and so does the release workflow.
/// </summary>
internal static partial class SelfTest
{
    private static TextWriter _out = TextWriter.Null;
    private static int _passed, _failed;

    public static int Run()
    {
        _out = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true };
        _out.WriteLine($"EthernetTools {AppInfo.Version} self-test");
        try
        {
            Frames();
            SetAnswers();
            IdentifyAnswers();
            StationNames();
            SetNameDialog();
            Snmp();
            SnmpWalks();
            LldpFrames();
            SnmpTables();
            TopologyMap();
        }
        catch (Exception ex)
        {
            _out.WriteLine($"  ERROR {ex}");
            _failed++;
        }
        _out.WriteLine(_failed == 0
            ? $"All {_passed} self-test checks passed"
            : $"{_failed} of {_passed + _failed} self-test checks failed");
        _out.Flush();
        return _failed == 0 ? 0 : 1;
    }

    private static void Check(string name, bool ok, string detail = "")
    {
        if (ok) { _passed++; _out.WriteLine($"  PASS  {name}"); }
        else { _failed++; _out.WriteLine($"  FAIL  {name}  {detail}"); }
    }

    private static void Section(string name) => _out.WriteLine(name);

    // ---- DCP frames -------------------------------------------------------------------------------------------

    private static readonly PhysicalAddress Own = new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    private static readonly PhysicalAddress Device = new([0x00, 0x1b, 0x1b, 0x12, 0x34, 0x56]);
    private static readonly PhysicalAddress Other = new([0x00, 0x1b, 0x1b, 0x12, 0x34, 0x57]);

    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes);

    private static void Frames()
    {
        Section("dcp frames");
        byte[] identify = DcpProtocol.BuildIdentifyAllRequest(Own, 0x01020304);
        Check("identify: to the DCP multicast address, from the adapter, EtherType 0x8892",
            Hex(identify.AsSpan(0, 14)) == "010ECF000000" + "020000000001" + "8892");
        Check("identify: FrameID 0xFEFE, Identify request, the xid, response delay 0x0080, 4 bytes of blocks",
            Hex(identify.AsSpan(14, 12)) == "FEFE0500010203040080" + "0004");
        Check("identify: the All selector block, padded to 60 bytes",
            Hex(identify.AsSpan(26, 4)) == "FFFF0000" && identify.Length == 60);

        byte[] odd = DcpProtocol.BuildSetNameRequest(Own, Device, 7, "plc"); // 3 letters: a block of odd length
        Check("set name: unicast to the device, from the adapter, EtherType 0x8892",
            Hex(odd.AsSpan(0, 14)) == "001B1B123456" + "020000000001" + "8892");
        Check("set name: FrameID 0xFEFD, Set request, the xid, no response delay",
            Hex(odd.AsSpan(14, 10)) == "FEFD0400000000070000");
        Check("set name: Device > NameOfStation block, length 2 + name, qualifier 1 (permanent)",
            Hex(odd.AsSpan(26, 9)) == "02020005" + "0001" + Hex("plc"u8));
        Check("set name: an odd block is padded, and the data length counts the padding (4 + 5 + 1)",
            Hex(odd.AsSpan(24, 2)) == "000A" && odd[35] == 0 && odd.Length == 60);
        byte[] even = DcpProtocol.BuildSetNameRequest(Own, Device, 7, "plc1");
        Check("set name: an even block needs no padding (4 + 6)",
            Hex(even.AsSpan(24, 2)) == "000A" && Hex(even.AsSpan(26, 10)) == "02020006" + "0001" + Hex("plc1"u8));
        string longest = string.Join('.', Enumerable.Repeat(new string('a', 63), 3)) + "." + new string('b', 48); // 240
        byte[] big = DcpProtocol.BuildSetNameRequest(Own, Device, 7, longest);
        Check("set name: the longest name (240) fits, the frame grows past 60 bytes (14 + 12 + 4 + 242)",
            longest.Length == 240 && StationName.Problem(longest) is null && big.Length == 272
            && Hex(big.AsSpan(24, 2)) == "00F6" && Hex(big.AsSpan(28, 2)) == "00F2"
            && Encoding.ASCII.GetString(big, 32, 240) == longest);

        byte[] flash = DcpProtocol.BuildFlashRequest(Own, Device, 9);
        // The very bytes EthernetTools 26.11.0 sent for Flash LED.
        Check("flash: Control > Signal, flash once - the frame of 26.11.0, byte for byte",
            Hex(flash) == "001B1B123456" + "020000000001" + "8892" + "FEFD" + "0400" + "00000009" + "0000" + "0008"
                         + "05030004" + "0000" + "0100" + new string('0', (60 - 34) * 2));
    }

    // ---- the devices' answers to a Set ------------------------------------------------------------------------

    private static byte[] SetAnswer(PhysicalAddress from, uint xid, byte error, bool vlan = false, byte serviceType = 0x01)
    {
        var frame = new List<byte>(Own.GetAddressBytes());
        frame.AddRange(from.GetAddressBytes());
        if (vlan) frame.AddRange([0x81, 0x00, 0xc0, 0x00]);
        frame.AddRange([0x88, 0x92, 0xfe, 0xfd, 0x04, serviceType, (byte)(xid >> 24), (byte)(xid >> 16), (byte)(xid >> 8), (byte)xid,
            0x00, 0x00, 0x00, 0x08,
            // Control > Response, length 3: answering Device > NameOfStation, then the block error (and padding)
            0x05, 0x04, 0x00, 0x03, 0x02, 0x02, error, 0x00]);
        while (frame.Count < 60) frame.Add(0);
        return frame.ToArray();
    }

    private static void SetAnswers()
    {
        Section("set answers");
        Check("done (block error 0)",
            DcpProtocol.TryReadSetResponse(SetAnswer(Device, 7, 0), 7, Device, out byte e0) && e0 == 0);
        Check("refused in operation (block error 6), with its words",
            DcpProtocol.TryReadSetResponse(SetAnswer(Device, 7, 6), 7, Device, out byte e6) && e6 == 6
            && DcpProtocol.SetErrorText(e6).Contains("in operation"));
        Check("behind an 802.1Q tag, read the same",
            DcpProtocol.TryReadSetResponse(SetAnswer(Device, 7, 3, vlan: true), 7, Device, out byte e3) && e3 == 3);
        Check("'response, not supported' (service type 0x05) reads as unsupported",
            DcpProtocol.TryReadSetResponse(SetAnswer(Device, 7, 0, serviceType: 0x05), 7, Device, out byte e1) && e1 == 1);
        Check("another device's answer is not the answer",
            !DcpProtocol.TryReadSetResponse(SetAnswer(Other, 7, 0), 7, Device, out _));
        Check("another transaction's answer is not the answer",
            !DcpProtocol.TryReadSetResponse(SetAnswer(Device, 8, 0), 7, Device, out _));
        byte[] ownRequest = DcpProtocol.BuildSetNameRequest(Own, Device, 7, "plc1");
        Check("the request itself (captured going out) is not the answer",
            !DcpProtocol.TryReadSetResponse(ownRequest, 7, Device, out _) && !DcpProtocol.TryReadSetResponse(ownRequest, 7, Own, out _));
        Check("an Identify answer is not a Set answer",
            !DcpProtocol.TryReadSetResponse(IdentifyAnswer(7, vlan: false, "x"), 7, Device, out _));
    }

    // ---- Identify answers ---------------------------------------------------------------------------------------

    private static byte[] IdentifyAnswer(uint xid, bool vlan, string name)
    {
        var blocks = new List<byte>();
        void Block(byte option, byte sub, byte[] value)
        {
            int length = 2 + value.Length;
            blocks.AddRange([option, sub, (byte)(length >> 8), (byte)length, 0x00, 0x00]);
            blocks.AddRange(value);
            if (length % 2 == 1) blocks.Add(0);
        }
        Block(0x02, 0x01, Encoding.ASCII.GetBytes("ET 200SP"));
        Block(0x02, 0x02, Encoding.ASCII.GetBytes(name));
        Block(0x02, 0x03, [0x00, 0x2a, 0x03, 0x13]);
        Block(0x02, 0x04, [0x01, 0x00]);
        Block(0x01, 0x02, [192, 168, 0, 10, 255, 255, 255, 0, 192, 168, 0, 1]);
        var frame = new List<byte>(Own.GetAddressBytes());
        frame.AddRange(Device.GetAddressBytes());
        if (vlan) frame.AddRange([0x81, 0x00, 0xc0, 0x00]);
        frame.AddRange([0x88, 0x92, 0xfe, 0xff, 0x05, 0x01, (byte)(xid >> 24), (byte)(xid >> 16), (byte)(xid >> 8), (byte)xid,
            0, 0, (byte)(blocks.Count >> 8), (byte)blocks.Count]);
        frame.AddRange(blocks);
        while (frame.Count < 60) frame.Add(0);
        return frame.ToArray();
    }

    private static void IdentifyAnswers()
    {
        Section("identify answers");
        var dev = new NetDevice { MacAddress = Device };
        bool read = DcpProtocol.TryParseIdentifyResponse(IdentifyAnswer(0x01020304, vlan: false, "et200sp-u20-k1"), 0x01020304, dev);
        Check("read: name, type, IP, mask, gateway, vendor id, device id, role",
            read && dev.NameOfStation == "et200sp-u20-k1" && dev.VendorName == "ET 200SP"
            && Equals(dev.IPAddress, IPAddress.Parse("192.168.0.10")) && Equals(dev.SubnetMask, IPAddress.Parse("255.255.255.0"))
            && Equals(dev.Gateway, IPAddress.Parse("192.168.0.1")) && dev.VendorId == 0x002a && dev.DeviceId == 0x0313 && dev.DeviceRole == 1);
        var tagged = new NetDevice { MacAddress = Device };
        Check("behind an 802.1Q tag, read the same",
            DcpProtocol.TryParseIdentifyResponse(IdentifyAnswer(5, vlan: true, "x"), 5, tagged) && tagged.NameOfStation == "x");
        Check("another transaction's answer is not ours",
            !DcpProtocol.TryParseIdentifyResponse(IdentifyAnswer(5, vlan: false, "x"), 6, new NetDevice { MacAddress = Device }));
        Check("a Set answer is not an Identify answer",
            !DcpProtocol.TryParseIdentifyResponse(SetAnswer(Device, 5, 0), 5, new NetDevice { MacAddress = Device }));
    }

    // ---- station names: ProfinetTools' cases --------------------------------------------------------------------

    private static void StationNames()
    {
        Section("station names");
        using Stream stream = typeof(SelfTest).Assembly.GetManifestResourceStream("EthernetTools.station-names.json")
            ?? throw new InvalidOperationException("station-names.json is not embedded");
        using JsonDocument cases = JsonDocument.Parse(stream);
        var wrong = new List<string>();
        int count = 0;
        foreach (JsonElement name in cases.RootElement.GetProperty("valid").EnumerateArray())
        {
            count++;
            if (StationName.Problem(name.GetString()) is string problem) wrong.Add($"\"{name.GetString()}\" refused: {problem}");
        }
        foreach (JsonElement name in cases.RootElement.GetProperty("invalid").EnumerateArray())
        {
            count++;
            if (StationName.Problem(name.GetString()) is null) wrong.Add($"\"{name.GetString()}\" accepted");
        }
        Check($"ProfinetTools' {count} cases: the valid accepted, the invalid refused", count > 20 && wrong.Count == 0, string.Join(" | ", wrong));
        Check("longer than 240 is refused",
            StationName.Problem(string.Join('.', Enumerable.Repeat(new string('a', 60), 4)) + ".x") is string p && p.Contains("240"));

        bool refused;
        try { _ = DcpSet.SetNameAsync(null!, Device, "Plc_1"); refused = false; }
        catch (ArgumentException) { refused = true; }
        Check("Set Name refuses a name that is not a Profinet name before anything is sent", refused);
    }

    // ---- the Set Name dialog ------------------------------------------------------------------------------------

    private static void SetNameDialog()
    {
        Section("set name dialog");
        using var dialog = new SetNameForm("00:1B:1B:12:34:56", "plc1");
        Check("opens with the current name; setting it again is not offered",
            dialog.NewName == "plc1" && !dialog.CanSet && dialog.ProblemText.Contains("already"));
        dialog.TypeName("PLC2");
        Check("capitals become small letters, and a good name can be set",
            dialog.NewName == "plc2" && dialog.CanSet && dialog.ProblemText == "");
        dialog.TypeName("Plc_2");
        Check("a bad name says what is wrong, and cannot be set",
            dialog.NewName == "plc_2" && !dialog.CanSet && dialog.ProblemText.Contains("hyphens"));
        dialog.TypeName("192.168.0.1");
        Check("an IP address is not a name", !dialog.CanSet && dialog.ProblemText.Contains("IP address"));
        dialog.TypeName("");
        Check("nothing typed: no complaint yet, and nothing to set", !dialog.CanSet && dialog.ProblemText == "");

        using var unnamed = new SetNameForm("00:1B:1B:12:34:57", null);
        unnamed.TypeName("et200sp-u20-k1");
        Check("a device without a name can be given one", unnamed.CanSet && unnamed.NewName == "et200sp-u20-k1");
    }
}
