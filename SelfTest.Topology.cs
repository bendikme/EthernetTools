using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using EthernetTools.Pn;

namespace EthernetTools;

// The topology map's part of the self-test: the SNMP encoding, LLDP frames, the LLDP-MIB / BRIDGE-MIB tables, and a
// whole map built and laid out from a made-up network (no real names or addresses).
internal static partial class SelfTest
{
    // ---- SNMP (BER) -----------------------------------------------------------------------------------------------

    private static void Snmp()
    {
        Section("snmp");
        // the textbook v1 GET of sysDescr.0, community "public", request id 1
        byte[] get = Ber.Request(SnmpVersion.V1, "public", Ber.PduGet, 1, ["1.3.6.1.2.1.1.1.0"]);
        Check("GET sysDescr.0 (v1, public): the textbook bytes",
            Hex(get) == "302602010004067075626C6963A019020101020100020100300E300C06082B060102010101000500");
        byte[] lldpOid = Ber.Oid("1.0.8802.1.1.2.1.4.1.1");
        Check("an OID with a big arc (8802 = C4 62) encodes and reads back",
            Hex(lldpOid) == "060A28C462010102010401" + "01" && Ber.ReadOid(lldpOid.AsSpan(2)) == "1.0.8802.1.1.2.1.4.1.1");
        var ints = new (long Value, string Bytes)[] { (0, "020100"), (127, "02017F"), (128, "02020080"), (256, "02020100"), (-1, "0201FF"), (-129, "0202FF7F") };
        Check("INTEGERs in the fewest bytes that keep the sign, and back",
            ints.All(i => Hex(Ber.Integer(i.Value)) == i.Bytes && Ber.ReadInteger(Ber.Integer(i.Value).AsSpan(2)) == i.Value));

        string longText = new('x', 200);
        byte[] response = Ber.Sequence(0x30, Ber.Integer(1), Ber.OctetString("public"),
            Ber.Sequence(Ber.PduResponse, Ber.Integer(42), Ber.Integer(0), Ber.Integer(0),
                Ber.Sequence(0x30,
                    Ber.Sequence(0x30, Ber.Oid("1.3.6.1.2.1.1.5.0"), Ber.OctetString(longText)),
                    Ber.Sequence(0x30, Ber.Oid("1.3.6.1.2.1.2.2.1.10.1"), Ber.Tlv(SnmpValue.TagCounter32, [0xFF, 0xFF, 0xFF, 0xFF])),
                    Ber.Sequence(0x30, Ber.Oid("1.3.6.1.2.1.99"), Ber.Tlv(SnmpValue.TagEndOfMibView, [])))));
        var r = Ber.ReadResponse(response);
        Check("a response is read: request id, a 200-byte string (long-form length), a Counter32, endOfMibView",
            r.RequestId == 42 && r.ErrorStatus == 0 && r.VarBinds.Count == 3
            && r.VarBinds[0].Oid == "1.3.6.1.2.1.1.5.0" && r.VarBinds[0].Value.AsText() == longText
            && r.VarBinds[1].Value.AsInteger() == 4294967295 && r.VarBinds[2].Value.IsMissing);
        byte[] bulk = Ber.Request(SnmpVersion.V2c, "public", Ber.PduGetBulk, 7, ["1.3.6.1"], 0, 24);
        int at = 0;
        var (_, message) = Ber.Read(bulk, ref at);
        int m = 0;
        Ber.Read(message, ref m); Ber.Read(message, ref m);
        var (pdu, body) = Ber.Read(message, ref m);
        int p = 0;
        Ber.Read(body, ref p);
        long nonRepeaters = Ber.ReadInteger(Ber.Read(body, ref p).Content), repetitions = Ber.ReadInteger(Ber.Read(body, ref p).Content);
        Check("GETBULK (v2c): PDU 0xA5, version 1, non-repeaters 0, max-repetitions 24",
            pdu == Ber.PduGetBulk && bulk[4] == 1 && nonRepeaters == 0 && repetitions == 24);
        Check("OIDs compare by number, not by text", SnmpClient.CompareOid("1.3.6.1.2.1.2", "1.3.6.1.2.1.10") < 0
            && SnmpClient.CompareOid("1.3.6.1.2", "1.3.6.1.2.1") < 0 && SnmpClient.CompareOid("1.3.6", "1.3.6") == 0);
        bool refused;
        try { Ber.ReadResponse([0x30, 0x05, 0x02, 0x01]); refused = false; } catch (FormatException) { refused = true; }
        Check("a truncated message is refused, not misread", refused);
    }

    // ---- LLDP frames ----------------------------------------------------------------------------------------------

    private static byte[] LldpFrame(byte[] source, bool vlan, params (int Type, byte[] Value)[] tlvs)
    {
        var f = new List<byte> { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };
        f.AddRange(source);
        if (vlan) f.AddRange([0x81, 0x00, 0xE0, 0x00]);
        f.AddRange([0x88, 0xCC]);
        foreach (var (type, value) in tlvs)
        {
            f.Add((byte)((type << 1) | (value.Length >> 8)));
            f.Add((byte)value.Length);
            f.AddRange(value);
        }
        f.AddRange([0, 0]);
        while (f.Count < 60) f.Add(0);
        return f.ToArray();
    }

    private static byte[] Bytes(byte first, string text) => [first, .. Encoding.ASCII.GetBytes(text)];

    private static void LldpFrames()
    {
        Section("lldp frames");
        byte[] portMac = [0x02, 0, 0, 0, 0x10, 0x2F];
        // a switch: chassis and port by MAC, an org-specific TLV, name, bridge+router, a management address
        byte[] sw = LldpFrame(portMac, false,
            (1, [4, 0x02, 0, 0, 0, 0x10, 0x22]), (2, [3, .. portMac]), (3, [0, 120]),
            (127, [0x00, 0x12, 0x0F, 0x01, 0x03, 0x6C, 0x00, 0x00, 0x1E]),
            (5, Encoding.ASCII.GetBytes("core-sw1")), (7, [0x00, 0x14, 0x00, 0x14]),
            (8, [5, 1, 10, 0, 0, 253, 2, 0, 1, 0x86, 0xB3, 0]));
        var n = Lldp.Read(sw);
        Check("a switch's frame: chassis MAC, port MAC, name, bridge + router, management address",
            n is not null && n.Chassis.IsChassisMac && n.Chassis.ChassisText == "02:00:00:00:10:22" && n.Port.Subtype == 3
            && n.Port.PortText == "02:00:00:00:10:2F" && n.SystemName == "core-sw1"
            && n.Capabilities == (LldpCapabilities.Bridge | LldpCapabilities.Router)
            && Equals(n.ManagementAddress, IPAddress.Parse("10.0.0.253")) && n.SourceMac.AsSpan().SequenceEqual(portMac));
        Check("a port named by its MAC shows its description when there is one",
            n is not null && TopologyDiscovery.PortName(n.Port, "") == "02:00:00:00:10:2F" && TopologyDiscovery.PortName(n.Port, "gi1/0/13") == "gi1/0/13");

        // a Profinet device: chassis = name of station, port "port-002.<station>", station only; behind a VLAN tag
        byte[] pn = LldpFrame([0x02, 0, 0, 0, 0x20, 0x01], true,
            (1, Bytes(7, "et200sp-u20-k1")), (2, Bytes(7, "port-002.et200sp-u20-k1")), (3, [0, 20]), (7, [0x00, 0x80, 0x00, 0x80]));
        var d = Lldp.Read(pn);
        Check("a Profinet device's frame (behind an 802.1Q tag): its station name, \"port-002\", a station",
            d is not null && d.Chassis.ChassisText == "et200sp-u20-k1" && !d.Chassis.IsChassisMac
            && TopologyDiscovery.PortName(d.Port, "") == "port-002" && d.Capabilities == LldpCapabilities.Station);
        Check("a frame that is not LLDP is not read", Lldp.Read(DcpProtocol.BuildIdentifyAllRequest(Own, 1)) is null);
        Check("SNMP capability BITS (0x28: bridge, router) read in the frame's order",
            Lldp.FromSnmpBits([0x28]) == (LldpCapabilities.Bridge | LldpCapabilities.Router) && Lldp.FromSnmpBits([0x01, 0x00]) == LldpCapabilities.Station);
        Check("capability BITS with the two octets swapped (00 20, as HPE OfficeConnect sends them) read as a bridge",
            Lldp.FromSnmpBits([0x00, 0x20]) == LldpCapabilities.Bridge && Lldp.FromSnmpBits([0x00, 0x10]) == LldpCapabilities.WlanAccessPoint);
    }

    // ---- LLDP-MIB and BRIDGE-MIB tables ---------------------------------------------------------------------------

    private static SnmpVarBind Int(string oid, long v) => new(oid, new SnmpValue(SnmpValue.TagInteger, Ber.Integer(v)[2..]));
    private static SnmpVarBind Str(string oid, byte[] v) => new(oid, new SnmpValue(SnmpValue.TagOctetString, v));
    private static SnmpVarBind Str(string oid, string v) => Str(oid, Encoding.ASCII.GetBytes(v));

    private static void SnmpTables()
    {
        Section("snmp tables");
        const string rem = TopologyDiscovery.LldpRemTable, loc = TopologyDiscovery.LldpLocPortTable;
        var agent = new SnmpAgentData { Ip = IPAddress.Parse("10.0.0.2") };
        TopologyDiscovery.ReadNeighbors(agent,
        [
            Int($"{rem}.4.0.23.1", 4), Str($"{rem}.5.0.23.1", [0x02, 0, 0, 0, 0x10, 0x22]),
            Int($"{rem}.6.0.23.1", 5), Str($"{rem}.7.0.23.1", "gi1/0/31"), Str($"{rem}.8.0.23.1", ""),
            Str($"{rem}.9.0.23.1", "core-sw1"), Str($"{rem}.12.0.23.1", [0x28]),
        ],
        [Int($"{TopologyDiscovery.LldpRemManAddrIfSubtype}.0.23.1.1.4.10.0.0.253", 2)]);
        Check("lldpRemTable: a neighbour on local port 23 - chassis MAC, port, name, capabilities, management address",
            agent.Neighbors is [(23, var nb)] && nb.Chassis.ChassisText == "02:00:00:00:10:22" && nb.Port.PortText == "gi1/0/31"
            && nb.SystemName == "core-sw1" && nb.Capabilities == (LldpCapabilities.Bridge | LldpCapabilities.Router)
            && Equals(nb.ManagementAddress, IPAddress.Parse("10.0.0.253")));

        TopologyDiscovery.ReadLocalPorts(agent,
        [
            Int($"{loc}.2.5", 7), Str($"{loc}.3.5", "5"), Str($"{loc}.4.5", "5"),
            Int($"{loc}.2.1", 7), Str($"{loc}.3.1", "port-001.et200sp-u20-k1"), Str($"{loc}.4.1", "Siemens, port 1"),
        ]);
        Check("lldpLocPortTable: the ports' names (a Profinet port id as \"port-001\")",
            agent.LocalPorts.GetValueOrDefault(5) == "5" && agent.LocalPorts.GetValueOrDefault(1) == "port-001");

        TopologyDiscovery.ReadFdb(agent,
        [
            Int($"{TopologyDiscovery.Dot1dTpFdbPort}.0.1.236.176.238.206", 23),
            Int($"{TopologyDiscovery.Dot1qTpFdbPort}.1.0.12.41.43.114.41", 7),
            Int($"{TopologyDiscovery.Dot1dTpFdbPort}.2.0.0.0.0.1", 0),
        ]);
        Check("MAC tables (dot1d and dot1q indexes) read; a MAC on port 0 (the switch itself) left out",
            agent.Fdb.Count == 2 && agent.Fdb["00:01:EC:B0:EE:CE"] == 23 && agent.Fdb["00:0C:29:2B:72:29"] == 7);
        TopologyDiscovery.ReadBridgePortNames(agent, [Int($"{TopologyDiscovery.Dot1dBasePortIfIndex}.7", 1007)], [Str($"{TopologyDiscovery.IfName}.1007", "1/1/7")]);
        Check("a bridge port's name through its ifIndex", agent.PortName(7) == "1/1/7" && agent.PortName(5) == "5" && agent.PortName(99) == "99");
        agent.LocalPorts[7] = "38:21:C7:00:00:07";
        Check("an LLDP port name that is only a MAC gives way to the interface's name", agent.PortName(7) == "1/1/7");
    }

    // ---- a whole map ----------------------------------------------------------------------------------------------

    private static PhysicalAddress M(int last) => new([0x02, 0xAA, 0, 0, 0, (byte)last]);
    private static string Ms(int last) => string.Join(":", M(last).GetAddressBytes().Select(b => b.ToString("X2")));

    private static NetDevice Dev(int last, string? name = null, bool profinet = false) => new()
    {
        MacAddress = M(last),
        IPAddress = IPAddress.Parse($"10.0.0.{last}"),
        NameOfStation = profinet ? name : null,
        Hostname = profinet ? null : name,
        Sources = profinet ? DiscoverySource.Profinet | DiscoverySource.Arp : DiscoverySource.Arp,
    };

    private static LldpNeighbor Nb(LldpId chassis, LldpId port, string name = "", LldpCapabilities caps = LldpCapabilities.None) =>
        new(chassis, port, "", name, "", caps, null, []);

    private static LldpId ChassisMac(int last) => new(4, M(last).GetAddressBytes());
    private static LldpId Local(string text) => new(7, Encoding.ASCII.GetBytes(text));
    private static LldpId IfName(string text) => new(5, Encoding.ASCII.GetBytes(text));

    private static void TopologyMap()
    {
        Section("topology map");
        // This PC on core switch C (no SNMP) port gi1/0/7. A (SNMP) hangs off C; B (SNMP) off A; a Profinet ring
        // A - pn-1 - pn-2 - A; h1 alone on A:5; h2, h3 and an unknown MAC on A:6 (an unmanaged switch); h4 on B:3;
        // the router and seven hosts seen only through A:8 (towards C); h6 nowhere.
        var devices = new List<NetDevice>
        {
            Dev(1, "core"), Dev(2, "sw-a"), Dev(3, "sw-b"), Dev(11, "pn-1", profinet: true), Dev(12, "pn-2", profinet: true),
            Dev(21, "h1"), Dev(22, "h2"), Dev(23, "h3"), Dev(24, "h4"), Dev(26, "h6"), Dev(27, "h7"), Dev(254, "gw"),
        };
        devices.AddRange(Enumerable.Range(31, 7).Select(i => Dev(i, $"g{i}")));

        SnmpAgentData Agent(int last, LldpId chassis, params string[] ports)
        {
            var a = new SnmpAgentData { Ip = IPAddress.Parse($"10.0.0.{last}"), LocalChassis = chassis, Services = ports.Length > 2 ? 2 : 72 };
            for (int i = 0; i < ports.Length; i++) a.LocalPorts[i + 1] = ports[i];
            return a;
        }
        var a = Agent(2, ChassisMac(2), "1", "2", "3", "4", "5", "6", "7", "8");
        a.Neighbors.Add((8, Nb(ChassisMac(1), IfName("gi1/0/31"), "core", LldpCapabilities.Bridge)));
        a.Neighbors.Add((2, Nb(ChassisMac(3), IfName("1"), "sw-b", LldpCapabilities.Bridge)));
        a.Neighbors.Add((3, Nb(Local("pn-1"), Local("port-001.pn-1"), "pn-1")));
        a.Neighbors.Add((4, Nb(Local("pn-2"), Local("port-002.pn-2"), "pn-2")));
        // a switch the scan did not find, reported by two LLDP agents of its own on A:7 - first by a model name
        a.Neighbors.Add((7, new LldpNeighbor(Local("x200"), IfName("ge-0/0/1"), "", "Vendor X-48 (PID", "", LldpCapabilities.Bridge, IPAddress.Parse("10.0.0.200"), [])));
        a.Neighbors.Add((7, new LldpNeighbor(ChassisMac(200), IfName("ge-0/0/1"), "", "edge-sw", "", LldpCapabilities.Bridge, IPAddress.Parse("10.0.0.200"), [])));
        foreach (var (mac, port) in new[] { (21, 5), (22, 6), (23, 6), (24, 2), (254, 8), (99, 8), (1, 8), (3, 2), (11, 3), (12, 4), (26 + 100, 6) }
                     .Concat(Enumerable.Range(31, 7).Select(i => (i, 8))))
            a.Fdb[Ms(mac)] = port;
        // B names its own ports "1/0/1".., where A's LLDP calls B's port "1": still one cable
        var b = Agent(3, ChassisMac(3), "1/0/1", "1/0/2", "1/0/3", "1/0/4");
        b.Neighbors.Add((1, Nb(ChassisMac(2), IfName("2"), "sw-a", LldpCapabilities.Bridge)));
        foreach (var (mac, port) in new[] { (24, 3), (2, 1), (21, 1), (22, 1), (23, 1) }) b.Fdb[Ms(mac)] = port;
        // h7: A says "towards B", B says "towards A" (tables of different ages) - where it is cannot be told
        a.Fdb[Ms(27)] = 2;
        b.Fdb[Ms(27)] = 1;
        var pn1 = Agent(11, Local("pn-1"), "port-001", "port-002");
        pn1.Neighbors.Add((1, Nb(ChassisMac(2), IfName("3"), "sw-a")));
        pn1.Neighbors.Add((2, Nb(Local("pn-2"), Local("port-001.pn-2"))));
        var pn2 = Agent(12, Local("pn-2"), "port-001", "port-002");
        pn2.Neighbors.Add((1, Nb(Local("pn-1"), Local("port-002.pn-1"))));
        pn2.Neighbors.Add((2, Nb(ChassisMac(2), IfName("4"), "sw-a")));
        var heard = new[] { Nb(ChassisMac(1), IfName("gi1/0/7"), "core", LldpCapabilities.Bridge) };

        var g = TopologyBuilder.Build(devices, new ThisPcInfo("this-pc", Ms(99), "10.0.0.99", "Ethernet"), heard, [a, b, pn1, pn2], IPAddress.Parse("10.0.0.254"));
        TopoNode N(string name) => g.Nodes.Single(n => n.Name == name);
        bool Linked(string x, string px, string y, string py) => g.Links.Count(l =>
            (l.A.Name == x && l.PortA == px && l.B.Name == y && l.PortB == py) || (l.A.Name == y && l.PortA == py && l.B.Name == x && l.PortB == px)) == 1;

        Check("This PC is linked to the switch it heard (its port, the switch's)", Linked("this-pc", "Ethernet", "core", "gi1/0/7"));
        Check("a cable both switches report is one link, each end with its own port name (A:2 - B:1/0/1, though A calls it \"1\")",
            Linked("sw-a", "2", "sw-b", "1/0/1") && g.Links.Count(l => l.A.Name is "sw-a" or "sw-b" && l.B.Name is "sw-a" or "sw-b") == 1);
        Check("the ring A - pn-1 - pn-2 - A: three links, reported from both ends, merged",
            Linked("sw-a", "3", "pn-1", "port-001") && Linked("pn-1", "port-002", "pn-2", "port-001") && Linked("pn-2", "port-002", "sw-a", "4"));
        Check("a switch known from LLDP only, reported twice: one box, named by its host name, with its chassis MAC, one link",
            g.Nodes.Count(n => n.Ip == "10.0.0.200") == 1 && g.Nodes.Single(n => n.Ip == "10.0.0.200") is { Name: "edge-sw", Kind: TopoKind.Switch } e
            && e.Mac == Ms(200) && Linked("sw-a", "7", "edge-sw", "ge-0/0/1"));
        Check("kinds: switches, Profinet devices, the default gateway a router",
            N("core").Kind == TopoKind.Switch && N("sw-a").Kind == TopoKind.Switch && N("sw-b").Kind == TopoKind.Switch
            && N("pn-1").Kind == TopoKind.Profinet && N("gw").Kind == TopoKind.Router);
        Check("a device alone on an edge port is placed there (h1 on A:5, h4 on B:1/0/3 - not on A's uplink to B)",
            Linked("sw-a", "5", "h1", "") && Linked("sw-b", "1/0/3", "h4", ""));
        var hub = g.Nodes.SingleOrDefault(n => n.Kind == TopoKind.UnmanagedSwitch);
        Check("several MACs on one port without an LLDP neighbour: an unmanaged switch, with h2, h3 and one unknown MAC",
            hub is not null && hub.Members.Select(m => m.Name).OrderBy(s => s).SequenceEqual(["h2", "h3"]) && hub.UnknownMacs == 1
            && g.Links.Any(l => l.A.Name == "sw-a" && l.PortA == "6" && ReferenceEquals(l.B, hub)));
        var behind = g.Nodes.SingleOrDefault(n => n.Kind == TopoKind.Group && n.Name == "Port not known");
        Check("seen only towards a switch without SNMP: behind it, port not known - the router drawn, seven hosts as one group",
            Linked("core", "", "gw", "") && behind is not null && behind.Members.Count == 7
            && g.Links.Any(l => l.A.Name == "core" && ReferenceEquals(l.B, behind)) && !g.Nodes.Any(n => n.Name == "g31"));
        Check("not located: a device no table names (h6), and one two switches each place behind the other (h7)",
            g.NotLocated is { } nl && nl.Members.Select(m => m.Name).OrderBy(s => s).SequenceEqual(["h6", "h7"]));

        var layout = TopologyLayout.Layout(g);
        bool overlap = layout.Nodes.Any(x => layout.Nodes.Any(y => !ReferenceEquals(x, y) && RectangleF.Intersect(x.Box, y.Box) is { Width: > 0.5f, Height: > 0.5f }));
        Check("layout: every box placed once, none overlapping, This PC on top",
            layout.Nodes.Count == g.Nodes.Count && layout.Nodes.Select(n => n.Node).Distinct().Count() == g.Nodes.Count && !overlap
            && layout.Nodes.First(n => n.Node.Kind == TopoKind.ThisPc).Box.Top == layout.Nodes.Min(n => n.Box.Top));
        Check("layout: the ring's closing link drawn as redundant (one), every other link along the tree",
            layout.Links.Count(l => l.Redundant) == 1 && layout.Links.Count == g.Links.Count);
        Check("layout: the cable label names both ends' ports", layout.Nodes.Any(n => n.Node.Name == "sw-b" && n.Label == "2 ↔ 1/0/1"));

        // many devices on one port wrap into rows of six, still without overlap
        var many = new TopoGraph();
        var root = new TopoNode { Id = "r", Kind = TopoKind.Switch, Name = "r" };
        many.Nodes.Add(root);
        many.Root = root;
        for (int i = 0; i < 20; i++)
        {
            var leaf = new TopoNode { Id = "l" + i, Name = "l" + i };
            many.Nodes.Add(leaf);
            many.Links.Add(new TopoLink(root, (i + 1).ToString(), leaf, "", "MAC table"));
        }
        var wrapped = TopologyLayout.Layout(many);
        bool wrappedOverlap = wrapped.Nodes.Any(x => wrapped.Nodes.Any(y => !ReferenceEquals(x, y) && x.Box.IntersectsWith(y.Box)));
        Check("layout: 20 devices under one switch in rows of six (4 rows), none overlapping",
            !wrappedOverlap && wrapped.Nodes.Where(n => n.Node != root).Select(n => n.Box.Top).Distinct().Count() == 4);

        using var bmp = new Bitmap(400, 300);
        using (var gr = Graphics.FromImage(bmp)) TopologyView.Render(gr, layout);
        Check("the map draws (no exception)", true);
    }
}
