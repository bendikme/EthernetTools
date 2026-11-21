using System.Buffers.Binary;
using System.Net;
using System.Text;
using System.Xml.Linq;
using EthernetTools.Pn;

namespace EthernetTools;

// Spanning tree and CDP heard on the adapter, duplicate addresses and names, I&M0, saved maps (compare, merge) and
// the draw.io export.
internal static partial class SelfTest
{
    /// <summary>An RST BPDU as Dyn-sw253 sent it on the office LAN (bridge, port 13, root, cost 20000) - with made-up MACs.</summary>
    private static byte[] Bpdu(byte[] bridge, int port, byte[] root, uint cost, byte type = 0x02, bool pvst = false)
    {
        var f = new List<byte>();
        f.AddRange(pvst ? [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCD] : [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]);
        f.AddRange(bridge[..5]); f.Add((byte)(bridge[5] + 0x0D)); // the port's own MAC
        f.AddRange([0x00, 0x27]);
        f.AddRange(pvst ? [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x01, 0x0B] : [0x42, 0x42, 0x03]);
        f.AddRange([0x00, 0x00, 0x02, type, 0x3C, 0x80, 0x00]); f.AddRange(root);
        f.AddRange([(byte)(cost >> 24), (byte)(cost >> 16), (byte)(cost >> 8), (byte)cost, 0x80, 0x00]); f.AddRange(bridge);
        f.AddRange([(byte)(0x80 | port >> 8), (byte)port, 0x01, 0x00, 0x14, 0x00, 0x02, 0x00, 0x0F, 0x00, 0x00]);
        while (f.Count < 60) f.Add(0);
        return f.ToArray();
    }

    private static byte[] CdpFrame(byte[] source, string device, string port, string platform, IPAddress address)
    {
        var f = new List<byte> { 0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC };
        f.AddRange(source);
        f.AddRange([0x00, 0x00, 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00, 0x02, 0xB4, 0x00, 0x00]);
        void Tlv(int type, byte[] value) { f.AddRange([(byte)(type >> 8), (byte)type, (byte)((value.Length + 4) >> 8), (byte)(value.Length + 4)]); f.AddRange(value); }
        Tlv(1, Encoding.ASCII.GetBytes(device));
        Tlv(2, [0, 0, 0, 1, 0x01, 0x01, 0xCC, 0x00, 0x04, .. address.GetAddressBytes()]);
        Tlv(3, Encoding.ASCII.GetBytes(port));
        Tlv(4, [0, 0, 0, 0x08]);
        Tlv(6, Encoding.ASCII.GetBytes(platform));
        return f.ToArray();
    }

    private static byte[] Im0Block()
    {
        var b = new List<byte> { 0x00, 0x20, 0x00, 0x38, 0x01, 0x00, 0x00, 0x2A };
        b.AddRange(Encoding.ASCII.GetBytes("6ES7 155-6AU01-0BN0".PadRight(20)));
        b.AddRange(Encoding.ASCII.GetBytes("S C-X4U123456".PadRight(16)));
        b.AddRange([0x00, 0x05, (byte)'V', 4, 1, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x01, 0x00, 0x1E]);
        return b.ToArray();
    }

    private static void Features()
    {
        // ---- spanning tree and CDP ----------------------------------------------------------------------------
        Section("spanning tree and cdp");
        byte[] core = M(1).GetAddressBytes(), rootSw = M(5).GetAddressBytes();
        var stp = Stp.Read(Bpdu(core, 13, rootSw, 20000));
        Check("an RST BPDU: the bridge (chassis MAC), the port it came from (port 13), the root bridge and the cost",
            stp is { Protocol: "STP", RootPathCost: 20000 } && stp.Chassis.ChassisText == Ms(1) && stp.Port.PortText == "port 13"
            && stp.RootBridge!.SequenceEqual(rootSw) && stp.Capabilities == LldpCapabilities.Bridge);
        Check("Cisco PVST+ is read the same; a topology-change notice (no ids) is not",
            Stp.Read(Bpdu(core, 13, rootSw, 20000, pvst: true)) is { Port.PortText: "port 13" } && Stp.Read(Bpdu(core, 13, rootSw, 20000, type: 0x80)) is null);
        Check("one link's cost: 20000 (1 Gbit/s), 2000, 19; two links' (40000) is not", Stp.IsOneLink(20000) && Stp.IsOneLink(2000) && Stp.IsOneLink(19) && !Stp.IsOneLink(40000));
        var cdp = Cdp.Read(CdpFrame(core, Convert.ToHexString(core).ToLowerInvariant(), "gi1/0/13", "Cisco SG350X-48", IPAddress.Parse("10.0.0.1")));
        Check("CDP: a device id that is a MAC (as Cisco small-business switches send it), the port, platform, switch, address",
            cdp is { Protocol: "CDP", SystemDescription: "Cisco SG350X-48" } && cdp.Chassis.ChassisText == Ms(1) && cdp.Port.PortText == "gi1/0/13"
            && cdp.Capabilities.HasFlag(LldpCapabilities.Bridge) && Equals(cdp.ManagementAddress, IPAddress.Parse("10.0.0.1")));
        Check("L2Hello reads all three", L2Hello.Read(Bpdu(core, 13, rootSw, 20000)) is { Protocol: "STP" } && L2Hello.Read(CdpFrame(core, "sw", "1", "x", IPAddress.Loopback)) is { Protocol: "CDP" });

        var devices = new List<NetDevice> { Dev(1, "core"), Dev(5, "root-sw"), Dev(21, "h1") };
        var pc = new ThisPcInfo("this-pc", Ms(99), "10.0.0.99", "Ethernet");
        var g = TopologyBuilder.Build(devices, pc, [stp!, cdp!], [], null);
        TopoNode N(TopoGraph graph, string name) => graph.Nodes.Single(n => n.Name == name);
        var pcLink = g.Links.SingleOrDefault(l => l.A.Kind == TopoKind.ThisPc || l.B.Kind == TopoKind.ThisPc);
        Check("This PC on the switch it heard, on CDP's port name (gi1/0/13) rather than spanning tree's \"port 13\"",
            pcLink is not null && (pcLink.A.Name == "core" ? pcLink.PortA : pcLink.PortB) == "gi1/0/13" && N(g, "core").Kind == TopoKind.Switch);
        var onlyStp = TopologyBuilder.Build(devices, pc, [stp!], [], null);
        Check("with spanning tree alone: on \"port 13\"", onlyStp.Links.Any(l => l.A.Kind == TopoKind.ThisPc && l.PortB == "port 13"));
        Check("the root bridge is marked, and the switch one link's cost from it is drawn cabled to it (probable)",
            N(g, "root-sw") is { StpRoot: true, Kind: TopoKind.Switch }
            && g.Links.Any(l => l.Source == "STP (probable)" && l.A.Name == "core" && l.B.Name == "root-sw"));
        var far = TopologyBuilder.Build(devices, pc, [Stp.Read(Bpdu(core, 13, rootSw, 40000))!], [], null);
        var farRoot = far.Nodes.Concat(far.NotLocated?.Members ?? []).Single(n => n.Name == "root-sw");
        Check("two links' cost: the root is marked, but no cable is drawn to it (where it is stays unknown)",
            farRoot.StpRoot && !far.Links.Any(l => l.Source == "STP (probable)"));

        // ---- duplicate addresses and names ----------------------------------------------------------------------
        Section("duplicates");
        var dupA = Dev(10, "a"); var dupB = Dev(11, "b"); dupB.IPAddress = IPAddress.Parse("10.0.0.10");
        var pnX = Dev(12, "plc", profinet: true); var pnY = Dev(13, "PLC", profinet: true); var fine = Dev(14, "c");
        var claims = new Dictionary<string, HashSet<string>>
        {
            ["10.0.0.10"] = new(StringComparer.OrdinalIgnoreCase) { Ms(10), Ms(11) },
            ["10.0.0.14"] = new(StringComparer.OrdinalIgnoreCase) { Ms(14) },
        };
        var problems = Conflicts.Find([dupA, dupB, pnX, pnY, fine], claims);
        Check("an IP two MACs claim in ARP: both have the problem, each naming the other",
            problems.GetValueOrDefault(dupA)?.Contains(Ms(11)) == true && problems.GetValueOrDefault(dupB)?.Contains(Ms(10)) == true);
        Check("a name of station on two Profinet devices (any case): both; a device with neither: none",
            problems.GetValueOrDefault(pnX)?.Contains("name of station") == true && problems.GetValueOrDefault(pnY)?.Contains(Ms(12)) == true
            && !problems.ContainsKey(fine));

        // ---- I&M0 -------------------------------------------------------------------------------------------------
        Section("i&m0");
        var im = ProfinetRpc.ReadIm0(Im0Block());
        Check("I&M0: vendor, order number, serial, hardware revision, firmware V4.1.0",
            im is { VendorId: 0x002A, OrderId: "6ES7 155-6AU01-0BN0", SerialNumber: "S C-X4U123456", HardwareRevision: 5, SoftwareRevision: "V4.1.0" });
        using (var device = new FakePnDevice(new Dictionary<(ushort, ushort), byte[]> { [(ProfinetRpc.IndexIm0, 0x8000)] = Im0Block() }))
        {
            var read = Task.Run(() => ProfinetRpc.ReadIm0Async(IPAddress.Loopback, 0x002A, 0x0313, TimeSpan.FromMilliseconds(300), CancellationToken.None, device.Port))
                .GetAwaiter().GetResult();
            Check("I&M0 over PNIO RPC: subslot 1 refused, read at 0x8000", read is { OrderId: "6ES7 155-6AU01-0BN0" });
        }

        // ---- saved maps: compare, merge --------------------------------------------------------------------------
        Section("saved maps");
        TopoGraph Map(params (string Name, int Mac, string Port)[] devicesOnS)
        {
            var map = new TopoGraph();
            var me = new TopoNode { Id = "this-pc", Kind = TopoKind.ThisPc, Name = "this-pc", Mac = Ms(99) };
            var s = new TopoNode { Id = "mac:" + Ms(2), Kind = TopoKind.Switch, Name = "sw", Mac = Ms(2) };
            map.Nodes.AddRange([me, s]);
            map.Root = me;
            map.Links.Add(new TopoLink(me, "Ethernet", s, "", "MAC table"));
            foreach (var (name, mac, port) in devicesOnS)
            {
                var d = new TopoNode { Id = "mac:" + Ms(mac), Kind = TopoKind.Host, Name = name, Mac = Ms(mac), Ip = $"10.0.0.{mac}" };
                map.Nodes.Add(d);
                map.Links.Add(new TopoLink(s, port, d, "", "MAC table"));
            }
            return map;
        }
        var before = TopologySnapshot.From(Map(("d1", 31, "1"), ("d2", 32, "2"), ("d3", 33, "")), "pc-a", "Ethernet");
        var json = before.ToJson();
        var back = TopologySnapshot.FromJson(json);
        Check("a map saved to JSON reads back the same", back.Nodes.Count == before.Nodes.Count && back.Links.Count == before.Links.Count && back.Pc == "pc-a");
        var now = TopologySnapshot.From(Map(("d1", 31, "4"), ("d3", 33, "3"), ("d4", 34, "5")), "pc-a", "Ethernet");
        var diff = SnapshotDiff.Compare(back, now);
        Check("compared: d4 new, d2 gone, d1 moved (port 1 -> 4); d3 only newly located (port ? -> 3) is not a move",
            diff.New.Select(n => n.Name).SequenceEqual(["d4"]) && diff.Gone.Select(n => n.Name).SequenceEqual(["d2"])
            && diff.Moved is [{ Device.Name: "d1" } moved] && moved.From.Contains("port 1") && moved.To.Contains("port 4")
            && diff.Report(back).Contains("Moved (1)"));
        bool refused;
        try { TopologySnapshot.FromJson("{\"nothing\": 1}"); refused = false; } catch (Exception) { refused = true; }
        Check("a file that is not a saved map is refused", refused);

        // this map: d5 behind sw, port not known; another PC's map: that PC on sw port 7 (spanning tree), d5 on port 9
        var here = Map();
        var d5 = new TopoNode { Id = "mac:" + Ms(35), Kind = TopoKind.Host, Name = "d5", Mac = Ms(35) };
        var unknownPort = new TopoNode { Id = "behind:sw", Kind = TopoKind.Group, Name = "Port not known" };
        unknownPort.Members.Add(d5);
        here.Nodes.Add(unknownPort);
        here.Links.Add(new TopoLink(here.Nodes[1], "", unknownPort, "", "MAC table"));
        var theirs = new TopologySnapshot
        {
            Pc = "pc-b", Adapter = "Ethernet",
            Nodes = [new() { Id = "this-pc", Kind = "ThisPc", Name = "pc-b", Mac = Ms(98) }, new() { Id = "x", Kind = "Switch", Name = "sw", Mac = Ms(2) },
                     new() { Id = "y", Kind = "Host", Name = "d5", Mac = Ms(35) }],
            Links = [new() { A = "this-pc", PortA = "Ethernet", B = "x", PortB = "port 7", Source = "STP (heard)" },
                     new() { A = "x", PortA = "9", B = "y", PortB = "", Source = "MAC table" }],
        };
        int added = TopologyMerge.Apply(here, theirs);
        Check("merged: the other PC drawn on its port (7), d5 moved from \"port not known\" onto port 9, the empty group gone",
            added == 2 && here.Links.Any(l => l.B.Name == "pc-b (other PC)" && l.PortA == "port 7" || l.A.Name == "pc-b (other PC)" && l.PortB == "port 7")
            && here.Links.Any(l => l.A.Name == "sw" && l.PortA == "9" && l.B == d5) && !here.Nodes.Contains(unknownPort) && here.Nodes.Contains(d5));
        Check("merging the same map again adds nothing", TopologyMerge.Apply(here, theirs) == 0);

        // ---- CDP over SNMP (CISCO-CDP-MIB), and the switch tables ---------------------------------------------------
        Section("cdp-mib and tables");
        const string cdp1 = TopologyDiscovery.CdpCacheTable;
        var coreAgent = new SnmpAgentData { Ip = IPAddress.Parse("10.0.0.1"), LocalChassis = ChassisMac(1), Services = 2, SysName = "core" };
        TopologyDiscovery.ReadCdpNeighbors(coreAgent,
        [
            Int($"{cdp1}.3.10049.1", 1), Str($"{cdp1}.4.10049.1", [10, 0, 0, 6]), Str($"{cdp1}.6.10049.1", "edge-sw"),
            Str($"{cdp1}.7.10049.1", "GigabitEthernet0/1"), Str($"{cdp1}.8.10049.1", "cisco WS-C2960"), Str($"{cdp1}.9.10049.1", [0, 0, 0, 0x28]),
            Str($"{cdp1}.6.10050.3", "02aa.0000.0007"), Str($"{cdp1}.7.10050.3", "gi1/0/2"), Str($"{cdp1}.9.10050.3", [0, 0, 0, 0x01]),
            // as the office's Aruba fills it for a neighbour it knows by LLDP: the device id as six raw MAC bytes
            Str($"{cdp1}.6.15.1", M(8).GetAddressBytes()), Str($"{cdp1}.7.15.1", "1"), Str($"{cdp1}.9.15.1", [0, 0, 0, 0x08]),
        ]);
        TopologyDiscovery.ReadIfNames(coreAgent, [Str($"{TopologyDiscovery.IfName}.10049", "Gi1/0/49"), Str($"{TopologyDiscovery.IfName}.10050", "Gi1/0/50")]);
        LldpNeighbor CdpOn(int ifIndex) => coreAgent.Neighbors.Single(n => n.LocalPort == -ifIndex).Neighbor;
        var e1 = CdpOn(10049);
        Check("cdpCacheTable: device id, port, platform, switch capability, address; a device id as a Cisco-dotted MAC or six raw bytes is the chassis MAC; local port by ifName",
            coreAgent.Neighbors.Count == 3 && e1 is { Protocol: "CDP", SystemName: "edge-sw", SystemDescription: "cisco WS-C2960" }
            && e1.Port.PortText == "GigabitEthernet0/1" && e1.Capabilities.HasFlag(LldpCapabilities.Bridge) && Equals(e1.ManagementAddress, IPAddress.Parse("10.0.0.6"))
            && CdpOn(10050).Chassis.ChassisText == Ms(7) && CdpOn(10050).Capabilities.HasFlag(LldpCapabilities.Router)
            && CdpOn(15).Chassis.ChassisText == Ms(8) && CdpOn(15).SystemName == ""
            && coreAgent.PortName(-10049) == "Gi1/0/49" && coreAgent.PortName(-99) == "ifIndex 99");
        var cdpMap = TopologyBuilder.Build([Dev(1, "core"), Dev(6, "edge-sw"), Dev(7, "rtr")], pc, [], [coreAgent], null);
        Check("on the map: a cable from CDP, each end's port (Gi1/0/49 - GigabitEthernet0/1)",
            cdpMap.Links.Any(l => l.Source == "CDP" && l.A.Name == "core" && l.PortA == "Gi1/0/49" && l.B.Name == "edge-sw" && l.PortB == "GigabitEthernet0/1"));
        coreAgent.Neighbors.Insert(0, (49, Nb(new LldpId(7, Encoding.ASCII.GetBytes("edge-sw")), IfName("gi0/1"), "edge-sw", LldpCapabilities.Bridge)));
        var both = TopologyBuilder.Build([Dev(1, "core"), Dev(6, "edge-sw"), Dev(7, "rtr")], pc, [], [coreAgent], null);
        Check("the same cable from LLDP and CDP: one cable, LLDP's", both.Links.Count(l => (l.A.Name, l.B.Name) is ("core", "edge-sw") or ("edge-sw", "core")) == 1
            && both.Links.Single(l => l.B.Name == "edge-sw").Source == "LLDP");

        coreAgent.Fdb[Ms(21)] = 5; coreAgent.Fdb[Ms(22)] = 6; coreAgent.Fdb[Ms(23)] = 6;
        using (var tables = new SwitchTablesForm([coreAgent], [stp!, cdp!], [Dev(21, "h1"), Dev(22, "h2")], coreAgent))
        {
            var t = tables.TablesFor(coreAgent);
            var mac = t[0];
            Check("switch tables: the MAC table (3 rows, MACs per port, the device each is), LLDP (1) and CDP (3) neighbours",
                mac.Rows.Count == 3 && t[1].Rows.Count == 1 && t[2].Rows.Count == 3
                && mac.Rows.Cast<System.Data.DataRow>().Any(r => (string)r["MAC"] == Ms(22) && (int)r["MACs on port"] == 2 && (string)r["Device"] == "h2")
                && t[2].Rows.Cast<System.Data.DataRow>().Any(r => (string)r["Local port"] == "Gi1/0/49"));
            var heardTable = SwitchTablesForm.HeardTable([stp!, cdp!]);
            Check("what This PC heard: CDP before spanning tree, the root bridge and cost shown",
                heardTable.Rows.Count == 2 && (string)heardTable.Rows[0]["Protocol"] == "CDP" && (string)heardTable.Rows[1]["Root path cost"] == "20000");
            string csvText = SwitchTablesForm.TableText(t[2], ',');
            Check("a table as CSV: the header, then one line per row, quoted where needed",
                csvText.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length == 4 && csvText.StartsWith("Local port,Chassis,Port"));
        }

        // ---- draw.io ----------------------------------------------------------------------------------------------
        Section("draw.io");
        var layout = TopologyLayout.Layout(TopologyBuilder.Build(devices, pc, [stp!, cdp!], [], null));
        var xml = XDocument.Parse(DrawIoExport.Build(layout, "test"));
        var cells = xml.Descendants("mxCell").ToList();
        Check("draw.io: an mxGraph file, one vertex per box and one edge per cable, cables labelled with their ports",
            xml.Root?.Name == "mxfile" && cells.Count(c => (string?)c.Attribute("vertex") == "1") == layout.Nodes.Count
            && cells.Count(c => (string?)c.Attribute("edge") == "1") == layout.Links.Count
            && cells.Any(c => ((string?)c.Attribute("value"))?.Contains("gi1/0/13") == true));
    }
}
