using System.Net;

namespace EthernetTools.Pn;

public enum TopoKind { ThisPc, Switch, Router, Profinet, Host, UnmanagedSwitch, Group }

/// <summary>A box on the map: a device, an inferred unmanaged switch, or a group of devices drawn as one.</summary>
public sealed class TopoNode
{
    public required string Id { get; init; }
    public TopoKind Kind { get; set; }
    public string Name { get; set; } = "";
    public string? Ip { get; set; }
    public string? Mac { get; set; }
    public string? Vendor { get; set; }
    /// <summary>More about it (the SNMP sysDescr, the LLDP system description, how it was placed).</summary>
    public string? Detail { get; set; }
    /// <summary>The scanned device it is, if any (to select it in the device list).</summary>
    public NetDevice? Device { get; set; }
    /// <summary>A group's devices, or an unmanaged switch's.</summary>
    public List<TopoNode> Members { get; } = new();
    /// <summary>MAC addresses seen where this group / unmanaged switch is that are not among the scanned devices.</summary>
    public int UnknownMacs { get; set; }
    /// <summary>It answered SNMP.</summary>
    public bool Managed { get; set; }

    public override string ToString() => $"{Kind} {Name}";
}

/// <summary>A cable: two boxes and the port at each end ("" where the port is not known).</summary>
public sealed record TopoLink(TopoNode A, string PortA, TopoNode B, string PortB, string Source)
{
    /// <summary>The port's name at that end is the device's own (its LLDP-MIB), not a neighbour's view of it.</summary>
    public bool OwnA { get; init; }
    public bool OwnB { get; init; }
}

public sealed class TopoGraph
{
    public List<TopoNode> Nodes { get; } = new();
    public List<TopoLink> Links { get; } = new();
    public TopoNode? Root { get; set; }
    /// <summary>The devices it could not place (drawn apart, as one group).</summary>
    public TopoNode? NotLocated { get; set; }
    /// <summary>
    /// Switches that do not tell their ports and MAC tables: asked over SNMP without an answer, or with no address to
    /// ask. What is behind them is "port not known" or "not located".
    /// </summary>
    public List<TopoNode> Silent { get; } = new();
}

/// <summary>This PC as the map shows it.</summary>
public sealed record ThisPcInfo(string Name, string Mac, string? Ip, string AdapterName);

/// <summary>
/// Builds the map from what was found: the scanned devices, the LLDP neighbour heard on the adapter, and what the
/// SNMP agents told (LLDP neighbours per port, MAC tables).
/// <list type="bullet">
/// <item>Links: every LLDP neighbour an agent reports (both ends' ports), merged when both ends report the same
/// cable; the neighbour heard on the adapter links This PC.</item>
/// <item>Devices without an LLDP link are placed by the switches' MAC tables: on the edge-most port that sees them
/// (one that leads to no other known switch). A port that sees more than one MAC and has no LLDP neighbour has an
/// unmanaged switch (or a hub, an access point, a virtual-machine host) behind it. A device seen only through a
/// port that leads to a neighbour the map cannot look into is "behind" that neighbour - its port not known.</item>
/// <item>The default gateway is a router.</item>
/// </list>
/// </summary>
public static class TopologyBuilder
{
    /// <summary>More hosts than this behind one place are drawn as one group box.</summary>
    public const int GroupAbove = 6;

    /// <param name="askedSnmp">The addresses asked over SNMP; null while nothing has been asked yet (no switch is then
    /// called silent).</param>
    /// <param name="answeredMacs">The devices that answered just before the MAC tables were read (refreshing them): one
    /// missing from a readable switch's table is placed on This PC's side of that switch.</param>
    /// <param name="snmpProblems">Why a device that answers SNMP refused (an SNMPv3 report), by its address.</param>
    public static TopoGraph Build(IReadOnlyList<NetDevice> devices, ThisPcInfo thisPc, IReadOnlyList<LldpNeighbor> heardOnAdapter,
        IReadOnlyList<SnmpAgentData> agents, IPAddress? gateway, IReadOnlyCollection<IPAddress>? askedSnmp = null,
        IReadOnlyCollection<string>? answeredMacs = null, IReadOnlyDictionary<string, string>? snmpProblems = null)
    {
        var graph = new TopoGraph();
        var byMac = new Dictionary<string, TopoNode>(StringComparer.OrdinalIgnoreCase);
        var byIp = new Dictionary<string, List<TopoNode>>();

        TopoNode Add(TopoNode node)
        {
            graph.Nodes.Add(node);
            if (node.Mac is { Length: > 0 } mac) byMac.TryAdd(mac, node);
            if (node.Ip is { Length: > 0 } ip)
            {
                if (!byIp.TryGetValue(ip, out var list)) byIp[ip] = list = new List<TopoNode>();
                list.Add(node);
            }
            return node;
        }

        // ---- the boxes: This PC, every scanned device, every SNMP agent ------------------------------------------
        var pc = Add(new TopoNode
        {
            Id = "this-pc", Kind = TopoKind.ThisPc, Name = thisPc.Name, Mac = thisPc.Mac, Ip = thisPc.Ip,
            Detail = $"This PC, adapter {thisPc.AdapterName}",
        });
        graph.Root = pc;
        foreach (var d in devices)
        {
            if (string.Equals(d.MacString, thisPc.Mac, StringComparison.OrdinalIgnoreCase)) continue;
            bool profinet = d.Sources.HasFlag(DiscoverySource.Profinet);
            Add(new TopoNode
            {
                Id = "mac:" + d.MacString,
                Kind = profinet ? TopoKind.Profinet : TopoKind.Host,
                Name = d.NameOfStation ?? d.Hostname ?? "",
                Mac = d.MacString,
                Ip = d.IPAddress?.ToString(),
                Vendor = d.VendorName,
                Device = d,
            });
        }

        var agentNode = new Dictionary<SnmpAgentData, TopoNode>();
        foreach (var agent in agents)
        {
            string ip = agent.Ip.ToString();
            string? chassisMac = agent.LocalChassis is { IsChassisMac: true } c ? c.ChassisText : null;
            // the scanned device it is: by its chassis MAC, else by its address
            TopoNode? node = chassisMac is not null && byMac.TryGetValue(chassisMac, out var m) ? m
                : byIp.TryGetValue(ip, out var same) ? same.FirstOrDefault(n => n.Kind != TopoKind.ThisPc) ?? same[0]
                : null;
            node ??= Add(new TopoNode { Id = "snmp:" + ip, Kind = TopoKind.Host, Ip = ip, Mac = chassisMac });
            node.Managed = true;
            if (agent.SysName.Length > 0 && node.Kind != TopoKind.ThisPc) node.Name = agent.SysName;
            node.Detail = agent.FromProfinet
                ? Join(node.Detail, "Neighbours read through Profinet (PDPortDataReal): it does not answer SNMP.")
                : agent.SysDescr;
            if (node.Kind != TopoKind.ThisPc && agent.IsBridge && (node.Kind != TopoKind.Profinet || agent.LocalPorts.Count > 2 || agent.Fdb.Count > 0))
                node.Kind = TopoKind.Switch;
            if (chassisMac is not null) byMac.TryAdd(chassisMac, node);
            agentNode[agent] = node;
        }

        // ---- LLDP: who is the neighbour? ------------------------------------------------------------------------
        var namedByLldp = new HashSet<TopoNode>();
        TopoNode Resolve(LldpNeighbor n)
        {
            if (n.Chassis.IsChassisMac && byMac.TryGetValue(n.Chassis.ChassisText, out var byChassis)) return byChassis;
            if (n.SourceMac.Length == 6 && byMac.TryGetValue(string.Join(":", n.SourceMac.Select(b => b.ToString("X2"))), out var bySource))
                return bySource;
            if (n.ManagementAddress is { } ip && byIp.TryGetValue(ip.ToString(), out var withIp))
                return withIp.FirstOrDefault(x => x.Managed) ?? withIp[0];
            string chassisText = n.Chassis.ChassisText;
            foreach (string name in new[] { n.SystemName, chassisText }.Where(s => s.Length > 0))
            {
                var hit = graph.Nodes.FirstOrDefault(x => x.Kind != TopoKind.Group && SameName(x, name));
                if (hit is not null) return hit;
            }
            // a device the scan did not find (no IP in this subnet, or it does not answer ARP)
            string id = "lldp:" + (n.Chassis.IsChassisMac ? chassisText : n.SystemName.Length > 0 ? n.SystemName : chassisText);
            var known = graph.Nodes.FirstOrDefault(x => x.Id == id);
            if (known is not null) return known;
            var kind = n.Capabilities.HasFlag(LldpCapabilities.Bridge) && !n.Capabilities.HasFlag(LldpCapabilities.Station) ? TopoKind.Switch
                : n.Capabilities.HasFlag(LldpCapabilities.Router) ? TopoKind.Router
                : TopoKind.Host;
            var created = Add(new TopoNode
            {
                Id = id, Kind = kind,
                Name = n.SystemName.Length > 0 ? n.SystemName : chassisText,
                Ip = n.ManagementAddress?.ToString(),
                Mac = n.Chassis.IsChassisMac ? chassisText : null,
                Detail = "Known from LLDP only (the scan did not find it).",
            });
            namedByLldp.Add(created);
            return created;
        }

        bool SameName(TopoNode node, string name)
        {
            static string Short(string s) => s.Split('.')[0];
            return node.Name.Length > 0 && (string.Equals(node.Name, name, StringComparison.OrdinalIgnoreCase)
                || string.Equals(Short(node.Name), Short(name), StringComparison.OrdinalIgnoreCase));
        }

        // ownA / ownB: that end's port is named by the device itself (an agent's own port), not by its neighbour
        void Link(TopoNode a, string portA, TopoNode b, string portB, string source, bool ownA = false, bool ownB = false)
        {
            if (ReferenceEquals(a, b)) return;
            // The same cable reported from both ends, or twice from one: keep one. A port carries one cable, so two
            // reports between the same two boxes that agree on one end's port are one cable, even when the other end
            // names its port differently (its own "1/0/1" against the neighbour's "1"): each end keeps its own name.
            foreach (var (l, i) in graph.Links.Select((l, i) => (l, i)))
            {
                bool forward = ReferenceEquals(l.A, a) && ReferenceEquals(l.B, b);
                bool reverse = ReferenceEquals(l.A, b) && ReferenceEquals(l.B, a);
                if (!forward && !reverse) continue;
                var (la, lownA) = forward ? (l.PortA, l.OwnA) : (l.PortB, l.OwnB);
                var (lb, lownB) = forward ? (l.PortB, l.OwnB) : (l.PortA, l.OwnA);
                bool same = Same(la, portA) || Same(lb, portB) || (Fits(la, portA) && Fits(lb, portB));
                if (!same) continue;
                var (pa, oa) = Pick(la, lownA, portA, ownA);
                var (pb, ob) = Pick(lb, lownB, portB, ownB);
                graph.Links[i] = forward
                    ? l with { PortA = pa, OwnA = oa, PortB = pb, OwnB = ob }
                    : l with { PortA = pb, OwnA = ob, PortB = pa, OwnB = oa };
                return;
            }
            graph.Links.Add(new TopoLink(a, portA, b, portB, source) { OwnA = ownA, OwnB = ownB });

            static bool Same(string x, string y) => x.Length > 0 && string.Equals(x, y, StringComparison.OrdinalIgnoreCase);
            static bool Fits(string known, string port) => known.Length == 0 || port.Length == 0 || Same(known, port);
            static (string, bool) Pick(string old, bool oldOwn, string now, bool nowOwn) =>
                now.Length > 0 && nowOwn && !oldOwn ? (now, true) : old.Length > 0 ? (old, oldOwn) : (now, nowOwn);
        }

        void Learn(TopoNode node, LldpNeighbor n)
        {
            if (node.Mac is null && n.Chassis.IsChassisMac)
            {
                node.Mac = n.Chassis.ChassisText;
                byMac.TryAdd(node.Mac, node);
            }
            // what LLDP tells of a box the scan knew only by its addresses; of two names, the one that reads like a
            // host name ("Dyn-sw253" rather than "Cisco SG350X-48 (PI...", which some agents report)
            static bool HostLike(string s) => s.Length > 0 && !s.Any(char.IsWhiteSpace);
            if (n.SystemName.Length > 0 && (node.Name.Length == 0
                    || (namedByLldp.Contains(node) && !HostLike(node.Name) && HostLike(n.SystemName))))
            {
                node.Name = n.SystemName;
                namedByLldp.Add(node);
            }
            if (n.SystemDescription.Length > 0 && (string.IsNullOrEmpty(node.Detail) || node.Detail.StartsWith("Known from LLDP only")))
                node.Detail = n.SystemDescription + (node.Detail is { Length: > 0 } d ? "\n" + d : "");
        }

        foreach (var (agent, node) in agentNode)
            foreach (var (localPort, neighbor) in agent.Neighbors)
            {
                var other = Resolve(neighbor);
                Learn(other, neighbor);
                if (other.Kind == TopoKind.Host && neighbor.Capabilities.HasFlag(LldpCapabilities.Bridge)
                    && !neighbor.Capabilities.HasFlag(LldpCapabilities.Station) && other.Device?.Sources.HasFlag(DiscoverySource.Profinet) != true)
                    other.Kind = TopoKind.Switch;
                Link(node, agent.PortName(localPort), other, TopologyDiscovery.PortName(neighbor.Port, neighbor.PortDescription), "LLDP", ownA: true);
            }
        foreach (var neighbor in heardOnAdapter)
        {
            var other = Resolve(neighbor);
            if (ReferenceEquals(other, pc)) continue;
            Learn(other, neighbor);
            if (other.Kind == TopoKind.Host && neighbor.Capabilities.HasFlag(LldpCapabilities.Bridge)) other.Kind = TopoKind.Switch;
            Link(pc, thisPc.AdapterName, other, TopologyDiscovery.PortName(neighbor.Port, neighbor.PortDescription), "LLDP (heard)", ownA: true);
        }

        // ---- routers --------------------------------------------------------------------------------------------
        if (gateway is not null && byIp.TryGetValue(gateway.ToString(), out var routers))
            foreach (var r in routers.Where(r => r.Kind is TopoKind.Host)) { r.Kind = TopoKind.Router; r.Detail = Join(r.Detail, "Default gateway"); }

        // ---- MAC tables: place what LLDP did not ----------------------------------------------------------------
        var linked = new HashSet<TopoNode>(graph.Links.SelectMany(l => new[] { l.A, l.B }));
        var bridges = agentNode.Where(a => a.Key.Fdb.Count > 0).ToList();
        var portMacs = new Dictionary<(TopoNode Switch, int Port), List<string>>();
        foreach (var (agent, node) in bridges)
            foreach (var (mac, port) in agent.Fdb)
            {
                if (!portMacs.TryGetValue((node, port), out var list)) portMacs[(node, port)] = list = new List<string>();
                list.Add(mac);
            }

        // A port leads to a neighbour when LLDP names one there (an uplink, a ring port, a Profinet line).
        TopoNode? NeighborOn(SnmpAgentData agent, int port)
        {
            string name = agent.PortName(port);
            var node = agentNode[agent];
            var link = graph.Links.FirstOrDefault(l => l.Source.StartsWith("LLDP")
                && ((ReferenceEquals(l.A, node) && l.PortA == name) || (ReferenceEquals(l.B, node) && l.PortB == name)));
            return link is null ? null : ReferenceEquals(link.A, node) ? link.B : link.A;
        }

        var unmanaged = new Dictionary<(TopoNode, int), TopoNode>();
        var behind = new Dictionary<TopoNode, TopoNode>(); // neighbour -> its "port not known" group
        // This PC's place in each readable switch's (complete) table: a device that answered just now - its answer
        // reached This PC - but is missing from such a table did not send it through that switch. It is on This PC's
        // side of the switch, behind the port This PC is seen on. Which switch first; the port where it can be told.
        var answered = answeredMacs is null ? null : new HashSet<string>(answeredMacs, StringComparer.OrdinalIgnoreCase);
        var pcSide = thisPc.Mac is { Length: > 0 } pcMac
            ? bridges.Where(b => b.Key.FdbComplete && b.Key.Fdb.ContainsKey(pcMac))
                .Select(b => (Agent: b.Key, Switch: b.Value, Port: b.Key.Fdb[pcMac])).ToList()
            : [];
        bool Readable(TopoNode n) => bridges.Any(b => ReferenceEquals(b.Value, n));

        void OnPort(SnmpAgentData agent, TopoNode sw, int portNumber, TopoNode node, bool inferred)
        {
            string port = agent.PortName(portNumber);
            int macs = portMacs.TryGetValue((sw, portNumber), out var list) ? list.Count + (inferred ? 1 : 0) : 1;
            if (macs <= 1)
            {
                Link(sw, port, node, "", "MAC table");
                node.Detail = Join(node.Detail, $"Placed by {sw.Name}'s MAC table.");
                return;
            }
            if (!unmanaged.TryGetValue((sw, portNumber), out var hub))
            {
                var known = (list ?? []).Count(m => byMac.ContainsKey(m));
                hub = Add(new TopoNode
                {
                    Id = $"hub:{sw.Id}:{portNumber}", Kind = TopoKind.UnmanagedSwitch,
                    Name = "Unmanaged switch?",
                    UnknownMacs = Math.Max(0, (list?.Count ?? 0) - known),
                    Detail = $"{macs} MAC addresses on {sw.Name} port {port}, and no LLDP neighbour there: an " +
                             "unmanaged switch, a hub, an access point or a virtual-machine host.",
                });
                unmanaged[(sw, portNumber)] = hub;
                Link(sw, port, hub, "", "MAC table");
            }
            hub.Members.Add(node);
            Link(hub, "", node, "", "MAC table");
        }

        void Behind(TopoNode via, TopoNode node)
        {
            if (!behind.TryGetValue(via, out var group))
            {
                group = Add(new TopoNode
                {
                    Id = "behind:" + via.Id, Kind = TopoKind.Group, Name = "Port not known",
                    Detail = $"Behind {via.Name}, which does not tell its own MAC table (no SNMP): the port is not known.",
                });
                behind[via] = group;
                Link(via, "", group, "", "MAC table");
            }
            group.Members.Add(node);
        }

        foreach (var node in graph.Nodes.ToList())
        {
            if (node.Kind is TopoKind.Group or TopoKind.UnmanagedSwitch || linked.Contains(node) || node.Mac is null) continue;
            var seen = bridges
                .Where(b => b.Key.Fdb.ContainsKey(node.Mac))
                .Select(b => (Agent: b.Key, Switch: b.Value, Port: b.Key.Fdb[node.Mac]))
                .Where(c => !ReferenceEquals(c.Switch, node))
                .ToList();

            // what the tables say: the edge-most port that sees it
            var edge = seen.Where(c => NeighborOn(c.Agent, c.Port) is null)
                .OrderBy(c => portMacs[(c.Switch, c.Port)].Count).FirstOrDefault();
            if (edge.Switch is not null) { OnPort(edge.Agent, edge.Switch, edge.Port, node, inferred: false); continue; }

            // only seen through ports that lead on to a neighbour: it is somewhere behind the one whose own MAC table
            // cannot be read. When every such neighbour is a switch whose table was read (each says "behind the
            // other": tables of different ages), the tables cannot tell.
            var via = seen.Select(c => NeighborOn(c.Agent, c.Port)!).FirstOrDefault(n => !Readable(n));
            if (via is not null) { Behind(via, node); continue; }

            // not (or not consistently) in the tables, but it answered just now: on This PC's side of each readable
            // switch whose table misses it
            if (answered is null || node.Kind == TopoKind.ThisPc || !answered.Contains(node.Mac)) continue;
            foreach (var side in pcSide.Where(c => !c.Agent.Fdb.ContainsKey(node.Mac) && !ReferenceEquals(c.Switch, node)))
            {
                var next = NeighborOn(side.Agent, side.Port);
                if (next is not null && Readable(next)) continue; // that switch's table says more
                node.Detail = Join(node.Detail, $"Not in {side.Switch.Name}'s MAC table, though it answered just now: its answer " +
                                                $"did not pass {side.Switch.Name}, so it is on This PC's side of it.");
                if (next is null) OnPort(side.Agent, side.Switch, side.Port, node, inferred: true);
                else Behind(next, node);
                break;
            }
        }

        // ---- big groups stay one box; small ones, routers, switches and Profinet devices are drawn ---------------
        foreach (var group in behind.Values.ToList())
        {
            var show = group.Members.Where(m => m.Kind is not TopoKind.Host || group.Members.Count <= GroupAbove).ToList();
            foreach (var m in show)
            {
                group.Members.Remove(m);
                var via = graph.Links.First(l => ReferenceEquals(l.B, group)).A;
                Link(via, "", m, "", "MAC table");
                m.Detail = Join(m.Detail, $"Behind {via.Name}; the port is not known.");
            }
            if (group.Members.Count == 0)
            {
                graph.Links.RemoveAll(l => ReferenceEquals(l.B, group));
                graph.Nodes.Remove(group);
            }
            else group.Name = "Port not known";
        }
        foreach (var hub in unmanaged.Values)
        {
            hub.Name = $"Unmanaged switch? ({hub.Members.Count + hub.UnknownMacs} MACs)";
            if (hub.Members.Count(m => m.Kind == TopoKind.Host) <= GroupAbove) continue;
            var hosts = hub.Members.Where(m => m.Kind == TopoKind.Host).ToList();
            var group = Add(new TopoNode { Id = "group:" + hub.Id, Kind = TopoKind.Group, Name = "Devices" });
            group.Members.AddRange(hosts);
            graph.Links.RemoveAll(l => ReferenceEquals(l.A, hub) && hosts.Contains(l.B));
            Link(hub, "", group, "", "MAC table");
        }

        // a group's members are drawn as the group: not as boxes of their own
        foreach (var g in graph.Nodes.Where(n => n.Kind == TopoKind.Group).ToList())
            foreach (var m in g.Members) graph.Nodes.Remove(m);

        // ---- what could not be placed ---------------------------------------------------------------------------
        var placed = new HashSet<TopoNode>(graph.Links.SelectMany(l => new[] { l.A, l.B }));
        var lost = graph.Nodes.Where(n => !placed.Contains(n) && n.Kind != TopoKind.ThisPc).ToList();
        if (lost.Count > 0)
        {
            var notLocated = new TopoNode { Id = "not-located", Kind = TopoKind.Group, Name = "Not located" };
            notLocated.Detail = "No LLDP neighbour names them and no switch that answers SNMP has them in its MAC table.";
            notLocated.Members.AddRange(lost);
            foreach (var n in lost) graph.Nodes.Remove(n);
            graph.Nodes.Add(notLocated);
            graph.NotLocated = notLocated;
        }

        // ---- switches that do not tell (their ports, their MAC tables) ------------------------------------------
        if (askedSnmp is not null)
        {
            var asked = askedSnmp.Select(a => a.ToString()).ToHashSet();
            foreach (var n in graph.Nodes.Concat(graph.NotLocated?.Members ?? []))
            {
                if (n.Kind != TopoKind.Switch || n.Managed) continue;
                if (n.Ip is { Length: > 0 } ip && !asked.Contains(ip)) continue; // not asked (yet)
                graph.Silent.Add(n);
                string? problem = n.Ip is { Length: > 0 } && snmpProblems?.TryGetValue(n.Ip, out var p) == true ? p : null;
                n.Detail = Join(n.Detail, problem is not null
                    ? $"Answers SNMP, but not to EthernetTools: {problem}. Its ports and MAC table are not known."
                    : n.Ip is { Length: > 0 }
                    ? "Did not answer SNMP: its ports and MAC table are not known. Enable SNMP (read-only) on it for a complete map."
                    : "No management address known: it could not be asked over SNMP, so its ports and MAC table are not known.");
            }
        }
        return graph;
    }

    private static string Join(string? a, string b) => string.IsNullOrEmpty(a) ? b : a + "\n" + b;
}
