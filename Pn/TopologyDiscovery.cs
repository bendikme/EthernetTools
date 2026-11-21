using System.Net;
using System.Net.NetworkInformation;
using SharpPcap;
using SharpPcap.LibPcap;

namespace EthernetTools.Pn;

/// <summary>What one SNMP agent told about itself: its LLDP ports and neighbours, and (a switch) its MAC table.</summary>
public sealed class SnmpAgentData
{
    public required IPAddress Ip { get; init; }
    public SnmpVersion Version { get; init; }
    public string SysName { get; init; } = "";
    public string SysDescr { get; init; } = "";
    /// <summary>sysServices: 2 = layer 2 (a bridge), 4 = layer 3 (routes), 72 = an end station.</summary>
    public int Services { get; init; }
    public LldpId? LocalChassis { get; init; }
    /// <summary>LLDP local ports: lldpLocPortNum -> the port's name.</summary>
    public Dictionary<int, string> LocalPorts { get; } = new();
    /// <summary>LLDP neighbours, by the local port they were heard on.</summary>
    public List<(int LocalPort, LldpNeighbor Neighbor)> Neighbors { get; } = new();
    /// <summary>The MAC table (BRIDGE-MIB): MAC (AA:BB:..) -> bridge port.</summary>
    public Dictionary<string, int> Fdb { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Bridge port -> the port's name (ifName through dot1dBasePortIfIndex), where known.</summary>
    public Dictionary<int, string> BridgePortNames { get; } = new();

    public bool IsBridge => (Services & 2) != 0 || LocalPorts.Count >= 3 || Fdb.Count > 0;

    /// <summary>A port's name: LLDP's, else the interface's, else its number. An LLDP name that is only a MAC address
    /// gives way to the interface's name.</summary>
    public string PortName(int port)
    {
        bool hasLldp = LocalPorts.TryGetValue(port, out var lldp) && lldp.Length > 0;
        bool hasIf = BridgePortNames.TryGetValue(port, out var ifName) && ifName.Length > 0;
        if (hasLldp && !(hasIf && LooksLikeMac(lldp!))) return lldp!;
        return hasIf ? ifName! : hasLldp ? lldp! : port.ToString();
    }

    private static bool LooksLikeMac(string s) => s.Length == 17 && s.Count(c => c == ':') == 5;
}

/// <summary>
/// Reads, over SNMP (read-only, v2c then v1), what each device knows of the topology: system name, LLDP-MIB local
/// ports and neighbours (IEEE 802.1AB, 1.0.8802.1.1.2) and - from switches - the BRIDGE-MIB MAC table.
/// </summary>
public static class TopologyDiscovery
{
    public const string SysDescr = "1.3.6.1.2.1.1.1.0", SysName = "1.3.6.1.2.1.1.5.0", SysServices = "1.3.6.1.2.1.1.7.0";
    public const string LldpLocChassisIdSubtype = "1.0.8802.1.1.2.1.3.1.0", LldpLocChassisId = "1.0.8802.1.1.2.1.3.2.0";
    public const string LldpLocPortTable = "1.0.8802.1.1.2.1.3.7.1";   // .2 id subtype, .3 id, .4 desc . portNum
    public const string LldpRemTable = "1.0.8802.1.1.2.1.4.1.1";       // .col . timeMark . localPort . index
    public const string LldpRemManAddrIfSubtype = "1.0.8802.1.1.2.1.4.2.1.3"; // . timeMark.localPort.index.addrSubtype.len.addr
    public const string Dot1dBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2";
    public const string Dot1dTpFdbPort = "1.3.6.1.2.1.17.4.3.1.2";     // . mac(6)
    public const string Dot1qTpFdbPort = "1.3.6.1.2.1.17.7.1.2.2.1.2"; // . fdbId . mac(6)
    public const string IfName = "1.3.6.1.2.1.31.1.1.1.1";

    /// <summary>
    /// Ask every address (64 at a time); the agents that answer, with what they told. <paramref name="progress"/>
    /// hears how far it is.
    /// </summary>
    public static async Task<List<SnmpAgentData>> ProbeAsync(IReadOnlyCollection<IPAddress> addresses, string community,
        IProgress<string>? progress, CancellationToken ct)
    {
        var agents = new List<SnmpAgentData>();
        int done = 0;
        using var gate = new SemaphoreSlim(64);
        await Task.WhenAll(addresses.Distinct().Select(async ip =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var agent = await ProbeOneAsync(ip, community, ct).ConfigureAwait(false);
                if (agent is not null) lock (agents) agents.Add(agent);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { /* one device's trouble is not the map's */ }
            finally
            {
                gate.Release();
                int n = Interlocked.Increment(ref done);
                progress?.Report($"SNMP: {n}/{addresses.Count} asked, {agents.Count} answered...");
            }
        })).ConfigureAwait(false);
        return ByAddress(agents);
    }

    /// <summary>
    /// Ask <paramref name="addresses"/> and follow LLDP from there, the way PRONETA and TIA Portal do: the management
    /// addresses the agents' neighbours (and <paramref name="heard"/>, the adapter's) report that were not asked yet
    /// are asked next, round after round, until none is new. That reaches switches the scan did not find (a missed
    /// ARP answer, a management VLAN or subnet of their own). <paramref name="asked"/> gathers every address asked;
    /// <paramref name="known"/> are agents an earlier call found (kept, not asked again). A device that answers on
    /// two of its addresses is kept once.
    /// </summary>
    public static async Task<List<SnmpAgentData>> CrawlAsync(IReadOnlyCollection<IPAddress> addresses, IReadOnlyCollection<LldpNeighbor> heard,
        string community, ISet<IPAddress> asked, IReadOnlyCollection<SnmpAgentData>? known, IProgress<string>? progress, CancellationToken ct,
        int maxRounds = 6, int maxFollowed = 256)
    {
        var agents = new List<SnmpAgentData>(known ?? []);
        var next = addresses.Distinct().Where(asked.Add).ToList();
        int followed = 0;
        for (int round = 0; round < maxRounds; round++)
        {
            var follow = FollowUp(agents, heard, asked).Take(Math.Max(0, maxFollowed - followed)).ToList();
            followed += follow.Count;
            foreach (var ip in follow) asked.Add(ip);
            next.AddRange(follow);
            if (next.Count == 0) break;
            if (follow.Count > 0) progress?.Report($"SNMP: following LLDP to {follow.Count} more address(es)...");
            foreach (var agent in await ProbeAsync(next, community, progress, ct).ConfigureAwait(false))
                if (!agents.Any(a => SameDevice(a, agent))) agents.Add(agent);
            next = new List<IPAddress>();
        }
        return ByAddress(agents);
    }

    /// <summary>The IPv4 management addresses LLDP names (the agents' neighbours, the adapter's) that are not in <paramref name="asked"/>.</summary>
    public static List<IPAddress> FollowUp(IEnumerable<SnmpAgentData> agents, IEnumerable<LldpNeighbor> heard, ICollection<IPAddress> asked) =>
        agents.SelectMany(a => a.Neighbors.Select(n => n.Neighbor)).Concat(heard)
            .Select(n => n.ManagementAddress)
            .OfType<IPAddress>()
            .Where(ip => Askable(ip) && !asked.Contains(ip))
            .Distinct()
            .ToList();

    /// <summary>A unicast IPv4 address worth asking: not 0.x, loopback, multicast or broadcast.</summary>
    public static bool Askable(IPAddress ip)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        byte first = ip.GetAddressBytes()[0];
        return first is > 0 and < 224 && !IPAddress.IsLoopback(ip);
    }

    /// <summary>Two answers from one device (two of its addresses): the same LLDP chassis id.</summary>
    public static bool SameDevice(SnmpAgentData a, SnmpAgentData b) =>
        a.Ip.Equals(b.Ip) || (a.LocalChassis is { Value.Length: > 0 } x && b.LocalChassis is { } y && x.Equals(y));

    private static List<SnmpAgentData> ByAddress(IEnumerable<SnmpAgentData> agents) =>
        agents.OrderBy(a => a.Ip.GetAddressBytes(), Comparer<byte[]>.Create((x, y) => x.AsSpan().SequenceCompareTo(y))).ToList();

    public static async Task<SnmpAgentData?> ProbeOneAsync(IPAddress ip, string community, CancellationToken ct)
    {
        string[] system = [SysName, SysDescr, SysServices, LldpLocChassisIdSubtype, LldpLocChassisId];
        foreach (var version in new[] { SnmpVersion.V2c, SnmpVersion.V1 })
        {
            // v2c with one retry; v1 (older Profinet devices, some switches) once more, without
            var client = new SnmpClient(ip, community, version, TimeSpan.FromSeconds(1), retries: version == SnmpVersion.V2c ? 1 : 0);
            var sys = await client.GetAsync(system, ct).ConfigureAwait(false);
            if (sys is null || sys.Count < 5) continue;

            var agent = new SnmpAgentData
            {
                Ip = ip,
                Version = version,
                SysName = sys[0].Value.IsMissing ? "" : sys[0].Value.AsText(),
                SysDescr = sys[1].Value.IsMissing ? "" : sys[1].Value.AsText(),
                Services = sys[2].Value.IsMissing ? 0 : (int)sys[2].Value.AsInteger(),
                LocalChassis = sys[3].Value.IsMissing || sys[4].Value.IsMissing
                    ? null : new LldpId((byte)sys[3].Value.AsInteger(), sys[4].Value.AsBytes()),
            };
            ReadLocalPorts(agent, await client.WalkAsync(LldpLocPortTable, ct, 3000).ConfigureAwait(false));
            ReadNeighbors(agent,
                await client.WalkAsync(LldpRemTable, ct, 6000).ConfigureAwait(false),
                await client.WalkAsync(LldpRemManAddrIfSubtype, ct, 2000).ConfigureAwait(false));
            if (agent.IsBridge)
            {
                var fdb = await client.WalkAsync(Dot1dTpFdbPort, ct, 16000).ConfigureAwait(false);
                if (fdb is null or { Count: 0 }) fdb = await client.WalkAsync(Dot1qTpFdbPort, ct, 16000).ConfigureAwait(false);
                ReadFdb(agent, fdb);
                if (agent.Fdb.Count > 0)
                    ReadBridgePortNames(agent,
                        await client.WalkAsync(Dot1dBasePortIfIndex, ct, 2000).ConfigureAwait(false),
                        await client.WalkAsync(IfName, ct, 2000).ConfigureAwait(false));
            }
            return agent;
        }
        return null;
    }

    // ---- reading the tables (also used by the self-test) ----------------------------------------------------------

    /// <summary>The index arcs after <paramref name="column"/> (an OID prefix) in <paramref name="oid"/>, or null.</summary>
    public static uint[]? Index(string oid, string column)
    {
        string prefix = column + ".";
        return oid.StartsWith(prefix, StringComparison.Ordinal) ? Ber.ParseOid(oid[prefix.Length..]) : null;
    }

    public static void ReadLocalPorts(SnmpAgentData agent, List<SnmpVarBind>? rows)
    {
        if (rows is null) return;
        var subtype = new Dictionary<int, byte>();
        var id = new Dictionary<int, byte[]>();
        var desc = new Dictionary<int, string>();
        foreach (var row in rows)
        {
            var ix = Index(row.Oid, LldpLocPortTable);
            if (ix is not { Length: 2 }) continue;
            int port = (int)ix[1];
            switch (ix[0])
            {
                case 2: subtype[port] = (byte)row.Value.AsInteger(); break;
                case 3: id[port] = row.Value.AsBytes(); break;
                case 4: desc[port] = row.Value.AsText(); break;
            }
        }
        foreach (int port in id.Keys.Union(desc.Keys))
        {
            string name = id.TryGetValue(port, out var raw)
                ? PortName(new LldpId(subtype.GetValueOrDefault(port, (byte)7), raw), desc.GetValueOrDefault(port, ""))
                : desc.GetValueOrDefault(port, "");
            agent.LocalPorts[port] = name.Length > 0 ? name : port.ToString();
        }
    }

    public static void ReadNeighbors(SnmpAgentData agent, List<SnmpVarBind>? rows, List<SnmpVarBind>? manAddr)
    {
        if (rows is null) return;
        var fields = new SortedDictionary<(int Port, int Index), Dictionary<uint, SnmpValue>>();
        foreach (var row in rows)
        {
            var ix = Index(row.Oid, LldpRemTable);
            if (ix is not { Length: 4 }) continue; // column . timeMark . localPort . index
            var key = ((int)ix[2], (int)ix[3]);
            if (!fields.TryGetValue(key, out var f)) fields[key] = f = new Dictionary<uint, SnmpValue>();
            f[ix[0]] = row.Value;
        }
        var addresses = new Dictionary<(int, int), IPAddress>();
        foreach (var row in manAddr ?? [])
        {
            var ix = Index(row.Oid, LldpRemManAddrIfSubtype);
            // timeMark . localPort . index . addrSubtype(1 = IPv4) . length(4) . a.b.c.d
            if (ix is { Length: 9 } && ix[3] == 1 && ix[4] == 4)
                addresses.TryAdd(((int)ix[1], (int)ix[2]), new IPAddress(ix[5..9].Select(a => (byte)a).ToArray()));
        }
        foreach (var ((port, index), f) in fields)
        {
            if (!f.TryGetValue(5, out var chassis) || !f.TryGetValue(7, out var portId)) continue;
            string Text(uint column) => f.TryGetValue(column, out var v) && !v.IsMissing ? v.AsText() : "";
            var neighbor = new LldpNeighbor(
                new LldpId((byte)(f.TryGetValue(4, out var cs) ? cs.AsInteger() : 7), chassis.AsBytes()),
                new LldpId((byte)(f.TryGetValue(6, out var ps) ? ps.AsInteger() : 7), portId.AsBytes()),
                Text(8), Text(9), Text(10),
                f.TryGetValue(12, out var caps) ? Lldp.FromSnmpBits(caps.AsBytes()) : LldpCapabilities.None,
                addresses.GetValueOrDefault((port, index)),
                []);
            agent.Neighbors.Add((port, neighbor));
        }
    }

    public static void ReadFdb(SnmpAgentData agent, List<SnmpVarBind>? rows)
    {
        foreach (var row in rows ?? [])
        {
            uint[]? ix = Index(row.Oid, Dot1dTpFdbPort) ?? Index(row.Oid, Dot1qTpFdbPort)?.Skip(1).ToArray();
            if (ix is not { Length: 6 }) continue;
            int port = (int)row.Value.AsInteger();
            if (port <= 0) continue; // 0: learned, but not on a port (the switch itself)
            agent.Fdb[string.Join(":", ix.Select(b => ((byte)b).ToString("X2")))] = port;
        }
    }

    public static void ReadBridgePortNames(SnmpAgentData agent, List<SnmpVarBind>? basePortIfIndex, List<SnmpVarBind>? ifNames)
    {
        var names = new Dictionary<int, string>();
        foreach (var row in ifNames ?? [])
            if (Index(row.Oid, IfName) is { Length: 1 } ix) names[(int)ix[0]] = row.Value.AsText();
        foreach (var row in basePortIfIndex ?? [])
            if (Index(row.Oid, Dot1dBasePortIfIndex) is { Length: 1 } ix && names.TryGetValue((int)row.Value.AsInteger(), out var name))
                agent.BridgePortNames[(int)ix[0]] = name;
    }

    /// <summary>
    /// A port's name for a map: Profinet's "port-001.station" as "port-001"; a MAC or a bare number as the
    /// description when there is one.
    /// </summary>
    public static string PortName(LldpId id, string description)
    {
        string text = id.PortText;
        if (text.StartsWith("port-", StringComparison.OrdinalIgnoreCase) && text.IndexOf('.') is > 0 and var dot) text = text[..dot];
        bool weak = id.Subtype == 3 || text.Length == 0; // a MAC address says little on a map
        return weak && description.Length > 0 ? description : text;
    }
}

/// <summary>
/// Listens for LLDP on an adapter (its own capture handle, beside a scan's): who the adapter is plugged into.
/// LLDP is never forwarded by a switch, so only the direct neighbour is heard - every 5 to 30 s.
/// </summary>
public sealed class LldpListener
{
    public event Action<LldpNeighbor>? Heard;

    public Task RunAsync(AdapterInfo adapter, TimeSpan duration, CancellationToken ct) => Task.Run(() =>
    {
        string name = adapter.PcapDevice?.Name ?? throw new InvalidOperationException($"'{adapter.FriendlyName}' is not bound to Npcap.");
        using var pcap = LibPcapLiveDeviceList.New().FirstOrDefault(d => d.Name == name)
            ?? throw new InvalidOperationException("The adapter is not there any more. Press Refresh.");
        pcap.Open(new DeviceConfiguration { Mode = DeviceModes.Promiscuous, ReadTimeout = 100, Immediate = true });
        pcap.Filter = "ether proto 0x88cc or (vlan and ether proto 0x88cc)";
        byte[] own = adapter.MacAddress.GetAddressBytes();
        var clock = System.Diagnostics.Stopwatch.StartNew();
        while (clock.Elapsed < duration && !ct.IsCancellationRequested)
        {
            if (pcap.GetNextPacket(out PacketCapture capture) != GetPacketStatus.PacketRead) continue;
            if (Lldp.Read(capture.Data) is { } neighbor && !neighbor.SourceMac.AsSpan().SequenceEqual(own))
                Heard?.Invoke(neighbor);
        }
    }, ct);
}
