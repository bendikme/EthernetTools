using System.Text.Json;
using System.Text.Json.Serialization;

namespace EthernetTools.Pn;

/// <summary>A box of a saved map: a device, a switch, a group (and the group it is drawn in, for a group's members).</summary>
public sealed class SnapNode
{
    public string Id { get; set; } = "";
    public string Kind { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Ip { get; set; }
    public string? Mac { get; set; }
    public string? Vendor { get; set; }
    /// <summary>The group box it is drawn in ("Port not known", "Devices", "Not located"), if any.</summary>
    public string? Group { get; set; }
    public bool Guessed { get; set; }

    /// <summary>What it is across maps: its MAC, else (a switch known by name only) its name.</summary>
    [JsonIgnore]
    public string Key => Mac is { Length: > 0 } ? Mac.ToUpperInvariant() : "name:" + Name.ToLowerInvariant();

    [JsonIgnore]
    public bool IsDevice => Kind is nameof(TopoKind.Host) or nameof(TopoKind.Profinet) or nameof(TopoKind.Router);
}

/// <summary>A cable of a saved map: two boxes (by id), the port at each end, where it was learned.</summary>
public sealed class SnapLink
{
    public string A { get; set; } = "";
    public string PortA { get; set; } = "";
    public string B { get; set; } = "";
    public string PortB { get; set; } = "";
    public string Source { get; set; } = "";
}

/// <summary>
/// A map saved to a file (JSON): its boxes and cables, who took it, when and where. Compared with a later map it
/// says what is new, gone or moved; merged into the map of another PC it adds the ports this PC knew (its own above
/// all, from LLDP, CDP or spanning tree).
/// </summary>
public sealed class TopologySnapshot
{
    public int Version { get; set; } = 1;
    public DateTime TakenUtc { get; set; }
    public string Pc { get; set; } = "";
    public string Adapter { get; set; } = "";
    public List<SnapNode> Nodes { get; set; } = new();
    public List<SnapLink> Links { get; set; } = new();

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static TopologySnapshot FromJson(string json) =>
        // a saved map always has its time and at least This PC's box
        JsonSerializer.Deserialize<TopologySnapshot>(json, Json) is { Nodes.Count: > 0, Links: not null } s && s.Version >= 1 && s.TakenUtc != default
            ? s : throw new FormatException("Not a saved EthernetTools map.");

    /// <summary>The map as it stands: every box (a group's members too), every cable.</summary>
    public static TopologySnapshot From(TopoGraph graph, string pc, string adapter, DateTime? takenUtc = null)
    {
        var s = new TopologySnapshot { TakenUtc = takenUtc ?? DateTime.UtcNow, Pc = pc, Adapter = adapter };
        SnapNode Of(TopoNode n, string? group) => new()
        {
            Id = n.Id, Kind = n.Kind.ToString(), Name = n.Name, Ip = n.Ip, Mac = n.Mac, Vendor = n.Vendor, Group = group, Guessed = n.Guessed,
        };
        foreach (var n in graph.Nodes)
        {
            s.Nodes.Add(Of(n, null));
            if (n.Kind == TopoKind.Group)
                foreach (var m in n.Members) s.Nodes.Add(Of(m, n.Id));
        }
        foreach (var l in graph.Links)
            s.Links.Add(new SnapLink { A = l.A.Id, PortA = l.PortA, B = l.B.Id, PortB = l.PortB, Source = l.Source });
        return s;
    }

    /// <summary>
    /// Where a device is: the switch (or unmanaged switch) it hangs on, by key, and the port there ("" when not
    /// known). Several when it has several cables; none when not located.
    /// </summary>
    public Dictionary<string, string> Placement(SnapNode node)
    {
        var byId = Nodes.GroupBy(n => n.Id).ToDictionary(g => g.Key, g => g.First());
        var result = new Dictionary<string, string>();
        if (node.Group is { } group)
        {
            // a group's member: where the group hangs, its port not known
            foreach (var l in Links.Where(l => l.B == group || l.A == group))
                if (byId.TryGetValue(l.A == group ? l.B : l.A, out var parent)) result[parent.Key] = "";
            return result;
        }
        foreach (var l in Links.Where(l => l.A == node.Id || l.B == node.Id))
        {
            bool a = l.A == node.Id;
            if (!byId.TryGetValue(a ? l.B : l.A, out var other) || other.IsDevice || other.Kind == nameof(TopoKind.ThisPc)) continue;
            result[other.Kind == nameof(TopoKind.UnmanagedSwitch) ? "hub:" + other.Id : other.Key] = a ? l.PortB : l.PortA;
        }
        return result;
    }

    public string NameOf(string key) =>
        Nodes.FirstOrDefault(n => n.Key == key || "hub:" + n.Id == key) is { } n ? (n.Name.Length > 0 ? n.Name : n.Ip ?? n.Mac ?? key) : key;
}

/// <summary>What changed between two maps of the same network.</summary>
public sealed record SnapshotDiff(List<SnapNode> New, List<SnapNode> Gone, List<(SnapNode Device, string From, string To)> Moved)
{
    public bool None => New.Count == 0 && Gone.Count == 0 && Moved.Count == 0;

    /// <summary>
    /// <paramref name="before"/> against <paramref name="now"/>: devices and switches new or gone (by MAC); devices
    /// moved - behind another switch, or on another known port of the same one. A port newly known (it was "port ?")
    /// is not a move.
    /// </summary>
    public static SnapshotDiff Compare(TopologySnapshot before, TopologySnapshot now)
    {
        static bool Counts(SnapNode n) => n.Mac is { Length: > 0 } && n.Kind is not (nameof(TopoKind.ThisPc) or nameof(TopoKind.Group) or nameof(TopoKind.UnmanagedSwitch));
        var old = before.Nodes.Where(Counts).GroupBy(n => n.Key).ToDictionary(g => g.Key, g => g.First());
        var cur = now.Nodes.Where(Counts).GroupBy(n => n.Key).ToDictionary(g => g.Key, g => g.First());
        var diff = new SnapshotDiff(
            cur.Where(kv => !old.ContainsKey(kv.Key)).Select(kv => kv.Value).ToList(),
            old.Where(kv => !cur.ContainsKey(kv.Key)).Select(kv => kv.Value).ToList(),
            new());
        foreach (var (key, n) in cur)
        {
            if (!n.IsDevice || !old.TryGetValue(key, out var o)) continue;
            var was = before.Placement(o);
            var isNow = now.Placement(n);
            if (was.Count == 0 || isNow.Count == 0) continue; // not located on one of them: nothing to compare
            bool otherSwitch = !was.Keys.Intersect(isNow.Keys).Any();
            bool otherPort = was.Any(w => isNow.TryGetValue(w.Key, out var p) && w.Value.Length > 0 && p.Length > 0
                                          && !string.Equals(w.Value, p, StringComparison.OrdinalIgnoreCase));
            if (otherSwitch || otherPort)
                diff.Moved.Add((n, Describe(before, was), Describe(now, isNow)));
        }
        return diff;

        static string Describe(TopologySnapshot s, Dictionary<string, string> at) =>
            string.Join(", ", at.Select(kv => kv.Value.Length > 0 ? $"{s.NameOf(kv.Key)} port {kv.Value}" : $"behind {s.NameOf(kv.Key)}"));
    }

    public string Report(TopologySnapshot before)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Compared with the map saved {before.TakenUtc.ToLocalTime():yyyy-MM-dd HH:mm} on {before.Pc} ({before.Adapter}).");
        sb.AppendLine();
        if (None) { sb.AppendLine("Nothing has changed: the same devices, in the same places."); return sb.ToString(); }
        static string Name(SnapNode n) => $"{(n.Name.Length > 0 ? n.Name : "(no name)")}  {n.Ip}  {n.Mac}  {n.Vendor}".TrimEnd();
        if (New.Count > 0) { sb.AppendLine($"New ({New.Count}):"); foreach (var n in New) sb.AppendLine("  + " + Name(n)); sb.AppendLine(); }
        if (Gone.Count > 0) { sb.AppendLine($"Gone ({Gone.Count}):"); foreach (var n in Gone) sb.AppendLine("  - " + Name(n)); sb.AppendLine(); }
        if (Moved.Count > 0)
        {
            sb.AppendLine($"Moved ({Moved.Count}):");
            foreach (var (n, from, to) in Moved) sb.AppendLine($"  > {Name(n)}\n      was: {from}\n      now: {to}");
        }
        return sb.ToString();
    }
}

/// <summary>
/// Adds to a map what a map saved on another PC knew and this one does not: cables whose switch end has a port -
/// that PC's own port above all (its LLDP, CDP or spanning tree), and ports its switches' tables told. A device the
/// map had only as "port not known" (or not located) moves onto the port.
/// </summary>
public static class TopologyMerge
{
    /// <returns>How many cables were added.</returns>
    public static int Apply(TopoGraph graph, TopologySnapshot other)
    {
        var otherById = other.Nodes.GroupBy(n => n.Id).ToDictionary(g => g.Key, g => g.First());
        // every box of this map, a group's members too, by key
        var here = new Dictionary<string, TopoNode>();
        var groupOf = new Dictionary<TopoNode, TopoNode>();
        foreach (var n in graph.Nodes.ToList())
        {
            Index(n);
            if (n.Kind is TopoKind.Group) foreach (var m in n.Members) { Index(m); groupOf[m] = n; }
        }
        void Index(TopoNode n)
        {
            if (n.Mac is { Length: > 0 } mac) here.TryAdd(mac.ToUpperInvariant(), n);
            if (n.Kind is TopoKind.Switch && n.Name.Length > 0) here.TryAdd("name:" + n.Name.ToLowerInvariant(), n);
        }

        int added = 0;
        foreach (var l in other.Links)
        {
            if (!otherById.TryGetValue(l.A, out var a) || !otherById.TryGetValue(l.B, out var b)) continue;
            bool aSwitch = a.Kind == nameof(TopoKind.Switch), bSwitch = b.Kind == nameof(TopoKind.Switch);
            string switchPort = aSwitch ? l.PortA : bSwitch ? l.PortB : "";
            if (switchPort.Length == 0) continue; // only what names a switch port
            var na = Find(a) ?? (a.Kind == nameof(TopoKind.ThisPc) ? OtherPc(a) : null);
            var nb = Find(b) ?? (b.Kind == nameof(TopoKind.ThisPc) ? OtherPc(b) : null);
            if (na is null || nb is null || ReferenceEquals(na, nb)) continue;
            if (graph.Links.Any(x => Joins(x, na, nb) && (x.PortA.Length > 0 || x.PortB.Length > 0))) continue; // known already
            var device = aSwitch && !bSwitch ? nb : bSwitch && !aSwitch ? na : null;
            if (device is not null) Unplace(device);
            graph.Links.RemoveAll(x => Joins(x, na, nb));
            graph.Links.Add(new TopoLink(na, l.PortA, nb, l.PortB, $"{l.Source} (from {other.Pc})"));
            added++;
        }
        return added;

        TopoNode? Find(SnapNode s) => here.GetValueOrDefault(s.Key) ?? (s.Kind == nameof(TopoKind.Switch) ? here.GetValueOrDefault("name:" + s.Name.ToLowerInvariant()) : null);

        TopoNode OtherPc(SnapNode s)
        {
            var pc = new TopoNode
            {
                Id = "pc:" + (s.Mac ?? s.Name), Kind = TopoKind.Host, Name = $"{s.Name} (other PC)", Mac = s.Mac, Ip = s.Ip,
                Detail = $"The PC that saved a map on {other.TakenUtc.ToLocalTime():yyyy-MM-dd HH:mm}; its port is what it heard there.",
            };
            graph.Nodes.Add(pc);
            if (s.Mac is { Length: > 0 } mac) here[mac.ToUpperInvariant()] = pc;
            return pc;
        }

        void Unplace(TopoNode device)
        {
            // out of a group ("port not known", "Devices", "Not located") or an unmanaged switch, and its weak cables
            foreach (var g in graph.Nodes.Where(n => n.Kind is TopoKind.Group or TopoKind.UnmanagedSwitch).ToList())
            {
                if (!g.Members.Remove(device)) continue;
                if (g.Kind == TopoKind.Group && g.Members.Count == 0)
                {
                    graph.Nodes.Remove(g);
                    graph.Links.RemoveAll(x => ReferenceEquals(x.A, g) || ReferenceEquals(x.B, g));
                    if (ReferenceEquals(graph.NotLocated, g)) graph.NotLocated = null;
                }
            }
            if (!graph.Nodes.Contains(device)) graph.Nodes.Add(device);
            graph.Links.RemoveAll(x => (ReferenceEquals(x.A, device) || ReferenceEquals(x.B, device)) && x.PortA.Length == 0 && x.PortB.Length == 0);
        }

        static bool Joins(TopoLink x, TopoNode p, TopoNode q) =>
            (ReferenceEquals(x.A, p) && ReferenceEquals(x.B, q)) || (ReferenceEquals(x.A, q) && ReferenceEquals(x.B, p));
    }
}
