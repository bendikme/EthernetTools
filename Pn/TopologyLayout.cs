using System.Drawing;
using System.Text.RegularExpressions;

namespace EthernetTools.Pn;

/// <summary>A box placed on the map, with the label of the cable that leads to it (its parent's port and its own).</summary>
public sealed record PlacedNode(TopoNode Node, RectangleF Box, string Label);

/// <summary>A cable drawn: its path, and whether it is a redundant one (a ring's closing link, a second path).</summary>
public sealed record PlacedLink(TopoLink Link, PointF[] Path, bool Redundant, bool FromMacTable);

public sealed class TopoLayout
{
    public List<PlacedNode> Nodes { get; } = new();
    public List<PlacedLink> Links { get; } = new();
    public RectangleF Bounds { get; set; }

    public PlacedNode? At(PointF world) => Nodes.LastOrDefault(n => n.Box.Contains(world));
}

/// <summary>
/// Lays the map out as a tree from This PC (top) down: switches with their ports, devices below their port. Long
/// rows of end devices wrap into a grid; each row hangs from a line of its own. Parts of the network not reached
/// from This PC stand beside it; the devices not located are one box at the end. A link that closes a ring (or a
/// second path) is drawn dashed, straight.
/// </summary>
public static partial class TopologyLayout
{
    public const float W = 184, H = 50, HGap = 26, LevelGap = 66, BusOffset = 22, Stub = 14;
    public const int LeafColumns = 6;

    private sealed class Tree
    {
        public required TopoNode Node { get; init; }
        public string Label { get; init; } = "";
        public TopoLink? Link { get; init; }
        public List<Tree> Children { get; } = new();
        public float Width, Height, ItemsWidth;
        public List<Tree> Inner => Children.Where(c => c.Children.Count > 0).ToList();
        public List<Tree> Leaves => Children.Where(c => c.Children.Count == 0).ToList();
    }

    public static TopoLayout Layout(TopoGraph graph)
    {
        var layout = new TopoLayout();
        var adjacency = graph.Nodes.ToDictionary(n => n, _ => new List<TopoLink>());
        foreach (var l in graph.Links)
        {
            if (adjacency.TryGetValue(l.A, out var a)) a.Add(l);
            if (adjacency.TryGetValue(l.B, out var b)) b.Add(l);
        }

        var visited = new HashSet<TopoNode>();
        var treeLinks = new HashSet<TopoLink>();
        var roots = new List<Tree>();

        Tree Grow(TopoNode root)
        {
            var top = new Tree { Node = root };
            visited.Add(root);
            var queue = new Queue<Tree>();
            queue.Enqueue(top);
            while (queue.Count > 0)
            {
                var t = queue.Dequeue();
                var next = adjacency[t.Node]
                    .Select(l => (Link: l, Other: ReferenceEquals(l.A, t.Node) ? l.B : l.A,
                                  Mine: ReferenceEquals(l.A, t.Node) ? l.PortA : l.PortB,
                                  Theirs: ReferenceEquals(l.A, t.Node) ? l.PortB : l.PortA))
                    .Where(x => !visited.Contains(x.Other))
                    .OrderBy(x => KindOrder(x.Other.Kind)).ThenBy(x => NaturalKey(x.Mine)).ThenBy(x => x.Other.Name)
                    .ToList();
                foreach (var x in next)
                {
                    if (!visited.Add(x.Other)) continue;
                    treeLinks.Add(x.Link);
                    var child = new Tree { Node = x.Other, Link = x.Link, Label = CableLabel(x.Mine, x.Theirs) };
                    t.Children.Add(child);
                    queue.Enqueue(child);
                }
            }
            return top;
        }

        if (graph.Root is not null) roots.Add(Grow(graph.Root));
        foreach (var n in graph.Nodes.Where(n => !ReferenceEquals(n, graph.NotLocated))
                     .OrderByDescending(n => adjacency[n].Count).ThenBy(n => n.Name))
            if (!visited.Contains(n) && adjacency[n].Count > 0) roots.Add(Grow(n));
        foreach (var n in graph.Nodes.Where(n => !visited.Contains(n) && !ReferenceEquals(n, graph.NotLocated)))
            roots.Add(Grow(n));
        if (graph.NotLocated is not null) roots.Add(Grow(graph.NotLocated));

        float left = 0;
        foreach (var root in roots)
        {
            Measure(root);
            Place(root, left, 0, layout);
            left += root.Width + 3 * HGap;
        }

        // the links the tree did not use: rings and second paths
        foreach (var l in graph.Links.Where(l => !treeLinks.Contains(l)))
        {
            var a = layout.Nodes.FirstOrDefault(n => ReferenceEquals(n.Node, l.A));
            var b = layout.Nodes.FirstOrDefault(n => ReferenceEquals(n.Node, l.B));
            if (a is null || b is null) continue;
            layout.Links.Add(new PlacedLink(l, [Center(a.Box), Center(b.Box)], true, Inferred(l)));
        }

        var all = layout.Nodes.Select(n => n.Box).Concat(layout.Links.SelectMany(l => l.Path.Select(p => new RectangleF(p, SizeF.Empty))));
        float x0 = all.Min(r => r.Left), y0 = all.Min(r => r.Top), x1 = all.Max(r => r.Right), y1 = all.Max(r => r.Bottom);
        layout.Bounds = RectangleF.FromLTRB(x0, y0 - 20, x1, y1);
        return layout;
    }

    private static void Measure(Tree t)
    {
        foreach (var c in t.Children) Measure(c);
        var inner = t.Inner;
        var leaves = t.Leaves;
        int cols = Math.Min(leaves.Count, LeafColumns), rows = (leaves.Count + LeafColumns - 1) / LeafColumns;
        float block = cols > 0 ? cols * W + (cols - 1) * HGap : 0;
        int items = inner.Count + (leaves.Count > 0 ? 1 : 0);
        t.ItemsWidth = inner.Sum(c => c.Width) + block + Math.Max(0, items - 1) * HGap;
        t.Width = Math.Max(W, t.ItemsWidth);
        float below = Math.Max(inner.Count > 0 ? inner.Max(c => c.Height) : 0, rows > 0 ? rows * (H + LevelGap) - LevelGap : 0);
        t.Height = H + (t.Children.Count > 0 ? LevelGap + below : 0);
    }

    private static void Place(Tree t, float left, float top, TopoLayout layout)
    {
        var box = new RectangleF(left + (t.Width - W) / 2, top, W, H);
        layout.Nodes.Add(new PlacedNode(t.Node, box, t.Label));
        if (t.Children.Count == 0) return;

        var from = new PointF(box.Left + W / 2, box.Bottom);
        float bus = box.Bottom + BusOffset;
        float childTop = top + H + LevelGap;
        float x = left + (t.Width - t.ItemsWidth) / 2;

        foreach (var c in t.Inner)
        {
            Place(c, x, childTop, layout);
            var cb = new RectangleF(x + (c.Width - W) / 2, childTop, W, H);
            AddLink(layout, c, [from, new(from.X, bus), new(cb.Left + Stub, bus), new(cb.Left + Stub, cb.Top)]);
            x += c.Width + HGap;
        }

        var leaves = t.Leaves;
        float trunk = x - HGap / 2;
        for (int i = 0; i < leaves.Count; i++)
        {
            int row = i / LeafColumns, col = i % LeafColumns;
            var cb = new RectangleF(x + col * (W + HGap), childTop + row * (H + LevelGap), W, H);
            layout.Nodes.Add(new PlacedNode(leaves[i].Node, cb, leaves[i].Label));
            float rowBus = cb.Top - LevelGap + BusOffset;
            PointF[] path = row == 0
                ? [from, new(from.X, bus), new(cb.Left + Stub, bus), new(cb.Left + Stub, cb.Top)]
                : [from, new(from.X, bus), new(trunk, bus), new(trunk, rowBus), new(cb.Left + Stub, rowBus), new(cb.Left + Stub, cb.Top)];
            AddLink(layout, leaves[i], path);
        }
    }

    private static void AddLink(TopoLayout layout, Tree child, PointF[] path)
    {
        if (child.Link is { } link) layout.Links.Add(new PlacedLink(link, path, false, Inferred(link)));
    }

    /// <summary>"23 ↔ gi1/0/31": the parent's port and the child's; "?" for a port not known.</summary>
    /// <summary>A cable inferred, not reported by LLDP or CDP at an end: placed by a MAC table, or probable from spanning tree.</summary>
    public static bool Inferred(TopoLink link) => link.Source.StartsWith("MAC table") || link.Source.EndsWith("(probable)");

    public static string CableLabel(string parentPort, string childPort) =>
        parentPort.Length == 0 && childPort.Length == 0 ? "port ?"
        : childPort.Length == 0 ? $"port {parentPort}"
        : $"{(parentPort.Length > 0 ? parentPort : "?")} ↔ {childPort}";

    private static int KindOrder(TopoKind kind) => kind switch
    {
        TopoKind.Switch => 0, TopoKind.Router => 1, TopoKind.UnmanagedSwitch => 2, TopoKind.Profinet => 3,
        TopoKind.ThisPc => 4, TopoKind.Host => 5, _ => 6,
    };

    /// <summary>Port names in their natural order: "2" before "10", "1/0/2" before "1/0/10".</summary>
    private static string NaturalKey(string s) => Digits().Replace(s, m => m.Value.PadLeft(8, '0'));

    [GeneratedRegex(@"\d+")]
    private static partial Regex Digits();

    private static PointF Center(RectangleF r) => new(r.Left + r.Width / 2, r.Top + r.Height / 2);
}
