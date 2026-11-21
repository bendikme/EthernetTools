using System.Security;
using System.Text;
using EthernetTools.Pn;

namespace EthernetTools;

/// <summary>
/// The map as a draw.io / diagrams.net file (uncompressed mxGraph XML): every box where it is on the map, in its
/// kind's colours, and every cable with its ports as the label - dotted (from a MAC table) and dashed (a ring's
/// closing link) as on screen. Opens in draw.io, and from there in Visio.
/// </summary>
internal static class DrawIoExport
{
    public static string Build(TopoLayout layout, string title)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<mxfile host=\"EthernetTools\">");
        sb.AppendLine($"  <diagram name=\"{X(title)}\">");
        sb.AppendLine("    <mxGraphModel grid=\"0\" guides=\"1\" page=\"0\"><root>");
        sb.AppendLine("      <mxCell id=\"0\"/><mxCell id=\"1\" parent=\"0\"/>");
        var ids = new Dictionary<TopoNode, string>();
        float ox = layout.Bounds.X, oy = layout.Bounds.Y;
        int i = 0;
        foreach (var p in layout.Nodes)
        {
            var n = p.Node;
            string id = "n" + (++i);
            ids[n] = id;
            var (fill, border, tag) = TopologyView.Style(n.Kind);
            if (n.Guessed) tag += "?";
            string name = n.Name.Length > 0 ? n.Name : n.Ip ?? n.Mac ?? n.Id;
            string second = n.Kind == TopoKind.Group
                ? $"{n.Members.Count} device(s)"
                : string.Join("  ", new[] { n.Ip, n.Vendor }.Where(s => !string.IsNullOrEmpty(s)));
            string value = $"{name} [{tag}]" + (second.Length > 0 ? "\n" + second : "");
            string style = $"rounded=1;whiteSpace=wrap;html=0;fontSize=11;fillColor={Hex(fill)};strokeColor={Hex(border)};" +
                           (n.Kind == TopoKind.UnmanagedSwitch ? "dashed=1;" : "") + (n.Kind == TopoKind.Group ? "shadow=1;" : "");
            sb.AppendLine($"      <mxCell id=\"{id}\" value=\"{X(value)}\" style=\"{style}\" vertex=\"1\" parent=\"1\">" +
                          $"<mxGeometry x=\"{p.Box.X - ox:0}\" y=\"{p.Box.Y - oy:0}\" width=\"{p.Box.Width:0}\" height=\"{p.Box.Height:0}\" as=\"geometry\"/></mxCell>");
        }
        int e = 0;
        foreach (var l in layout.Links)
        {
            if (!ids.TryGetValue(l.Link.A, out var a) || !ids.TryGetValue(l.Link.B, out var b)) continue;
            string label = TopologyLayout.CableLabel(l.Link.PortA, l.Link.PortB);
            string style = "endArrow=none;html=0;fontSize=10;edgeStyle=orthogonalEdgeStyle;" +
                           (l.Redundant ? "dashed=1;strokeColor=#E08000;" : l.FromMacTable ? "dashed=1;dashPattern=1 3;strokeColor=#808080;" : "strokeColor=#404040;");
            sb.AppendLine($"      <mxCell id=\"e{++e}\" value=\"{X(label)}\" style=\"{style}\" edge=\"1\" parent=\"1\" source=\"{a}\" target=\"{b}\">" +
                          "<mxGeometry relative=\"1\" as=\"geometry\"/></mxCell>");
        }
        sb.AppendLine("    </root></mxGraphModel>");
        sb.AppendLine("  </diagram>");
        sb.AppendLine("</mxfile>");
        return sb.ToString();

        static string Hex(Color c) => $"#{c.R:X2}{c.G:X2}{c.B:X2}";
        static string X(string s) => (SecurityElement.Escape(s) ?? "").Replace("\n", "&#xa;");
    }
}
