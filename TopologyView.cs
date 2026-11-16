using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Text;
using EthernetTools.Pn;

namespace EthernetTools;

/// <summary>
/// Draws a <see cref="TopoLayout"/>: the wheel zooms (around the pointer), dragging pans, hovering a box tells about
/// it, double-clicking one raises <see cref="NodeActivated"/>.
/// </summary>
internal sealed class TopologyView : Control
{
    private TopoLayout? _layout;
    private float _scale = 1f;
    private PointF _offset = new(20, 20);
    private Point? _dragFrom;
    private PointF _dragOffset;
    private PlacedNode? _hover;
    private readonly ToolTip _tip = new() { AutoPopDelay = 30000, InitialDelay = 300, ReshowDelay = 100 };

    public event Action<TopoNode>? NodeActivated;

    public TopologyView()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint
                 | ControlStyles.ResizeRedraw | ControlStyles.Selectable, true);
        BackColor = Color.White;
    }

    public TopoLayout? CurrentLayout => _layout;

    /// <summary>
    /// Show <paramref name="layout"/>. <paramref name="reset"/>: start the view afresh - the whole map when it can
    /// be read that way, else readable around This PC (Fit shows it all); otherwise keep the view where it is.
    /// </summary>
    public void SetLayout(TopoLayout layout, bool reset)
    {
        _layout = layout;
        _hover = null;
        _tip.SetToolTip(this, ""); // what it said was about the map before
        if (!reset) { Invalidate(); return; }
        if (FitScale() >= ReadableScale) { Fit(); return; }
        var start = (layout.Nodes.FirstOrDefault(n => n.Node.Kind == TopoKind.ThisPc) ?? layout.Nodes.FirstOrDefault())?.Box;
        if (start is not { } box) { Fit(); return; }
        _scale = 0.9f;
        _offset = new PointF(Width / 2f - (box.Left + box.Width / 2) * _scale, ViewMargin - layout.Bounds.Top * _scale);
        Invalidate();
    }

    /// <summary>Below this scale the boxes' text is too small to read.</summary>
    private const float ReadableScale = 0.7f;
    private const float ViewMargin = 30;

    private float FitScale()
    {
        if (_layout is null || Width < 10 || Height < 10) return 1;
        var b = _layout.Bounds;
        return Math.Clamp(Math.Min((Width - 2 * ViewMargin) / Math.Max(b.Width, 1), (Height - 2 * ViewMargin - 40) / Math.Max(b.Height, 1)), 0.05f, 1.4f);
    }

    public void Fit()
    {
        if (_layout is null || Width < 10 || Height < 10) { Invalidate(); return; }
        var b = _layout.Bounds;
        _scale = FitScale();
        _offset = new PointF((Width - b.Width * _scale) / 2 - b.Left * _scale, ViewMargin - b.Top * _scale);
        Invalidate();
    }

    public void Zoom(float factor) => ZoomAt(new PointF(Width / 2f, Height / 2f), factor);

    private void ZoomAt(PointF screen, float factor)
    {
        float scale = Math.Clamp(_scale * factor, 0.05f, 4f);
        var world = ToWorld(screen);
        _scale = scale;
        _offset = new PointF(screen.X - world.X * _scale, screen.Y - world.Y * _scale);
        Invalidate();
    }

    private PointF ToWorld(PointF screen) => new((screen.X - _offset.X) / _scale, (screen.Y - _offset.Y) / _scale);

    // ---- mouse -----------------------------------------------------------------------------------------------

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        ZoomAt(e.Location, e.Delta > 0 ? 1.15f : 1 / 1.15f);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        Focus();
        if (e.Button == MouseButtons.Left) { _dragFrom = e.Location; _dragOffset = _offset; Cursor = Cursors.SizeAll; }
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);
        _dragFrom = null;
        Cursor = Cursors.Default;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (_dragFrom is { } from)
        {
            _offset = new PointF(_dragOffset.X + e.X - from.X, _dragOffset.Y + e.Y - from.Y);
            Invalidate();
            return;
        }
        var hit = _layout?.At(ToWorld(e.Location));
        if (!ReferenceEquals(hit, _hover))
        {
            _hover = hit;
            _tip.SetToolTip(this, hit is null ? "" : Describe(hit.Node));
            Invalidate();
        }
    }

    protected override void OnMouseDoubleClick(MouseEventArgs e)
    {
        base.OnMouseDoubleClick(e);
        if (_layout?.At(ToWorld(e.Location)) is { } hit) NodeActivated?.Invoke(hit.Node);
    }

    /// <summary>What the tooltip says about a box.</summary>
    public static string Describe(TopoNode n)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{Title(n)}   [{KindText(n.Kind)}{(n.Managed ? ", SNMP" : "")}]");
        if (n.Ip is not null) sb.AppendLine($"IP: {n.Ip}");
        if (n.Mac is not null) sb.AppendLine($"MAC: {n.Mac}");
        if (!string.IsNullOrEmpty(n.Vendor)) sb.AppendLine($"Vendor: {n.Vendor}");
        if (!string.IsNullOrEmpty(n.Detail)) sb.AppendLine(n.Detail.Length > 300 ? n.Detail[..300] + "..." : n.Detail);
        if (n.Members.Count > 0)
        {
            sb.AppendLine();
            foreach (var m in n.Members.Take(40)) sb.AppendLine($"  {Title(m)}   {m.Ip} {m.Mac}");
            if (n.Members.Count > 40) sb.AppendLine($"  ... and {n.Members.Count - 40} more");
        }
        if (n.UnknownMacs > 0) sb.AppendLine($"  + {n.UnknownMacs} MAC address(es) not among the scanned devices");
        return sb.ToString().TrimEnd();
    }

    public static string Title(TopoNode n) =>
        n.Name.Length > 0 ? n.Name : n.Ip ?? n.Mac ?? n.Id;

    private static string KindText(TopoKind k) => k switch
    {
        TopoKind.ThisPc => "this PC", TopoKind.Switch => "switch", TopoKind.Router => "router",
        TopoKind.Profinet => "Profinet device", TopoKind.UnmanagedSwitch => "unmanaged switch?",
        TopoKind.Group => "group", _ => "device",
    };

    // ---- drawing ---------------------------------------------------------------------------------------------

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        if (_layout is null)
        {
            TextRenderer.DrawText(g, "Discovering...", Font, ClientRectangle, Color.Gray,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            return;
        }
        var state = g.Save();
        g.TranslateTransform(_offset.X, _offset.Y);
        g.ScaleTransform(_scale, _scale);
        Render(g, _layout, _hover);
        g.Restore(state);
        DrawLegend(g);
    }

    /// <summary>Draw the whole map in world coordinates (the view's paint, and the PNG export).</summary>
    public static void Render(Graphics g, TopoLayout layout, PlacedNode? hover = null)
    {
        using var cable = new Pen(Color.FromArgb(70, 80, 95), 1.6f);
        using var inferred = new Pen(Color.FromArgb(120, 130, 145), 1.3f) { DashStyle = DashStyle.Dot };
        using var redundant = new Pen(Color.FromArgb(220, 120, 0), 1.6f) { DashStyle = DashStyle.Dash };
        foreach (var l in layout.Links)
        {
            var pen = l.Redundant ? redundant : l.FromMacTable ? inferred : cable;
            if (l.Path.Length >= 2) g.DrawLines(pen, l.Path);
            if (l.Redundant)
            {
                var a = l.Path[0]; var b = l.Path[^1];
                string text = TopologyLayout.CableLabel(l.Link.PortA, l.Link.PortB);
                if (text.Length > 0) Label(g, text, new PointF((a.X + b.X) / 2, (a.Y + b.Y) / 2), Color.FromArgb(180, 90, 0));
            }
        }

        using var nameFont = new Font("Segoe UI Semibold", 9f);
        using var lineFont = new Font("Segoe UI", 8f);
        using var tagFont = new Font("Segoe UI", 6.5f, FontStyle.Bold);
        foreach (var n in layout.Nodes)
        {
            if (n.Label.Length > 0)
                Label(g, n.Label, new PointF(n.Box.Left + TopologyLayout.Stub + 4, n.Box.Top - 17), Color.FromArgb(60, 60, 60), left: true);
            DrawBox(g, n, ReferenceEquals(n, hover), nameFont, lineFont, tagFont);
        }
    }

    private static void Label(Graphics g, string text, PointF at, Color color, bool left = false)
    {
        using var font = new Font("Segoe UI", 7.5f);
        var size = g.MeasureString(text, font);
        float width = Math.Min(size.Width, TopologyLayout.W - TopologyLayout.Stub - 6);
        var rect = left ? new RectangleF(at.X, at.Y, width, size.Height) : new RectangleF(at.X - width / 2, at.Y - size.Height / 2, width, size.Height);
        using var back = new SolidBrush(Color.FromArgb(235, 255, 255, 255));
        g.FillRectangle(back, rect);
        using var brush = new SolidBrush(color);
        using var format = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap };
        g.DrawString(text, font, brush, rect, format);
    }

    private static (Color Fill, Color Border, string Tag) Style(TopoKind kind) => kind switch
    {
        TopoKind.ThisPc => (Color.FromArgb(226, 246, 233), Color.FromArgb(30, 140, 80), "THIS PC"),
        TopoKind.Switch => (Color.FromArgb(225, 236, 255), Color.FromArgb(45, 105, 205), "SWITCH"),
        TopoKind.Router => (Color.FromArgb(240, 230, 255), Color.FromArgb(120, 70, 190), "ROUTER"),
        TopoKind.Profinet => (Color.FromArgb(255, 243, 222), Color.FromArgb(220, 135, 0), "PROFINET"),
        TopoKind.UnmanagedSwitch => (Color.FromArgb(240, 245, 252), Color.FromArgb(110, 140, 190), "UNMANAGED?"),
        TopoKind.Group => (Color.FromArgb(244, 245, 247), Color.FromArgb(140, 145, 155), "GROUP"),
        _ => (Color.FromArgb(250, 250, 251), Color.FromArgb(150, 155, 165), "DEVICE"),
    };

    private static void DrawBox(Graphics g, PlacedNode p, bool hover, Font nameFont, Font lineFont, Font tagFont)
    {
        var n = p.Node;
        var (fill, border, tag) = Style(n.Kind);
        var r = p.Box;
        using var fillBrush = new SolidBrush(fill);
        using var pen = new Pen(hover ? Color.FromArgb(0, 120, 215) : border, hover ? 2.4f : 1.3f);
        if (n.Kind == TopoKind.UnmanagedSwitch) pen.DashStyle = DashStyle.Dash;
        if (n.Kind == TopoKind.Group)
            for (int i = 2; i >= 1; i--)
            {
                using var shadow = RoundRect(new RectangleF(r.X + 4 * i, r.Y - 4 * i, r.Width, r.Height), 6);
                g.FillPath(fillBrush, shadow);
                g.DrawPath(pen, shadow);
            }
        using (var path = RoundRect(r, 6))
        {
            g.FillPath(fillBrush, path);
            g.DrawPath(pen, path);
        }

        using var tagBrush = new SolidBrush(border);
        var tagSize = g.MeasureString(tag, tagFont);
        g.DrawString(tag, tagFont, tagBrush, r.Right - tagSize.Width - 4, r.Top + 3);

        using var text = new SolidBrush(Color.FromArgb(30, 30, 35));
        using var dim = new SolidBrush(Color.FromArgb(95, 100, 110));
        using var format = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap };
        g.DrawString(Title(n), nameFont, text, new RectangleF(r.X + 7, r.Y + 6, r.Width - tagSize.Width - 14, 18), format);
        string second = n.Kind == TopoKind.Group
            ? $"{n.Members.Count} device(s){(n.UnknownMacs > 0 ? $" + {n.UnknownMacs} MAC(s)" : "")} - hover for the list"
            : string.Join("  ", new[] { n.Ip, n.Kind is TopoKind.Profinet or TopoKind.Host ? n.Vendor : null, n.Ip is null ? n.Mac : null }
                .Where(s => !string.IsNullOrEmpty(s)));
        g.DrawString(second, lineFont, dim, new RectangleF(r.X + 7, r.Y + 27, r.Width - 12, 16), format);
    }

    private static GraphicsPath RoundRect(RectangleF r, float radius)
    {
        var path = new GraphicsPath();
        float d = radius * 2;
        path.AddArc(r.X, r.Y, d, d, 180, 90);
        path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }

    private void DrawLegend(Graphics g)
    {
        var items = new (string Text, Pen Pen)[]
        {
            ("cable, both ends from LLDP", new Pen(Color.FromArgb(70, 80, 95), 1.6f)),
            ("placed by a switch's MAC table", new Pen(Color.FromArgb(120, 130, 145), 1.3f) { DashStyle = DashStyle.Dot }),
            ("closes a ring / second path", new Pen(Color.FromArgb(220, 120, 0), 1.6f) { DashStyle = DashStyle.Dash }),
        };
        int y = Height - 12 - items.Length * 16;
        using var back = new SolidBrush(Color.FromArgb(230, 255, 255, 255));
        g.FillRectangle(back, 6, y - 4, 230, items.Length * 16 + 6);
        foreach (var (text, pen) in items)
        {
            g.DrawLine(pen, 12, y + 7, 40, y + 7);
            TextRenderer.DrawText(g, text, Font, new Point(46, y), Color.FromArgb(70, 70, 70));
            pen.Dispose();
            y += 16;
        }
    }

    /// <summary>The whole map as a PNG (1:1, at most 16000 px a side).</summary>
    public static void SavePng(TopoLayout layout, string file)
    {
        const float margin = 30;
        var b = layout.Bounds;
        float scale = Math.Min(1f, 16000 / Math.Max(b.Width + 2 * margin, b.Height + 2 * margin));
        using var bmp = new Bitmap((int)Math.Ceiling((b.Width + 2 * margin) * scale), (int)Math.Ceiling((b.Height + 2 * margin) * scale));
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(Color.White);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
            g.ScaleTransform(scale, scale);
            g.TranslateTransform(margin - b.Left, margin - b.Top);
            Render(g, layout);
        }
        bmp.Save(file, ImageFormat.Png);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _tip.Dispose();
        base.Dispose(disposing);
    }
}
