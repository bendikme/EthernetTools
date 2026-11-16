using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using EthernetTools.Pn;

namespace EthernetTools;

/// <summary>
/// The topology map of the scanned network. On opening it asks every scanned device over SNMP (read-only) for its
/// LLDP neighbours and - switches - its MAC table, listens for LLDP on the adapter for half a minute, and draws what
/// it learns (<see cref="TopologyBuilder"/>, <see cref="TopologyLayout"/>).
/// </summary>
internal sealed class TopologyForm : Form
{
    private readonly AdapterInfo _adapter;
    private readonly IReadOnlyList<NetDevice> _devices;
    private readonly List<LldpNeighbor> _heard;
    private readonly Action<NetDevice>? _select;
    private List<SnmpAgentData> _agents = new();
    private TopoGraph? _graph;
    private CancellationTokenSource? _cts;
    private bool _discovering;

    private readonly TopologyView view;
    private readonly ToolStripButton btnDiscover, btnFit, btnExport;
    private readonly ToolStripTextBox txtCommunity;
    private readonly ToolStripStatusLabel lblStatus;

    /// <param name="heard">LLDP neighbours the scan already heard on the adapter.</param>
    /// <param name="select">Selects a device in the main window's list (double-click on a box).</param>
    public TopologyForm(AdapterInfo adapter, IReadOnlyList<NetDevice> devices, IEnumerable<LldpNeighbor> heard, Action<NetDevice>? select)
    {
        _adapter = adapter;
        _devices = devices;
        _heard = heard.ToList();
        _select = select;

        Text = $"Topology  -  {adapter.FriendlyName}";
        if (AppInfo.Icon is { } icon) Icon = icon;
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Segoe UI", 9f);
        ClientSize = new Size(1200, 760);
        MinimumSize = new Size(600, 400);
        StartPosition = FormStartPosition.CenterParent;
        KeyPreview = true;

        var tools = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, RenderMode = ToolStripRenderMode.System, Padding = new Padding(8, 2, 8, 2) };
        btnDiscover = new ToolStripButton("Discover again") { ToolTipText = "Ask the devices again over SNMP and listen for LLDP" };
        txtCommunity = new ToolStripTextBox { Text = "public", Width = 110, ToolTipText = "SNMP community (read)" };
        btnFit = new ToolStripButton("Fit") { ToolTipText = "Fit the map to the window (F)" };
        var btnIn = new ToolStripButton("+") { ToolTipText = "Zoom in (+, or the mouse wheel)" };
        var btnOut = new ToolStripButton("-") { ToolTipText = "Zoom out (-)" };
        btnExport = new ToolStripButton("Export PNG...") { ToolTipText = "Save the whole map as a picture" };
        tools.Items.AddRange(new ToolStripItem[]
        {
            btnDiscover, new ToolStripSeparator(), new ToolStripLabel("SNMP community:"), txtCommunity, new ToolStripSeparator(),
            btnFit, btnIn, btnOut, new ToolStripSeparator(), btnExport,
            new ToolStripLabel("Drag to move, wheel to zoom, hover a box for details, double-click to select it in the list")
                { Alignment = ToolStripItemAlignment.Right, ForeColor = Color.Gray },
        });

        var status = new StatusStrip();
        lblStatus = new ToolStripStatusLabel("") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
        status.Items.Add(lblStatus);

        view = new TopologyView { Dock = DockStyle.Fill };
        Controls.Add(view);
        Controls.Add(tools);
        Controls.Add(status);

        btnDiscover.Click += async (_, _) => await DiscoverAsync();
        btnFit.Click += (_, _) => view.Fit();
        btnIn.Click += (_, _) => view.Zoom(1.25f);
        btnOut.Click += (_, _) => view.Zoom(1 / 1.25f);
        btnExport.Click += (_, _) => Export();
        view.NodeActivated += n => { if (n.Device is { } d) _select?.Invoke(d); };
        KeyDown += (_, e) =>
        {
            if (txtCommunity.Focused) return;
            if (e.KeyCode == Keys.F) { view.Fit(); e.Handled = true; }
            else if (e.KeyCode is Keys.Add or Keys.Oemplus) { view.Zoom(1.25f); e.Handled = true; }
            else if (e.KeyCode is Keys.Subtract or Keys.OemMinus) { view.Zoom(1 / 1.25f); e.Handled = true; }
        };
        Shown += async (_, _) => { Rebuild(fit: true); await DiscoverAsync(); };
        FormClosing += (_, _) => _cts?.Cancel();
    }

    /// <summary>The map as it stands (for the self-test and the export).</summary>
    internal TopoGraph? Graph => _graph;

    private async Task DiscoverAsync()
    {
        if (_discovering) return;
        _discovering = true;
        btnDiscover.Enabled = false;
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        try
        {
            // LLDP on the adapter, beside the SNMP questions: who This PC is plugged into (sent every 5-30 s)
            var listener = new LldpListener();
            listener.Heard += n =>
            {
                if (IsDisposed || !IsHandleCreated) return;
                BeginInvoke(() =>
                {
                if (IsDisposed) return;
                if (_heard.Any(h => h.Chassis.Equals(n.Chassis) && h.Port.Equals(n.Port))) return;
                _heard.Add(n);
                Rebuild(fit: false);
                });
            };
            var listening = listener.RunAsync(_adapter, TimeSpan.FromSeconds(35), ct);
            _ = listening.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);

            var addresses = _devices.Where(d => d.IPAddress is { AddressFamily: AddressFamily.InterNetwork })
                .Select(d => d.IPAddress!).Distinct().ToList();
            var progress = new Progress<string>(s => { if (!IsDisposed) lblStatus.Text = s; });
            _agents = await TopologyDiscovery.ProbeAsync(addresses, txtCommunity.Text.Trim(), progress, ct);
            Rebuild(fit: true);
            lblStatus.Text = Summary() + "  Listening for LLDP on the adapter for a while longer...";
            try { await listening; } catch (OperationCanceledException) { } catch (Exception) { }
            if (!IsDisposed) lblStatus.Text = Summary();
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!IsDisposed) lblStatus.Text = "Discovery failed: " + ex.Message;
        }
        finally
        {
            _discovering = false;
            if (!IsDisposed) btnDiscover.Enabled = true;
        }
    }

    private void Rebuild(bool fit)
    {
        if (IsDisposed) return;
        var thisPc = new ThisPcInfo(Environment.MachineName, _adapter.MacString(), OwnIPv4()?.ToString(), _adapter.FriendlyName);
        _graph = TopologyBuilder.Build(_devices, thisPc, _heard, _agents, Gateway());
        view.SetLayout(TopologyLayout.Layout(_graph), reset: fit);
    }

    private string Summary()
    {
        if (_graph is null) return "";
        int switches = _graph.Nodes.Count(n => n.Kind == TopoKind.Switch);
        int answered = _agents.Count;
        int bridges = _agents.Count(a => a.Fdb.Count > 0);
        int notLocated = _graph.NotLocated?.Members.Count ?? 0;
        return $"{answered} device(s) answered SNMP ({bridges} with a MAC table), {_heard.Count} LLDP neighbour(s) heard on " +
               $"{_adapter.FriendlyName}; {switches} switch(es), {_graph.Links.Count} link(s), {notLocated} device(s) not located.";
    }

    private IPAddress? OwnIPv4() => _adapter.NetworkInterface.GetIPProperties().UnicastAddresses
        .Select(u => u.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);

    private IPAddress? Gateway() => _adapter.NetworkInterface.GetIPProperties().GatewayAddresses
        .Select(g => g.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));

    private void Export()
    {
        if (view.CurrentLayout is not { } layout) return;
        using var sfd = new SaveFileDialog
        {
            Filter = "PNG pictures (*.png)|*.png",
            FileName = $"topology-{DateTime.Now:yyyyMMdd-HHmmss}.png",
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            TopologyView.SavePng(layout, sfd.FileName);
            lblStatus.Text = $"Saved {sfd.FileName}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}

internal static class AdapterInfoExtensions
{
    public static string MacString(this AdapterInfo adapter) =>
        string.Join(":", adapter.MacAddress.GetAddressBytes().Select(b => b.ToString("X2")));
}
