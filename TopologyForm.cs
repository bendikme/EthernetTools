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
    /// <summary>The scanned devices and those the refresh heard that the scan missed: what the map draws.</summary>
    private List<NetDevice> _mapDevices;
    private readonly List<LldpNeighbor> _heard;
    private readonly Action<NetDevice>? _select;
    private List<SnmpAgentData> _agents = new();
    /// <summary>The addresses asked over SNMP by the last discovery; null until it has asked.</summary>
    private HashSet<IPAddress>? _asked;
    private string _community = "public";
    /// <summary>The SNMPv3 user, for the whole session (never saved).</summary>
    private static SnmpV3Credentials? s_v3;
    /// <summary>The devices that answered the refresh just before the MAC tables were read; null until then.</summary>
    private HashSet<string>? _answered;
    /// <summary>Why devices that answer SNMP refused (SNMPv3 reports), by address.</summary>
    private Dictionary<string, string> _problems = new();
    /// <summary>Devices that speak only SNMPv3 and are made by a maker of switches and access points: address -> maker.</summary>
    private Dictionary<string, string> _network = new();
    /// <summary>The last discovery has listened for LLDP on the adapter to the end.</summary>
    private bool _listened;
    private TopoGraph? _graph;
    private CancellationTokenSource? _cts;
    private bool _discovering;

    private const int ListenSeconds = 35;

    private readonly TopologyView view;
    private readonly ToolStripButton btnDiscover, btnFit, btnExport, btnV3;
    private readonly ToolStripTextBox txtCommunity;
    private readonly ToolStripStatusLabel lblStatus, lblWarn;

    /// <param name="heard">LLDP neighbours the scan already heard on the adapter.</param>
    /// <param name="select">Selects a device in the main window's list (double-click on a box).</param>
    public TopologyForm(AdapterInfo adapter, IReadOnlyList<NetDevice> devices, IEnumerable<LldpNeighbor> heard, Action<NetDevice>? select)
    {
        _adapter = adapter;
        _devices = devices;
        _mapDevices = devices.ToList();
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
        btnV3 = new ToolStripButton(V3Text()) { ToolTipText = "An SNMPv3 user to ask with (asked before v2c and v1; kept until EthernetTools closes)" };
        btnFit = new ToolStripButton("Fit") { ToolTipText = "Fit the map to the window (F)" };
        var btnIn = new ToolStripButton("+") { ToolTipText = "Zoom in (+, or the mouse wheel)" };
        var btnOut = new ToolStripButton("-") { ToolTipText = "Zoom out (-)" };
        btnExport = new ToolStripButton("Export PNG...") { ToolTipText = "Save the whole map as a picture" };
        tools.Items.AddRange(new ToolStripItem[]
        {
            btnDiscover, new ToolStripSeparator(), new ToolStripLabel("SNMP community:"), txtCommunity, btnV3, new ToolStripSeparator(),
            btnFit, btnIn, btnOut, new ToolStripSeparator(), btnExport,
            new ToolStripLabel("Drag to move, wheel to zoom, hover a box for details, double-click to select it in the list")
                { Alignment = ToolStripItemAlignment.Right, ForeColor = Color.Gray },
        });

        var status = new StatusStrip { ShowItemToolTips = true };
        lblStatus = new ToolStripStatusLabel("") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
        // why the map is not complete: switches that do not answer SNMP, no LLDP heard on the adapter (details in the tooltip)
        lblWarn = new ToolStripStatusLabel("") { ForeColor = Color.DarkOrange, Visible = false };
        status.Items.Add(lblStatus);
        status.Items.Add(lblWarn);

        view = new TopologyView { Dock = DockStyle.Fill };
        Controls.Add(view);
        Controls.Add(tools);
        Controls.Add(status);

        btnDiscover.Click += async (_, _) => await DiscoverAsync();
        btnFit.Click += (_, _) => view.Fit();
        btnIn.Click += (_, _) => view.Zoom(1.25f);
        btnOut.Click += (_, _) => view.Zoom(1 / 1.25f);
        btnExport.Click += (_, _) => Export();
        btnV3.Click += async (_, _) =>
        {
            using var dialog = new SnmpV3Form(s_v3);
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            s_v3 = dialog.Credentials;
            btnV3.Text = V3Text();
            await DiscoverAsync();
        };
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

    private static string V3Text() => s_v3 is null ? "SNMPv3..." : $"SNMPv3: {s_v3.User}";

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
        _community = txtCommunity.Text.Trim();
        _asked = null;
        _answered = null;
        _network = new Dictionary<string, string>();
        _listened = false;
        UpdateWarnings();
        var snmp = new SnmpSettings(_community, s_v3);
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
            var listening = listener.RunAsync(_adapter, TimeSpan.FromSeconds(ListenSeconds), ct);
            _ = listening.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);

            var progress = new Progress<string>(s => { if (!IsDisposed) lblStatus.Text = s; });

            // first, refresh the switches' MAC tables and see who is there now (each answer passes the switches on
            // its way to This PC); the tables are read right after
            lblStatus.Text = "Asking every device once more (ARP, DCP), so the switches' MAC tables are fresh...";
            HashSet<string>? answered = null;
            var mapDevices = _devices.ToList();
            try
            {
                var refresh = await TopologyDiscovery.RefreshAsync(_adapter, _devices, Gateway() is { } gw ? [gw] : [], TimeSpan.FromSeconds(2.5), ct);
                answered = refresh.Answered;
                // devices the scan missed (it happens: a lost ARP answer, the gateway among them) but that spoke now
                var known = _devices.Select(d => d.MacString).ToHashSet(StringComparer.OrdinalIgnoreCase);
                known.Add(_adapter.MacString());
                mapDevices.AddRange(refresh.Arp.Where(kv => !known.Contains(kv.Key)).Select(kv => TopologyDiscovery.HeardDevice(kv.Key, kv.Value)));
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { /* without it, the tables are as they are */ }
            _mapDevices = mapDevices;

            // the scanned devices, then whatever their LLDP neighbours name (switches the scan did not find)
            var addresses = _mapDevices.Where(d => d.IPAddress is { AddressFamily: AddressFamily.InterNetwork })
                .Select(d => d.IPAddress!).Distinct().ToList();
            var asked = new HashSet<IPAddress>(); // the crawl's own: Rebuild reads _asked on the UI thread meanwhile
            _agents = await TopologyDiscovery.CrawlAsync(addresses, _heard.ToList(), snmp, asked, null, progress, ct);
            _asked = new HashSet<IPAddress>(asked);
            _answered = answered;
            _problems = new Dictionary<string, string>(snmp.Problems);

            // Profinet devices that do not answer SNMP: their own port records
            _agents = await ReadProfinetAsync(_agents, progress, ct);
            Rebuild(fit: true);

            // without a v3 user: which of the devices that stayed silent speak SNMPv3, and which of those are probably
            // switches or access points (their maker, from the engine ID they give anyone, or from the MAC)
            if (s_v3 is null)
            {
                lblStatus.Text = "SNMPv3: asking the devices that did not answer v1/v2c whether they speak SNMPv3...";
                var answeredIps = _agents.Select(a => a.Ip.ToString()).ToHashSet();
                var macByIp = new Dictionary<string, string>();
                foreach (var d in _mapDevices) if (d.IPAddress is { } dip) macByIp.TryAdd(dip.ToString(), d.MacString);
                foreach (var n in _graph?.Nodes ?? []) if (n.Ip is { } nip && n.Mac is { } nmac) macByIp.TryAdd(nip, nmac);
                using var gate = new SemaphoreSlim(64);
                var engines = await Task.WhenAll(asked.Where(ip => !answeredIps.Contains(ip.ToString())).Select(async ip =>
                {
                    await gate.WaitAsync(ct);
                    try { return (Ip: ip.ToString(), Engine: await TopologyDiscovery.V3EngineAsync(ip, ct)); }
                    finally { gate.Release(); }
                }));
                foreach (var (ip, engine) in engines)
                {
                    if (engine is null) continue;
                    _problems.TryAdd(ip, "it answers SNMPv3 only; enter a v3 user with SNMPv3... on the toolbar");
                    if (TopologyDiscovery.NetworkMaker(engine, macByIp.GetValueOrDefault(ip)) is { } maker) _network[ip] = maker;
                }
                Rebuild(fit: true);
            }
            lblStatus.Text = Summary() + "  Listening for LLDP on the adapter for a while longer...";
            bool listenedToTheEnd = true;
            try { await listening; }
            catch (OperationCanceledException) { listenedToTheEnd = false; }
            catch (Exception) { listenedToTheEnd = false; }
            if (IsDisposed || ct.IsCancellationRequested) return;
            _listened = listenedToTheEnd;

            // what was heard on the adapter meanwhile may name a switch not asked yet
            int before = _agents.Count;
            _agents = await TopologyDiscovery.CrawlAsync([], _heard.ToList(), snmp, asked, _agents, progress, ct);
            _asked = new HashSet<IPAddress>(asked);
            foreach (var (ip, problem) in snmp.Problems) _problems[ip] = problem;
            if (IsDisposed) return;
            Rebuild(fit: _agents.Count != before);
            lblStatus.Text = Summary();
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
        _graph = TopologyBuilder.Build(_mapDevices, thisPc, _heard, _agents, Gateway(), _asked, _answered, _problems, _network);
        view.SetLayout(TopologyLayout.Layout(_graph), reset: fit);
        UpdateWarnings();
    }

    /// <summary>
    /// Profinet devices (with an address) that did not answer SNMP: their ports' neighbours from their own records
    /// (PDPortDataReal over PNIO RPC), as PRONETA reads them. Sixteen at a time.
    /// </summary>
    private async Task<List<SnmpAgentData>> ReadProfinetAsync(List<SnmpAgentData> agents, IProgress<string> progress, CancellationToken ct)
    {
        var answeredSnmp = agents.Select(a => a.Ip).ToHashSet();
        var profinet = _devices.Where(d => d.Sources.HasFlag(DiscoverySource.Profinet)
                && d.IPAddress is { AddressFamily: AddressFamily.InterNetwork } ip && TopologyDiscovery.Askable(ip) && !answeredSnmp.Contains(ip))
            .ToList();
        if (profinet.Count == 0) return agents;
        progress.Report($"Profinet: reading the port records of {profinet.Count} device(s) that don't answer SNMP...");
        var found = new List<SnmpAgentData>();
        using var gate = new SemaphoreSlim(16);
        await Task.WhenAll(profinet.Select(async d =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var ports = await ProfinetRpc.ReadPortsAsync(d.IPAddress!, d.VendorId, d.DeviceId, TimeSpan.FromMilliseconds(700), ct)
                    .ConfigureAwait(false);
                if (ports.Count > 0) lock (found) found.Add(ProfinetRpc.ToAgent(d, ports));
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { /* one device's trouble is not the map's */ }
            finally { gate.Release(); }
        }));
        _profinetRead = found.Count;
        return agents.Concat(found).ToList();
    }

    private int _profinetRead;

    /// <summary>Says, beside the status, why the map is not complete; the whole of it in the tooltip.</summary>
    private void UpdateWarnings()
    {
        if (IsDisposed) return;
        var shortText = new List<string>();
        var longText = new List<string>();
        // known switches first, then probable ones; real names before bare numbers
        var silent = (_asked is null ? [] : _graph?.Silent ?? []).OrderBy(n => n.Guessed).ThenBy(n => n.Name.Length <= 2).ToList();
        if (silent.Count > 0)
        {
            static string Name(TopoNode n) => n.Name.Length > 0 ? n.Name : n.Ip ?? n.Id;
            var refused = silent.Where(n => n.Ip is { Length: > 0 } ip && _problems.ContainsKey(ip)).ToList();
            var unanswered = silent.Where(n => n.Ip is { Length: > 0 } ip && !_problems.ContainsKey(ip)).ToList();
            var noAddress = silent.Where(n => n.Ip is not { Length: > 0 }).ToList();
            int v3Only = silent.Count(n => n.Ip is { } ip && _problems.TryGetValue(ip, out var p) && p.Contains("SNMPv3 only"));
            shortText.Add($"No SNMP from {silent.Count} switch(es){(v3Only > 0 ? $", {v3Only} of them SNMPv3 only" : "")}: " +
                          $"{string.Join(", ", silent.Take(3).Select(Name))}{(silent.Count > 3 ? ", ..." : "")}");
            if (refused.Count > 0)
                longText.Add("These switches answer SNMP, but not to EthernetTools: " +
                             string.Join("; ", refused.Select(n => $"{Name(n)} ({n.Ip}): {_problems[n.Ip!]}")) + ".");
            if (unanswered.Count > 0)
                longText.Add($"These switches did not answer SNMP (community \"{_community}\"), so their ports and MAC tables are not known: " +
                             string.Join(", ", unanswered.Select(n => $"{Name(n)} ({n.Ip})")) + ". What is behind them shows as \"port not known\" " +
                             "or \"not located\". Enable SNMP v1/v2c read-only on them (for this PC's address) for a complete map.");
            if (noAddress.Count > 0)
                longText.Add("No management address is known for " + string.Join(", ", noAddress.Select(Name)) +
                             " (neither the scan nor LLDP gave one), so they could not be asked over SNMP.");
        }
        if (_listened && _heard.Count == 0)
        {
            shortText.Add($"No LLDP heard on {_adapter.FriendlyName}");
            longText.Add($"No LLDP was heard on {_adapter.FriendlyName} in {ListenSeconds} s, so This PC's switch port is not known. " +
                         "The switch port may not send LLDP, or the network card keeps LLDP frames to itself (some Intel X710, XL710 " +
                         "and E810 cards have a firmware LLDP agent that does). This PC is then placed only by the switches' MAC tables.");
        }
        lblWarn.Visible = shortText.Count > 0;
        lblWarn.Text = "⚠ " + string.Join("  ·  ", shortText);
        lblWarn.ToolTipText = string.Join("\n\n", longText);
    }

    private string Summary()
    {
        if (_graph is null) return "";
        int switches = _graph.Nodes.Count(n => n.Kind == TopoKind.Switch);
        int answered = _agents.Count;
        int bridges = _agents.Count(a => a.Fdb.Count > 0);
        int notLocated = _graph.NotLocated?.Members.Count ?? 0;
        return $"{answered} of {_asked?.Count ?? 0} address(es) answered SNMP ({bridges} with a MAC table), {_heard.Count} LLDP neighbour(s) heard on " +
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
