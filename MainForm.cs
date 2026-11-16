using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using EthernetTools.Pn;
using SharpPcap;

namespace EthernetTools;

public partial class MainForm : Form
{
    private readonly SortableBindingList<NetDevice> _devices = new();
    private readonly List<NetDevice> _allDevices = new();
    private readonly Dictionary<string, NetDevice> _byMac = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<NetDevice> _pending = new();
    private readonly ConcurrentQueue<LldpNeighbor> _lldpHeard = new(); // on the adapter, during the last scan
    private AdapterInfo? _scannedAdapter;
    private CancellationTokenSource? _cts;
    private readonly System.Windows.Forms.Timer _refreshTimer;
    private readonly System.Windows.Forms.Timer _drainTimer;
    private readonly System.Windows.Forms.Timer _filterTimer;
    private int _lastSeenColIndex = -1;

    public MainForm()
    {
        InitializeComponent();
        gridDevices.AutoGenerateColumns = false;
        gridDevices.DataSource = _devices;
        EnableDoubleBuffer(gridDevices);
        Load += (_, _) =>
        {
            RefreshAdapters();
            _lastSeenColIndex = gridDevices.Columns[nameof(NetDevice.LastSeenText)]?.Index ?? -1;
        };
        FormClosing += (_, _) => _cts?.Cancel();

        // Drain the device queue at 60 fps -> batched UI updates instead of one BeginInvoke per packet.
        _drainTimer = new System.Windows.Forms.Timer(components) { Interval = 16 };
        _drainTimer.Tick += (_, _) => DrainPending();
        _drainTimer.Start();

        // Repaint only the "Last Seen" column once a second.
        _refreshTimer = new System.Windows.Forms.Timer(components) { Interval = 1000 };
        _refreshTimer.Tick += (_, _) => InvalidateLastSeen();
        _refreshTimer.Start();

        // Debounced filter so typing doesn't rebuild the grid on every keystroke.
        _filterTimer = new System.Windows.Forms.Timer(components) { Interval = 150 };
        _filterTimer.Tick += (_, _) => { _filterTimer.Stop(); ApplyFilter(); };
        tstFilter.TextChanged += (_, _) => { _filterTimer.Stop(); _filterTimer.Start(); };
    }

    private static void EnableDoubleBuffer(DataGridView grid)
    {
        typeof(DataGridView)
            .GetProperty("DoubleBuffered", BindingFlags.Instance | BindingFlags.NonPublic)
            ?.SetValue(grid, true, null);
    }

    private void InvalidateLastSeen()
    {
        if (_devices.Count == 0) return;
        if (_lastSeenColIndex < 0) { gridDevices.Invalidate(); return; }
        var rect = gridDevices.GetColumnDisplayRectangle(_lastSeenColIndex, true);
        if (!rect.IsEmpty) gridDevices.Invalidate(rect);
    }

    private void RefreshAdapters()
    {
        cmbAdapters.Items.Clear();
        try
        {
            var adapters = AdapterInfo.EnumerateEthernet();
            foreach (var a in adapters)
                cmbAdapters.Items.Add(a);

            if (cmbAdapters.Items.Count > 0)
                cmbAdapters.SelectedIndex = 0;

            lblStatus.Text = adapters.Count == 0
                ? "No Ethernet adapters found. Is Npcap installed?"
                : $"{adapters.Count} Ethernet adapter(s) found.";
        }
        catch (Exception ex) when (IsNpcapMissing(ex))
        {
            lblStatus.Text = "Npcap is not installed. Install it from https://npcap.com and start EthernetTools again.";
        }
        catch (Exception ex)
        {
            lblStatus.Text = "Adapter enumeration failed: " + ex.Message;
        }
    }

    // wpcap.dll not found - directly, or wrapped (e.g. in a TypeInitializationException
    // when SharpPcap's static setup is the first to call into it).
    private static bool IsNpcapMissing(Exception? ex)
    {
        for (; ex is not null; ex = ex.InnerException)
            if (ex is DllNotFoundException) return true;
        return false;
    }

    private async void btnScan_Click(object? sender, EventArgs e)
    {
        if (cmbAdapters.SelectedItem is not AdapterInfo adapter)
        {
            MessageBox.Show(this, "Select an adapter first.", "Scan",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        _devices.Clear();
        _allDevices.Clear();
        _byMac.Clear();
        _lldpHeard.Clear();
        _scannedAdapter = adapter;
        UpdateCounters();

        SetScanningUi(true);
        progress.Style = ProgressBarStyle.Marquee;
        lblStatus.Text = $"Scanning on {adapter.FriendlyName}...";

        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;

        var scanner = new NetworkScanner();
        scanner.DeviceDiscoveredOrUpdated += dev =>
        {
            // Cheap: just queue. Drained on the UI thread by _drainTimer.
            _pending.Enqueue(dev);
        };
        scanner.LldpHeard += n => _lldpHeard.Enqueue(n);
        var status = new Progress<string>(s =>
        {
            if (!IsDisposed) lblStatus.Text = s;
        });

        try
        {
            var timeout = TimeSpan.FromSeconds((double)numTimeout.Value);
            var results = await Task.Run(
                () => scanner.ScanAsync(adapter, timeout, status, ct), ct);

            lblStatus.Text = ct.IsCancellationRequested
                ? $"Stopped. Found {results.Count} device(s)."
                : $"Done. Found {results.Count} device(s).";
        }
        catch (OperationCanceledException)
        {
            lblStatus.Text = $"Stopped. Found {_devices.Count} device(s).";
        }
        catch (PcapException ex)
        {
            lblStatus.Text = "Capture error: " + ex.Message;
        }
        catch (Exception ex)
        {
            lblStatus.Text = "Error: " + ex.Message;
        }
        finally
        {
            progress.Style = ProgressBarStyle.Continuous;
            SetScanningUi(false);
        }
    }

    private void btnStop_Click(object? sender, EventArgs e)
    {
        if (_cts is { IsCancellationRequested: false })
        {
            lblStatus.Text = "Stopping...";
            btnStop.Enabled = false;
            _cts.Cancel();
        }
    }

    private void btnRefresh_Click(object? sender, EventArgs e)
    {
        if ((ModifierKeys & Keys.Shift) == Keys.Shift)
        {
            ShowAdapterDiagnostics();
            return;
        }
        RefreshAdapters();
    }

    private void ShowAdapterDiagnostics()
    {
        var dlg = new ToolOutputForm("Adapter diagnostics  (Shift+Refresh)");
        dlg.Show(this);
        dlg.AppendText(AdapterInfo.Diagnose());
    }

    private void DrainPending()
    {
        if (_pending.IsEmpty) return;

        var filterText = tstFilter.Text;
        bool addedAny = false;
        var dirtyRows = new HashSet<int>();
        int drained = 0;

        // Cap per tick so a flood can't freeze the UI; remainder is picked up next tick.
        while (drained < 512 && _pending.TryDequeue(out var dev))
        {
            drained++;
            if (_byMac.TryGetValue(dev.MacString, out var existing))
            {
                int idx = _devices.IndexOf(existing);
                if (idx >= 0) dirtyRows.Add(idx);
            }
            else
            {
                _byMac[dev.MacString] = dev;
                _allDevices.Add(dev);
                if (PassesFilter(dev, filterText))
                {
                    _devices.Add(dev);
                    addedAny = true;
                }
            }
        }

        // Refresh updated rows in one go.
        foreach (var idx in dirtyRows)
            if (idx < _devices.Count) _devices.ResetItem(idx);

        if (addedAny || dirtyRows.Count > 0)
            UpdateCounters();
    }

    private void UpdateCounters()
    {
        int total = _allDevices.Count;
        int pn = _allDevices.Count(d => d.Sources.HasFlag(DiscoverySource.Profinet));
        lblCount.Text = $"Devices: {total}";
        lblPnCount.Text = $"PN: {pn}";
    }

    private void ApplyFilter()
    {
        var q = tstFilter.Text;
        gridDevices.SuspendLayout();
        _devices.RaiseListChangedEvents = false;
        try
        {
            _devices.Clear();
            foreach (var d in _allDevices)
                if (PassesFilter(d, q)) _devices.Add(d);
        }
        finally
        {
            _devices.RaiseListChangedEvents = true;
            _devices.ResetBindings();
            gridDevices.ResumeLayout();
        }
    }

    private static bool PassesFilter(NetDevice d, string? query)
    {
        if (string.IsNullOrWhiteSpace(query)) return true;
        var q = query.Trim();
        return Contains(d.MacString, q)
            || Contains(d.IPAddress?.ToString(), q)
            || Contains(d.DisplayName, q)
            || Contains(d.NameOfStation, q)
            || Contains(d.Hostname, q)
            || Contains(d.VendorName, q);

        static bool Contains(string? s, string q) =>
            !string.IsNullOrEmpty(s) && s.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private void GridDevices_RowPrePaint(object? sender, DataGridViewRowPrePaintEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _devices.Count) return;
        var dev = _devices[e.RowIndex];
        var row = gridDevices.Rows[e.RowIndex];
        if (dev.Sources.HasFlag(DiscoverySource.Profinet))
        {
            // Light orange tint for Profinet-confirmed devices.
            row.DefaultCellStyle.BackColor = Color.FromArgb(255, 246, 224);
        }
        else if (dev.IPAddress is null)
        {
            // No IP -> grey out.
            row.DefaultCellStyle.ForeColor = Color.Gray;
        }
    }

    private void SetScanningUi(bool scanning)
    {
        btnScan.Enabled = !scanning;
        btnRefresh.Enabled = !scanning;
        cmbAdapters.Enabled = !scanning;
        numTimeout.Enabled = !scanning;
        btnStop.Enabled = scanning;
    }

    // ============================================================ toolbar actions

    private NetDevice? SelectedDevice =>
        gridDevices.CurrentRow?.DataBoundItem as NetDevice;

    private bool RequireSelectedIp(out NetDevice dev, out System.Net.IPAddress ip)
    {
        dev = null!;
        ip = System.Net.IPAddress.None;
        var d = SelectedDevice;
        if (d is null)
        {
            MessageBox.Show(this, "Select a device first.", "No selection",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return false;
        }
        if (d.IPAddress is null)
        {
            MessageBox.Show(this, "Selected device has no IP address.", "No IP",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return false;
        }
        dev = d;
        ip = d.IPAddress;
        return true;
    }

    private async void OnPing()
    {
        if (!RequireSelectedIp(out var dev, out var ip)) return;
        var dlg = new ToolOutputForm($"Ping  -  {ip}  ({dev.DisplayName})");
        dlg.Show(this);
        try { await dlg.RunPingAsync(ip); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Ping error"); }
    }

    private async void OnTraceroute()
    {
        if (!RequireSelectedIp(out var dev, out var ip)) return;
        var dlg = new ToolOutputForm($"Traceroute  -  {ip}  ({dev.DisplayName})");
        dlg.Show(this);
        try { await dlg.RunTracerouteAsync(ip); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Traceroute error"); }
    }

    private async void OnPortScan()
    {
        if (!RequireSelectedIp(out var dev, out var ip)) return;
        var dlg = new ToolOutputForm($"Port Scan  -  {ip}  ({dev.DisplayName})");
        dlg.Show(this);
        try { await dlg.RunPortScanAsync(ip); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Port scan error"); }
    }

    // ---- Profinet DCP Set: Flash LED, Set Name -------------------------------------------
    // Each waits for the device's answer (up to 3 s) and says what it answered. They open their own
    // capture handle (DcpSet), so they may run while a scan does.

    private bool _dcpBusy;

    private bool RequireDcpTarget(out NetDevice dev, out AdapterInfo adapter)
    {
        dev = null!;
        adapter = null!;
        if (SelectedDevice is not { } d)
        {
            MessageBox.Show(this, "Select a device first.", "No selection",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return false;
        }
        if (cmbAdapters.SelectedItem is not AdapterInfo a)
        {
            MessageBox.Show(this, "Select an adapter first.", "No adapter",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return false;
        }
        if (_dcpBusy)
        {
            lblStatus.Text = "Waiting for the device's answer - try again in a moment.";
            return false;
        }
        dev = d;
        adapter = a;
        return true;
    }

    /// <summary>
    /// Run a DCP Set and report what came of it: on success nothing (the caller says what was done), otherwise in the
    /// status line and a message box. Null when it could not be sent at all.
    /// </summary>
    private async Task<DcpSetOutcome?> RunDcpSetAsync(NetDevice dev, string busyText, string refusedText, string title,
        Func<Task<DcpSetOutcome>> set)
    {
        _dcpBusy = true;
        lblStatus.Text = busyText;
        try
        {
            var outcome = await set();
            if (!outcome.Done)
            {
                string text = outcome.Answered
                    ? $"{dev.MacString} {refusedText}: {outcome.Message}."
                    : $"{dev.MacString} did not answer within {DcpSet.AnswerTimeout.TotalSeconds:0} s. " +
                      "Is it on this adapter's network, and powered?";
                lblStatus.Text = text;
                MessageBox.Show(this, text, title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            return outcome;
        }
        catch (Exception ex)
        {
            lblStatus.Text = $"{title}: {ex.Message}";
            MessageBox.Show(this, ex.Message, title, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return null;
        }
        finally
        {
            _dcpBusy = false;
        }
    }

    private async void OnFlash()
    {
        if (!RequireDcpTarget(out var dev, out var adapter)) return;
        var outcome = await RunDcpSetAsync(dev, $"Flash LED: asking {dev.MacString}...", "refused to flash its LED", "Flash LED",
            () => DcpSet.FlashAsync(adapter, dev.MacAddress));
        if (outcome is { Done: true })
            lblStatus.Text = $"{dev.MacString} flashes its LED.";
    }

    // ---- Topology map ---------------------------------------------------------------------------

    private void OnTopology()
    {
        if (_allDevices.Count == 0 || _scannedAdapter is null)
        {
            MessageBox.Show(this, "Scan first: the map is drawn from the devices the scan finds.", "Topology",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        // one LLDP neighbour per chassis and port
        var heard = _lldpHeard.GroupBy(n => (n.Chassis, n.Port)).Select(g => g.Last()).ToList();
        var form = new TopologyForm(_scannedAdapter, _allDevices.ToList(), heard, SelectDevice);
        form.Show(this);
    }

    /// <summary>Select <paramref name="dev"/> in the list (clearing the filter when it hides it) and bring the window up.</summary>
    private void SelectDevice(NetDevice dev)
    {
        int row = _devices.IndexOf(dev);
        if (row < 0 && tstFilter.Text.Length > 0)
        {
            tstFilter.Text = "";
            _filterTimer.Stop();
            ApplyFilter();
            row = _devices.IndexOf(dev);
        }
        if (row < 0) return;
        gridDevices.ClearSelection();
        gridDevices.CurrentCell = gridDevices.Rows[row].Cells[0];
        gridDevices.Rows[row].Selected = true;
        Activate();
    }

    protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
    {
        // F2 renames, as in Explorer: Set Name for the selected device.
        if (keyData == Keys.F2)
        {
            OnSetName();
            return true;
        }
        return base.ProcessCmdKey(ref msg, keyData);
    }

    private async void OnSetName()
    {
        if (!RequireDcpTarget(out var dev, out var adapter)) return;

        string device = string.Join("   ", new[] { dev.MacString, dev.IPAddress?.ToString(), dev.VendorName }
            .Where(s => !string.IsNullOrEmpty(s)));
        string name;
        using (var dlg = new SetNameForm(device, dev.NameOfStation))
        {
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            name = dlg.NewName;
        }

        // Two devices with one name: the controller reaches neither.
        var holder = _allDevices.FirstOrDefault(d => !ReferenceEquals(d, dev) && d.NameOfStation == name);
        if (holder is not null && MessageBox.Show(this,
                $"{holder.MacString} already has the name \"{name}\". Two devices with one name stop the PLC from " +
                $"reaching either.\n\nGive it to {dev.MacString} anyway?",
                "Name in use", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return;

        var outcome = await RunDcpSetAsync(dev, $"Setting the name of {dev.MacString} to \"{name}\"...",
            $"refused the name \"{name}\"", "Set Name", () => DcpSet.SetNameAsync(adapter, dev.MacAddress, name));
        if (outcome is { Done: true })
        {
            dev.NameOfStation = name;
            int row = _devices.IndexOf(dev);
            if (row >= 0) _devices.ResetItem(row);
            lblStatus.Text = $"{dev.MacString} is now named \"{name}\".";
        }
    }

    private void OnOpenWeb()
    {
        if (!RequireSelectedIp(out _, out var ip)) return;
        try
        {
            Process.Start(new ProcessStartInfo($"http://{ip}") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Open browser failed");
        }
    }

    private void OnWakeOnLan()
    {
        var dev = SelectedDevice;
        if (dev is null)
        {
            MessageBox.Show(this, "Select a device first.", "No selection",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        try
        {
            WakeOnLan.Send(dev.MacAddress);
            lblStatus.Text = $"Wake-on-LAN magic packet sent to {dev.MacString}.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "WoL failed",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void OnCopy(Func<NetDevice, string?> selector)
    {
        var dev = SelectedDevice;
        if (dev is null) return;
        var text = selector(dev);
        if (string.IsNullOrEmpty(text)) return;
        try { Clipboard.SetText(text); lblStatus.Text = $"Copied: {text}"; }
        catch { /* clipboard occasionally unavailable; ignore */ }
    }

    private static string FormatRow(NetDevice d) =>
        $"{d.MacString}\t{d.IPAddress}\t{d.DisplayName}\t{d.VendorName}\t{d.SubnetMask}\t{d.Gateway}\t{d.SourcesText}";

    private void OnExportCsv()
    {
        if (_devices.Count == 0)
        {
            MessageBox.Show(this, "No devices to export.", "Export",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        using var sfd = new SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            FileName = $"devices-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;

        var sb = new StringBuilder();
        sb.AppendLine("MAC,IP,Name,Vendor,SubnetMask,Gateway,Source,RTT_ms,LastSeenUtc");
        foreach (var d in _devices)
        {
            sb.Append(Csv(d.MacString)).Append(',')
              .Append(Csv(d.IPAddress?.ToString())).Append(',')
              .Append(Csv(d.DisplayName)).Append(',')
              .Append(Csv(d.VendorName)).Append(',')
              .Append(Csv(d.SubnetMask?.ToString())).Append(',')
              .Append(Csv(d.Gateway?.ToString())).Append(',')
              .Append(Csv(d.SourcesText)).Append(',')
              .Append(d.RttMs?.ToString() ?? "").Append(',')
              .Append(d.LastSeenUtc.ToString("o"))
              .AppendLine();
        }
        try
        {
            File.WriteAllText(sfd.FileName, sb.ToString(), Encoding.UTF8);
            lblStatus.Text = $"Exported {_devices.Count} device(s) to {sfd.FileName}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Export failed",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        static string Csv(string? s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            if (s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) < 0) return s;
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        }
    }
}
