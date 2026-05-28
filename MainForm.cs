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
        catch (DllNotFoundException)
        {
            lblStatus.Text = "Npcap not installed. Install from https://npcap.com (with WinPcap-API compat).";
        }
        catch (Exception ex)
        {
            lblStatus.Text = "Adapter enumeration failed: " + ex.Message;
        }
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

    private void OnFlash()
    {
        var dev = SelectedDevice;
        if (dev is null)
        {
            MessageBox.Show(this, "Select a device first.", "No selection",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        if (cmbAdapters.SelectedItem is not AdapterInfo adapter)
        {
            MessageBox.Show(this, "Select an adapter first.", "No adapter");
            return;
        }
        try
        {
            DcpFlash.Flash(adapter, dev.MacAddress);
            lblStatus.Text = $"DCP Flash sent to {dev.MacString} \u2014 the device's LED should blink.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Flash failed",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
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
