using EthernetTools.Pn;

namespace EthernetTools;

#nullable enable

partial class MainForm
{
    private System.ComponentModel.IContainer components = null!;

    // Top control row
    private Panel topPanel = null!;
    private ComboBox cmbAdapters = null!;
    private Button btnRefresh = null!;
    private Button btnScan = null!;
    private Button btnStop = null!;
    private NumericUpDown numTimeout = null!;
    private Label lblTimeout = null!;
    private Label lblAdapter = null!;

    // Toolbar
    private ToolStrip toolStrip = null!;
    private ToolStripButton tsbPing = null!;
    private ToolStripButton tsbTraceroute = null!;
    private ToolStripButton tsbPortScan = null!;
    private ToolStripButton tsbOpenWeb = null!;
    private ToolStripButton tsbWol = null!;
    private ToolStripButton tsbFlash = null!;
    private ToolStripSeparator tsSep1 = null!;
    private ToolStripButton tsbCopyIp = null!;
    private ToolStripButton tsbCopyMac = null!;
    private ToolStripButton tsbCopyRow = null!;
    private ToolStripSeparator tsSep2 = null!;
    private ToolStripButton tsbExportCsv = null!;
    private ToolStripSeparator tsSep3 = null!;
    private ToolStripLabel tslFilter = null!;
    private ToolStripTextBox tstFilter = null!;

    // Context menu
    private ContextMenuStrip gridMenu = null!;

    // Progress / grid / status
    private ProgressBar progress = null!;
    private DataGridView gridDevices = null!;
    private StatusStrip statusStrip = null!;
    private ToolStripStatusLabel lblStatus = null!;
    private ToolStripStatusLabel lblCount = null!;
    private ToolStripStatusLabel lblPnCount = null!;

    protected override void Dispose(bool disposing)
    {
        if (disposing && components != null) components.Dispose();
        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        components = new System.ComponentModel.Container();

        // ---------- Top panel (adapter + scan controls) ----------
        topPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 44,
            Padding = new Padding(8, 8, 8, 4),
        };

        lblAdapter = new Label
        {
            Text = "Adapter:",
            Location = new Point(8, 8),
            AutoSize = true,
            TextAlign = ContentAlignment.MiddleLeft,
        };

        cmbAdapters = new ComboBox
        {
            Location = new Point(72, 4),
            Width = 520,
            DropDownStyle = ComboBoxStyle.DropDownList,
            DropDownWidth = 700,
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
        };

        btnRefresh = new Button
        {
            Text = "Refresh",
            Width = 80,
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
        };
        btnRefresh.Click += btnRefresh_Click;

        lblTimeout = new Label
        {
            Text = "Timeout (s):",
            AutoSize = true,
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
            TextAlign = ContentAlignment.MiddleLeft,
        };

        numTimeout = new NumericUpDown
        {
            Width = 50,
            Minimum = 1,
            Maximum = 60,
            Value = 5,
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
        };

        btnScan = new Button
        {
            Text = "Scan",
            Width = 80,
            BackColor = Color.LightSteelBlue,
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
        };
        btnScan.Click += btnScan_Click;

        btnStop = new Button
        {
            Text = "Stop",
            Width = 70,
            Enabled = false,
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
        };
        btnStop.Click += btnStop_Click;

        topPanel.Controls.AddRange(new Control[]
        {
            lblAdapter, cmbAdapters, btnRefresh, lblTimeout, numTimeout, btnScan, btnStop,
        });
        topPanel.Layout += (_, _) => LayoutTopPanel();

        // ---------- Toolbar ----------
        toolStrip = new ToolStrip
        {
            Dock = DockStyle.Top,
            GripStyle = ToolStripGripStyle.Hidden,
            RenderMode = ToolStripRenderMode.System,
            Padding = new Padding(8, 2, 8, 2),
            ImageScalingSize = new Size(16, 16),
        };

        tsbPing = new ToolStripButton("Ping") { ToolTipText = "Ping selected device", DisplayStyle = ToolStripItemDisplayStyle.Text };
        tsbTraceroute = new ToolStripButton("Traceroute") { ToolTipText = "Trace the route to the selected device", DisplayStyle = ToolStripItemDisplayStyle.Text };
        tsbPortScan = new ToolStripButton("Port Scan") { ToolTipText = "TCP-connect scan of common IT/industrial ports", DisplayStyle = ToolStripItemDisplayStyle.Text };
        tsbOpenWeb = new ToolStripButton("Open Web") { ToolTipText = "Open http://<ip> in default browser", DisplayStyle = ToolStripItemDisplayStyle.Text };
        tsbWol = new ToolStripButton("Wake-on-LAN") { ToolTipText = "Send Wake-on-LAN magic packet", DisplayStyle = ToolStripItemDisplayStyle.Text };
        tsbFlash = new ToolStripButton("Flash LED") { ToolTipText = "Send Profinet DCP Signal — blinks the device's LED", DisplayStyle = ToolStripItemDisplayStyle.Text };
        tsSep1 = new ToolStripSeparator();
        tsbCopyIp = new ToolStripButton("Copy IP") { DisplayStyle = ToolStripItemDisplayStyle.Text };
        tsbCopyMac = new ToolStripButton("Copy MAC") { DisplayStyle = ToolStripItemDisplayStyle.Text };
        tsbCopyRow = new ToolStripButton("Copy Row") { DisplayStyle = ToolStripItemDisplayStyle.Text };
        tsSep2 = new ToolStripSeparator();
        tsbExportCsv = new ToolStripButton("Export CSV...") { DisplayStyle = ToolStripItemDisplayStyle.Text };
        tsSep3 = new ToolStripSeparator { Alignment = ToolStripItemAlignment.Right };
        tslFilter = new ToolStripLabel("Filter:") { Alignment = ToolStripItemAlignment.Right };
        tstFilter = new ToolStripTextBox { Width = 180, Alignment = ToolStripItemAlignment.Right, ToolTipText = "Filter by MAC, IP, name or vendor" };

        tsbPing.Click += (_, _) => OnPing();
        tsbTraceroute.Click += (_, _) => OnTraceroute();
        tsbPortScan.Click += (_, _) => OnPortScan();
        tsbOpenWeb.Click += (_, _) => OnOpenWeb();
        tsbWol.Click += (_, _) => OnWakeOnLan();
        tsbFlash.Click += (_, _) => OnFlash();
        tsbCopyIp.Click += (_, _) => OnCopy(c => c.IPAddress?.ToString());
        tsbCopyMac.Click += (_, _) => OnCopy(c => c.MacString);
        tsbCopyRow.Click += (_, _) => OnCopy(FormatRow);
        tsbExportCsv.Click += (_, _) => OnExportCsv();

        toolStrip.Items.AddRange(new ToolStripItem[]
        {
            tsbPing, tsbTraceroute, tsbPortScan, tsbOpenWeb, tsbWol, tsbFlash,
            tsSep1, tsbCopyIp, tsbCopyMac, tsbCopyRow,
            tsSep2, tsbExportCsv,
            tstFilter, tslFilter, tsSep3,
        });

        // ---------- Context menu ----------
        gridMenu = new ContextMenuStrip(components);
        gridMenu.Items.AddRange(new ToolStripItem[]
        {
            new ToolStripMenuItem("Ping",              null, (_, _) => OnPing()),
            new ToolStripMenuItem("Traceroute",        null, (_, _) => OnTraceroute()),
            new ToolStripMenuItem("Port scan",         null, (_, _) => OnPortScan()),
            new ToolStripMenuItem("Open in browser",   null, (_, _) => OnOpenWeb()),
            new ToolStripMenuItem("Wake-on-LAN",       null, (_, _) => OnWakeOnLan()),
            new ToolStripMenuItem("Flash LED (Profinet)", null, (_, _) => OnFlash()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Copy IP",           null, (_, _) => OnCopy(c => c.IPAddress?.ToString())),
            new ToolStripMenuItem("Copy MAC",          null, (_, _) => OnCopy(c => c.MacString)),
            new ToolStripMenuItem("Copy row",          null, (_, _) => OnCopy(FormatRow)),
        });

        // ---------- Progress (slim bar above grid) ----------
        progress = new ProgressBar
        {
            Dock = DockStyle.Top,
            Height = 6,
        };

        // ---------- Status bar ----------
        statusStrip = new StatusStrip { SizingGrip = true };
        lblStatus = new ToolStripStatusLabel("Ready.") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
        lblPnCount = new ToolStripStatusLabel("PN: 0") { BorderSides = ToolStripStatusLabelBorderSides.Left, ForeColor = Color.DarkOrange };
        lblCount = new ToolStripStatusLabel("Devices: 0") { BorderSides = ToolStripStatusLabelBorderSides.Left };
        statusStrip.Items.Add(lblStatus);
        statusStrip.Items.Add(lblPnCount);
        statusStrip.Items.Add(lblCount);

        // ---------- Grid ----------
        gridDevices = new DataGridView
        {
            Dock = DockStyle.Fill,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            ReadOnly = true,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = false,
            RowHeadersVisible = false,
            BackgroundColor = Color.White,
            GridColor = Color.FromArgb(235, 235, 235),
            BorderStyle = BorderStyle.None,
            EnableHeadersVisualStyles = false,
            ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize,
            ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle
            {
                BackColor = Color.FromArgb(245, 247, 250),
                ForeColor = Color.FromArgb(60, 60, 60),
                Font = new Font("Segoe UI Semibold", 9f),
                Padding = new Padding(6, 4, 6, 4),
                Alignment = DataGridViewContentAlignment.MiddleLeft,
                SelectionBackColor = Color.FromArgb(245, 247, 250),
                SelectionForeColor = Color.FromArgb(60, 60, 60),
            },
            DefaultCellStyle = new DataGridViewCellStyle
            {
                Padding = new Padding(6, 2, 6, 2),
                SelectionBackColor = Color.FromArgb(0, 120, 215),
                SelectionForeColor = Color.White,
            },
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None,
            AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle { BackColor = Color.FromArgb(248, 249, 251) },
            RowTemplate = { Height = 24 },
            ContextMenuStrip = gridMenu,
        };
        gridDevices.RowPrePaint += GridDevices_RowPrePaint;
        gridDevices.Columns.AddRange(new DataGridViewColumn[]
        {
            MakeColumn(nameof(NetDevice.MacString),    "MAC Address",   135),
            MakeColumn(nameof(NetDevice.IPAddress),    "IP Address",    105),
            MakeColumn(nameof(NetDevice.DisplayName),  "Name",          200),
            MakeColumn(nameof(NetDevice.VendorName),   "Vendor",        160),
            MakeColumn(nameof(NetDevice.SubnetMask),   "Subnet Mask",   105),
            MakeColumn(nameof(NetDevice.Gateway),      "Gateway",       105),
            MakeColumn(nameof(NetDevice.SourcesText),  "Source",        105),
            MakeColumn(nameof(NetDevice.RttText),      "RTT",            60),
            MakeColumn(nameof(NetDevice.LastSeenText), "Last Seen",      80),
        });
        gridDevices.CellMouseDown += GridDevices_CellMouseDown;
        gridDevices.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0) OnPing(); };

        // ---------- Form ----------
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Segoe UI", 9f);
        BackColor = Color.FromArgb(250, 250, 252);
        ClientSize = new Size(1100, 620);
        MinimumSize = new Size(900, 400);
        Text = $"EthernetTools v{AppInfo.Version} – Ethernet / Profinet Device Discovery";
        if (AppInfo.Icon is { } appIcon) Icon = appIcon;
        StartPosition = FormStartPosition.CenterScreen;

        // Add in *reverse* dock order so they stack correctly:
        //   Fill: grid
        //   Top:  progress, then toolStrip, then topPanel (last added = topmost)
        //   Bottom: statusStrip
        Controls.Add(gridDevices);
        Controls.Add(progress);
        Controls.Add(toolStrip);
        Controls.Add(topPanel);
        Controls.Add(statusStrip);

        AcceptButton = btnScan;
    }

    private void LayoutTopPanel()
    {
        // Right-aligned controls: Stop, Scan, numTimeout, lblTimeout, Refresh
        const int margin = 8;
        int right = topPanel.ClientSize.Width - margin;

        btnStop.Top = 4; btnStop.Left = right - btnStop.Width; right = btnStop.Left - 6;
        btnScan.Top = 4; btnScan.Left = right - btnScan.Width; right = btnScan.Left - 6;
        numTimeout.Top = 6; numTimeout.Left = right - numTimeout.Width; right = numTimeout.Left - 4;
        lblTimeout.Top = 8; lblTimeout.Left = right - lblTimeout.Width; right = lblTimeout.Left - 8;
        btnRefresh.Top = 4; btnRefresh.Left = right - btnRefresh.Width; right = btnRefresh.Left - 8;

        // Adapter combo fills the remaining space.
        cmbAdapters.Top = 5;
        cmbAdapters.Left = lblAdapter.Right + 8;
        cmbAdapters.Width = Math.Max(150, right - cmbAdapters.Left);
    }

    private static DataGridViewTextBoxColumn MakeColumn(string property, string header, int width)
        => new()
        {
            DataPropertyName = property,
            HeaderText = header,
            Width = width,
            SortMode = DataGridViewColumnSortMode.Automatic
        };

    private void GridDevices_CellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
    {
        // Make right-click select the row under the cursor before showing the context menu.
        if (e.Button == MouseButtons.Right && e.RowIndex >= 0)
        {
            gridDevices.ClearSelection();
            gridDevices.Rows[e.RowIndex].Selected = true;
            gridDevices.CurrentCell = gridDevices.Rows[e.RowIndex].Cells[Math.Max(0, e.ColumnIndex)];
        }
    }
}
