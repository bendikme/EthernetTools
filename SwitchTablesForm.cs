using System.Data;
using System.Text;
using EthernetTools.Pn;

namespace EthernetTools;

/// <summary>
/// The raw tables the map was built from, to see why a device is where it is (or not): for each device that answered
/// SNMP (or Profinet's records), its MAC table, LLDP neighbours and CDP neighbours; and what This PC heard on its
/// adapter (LLDP, CDP, spanning tree). Copy and CSV for each table.
/// </summary>
internal sealed class SwitchTablesForm : Form
{
    private readonly IReadOnlyList<SnmpAgentData> _agents;
    private readonly IReadOnlyList<LldpNeighbor> _heard;
    private readonly Dictionary<string, NetDevice> _byMac;
    private readonly ComboBox cmbSource;
    private readonly TabControl tabs;
    private readonly Label lblInfo;

    private const string HeardItem = "What This PC heard (LLDP, CDP, spanning tree)";

    public SwitchTablesForm(IReadOnlyList<SnmpAgentData> agents, IReadOnlyList<LldpNeighbor> heard, IEnumerable<NetDevice> devices, SnmpAgentData? select)
    {
        _agents = agents.Where(a => a.Fdb.Count > 0 || a.Neighbors.Count > 0 || a.LocalPorts.Count > 0).ToList();
        _heard = heard;
        _byMac = devices.GroupBy(d => d.MacString, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        Text = "Switch tables";
        if (AppInfo.Icon is { } icon) Icon = icon;
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Segoe UI", 9f);
        ClientSize = new Size(1000, 600);
        MinimumSize = new Size(600, 350);
        StartPosition = FormStartPosition.CenterParent;

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(8, 8, 8, 4), WrapContents = false };
        cmbSource = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 420 };
        foreach (var a in _agents) cmbSource.Items.Add(Describe(a));
        cmbSource.Items.Add(HeardItem);
        var copy = new Button { Text = "Copy", AutoSize = true };
        var csv = new Button { Text = "Export CSV...", AutoSize = true };
        top.Controls.AddRange([new Label { Text = "Device:", AutoSize = true, Margin = new Padding(0, 6, 4, 0) }, cmbSource, copy, csv]);
        lblInfo = new Label { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(10, 0, 8, 6), ForeColor = Color.DimGray };
        tabs = new TabControl { Dock = DockStyle.Fill };
        Controls.Add(tabs);
        Controls.Add(lblInfo);
        Controls.Add(top);

        cmbSource.SelectedIndexChanged += (_, _) => Fill();
        copy.Click += (_, _) => { if (Current() is { } t) { try { Clipboard.SetText(TableText(t, '\t')); } catch { } } };
        csv.Click += (_, _) => ExportCsv();
        int index = select is null ? -1 : _agents.ToList().IndexOf(select);
        cmbSource.SelectedIndex = index >= 0 ? index : cmbSource.Items.Count > 1 ? 0 : cmbSource.Items.Count - 1;
    }

    private static string Describe(SnmpAgentData a) =>
        $"{(a.SysName.Length > 0 ? a.SysName : a.Ip.ToString())}  ({a.Ip}{(a.FromProfinet ? ", Profinet records" : $", SNMP {a.Version}")})";

    // ---- the tables (also read by the self-test) ----

    /// <summary>The MAC table: MAC, bridge port, port name, how many MACs on that port, the device it is, its vendor.</summary>
    internal DataTable MacTable(SnmpAgentData a)
    {
        var t = new DataTable("MAC table");
        foreach (string c in new[] { "MAC", "Bridge port", "Port", "MACs on port", "Device", "IP", "Vendor" }) t.Columns.Add(c, c is "Bridge port" or "MACs on port" ? typeof(int) : typeof(string));
        var perPort = a.Fdb.GroupBy(kv => kv.Value).ToDictionary(g => g.Key, g => g.Count());
        foreach (var (mac, port) in a.Fdb.OrderBy(kv => kv.Value).ThenBy(kv => kv.Key))
        {
            _byMac.TryGetValue(mac, out var d);
            t.Rows.Add(mac, port, a.PortName(port), perPort[port], d?.DisplayName ?? "", d?.IPAddress?.ToString() ?? "", d?.VendorName ?? "");
        }
        return t;
    }

    /// <summary>Neighbours of one protocol: local port, chassis, port id, system name, description/platform, address, capabilities.</summary>
    internal static DataTable NeighborTable(string name, IEnumerable<(string LocalPort, LldpNeighbor N)> rows)
    {
        var t = new DataTable(name);
        foreach (string c in new[] { "Local port", "Chassis", "Port", "Port description", "System name", "Description / platform", "Address", "Capabilities" }) t.Columns.Add(c);
        foreach (var (local, n) in rows)
            t.Rows.Add(local, n.Chassis.ChassisText, n.Port.PortText, n.PortDescription, n.SystemName, n.SystemDescription.Replace("\r", " ").Replace("\n", " "),
                n.ManagementAddress?.ToString() ?? "", n.Capabilities.ToString());
        return t;
    }

    internal static DataTable HeardTable(IEnumerable<LldpNeighbor> heard)
    {
        var t = new DataTable("Heard");
        foreach (string c in new[] { "Protocol", "Chassis", "Port", "System name", "Description / platform", "Address", "Root bridge", "Root path cost" }) t.Columns.Add(c);
        foreach (var n in heard.OrderBy(L2Hello.Rank))
            t.Rows.Add(n.Protocol, n.Chassis.ChassisText, n.Port.PortText, n.SystemName, n.SystemDescription.Replace("\r", " ").Replace("\n", " "),
                n.ManagementAddress?.ToString() ?? "", n.RootBridge is { } r ? string.Join(":", r.Select(b => b.ToString("X2"))) : "",
                n.RootBridge is null ? "" : n.RootPathCost.ToString());
        return t;
    }

    internal IReadOnlyList<DataTable> TablesFor(SnmpAgentData a) =>
    [
        MacTable(a),
        NeighborTable("LLDP", a.Neighbors.Where(n => n.Neighbor.Protocol == "LLDP").Select(n => (a.PortName(n.LocalPort), n.Neighbor))),
        NeighborTable("CDP", a.Neighbors.Where(n => n.Neighbor.Protocol == "CDP").Select(n => (a.PortName(n.LocalPort), n.Neighbor))),
    ];

    private void Fill()
    {
        tabs.TabPages.Clear();
        bool heard = cmbSource.SelectedItem as string == HeardItem;
        var tables = heard ? new[] { HeardTable(_heard) } : TablesFor(_agents[cmbSource.SelectedIndex]);
        foreach (var t in tables)
        {
            var grid = new DataGridView
            {
                Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false, RowHeadersVisible = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCells, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                BackgroundColor = SystemColors.Window, BorderStyle = BorderStyle.None, DataSource = t,
            };
            var page = new TabPage($"{t.TableName} ({t.Rows.Count})") { Tag = t };
            page.Controls.Add(grid);
            tabs.TabPages.Add(page);
        }
        if (heard)
            lblInfo.Text = _heard.Count == 0
                ? "Nothing heard on the adapter yet (LLDP every 5-30 s, CDP every 60 s, spanning tree every 2 s)."
                : "What the switch port This PC is plugged into said about itself.";
        else
        {
            var a = _agents[cmbSource.SelectedIndex];
            lblInfo.Text = $"{a.SysDescr.Replace("\r", " ").Replace("\n", " ")}" +
                           (a.Fdb.Count > 0 && !a.FdbComplete ? "   The MAC table was read only in part." : "") +
                           (a.FromProfinet ? "   Read through Profinet's own records (PDPortDataReal)." : "");
        }
    }

    private DataTable? Current() => tabs.SelectedTab?.Tag as DataTable;

    internal static string TableText(DataTable t, char separator)
    {
        static string Cell(object? v, char sep)
        {
            string s = v?.ToString() ?? "";
            return sep == ',' && s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
        }
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(separator, t.Columns.Cast<DataColumn>().Select(c => Cell(c.ColumnName, separator))));
        foreach (DataRow r in t.Rows) sb.AppendLine(string.Join(separator, r.ItemArray.Select(v => Cell(v, separator))));
        return sb.ToString();
    }

    private void ExportCsv()
    {
        if (Current() is not { } t) return;
        using var sfd = new SaveFileDialog { Filter = "CSV files (*.csv)|*.csv", FileName = $"{t.TableName.Replace(' ', '-').ToLowerInvariant()}-{DateTime.Now:yyyyMMdd-HHmmss}.csv" };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;
        try { File.WriteAllText(sfd.FileName, TableText(t, ','), Encoding.UTF8); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }
}
