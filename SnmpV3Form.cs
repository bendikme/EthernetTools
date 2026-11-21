using EthernetTools.Pn;

namespace EthernetTools;

/// <summary>
/// The SNMPv3 user the Topology window asks with: name, authentication (MD5, SHA-1, SHA-256) and privacy (AES-128).
/// Kept in memory until EthernetTools closes; never written to disk.
/// </summary>
internal sealed class SnmpV3Form : Form
{
    private readonly TextBox txtUser, txtAuth, txtPriv;
    private readonly ComboBox cmbAuth, cmbPriv;
    private readonly Label lblError;

    /// <summary>The user as entered; null after Clear.</summary>
    public SnmpV3Credentials? Credentials { get; private set; }

    public SnmpV3Form(SnmpV3Credentials? current)
    {
        Text = "SNMPv3 user";
        if (AppInfo.Icon is { } icon) Icon = icon;
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Segoe UI", 9f);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new Padding(12);

        var grid = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Fill };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 240));
        Label L(string text) => new() { Text = text, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 8, 0) };

        txtUser = new TextBox { Dock = DockStyle.Fill, Text = current?.User ?? "" };
        cmbAuth = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
        cmbAuth.Items.AddRange(["None", "MD5", "SHA-1", "SHA-256"]);
        cmbAuth.SelectedIndex = (int)(current?.Auth ?? SnmpAuth.Sha1);
        txtAuth = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true, Text = current?.AuthPassword ?? "" };
        cmbPriv = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
        cmbPriv.Items.AddRange(["None", "AES-128"]);
        cmbPriv.SelectedIndex = (int)(current?.Priv ?? SnmpPriv.Aes128);
        txtPriv = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true, Text = current?.PrivPassword ?? "" };
        lblError = new Label { AutoSize = true, ForeColor = Color.Firebrick, MaximumSize = new Size(360, 0) };
        var note = new Label
        {
            AutoSize = true, ForeColor = Color.Gray, MaximumSize = new Size(360, 0),
            Text = "Asked before v2c and v1. Kept in memory until EthernetTools closes, never saved. Read-only: nothing is ever set.",
        };

        grid.Controls.Add(L("User name:"), 0, 0); grid.Controls.Add(txtUser, 1, 0);
        grid.Controls.Add(L("Authentication:"), 0, 1); grid.Controls.Add(cmbAuth, 1, 1);
        grid.Controls.Add(L("Auth password:"), 0, 2); grid.Controls.Add(txtAuth, 1, 2);
        grid.Controls.Add(L("Privacy:"), 0, 3); grid.Controls.Add(cmbPriv, 1, 3);
        grid.Controls.Add(L("Privacy password:"), 0, 4); grid.Controls.Add(txtPriv, 1, 4);
        grid.Controls.Add(note, 0, 5); grid.SetColumnSpan(note, 2);
        grid.Controls.Add(lblError, 0, 6); grid.SetColumnSpan(lblError, 2);

        var ok = new Button { Text = "OK", AutoSize = true };
        var clear = new Button { Text = "Don't use SNMPv3", AutoSize = true };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Bottom, Margin = new Padding(0, 8, 0, 0) };
        buttons.Controls.AddRange([cancel, ok, clear]);
        grid.Controls.Add(buttons, 0, 7); grid.SetColumnSpan(buttons, 2);
        Controls.Add(grid);
        AcceptButton = ok;
        CancelButton = cancel;

        void Enable()
        {
            txtAuth.Enabled = cmbPriv.Enabled = cmbAuth.SelectedIndex > 0;
            txtPriv.Enabled = cmbAuth.SelectedIndex > 0 && cmbPriv.SelectedIndex > 0;
        }
        cmbAuth.SelectedIndexChanged += (_, _) => Enable();
        cmbPriv.SelectedIndexChanged += (_, _) => Enable();
        Enable();

        ok.Click += (_, _) => Accept();
        clear.Click += (_, _) => { Credentials = null; DialogResult = DialogResult.OK; };
    }

    private void Accept()
    {
        if (Check() is { } error) { lblError.Text = error; return; }
        var auth = (SnmpAuth)cmbAuth.SelectedIndex;
        var priv = auth == SnmpAuth.None ? SnmpPriv.None : (SnmpPriv)cmbPriv.SelectedIndex;
        Credentials = new SnmpV3Credentials(txtUser.Text.Trim(), auth, auth == SnmpAuth.None ? "" : txtAuth.Text,
            priv, priv == SnmpPriv.None ? "" : txtPriv.Text);
        DialogResult = DialogResult.OK;
    }

    // ---- for the self-test: fill in, press, read ----
    internal string ErrorText => lblError.Text;
    internal string AuthText => cmbAuth.Text;
    internal string PrivText => cmbPriv.Text;
    internal void Fill(string user, SnmpAuth auth, string authPassword, SnmpPriv priv, string privPassword)
    {
        txtUser.Text = user;
        cmbAuth.SelectedIndex = (int)auth;
        txtAuth.Text = authPassword;
        cmbPriv.SelectedIndex = (int)priv;
        txtPriv.Text = privPassword;
    }
    internal void PressOk() => Accept();
    internal void PressClear() { Credentials = null; DialogResult = DialogResult.OK; }

    /// <summary>What is wrong with the entries, or null. Passwords: at least 8 characters (RFC 3414).</summary>
    private string? Check()
    {
        if (txtUser.Text.Trim().Length == 0) return "Enter the user name.";
        if (cmbAuth.SelectedIndex > 0 && txtAuth.Text.Length < 8) return "The authentication password has at least 8 characters.";
        if (cmbAuth.SelectedIndex > 0 && cmbPriv.SelectedIndex > 0 && txtPriv.Text.Length < 8) return "The privacy password has at least 8 characters.";
        return null;
    }
}
