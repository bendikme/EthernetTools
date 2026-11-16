namespace EthernetTools;

/// <summary>
/// Asks for a device's new Profinet name of station, and says what is wrong with it as it is typed (the rules of
/// <see cref="Pn.StationName"/>). Capitals are turned into small letters as they are typed.
/// </summary>
internal sealed class SetNameForm : Form
{
    private readonly TextBox txtName;
    private readonly Label lblProblem;
    private readonly Button btnSet;
    private readonly string _current;

    /// <param name="device">The device as the user knows it (MAC, IP, vendor).</param>
    /// <param name="currentName">Its name of station now, or null/empty when it has none.</param>
    public SetNameForm(string device, string? currentName)
    {
        _current = currentName ?? "";

        Text = "Set Name of Station";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Segoe UI", 9f);
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;

        const int width = 420;
        var layout = new TableLayoutPanel
        {
            ColumnCount = 1,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(12, 12, 12, 8),
        };

        Label Line(string text, Color? color = null, int top = 0) => new()
        {
            Text = text,
            AutoSize = true,
            MaximumSize = new Size(width, 0),
            ForeColor = color ?? SystemColors.ControlText,
            Margin = new Padding(0, top, 0, 2),
        };

        txtName = new TextBox
        {
            Text = _current,
            Width = width,
            MaxLength = Pn.StationName.MaxLength,
            Margin = new Padding(0, 2, 0, 2),
            AccessibleName = "New name",
        };
        lblProblem = Line("", Color.Firebrick);

        btnSet = new Button { Text = "Set Name", DialogResult = DialogResult.OK, AutoSize = true, Enabled = false };
        var btnCancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft,
            AutoSize = true,
            Width = width,
            Anchor = AnchorStyles.Right,
            Margin = new Padding(0, 10, 0, 0),
        };
        buttons.Controls.Add(btnCancel);
        buttons.Controls.Add(btnSet);

        layout.Controls.Add(Line($"Device:  {device}"));
        layout.Controls.Add(Line($"Current name:  {(_current.Length > 0 ? _current : "(none)")}"));
        layout.Controls.Add(Line("New name of station:", top: 10));
        layout.Controls.Add(txtName);
        layout.Controls.Add(lblProblem);
        layout.Controls.Add(Line(
            "Small letters a–z, digits, hyphens and dots, e.g. \"et200sp-u20-k1\". The device keeps the name after a " +
            "power cycle. A device that is connected to its controller refuses a new name.", SystemColors.GrayText, top: 6));
        layout.Controls.Add(buttons);
        Controls.Add(layout);

        AcceptButton = btnSet;
        CancelButton = btnCancel;

        txtName.TextChanged += (_, _) => OnNameChanged();
        Shown += (_, _) => { txtName.Focus(); txtName.SelectAll(); };
        Revalidate();
    }

    /// <summary>The name typed.</summary>
    public string NewName => txtName.Text;

    /// <summary>Why the name typed cannot be set ("" when it can, or when nothing is typed yet).</summary>
    internal string ProblemText => lblProblem.Text;

    /// <summary>Whether "Set Name" can be pressed.</summary>
    internal bool CanSet => btnSet.Enabled;

    /// <summary>Type <paramref name="text"/> into the name box, as a user would (the self-test's way in).</summary>
    internal void TypeName(string text) => txtName.Text = text;

    private void OnNameChanged()
    {
        string lower = txtName.Text.ToLowerInvariant();
        if (lower != txtName.Text)
        {
            int caret = txtName.SelectionStart;
            txtName.Text = lower; // raises TextChanged again, which validates
            txtName.SelectionStart = caret;
            return;
        }
        Revalidate();
    }

    private void Revalidate()
    {
        string name = txtName.Text;
        string? problem = name.Length == 0 ? "" : Pn.StationName.Problem(name);
        if (problem is null && name == _current) problem = "The device has this name already.";
        lblProblem.Text = problem ?? "";
        btnSet.Enabled = problem is null;
    }
}
