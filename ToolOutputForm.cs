using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace EthernetTools;

/// <summary>
/// Modeless live-output dialog that streams ping or traceroute results to a textbox.
/// </summary>
public sealed class ToolOutputForm : Form
{
    private readonly TextBox _output;
    private readonly Button _btnStop;
    private readonly Button _btnClose;
    private CancellationTokenSource? _cts;

    public ToolOutputForm(string title)
    {
        Text = title;
        Width = 720;
        Height = 460;
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = false;
        ShowIcon = false;

        _output = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Dock = DockStyle.Fill,
            Font = new Font(FontFamily.GenericMonospace, 9.5f),
            BackColor = Color.Black,
            ForeColor = Color.LightGreen,
        };

        var bottom = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            Height = 40,
            Padding = new Padding(8),
        };
        _btnClose = new Button { Text = "Close", Width = 90 };
        _btnClose.Click += (_, _) => Close();
        _btnStop = new Button { Text = "Stop", Width = 90, Enabled = false };
        _btnStop.Click += (_, _) => _cts?.Cancel();
        bottom.Controls.Add(_btnClose);
        bottom.Controls.Add(_btnStop);

        Controls.Add(_output);
        Controls.Add(bottom);

        FormClosing += (_, _) => _cts?.Cancel();
    }

    private void Append(string line)
    {
        if (IsDisposed) return;
        if (InvokeRequired) { BeginInvoke(() => Append(line)); return; }
        _output.AppendText(line + Environment.NewLine);
    }

    private void SetStopEnabled(bool enabled)
    {
        if (IsDisposed) return;
        if (InvokeRequired) { BeginInvoke(() => SetStopEnabled(enabled)); return; }
        _btnStop.Enabled = enabled;
    }

    public void AppendText(string text)
    {
        if (IsDisposed) return;
        if (InvokeRequired) { BeginInvoke(() => AppendText(text)); return; }
        _output.AppendText(text);
    }

    public async Task RunPingAsync(IPAddress target, int count = 8, int timeoutMs = 1500)
    {
        SetStopEnabled(true);
        _cts = new CancellationTokenSource();
        Append($"PING {target}");

        try
        {
            using var ping = new Ping();
            int ok = 0, fail = 0;
            var rtts = new List<long>();

            for (int i = 1; i <= count; i++)
            {
                if (_cts.IsCancellationRequested) break;
                try
                {
                    var reply = await ping.SendPingAsync(target, timeoutMs).ConfigureAwait(false);
                    if (reply.Status == IPStatus.Success)
                    {
                        ok++;
                        rtts.Add(reply.RoundtripTime);
                        Append($"  reply from {reply.Address}: time={reply.RoundtripTime} ms ttl={reply.Options?.Ttl}");
                    }
                    else
                    {
                        fail++;
                        Append($"  {reply.Status}");
                    }
                }
                catch (Exception ex)
                {
                    fail++;
                    Append($"  error: {ex.Message}");
                }
                await Task.Delay(500, _cts.Token).ContinueWith(_ => { }).ConfigureAwait(false);
            }

            Append("");
            Append($"--- statistics ---");
            Append($"  sent={ok + fail}  received={ok}  lost={fail} ({(ok + fail == 0 ? 0 : fail * 100 / (ok + fail))}%)");
            if (rtts.Count > 0)
                Append($"  rtt min={rtts.Min()} ms  avg={(long)rtts.Average()} ms  max={rtts.Max()} ms");
        }
        finally
        {
            SetStopEnabled(false);
        }
    }

    public async Task RunTracerouteAsync(IPAddress target, int maxHops = 30, int timeoutMs = 2000)
    {
        SetStopEnabled(true);
        _cts = new CancellationTokenSource();
        Append($"TRACEROUTE to {target}, max {maxHops} hops");

        try
        {
            using var ping = new Ping();
            var buf = Encoding.ASCII.GetBytes("EthernetTools-trace");
            for (int ttl = 1; ttl <= maxHops; ttl++)
            {
                if (_cts.IsCancellationRequested) break;
                var sw = Stopwatch.StartNew();
                PingReply reply;
                try
                {
                    reply = await ping.SendPingAsync(
                        target, timeoutMs, buf, new PingOptions(ttl, true)).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    Append($"{ttl,3}  *  ({ex.Message})");
                    continue;
                }
                sw.Stop();

                var addr = reply.Address?.ToString() ?? "*";
                if (reply.Status == IPStatus.Success)
                {
                    Append($"{ttl,3}  {addr,-18}  {sw.ElapsedMilliseconds} ms  [destination]");
                    break;
                }
                else if (reply.Status == IPStatus.TtlExpired || reply.Status == IPStatus.TimeExceeded)
                {
                    Append($"{ttl,3}  {addr,-18}  {sw.ElapsedMilliseconds} ms");
                }
                else if (reply.Status == IPStatus.TimedOut)
                {
                    Append($"{ttl,3}  *  request timed out");
                }
                else
                {
                    Append($"{ttl,3}  {addr,-18}  {reply.Status}");
                }
            }
            Append("");
            Append("--- done ---");
        }
        finally
        {
            SetStopEnabled(false);
        }
    }

    public async Task RunPortScanAsync(IPAddress target)
    {
        SetStopEnabled(true);
        _cts = new CancellationTokenSource();
        Append($"PORT SCAN  {target}  ({Pn.PortScanner.CommonPorts.Length} ports)");
        Append("");

        var scanner = new Pn.PortScanner();
        int open = 0, checkedCount = 0;
        var openList = new List<string>();
        scanner.PortOpen += t =>
        {
            Interlocked.Increment(ref open);
            var line = $"  OPEN   {t.Port,5}/tcp   {t.Service,-25}  ({t.RttMs} ms)";
            lock (openList) openList.Add(line);
            Append(line);
        };
        scanner.PortChecked += _ => Interlocked.Increment(ref checkedCount);

        try
        {
            await scanner.ScanAsync(target, Pn.PortScanner.CommonPorts, ct: _cts.Token).ConfigureAwait(false);
            Append("");
            Append($"--- {open} open / {checkedCount} probed ---");
        }
        finally
        {
            SetStopEnabled(false);
        }
    }
}
