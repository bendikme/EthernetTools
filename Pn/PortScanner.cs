using System.Net;
using System.Net.Sockets;

namespace EthernetTools.Pn;

/// <summary>Asynchronous TCP port scanner. Reports open ports as they are found.</summary>
public sealed class PortScanner
{
    /// <summary>Common ports for IT + industrial automation devices.</summary>
    public static readonly (int Port, string Name)[] CommonPorts =
    {
        (21,    "FTP"),
        (22,    "SSH"),
        (23,    "Telnet"),
        (25,    "SMTP"),
        (53,    "DNS"),
        (80,    "HTTP"),
        (102,   "Siemens S7 / ISO-TSAP"),
        (135,   "MS RPC"),
        (139,   "NetBIOS-SSN"),
        (161,   "SNMP"),
        (443,   "HTTPS"),
        (445,   "SMB"),
        (502,   "Modbus TCP"),
        (1883,  "MQTT"),
        (2222,  "EtherNet/IP (CIP)"),
        (3306,  "MySQL"),
        (3389,  "RDP"),
        (4840,  "OPC UA"),
        (5900,  "VNC"),
        (8000,  "HTTP-alt"),
        (8080,  "HTTP-proxy"),
        (8443,  "HTTPS-alt"),
        (9100,  "JetDirect / Printer"),
        (44818, "EtherNet/IP"),
    };

    public event Action<(int Port, string Service, long RttMs)>? PortOpen;
    public event Action<int>? PortChecked;

    public async Task ScanAsync(
        IPAddress target,
        IEnumerable<(int Port, string Name)> ports,
        int connectTimeoutMs = 600,
        int maxConcurrency = 32,
        CancellationToken ct = default)
    {
        using var sem = new SemaphoreSlim(maxConcurrency);
        var tasks = new List<Task>();

        foreach (var (port, name) in ports)
        {
            if (ct.IsCancellationRequested) break;
            await sem.WaitAsync(ct).ConfigureAwait(false);
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(connectTimeoutMs);

                    try
                    {
                        await socket.ConnectAsync(target, port, timeoutCts.Token).ConfigureAwait(false);
                        sw.Stop();
                        PortOpen?.Invoke((port, name, sw.ElapsedMilliseconds));
                    }
                    catch { /* closed / filtered / timeout */ }
                    PortChecked?.Invoke(port);
                }
                finally { sem.Release(); }
            }, ct));
        }

        try { await Task.WhenAll(tasks).ConfigureAwait(false); } catch { }
    }
}
