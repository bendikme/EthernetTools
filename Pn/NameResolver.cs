using System.Net;
using System.Net.Sockets;
using System.Text;

namespace EthernetTools.Pn;

/// <summary>
/// Resolve a hostname for an IPv4 address. Tries:
///   1. NBNS (NetBIOS Name Service, UDP/137) — works for Windows PCs in workgroups,
///      including those across subnets that don't answer reverse DNS.
///   2. Reverse DNS PTR lookup — works for hosts registered in DNS / mDNS.
/// </summary>
public static class NameResolver
{
    public static async Task<string?> ResolveAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct = default)
    {
        // Try NBNS first (faster for Windows endpoints).
        var nbns = await TryNbnsAsync(ip, timeout, ct).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(nbns)) return nbns;

        return await TryReverseDnsAsync(ip, timeout, ct).ConfigureAwait(false);
    }

    private static async Task<string?> TryReverseDnsAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            var task = Dns.GetHostEntryAsync(ip);
            var done = await Task.WhenAny(task, Task.Delay(timeout, ct)).ConfigureAwait(false);
            if (done != task) return null;
            var entry = await task.ConfigureAwait(false);
            var name = entry.HostName;
            if (string.IsNullOrEmpty(name) || name == ip.ToString()) return null;
            int dot = name.IndexOf('.');
            return dot > 0 ? name[..dot] : name;
        }
        catch { return null; }
    }

    // ---- NBNS NBSTAT query ----------------------------------------------------

    private static readonly byte[] NbstatQuery = BuildNbstatQuery();

    private static byte[] BuildNbstatQuery()
    {
        // Header: TXID 0x1234, flags 0x0010 (broadcast), QDCOUNT=1
        // Question: encoded "*\0\0...\0" (16-byte NetBIOS name = '*' + 15 zeros),
        // QType=NBSTAT(0x0021), QClass=IN(0x0001)
        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        // Header
        w.Write(new byte[] { 0x12, 0x34 }); // TXID
        w.Write(new byte[] { 0x00, 0x10 }); // Flags: broadcast
        w.Write(new byte[] { 0x00, 0x01 }); // QDCOUNT
        w.Write(new byte[] { 0x00, 0x00 }); // ANCOUNT
        w.Write(new byte[] { 0x00, 0x00 }); // NSCOUNT
        w.Write(new byte[] { 0x00, 0x00 }); // ARCOUNT

        // QNAME: 16-byte NetBIOS name "*"+15 nulls -> 32 chars first-level encoded
        // length octet 0x20 (=32), then 32 chars, then root label 0x00
        w.Write((byte)0x20);
        // '*' = 0x2A -> high nibble + 'A' = 'C', low nibble + 'A' = 'K'
        w.Write((byte)'C'); w.Write((byte)'K');
        for (int i = 0; i < 15; i++) { w.Write((byte)'A'); w.Write((byte)'A'); }
        w.Write((byte)0x00);

        // QTYPE NBSTAT, QCLASS IN
        w.Write(new byte[] { 0x00, 0x21 });
        w.Write(new byte[] { 0x00, 0x01 });
        return ms.ToArray();
    }

    private static async Task<string?> TryNbnsAsync(IPAddress ip, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Client.ReceiveTimeout = (int)timeout.TotalMilliseconds;

            var endpoint = new IPEndPoint(ip, 137);
            await udp.SendAsync(NbstatQuery, NbstatQuery.Length, endpoint).ConfigureAwait(false);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);

            var rxTask = udp.ReceiveAsync(cts.Token).AsTask();
            var done = await Task.WhenAny(rxTask, Task.Delay(timeout, cts.Token)).ConfigureAwait(false);
            if (done != rxTask) return null;

            var rx = await rxTask.ConfigureAwait(false);
            return ParseNbstatResponse(rx.Buffer);
        }
        catch { return null; }
    }

    private static string? ParseNbstatResponse(byte[] resp)
    {
        // Skip header (12) + question section. To avoid full DNS-name parsing, locate
        // the answer's RDATA via the fixed pattern: after QNAME (34 bytes) + QTYPE(2) +
        // QCLASS(2) we get answer NAME (compressed, 2 bytes) + TYPE(2) + CLASS(2) +
        // TTL(4) + RDLENGTH(2) + RDATA. RDATA starts with 1-byte NumberOfNames followed
        // by entries of (16-byte name + 2-byte flags).
        try
        {
            const int qNameLen = 34; // 1 + 32 + 1
            int pos = 12 + qNameLen + 4; // QTYPE/QCLASS
            // Answer record header
            pos += 2 + 2 + 2 + 4 + 2; // NAME ptr + TYPE + CLASS + TTL + RDLENGTH
            if (pos >= resp.Length) return null;

            int numNames = resp[pos++];
            for (int i = 0; i < numNames; i++)
            {
                if (pos + 18 > resp.Length) return null;
                var nameBytes = resp.AsSpan(pos, 15);
                byte suffix = resp[pos + 15];
                ushort flags = (ushort)((resp[pos + 16] << 8) | resp[pos + 17]);
                pos += 18;

                // Skip group entries (bit 15 set) — we want unique workstation/server names.
                bool isGroup = (flags & 0x8000) != 0;
                if (isGroup) continue;

                // 0x00 = workstation, 0x20 = file server
                if (suffix == 0x00 || suffix == 0x20)
                {
                    var name = Encoding.ASCII.GetString(nameBytes).TrimEnd(' ', '\0');
                    if (!string.IsNullOrEmpty(name)) return name;
                }
            }
        }
        catch { }
        return null;
    }
}
