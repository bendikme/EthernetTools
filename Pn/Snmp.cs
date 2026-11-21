using System.Net;
using System.Net.Sockets;
using System.Text;

namespace EthernetTools.Pn;

public enum SnmpVersion { V1 = 0, V2c = 1 }

/// <summary>An SNMP value: its BER tag and its content bytes.</summary>
public readonly record struct SnmpValue(byte Tag, byte[] Data)
{
    public const byte TagInteger = 0x02, TagOctetString = 0x04, TagNull = 0x05, TagOid = 0x06,
        TagIpAddress = 0x40, TagCounter32 = 0x41, TagGauge32 = 0x42, TagTimeTicks = 0x43, TagCounter64 = 0x46,
        TagNoSuchObject = 0x80, TagNoSuchInstance = 0x81, TagEndOfMibView = 0x82;

    /// <summary>noSuchObject, noSuchInstance or endOfMibView (v2c), or NULL: there is no value.</summary>
    public bool IsMissing => Tag is TagNull or TagNoSuchObject or TagNoSuchInstance or TagEndOfMibView;

    public long AsInteger() => Tag == TagInteger ? Ber.ReadInteger(Data) : (long)Ber.ReadUnsigned(Data);

    public byte[] AsBytes() => Data;

    /// <summary>The text of an OCTET STRING (printable ASCII/UTF-8, trailing NULs dropped); other types as their value.</summary>
    public string AsText() => Tag switch
    {
        TagOctetString => Encoding.UTF8.GetString(Data).TrimEnd('\0').Trim(),
        TagInteger or TagCounter32 or TagGauge32 or TagTimeTicks or TagCounter64 => AsInteger().ToString(),
        TagIpAddress when Data.Length == 4 => new IPAddress(Data).ToString(),
        TagOid => Ber.ReadOid(Data),
        _ => "",
    };

    public override string ToString() => IsMissing ? $"(missing 0x{Tag:x2})" : AsText();
}

public sealed record SnmpVarBind(string Oid, SnmpValue Value);

/// <summary>An SNMP message as read: the request it answers, the error status, the variable bindings.</summary>
public sealed record SnmpResponse(int RequestId, int ErrorStatus, int ErrorIndex, IReadOnlyList<SnmpVarBind> VarBinds);

/// <summary>
/// The BER (ASN.1 Basic Encoding Rules) subset SNMP v1/v2c needs: INTEGER, OCTET STRING, NULL, OBJECT IDENTIFIER,
/// SEQUENCE, the SNMP application types and the PDUs.
/// </summary>
public static class Ber
{
    public const byte PduGet = 0xA0, PduGetNext = 0xA1, PduResponse = 0xA2, PduGetBulk = 0xA5;

    // ---- writing ----------------------------------------------------------------------------------------------

    public static byte[] Tlv(byte tag, ReadOnlySpan<byte> content)
    {
        var length = Length(content.Length);
        var result = new byte[1 + length.Length + content.Length];
        result[0] = tag;
        length.CopyTo(result, 1);
        content.CopyTo(result.AsSpan(1 + length.Length));
        return result;
    }

    public static byte[] Sequence(byte tag, params byte[][] items) => Tlv(tag, items.SelectMany(i => i).ToArray());

    private static byte[] Length(int length) => length switch
    {
        < 0x80 => [(byte)length],
        <= 0xFF => [0x81, (byte)length],
        <= 0xFFFF => [0x82, (byte)(length >> 8), (byte)length],
        _ => [0x83, (byte)(length >> 16), (byte)(length >> 8), (byte)length],
    };

    public static byte[] Integer(long value)
    {
        // Two's complement, big-endian, as few bytes as keep the sign.
        var bytes = new List<byte>();
        long v = value;
        do { bytes.Insert(0, (byte)v); v >>= 8; }
        while (!((v == 0 && (bytes[0] & 0x80) == 0) || (v == -1 && (bytes[0] & 0x80) != 0)));
        return Tlv(SnmpValue.TagInteger, bytes.ToArray());
    }

    public static byte[] OctetString(string text) => Tlv(SnmpValue.TagOctetString, Encoding.ASCII.GetBytes(text));

    public static byte[] Null() => [SnmpValue.TagNull, 0x00];

    public static byte[] Oid(string oid)
    {
        uint[] arcs = ParseOid(oid);
        if (arcs.Length < 2) throw new ArgumentException($"\"{oid}\" is not an OID.");
        var content = new List<byte>();
        AddArc(content, arcs[0] * 40 + arcs[1]);
        for (int i = 2; i < arcs.Length; i++) AddArc(content, arcs[i]);
        return Tlv(SnmpValue.TagOid, content.ToArray());

        static void AddArc(List<byte> to, uint arc)
        {
            // base 128, the high bit set on every byte but the last
            var stack = new Stack<byte>();
            stack.Push((byte)(arc & 0x7F));
            for (arc >>= 7; arc > 0; arc >>= 7) stack.Push((byte)(0x80 | (arc & 0x7F)));
            to.AddRange(stack);
        }
    }

    public static uint[] ParseOid(string oid) =>
        oid.TrimStart('.').Split('.', StringSplitOptions.RemoveEmptyEntries).Select(uint.Parse).ToArray();

    /// <summary>A GET, GETNEXT or GETBULK request. For GETBULK the two numbers are non-repeaters and max-repetitions.</summary>
    public static byte[] Request(SnmpVersion version, string community, byte pdu, int requestId, IEnumerable<string> oids,
        int nonRepeaters = 0, int maxRepetitions = 0)
    {
        byte[][] varBinds = oids.Select(o => Sequence(0x30, Oid(o), Null())).ToArray();
        bool bulk = pdu == PduGetBulk;
        return Sequence(0x30,
            Integer((int)version),
            OctetString(community),
            Sequence(pdu,
                Integer(requestId),
                Integer(bulk ? nonRepeaters : 0),
                Integer(bulk ? maxRepetitions : 0),
                Sequence(0x30, varBinds)));
    }

    // ---- reading ----------------------------------------------------------------------------------------------

    /// <summary>One TLV at <paramref name="at"/>: its tag and content; <paramref name="at"/> moves past it.</summary>
    public static (byte Tag, byte[] Content) Read(ReadOnlySpan<byte> data, ref int at)
    {
        if (at + 2 > data.Length) throw new FormatException("BER: truncated");
        byte tag = data[at++];
        int length = data[at++];
        if ((length & 0x80) != 0)
        {
            int count = length & 0x7F;
            if (count is 0 or > 3 || at + count > data.Length) throw new FormatException("BER: bad length");
            length = 0;
            for (int i = 0; i < count; i++) length = (length << 8) | data[at++];
        }
        if (at + length > data.Length) throw new FormatException("BER: truncated");
        byte[] content = data.Slice(at, length).ToArray();
        at += length;
        return (tag, content);
    }

    public static long ReadInteger(ReadOnlySpan<byte> content)
    {
        if (content.Length == 0) return 0;
        long v = (sbyte)content[0];
        for (int i = 1; i < content.Length; i++) v = (v << 8) | content[i];
        return v;
    }

    public static ulong ReadUnsigned(ReadOnlySpan<byte> content)
    {
        ulong v = 0;
        foreach (byte b in content) v = (v << 8) | b;
        return v;
    }

    public static string ReadOid(ReadOnlySpan<byte> content)
    {
        if (content.Length == 0) return "";
        var arcs = new List<ulong>();
        ulong arc = 0;
        foreach (byte b in content)
        {
            arc = (arc << 7) | (uint)(b & 0x7F);
            if ((b & 0x80) == 0) { arcs.Add(arc); arc = 0; }
        }
        ulong first = arcs[0];
        var parts = new List<ulong> { first < 80 ? first / 40 : 2, first < 80 ? first % 40 : first - 80 };
        parts.AddRange(arcs.Skip(1));
        return string.Join('.', parts);
    }

    /// <summary>An SNMP v1/v2c response message, or an exception when it is not one.</summary>
    public static SnmpResponse ReadResponse(ReadOnlySpan<byte> message)
    {
        int at = 0;
        var (tag, body) = Read(message, ref at);
        if (tag != 0x30) throw new FormatException("SNMP: not a message");
        int b = 0;
        Read(body, ref b);                    // version
        Read(body, ref b);                    // community
        var (pduTag, pdu) = Read(body, ref b);
        if (pduTag != PduResponse) throw new FormatException($"SNMP: PDU 0x{pduTag:x2} is not a response");
        int p = 0;
        int requestId = (int)ReadInteger(Read(pdu, ref p).Content);
        int errorStatus = (int)ReadInteger(Read(pdu, ref p).Content);
        int errorIndex = (int)ReadInteger(Read(pdu, ref p).Content);
        var (_, list) = Read(pdu, ref p);
        var varBinds = new List<SnmpVarBind>();
        int l = 0;
        while (l < list.Length)
        {
            var (_, vb) = Read(list, ref l);
            int v = 0;
            var (oidTag, oid) = Read(vb, ref v);
            if (oidTag != SnmpValue.TagOid) throw new FormatException("SNMP: a variable binding without an OID");
            var (valueTag, value) = Read(vb, ref v);
            varBinds.Add(new SnmpVarBind(ReadOid(oid), new SnmpValue(valueTag, value)));
        }
        return new SnmpResponse(requestId, errorStatus, errorIndex, varBinds);
    }
}

/// <summary>
/// A small SNMP v1/v2c client over UDP port 161: GET, and a walk of a subtree (GETBULK with v2c, GETNEXT with v1).
/// Read-only - nothing is ever set.
/// </summary>
public sealed class SnmpClient
{
    private readonly IPAddress _host;
    private readonly string _community;
    private readonly TimeSpan _timeout;
    private readonly int _retries;
    private readonly int _port;
    private static int _requestId = Random.Shared.Next(1, int.MaxValue / 2);

    /// <summary>GETBULK's max-repetitions, then what a walk falls back to when an agent fails it.</summary>
    public const int BulkRepetitions = 24, SmallBulkRepetitions = 4;

    /// <param name="port">UDP port of the agent (161; the self-test's fake agent listens elsewhere).</param>
    public SnmpClient(IPAddress host, string community, SnmpVersion version, TimeSpan timeout, int retries = 1, int port = 161)
    {
        _host = host;
        _community = community;
        Version = version;
        _timeout = timeout;
        _retries = retries;
        _port = port;
    }

    public SnmpVersion Version { get; }

    /// <summary>The values of <paramref name="oids"/>, or null when the agent does not answer.</summary>
    public async Task<IReadOnlyList<SnmpVarBind>?> GetAsync(IReadOnlyList<string> oids, CancellationToken ct)
    {
        var response = await RequestAsync(Ber.PduGet, oids, 0, 0, ct).ConfigureAwait(false);
        if (response is null) return null;
        // v1 answers a missing object with error 2 (noSuchName) for the whole request: ask one by one.
        if (response.ErrorStatus != 0 && oids.Count > 1)
        {
            var one = new List<SnmpVarBind>();
            foreach (string oid in oids)
            {
                var r = await RequestAsync(Ber.PduGet, [oid], 0, 0, ct).ConfigureAwait(false);
                if (r is null) return null;
                one.Add(r.ErrorStatus == 0 && r.VarBinds.Count == 1
                    ? r.VarBinds[0]
                    : new SnmpVarBind(oid, new SnmpValue(SnmpValue.TagNoSuchObject, [])));
            }
            return one;
        }
        if (response.ErrorStatus != 0)
            return oids.Select(o => new SnmpVarBind(o, new SnmpValue(SnmpValue.TagNoSuchObject, []))).ToList();
        return response.VarBinds;
    }

    /// <summary>
    /// Every object under <paramref name="root"/>, in order (at most <paramref name="maxRows"/>). Null when the agent
    /// stops answering before the walk is done.
    /// <para>v2c walks with GETBULK. Small embedded agents (Profinet devices, small switches) may answer GETBULK with
    /// tooBig or genErr instead of trimming the answer, or not at all: the walk then goes on from where it is with
    /// fewer repetitions, and then with GETNEXT, before it gives up.</para>
    /// </summary>
    public async Task<List<SnmpVarBind>?> WalkAsync(string root, CancellationToken ct, int maxRows = 5000)
    {
        string prefix = root.TrimStart('.') + ".";
        var rows = new List<SnmpVarBind>();
        string next = root.TrimStart('.');
        int repetitions = Version == SnmpVersion.V2c ? BulkRepetitions : 0; // 0: GETNEXT
        while (rows.Count < maxRows)
        {
            ct.ThrowIfCancellationRequested();
            var response = repetitions > 0
                ? await RequestAsync(Ber.PduGetBulk, [next], 0, repetitions, ct).ConfigureAwait(false)
                : await RequestAsync(Ber.PduGetNext, [next], 0, 0, ct).ConfigureAwait(false);
            if (repetitions > 0 && (response is null || response.ErrorStatus != 0))
            {
                // the agent failed GETBULK: fewer repetitions, then GETNEXT, from the same place
                repetitions = repetitions > SmallBulkRepetitions ? SmallBulkRepetitions : 0;
                continue;
            }
            if (response is null) return rows.Count > 0 ? rows : null;
            if (response.ErrorStatus != 0 || response.VarBinds.Count == 0) return rows; // v1: noSuchName = the end
            foreach (var vb in response.VarBinds)
            {
                if (!vb.Oid.StartsWith(prefix, StringComparison.Ordinal) || vb.Value.Tag == SnmpValue.TagEndOfMibView)
                    return rows;
                if (CompareOid(vb.Oid, next) <= 0) return rows; // an agent that does not move forward
                rows.Add(vb);
                next = vb.Oid;
            }
        }
        return rows;
    }

    private async Task<SnmpResponse?> RequestAsync(byte pdu, IReadOnlyList<string> oids, int nonRepeaters, int maxRepetitions, CancellationToken ct)
    {
        int id = Interlocked.Increment(ref _requestId) & 0x7FFFFFFF;
        byte[] request = Ber.Request(Version, _community, pdu, id, oids, nonRepeaters, maxRepetitions);
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Connect(_host, _port);
        for (int attempt = 0; attempt <= _retries; attempt++)
        {
            await udp.SendAsync(request, ct).ConfigureAwait(false);
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
            wait.CancelAfter(_timeout);
            try
            {
                while (true)
                {
                    var received = await udp.ReceiveAsync(wait.Token).ConfigureAwait(false);
                    SnmpResponse response;
                    try { response = Ber.ReadResponse(received.Buffer); }
                    catch (FormatException) { continue; }
                    if (response.RequestId == id) return response;
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { /* timed out: try again */ }
            catch (SocketException) { return null; } // ICMP port unreachable: no agent
        }
        return null;
    }

    /// <summary>Numeric order of two OIDs.</summary>
    public static int CompareOid(string a, string b)
    {
        uint[] x = Ber.ParseOid(a), y = Ber.ParseOid(b);
        for (int i = 0; i < Math.Min(x.Length, y.Length); i++)
            if (x[i] != y[i]) return x[i].CompareTo(y[i]);
        return x.Length.CompareTo(y.Length);
    }
}
