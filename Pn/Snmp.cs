using System.Net;
using System.Net.Sockets;
using System.Text;

namespace EthernetTools.Pn;

public enum SnmpVersion { V1 = 0, V2c = 1, V3 = 3 }

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
    public const byte PduGet = 0xA0, PduGetNext = 0xA1, PduResponse = 0xA2, PduGetBulk = 0xA5, PduReport = 0xA8;

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
        return Sequence(0x30,
            Integer((int)version),
            OctetString(community),
            Pdu(pdu, requestId, oids, nonRepeaters, maxRepetitions));
    }

    /// <summary>A request PDU (its tag included): request id, the two numbers (GETBULK's), the OIDs with NULL values.</summary>
    public static byte[] Pdu(byte pdu, int requestId, IEnumerable<string> oids, int nonRepeaters = 0, int maxRepetitions = 0)
    {
        byte[][] varBinds = oids.Select(o => Sequence(0x30, Oid(o), Null())).ToArray();
        bool bulk = pdu == PduGetBulk;
        return Sequence(pdu,
            Integer(requestId),
            Integer(bulk ? nonRepeaters : 0),
            Integer(bulk ? maxRepetitions : 0),
            Sequence(0x30, varBinds));
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
        return ReadPdu(pdu);
    }

    /// <summary>A PDU's content (any PDU: request id, error status and index, variable bindings).</summary>
    public static SnmpResponse ReadPdu(ReadOnlySpan<byte> pdu)
    {
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
/// A small SNMP client over UDP port 161: GET, and a walk of a subtree (GETBULK with v2c and v3, GETNEXT with v1).
/// v1 and v2c with a community; v3 with a USM user (<see cref="SnmpV3Credentials"/>): engine discovery, then
/// authenticated (MD5, SHA-1, SHA-256) and encrypted (AES-128) requests. Read-only - nothing is ever set.
/// </summary>
public sealed class SnmpClient
{
    private readonly IPAddress _host;
    private readonly string _community;
    private readonly TimeSpan _timeout;
    private readonly int _retries;
    private readonly int _port;
    private static int _requestId = Random.Shared.Next(1, int.MaxValue / 2);
    private static long _salt = Random.Shared.NextInt64();

    // SNMPv3: the user, and what engine discovery learned (the engine, its boots and time, the localized keys)
    private readonly SnmpV3Credentials? _user;
    private byte[]? _engineId;
    private int _boots, _time;
    private readonly System.Diagnostics.Stopwatch _since = new();
    private byte[]? _authKey, _privKey;

    /// <summary>GETBULK's max-repetitions, then what a walk falls back to when an agent fails it.</summary>
    public const int BulkRepetitions = 24, SmallBulkRepetitions = 4;

    /// <param name="port">UDP port of the agent (161; the self-test's fake agent listens elsewhere).</param>
    public SnmpClient(IPAddress host, string community, SnmpVersion version, TimeSpan timeout, int retries = 1, int port = 161)
    {
        if (version == SnmpVersion.V3) throw new ArgumentException("SNMPv3 takes a user, not a community.");
        _host = host;
        _community = community;
        Version = version;
        _timeout = timeout;
        _retries = retries;
        _port = port;
    }

    /// <summary>An SNMPv3 client for <paramref name="user"/>.</summary>
    public SnmpClient(IPAddress host, SnmpV3Credentials user, TimeSpan timeout, int retries = 1, int port = 161)
    {
        _host = host;
        _community = "";
        _user = user;
        Version = SnmpVersion.V3;
        _timeout = timeout;
        _retries = retries;
        _port = port;
    }

    public SnmpVersion Version { get; }

    /// <summary>Why the last request got no answer, when the agent said why (an SNMPv3 report): "unknown user name" ...</summary>
    public string? LastError { get; private set; }

    /// <summary>The last walk reached the end of its subtree (not cut short by a silent agent or the row limit).</summary>
    public bool LastWalkComplete { get; private set; }

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
        LastWalkComplete = false;
        var rows = await WalkRowsAsync(root, ct, maxRows).ConfigureAwait(false);
        return rows;
    }

    private async Task<List<SnmpVarBind>?> WalkRowsAsync(string root, CancellationToken ct, int maxRows)
    {
        string prefix = root.TrimStart('.') + ".";
        var rows = new List<SnmpVarBind>();
        string next = root.TrimStart('.');
        int repetitions = Version != SnmpVersion.V1 ? BulkRepetitions : 0; // 0: GETNEXT
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
            if (response.ErrorStatus != 0 || response.VarBinds.Count == 0) { LastWalkComplete = true; return rows; } // v1: noSuchName = the end
            foreach (var vb in response.VarBinds)
            {
                if (!vb.Oid.StartsWith(prefix, StringComparison.Ordinal) || vb.Value.Tag == SnmpValue.TagEndOfMibView)
                {
                    LastWalkComplete = true;
                    return rows;
                }
                if (CompareOid(vb.Oid, next) <= 0) return rows; // an agent that does not move forward
                rows.Add(vb);
                next = vb.Oid;
            }
        }
        return rows;
    }

    private static int NextId() => Interlocked.Increment(ref _requestId) & 0x7FFFFFFF;

    private Task<SnmpResponse?> RequestAsync(byte pdu, IReadOnlyList<string> oids, int nonRepeaters, int maxRepetitions, CancellationToken ct)
    {
        if (Version == SnmpVersion.V3) return RequestV3Async(pdu, oids, nonRepeaters, maxRepetitions, ct);
        int id = NextId();
        byte[] request = Ber.Request(Version, _community, pdu, id, oids, nonRepeaters, maxRepetitions);
        return ExchangeAsync(request, buffer => Ber.ReadResponse(buffer) is { } r && r.RequestId == id ? r : null, ct);
    }

    /// <summary>Sends <paramref name="request"/> (again, on a time-out) until an answer <paramref name="match"/> accepts.</summary>
    private async Task<T?> ExchangeAsync<T>(byte[] request, Func<byte[], T?> match, CancellationToken ct) where T : class
    {
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
                    T? answer;
                    try { answer = match(received.Buffer); }
                    catch (Exception ex) when (ex is not OperationCanceledException) { continue; } // not an answer we can read
                    if (answer is not null) return answer;
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { /* timed out: try again */ }
            catch (SocketException) { return null; } // ICMP port unreachable: no agent
        }
        return null;
    }

    // ---- SNMPv3 ---------------------------------------------------------------------------------------------------

    /// <summary>SNMPv3: the engine ID engine discovery learned (null before, or when the agent did not answer).</summary>
    public byte[]? EngineId => _engineId;

    /// <summary>SNMPv3 only: the agent answers engine discovery.</summary>
    public Task<bool> DiscoverEngineAsync(CancellationToken ct) =>
        Version == SnmpVersion.V3 ? DiscoverAsync(ct) : Task.FromResult(false);

    /// <summary>Engine discovery (RFC 3414 4): an empty, unauthenticated request; the report names the engine, its boots and time.</summary>
    private async Task<bool> DiscoverAsync(CancellationToken ct)
    {
        int id = NextId();
        byte[] request = SnmpV3Message.Build(id, null, 4, [], 0, 0, Ber.Pdu(Ber.PduGet, id, []), null, null, []);
        var report = await ExchangeAsync(request, buffer => SnmpV3Message.Read(buffer, (_, _) => null) is { } m && m.MessageId == id ? m : null, ct)
            .ConfigureAwait(false);
        if (report is not { EngineId.Length: > 0 }) return false;
        _engineId = report.EngineId;
        _boots = report.Boots;
        _time = report.Time;
        _since.Restart();
        if (_user!.Auth != SnmpAuth.None)
        {
            _authKey = await Task.Run(() => Usm.LocalizedKey(_user.Auth, _user.AuthPassword, _engineId), ct).ConfigureAwait(false);
            if (_user.Priv != SnmpPriv.None)
                _privKey = await Task.Run(() => Usm.LocalizedKey(_user.Auth, _user.PrivPassword, _engineId), ct).ConfigureAwait(false);
        }
        return true;
    }

    private async Task<SnmpResponse?> RequestV3Async(byte pdu, IReadOnlyList<string> oids, int nonRepeaters, int maxRepetitions, CancellationToken ct)
    {
        if (_engineId is null && !await DiscoverAsync(ct).ConfigureAwait(false)) return null;
        var user = _user!;
        for (int attempt = 0; attempt < 2; attempt++)
        {
            int id = NextId();
            byte[] salt = new byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(salt, Interlocked.Increment(ref _salt));
            int time = _time + (int)_since.Elapsed.TotalSeconds;
            byte[] request = SnmpV3Message.Build(id, user, user.Flags, _engineId!, _boots, time,
                Ber.Pdu(pdu, id, oids, nonRepeaters, maxRepetitions), _authKey, _privKey, salt);
            var answer = await ExchangeAsync(request, buffer => SnmpV3Message.Read(buffer, Keys) is { } m && m.MessageId == id ? m : null, ct)
                .ConfigureAwait(false);
            if (answer is null) return null;
            if (answer.PduTag == Ber.PduReport)
            {
                string? reason = answer.Pdu?.VarBinds.FirstOrDefault()?.Oid;
                if (reason == UsmReport.NotInTimeWindows && attempt == 0)
                {
                    // the agent's clock, from its report: then once more
                    _boots = answer.Boots;
                    _time = answer.Time;
                    _since.Restart();
                    continue;
                }
                LastError = "SNMPv3: " + UsmReport.Text(reason);
                return null;
            }
            if (answer.Pdu is null) { LastError = "SNMPv3: the answer could not be decrypted"; return null; }
            if (user.Auth != SnmpAuth.None && !answer.Authentic) { LastError = "SNMPv3: the answer's digest does not match"; return null; }
            LastError = null;
            return answer.Pdu;
        }
        return null;
    }

    private (SnmpV3Credentials, byte[], byte[]?)? Keys(string user, byte[] engineId) =>
        _user is { Auth: not SnmpAuth.None } u && _authKey is not null && engineId.AsSpan().SequenceEqual(_engineId)
            ? (u, _authKey, _privKey) : null;

    /// <summary>Numeric order of two OIDs.</summary>
    public static int CompareOid(string a, string b)
    {
        uint[] x = Ber.ParseOid(a), y = Ber.ParseOid(b);
        for (int i = 0; i < Math.Min(x.Length, y.Length); i++)
            if (x[i] != y[i]) return x[i].CompareTo(y[i]);
        return x.Length.CompareTo(y.Length);
    }
}
