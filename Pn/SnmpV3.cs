using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace EthernetTools.Pn;

public enum SnmpAuth { None, Md5, Sha1, Sha256 }
public enum SnmpPriv { None, Aes128 }

/// <summary>
/// An SNMPv3 user (USM, RFC 3414): its name, authentication and privacy. Kept in memory only; never written out, and
/// <see cref="ToString"/> leaves the passwords out.
/// </summary>
public sealed record SnmpV3Credentials(string User, SnmpAuth Auth, string AuthPassword, SnmpPriv Priv, string PrivPassword)
{
    /// <summary>msgFlags: authentication, privacy (only with authentication), reportable.</summary>
    public byte Flags => (byte)((Auth != SnmpAuth.None ? 1 : 0) | (Auth != SnmpAuth.None && Priv != SnmpPriv.None ? 2 : 0) | 4);

    public string Level => Auth == SnmpAuth.None ? "noAuthNoPriv" : Priv == SnmpPriv.None ? "authNoPriv" : "authPriv";

    public override string ToString() => $"{User} ({Level}, {Auth}{(Priv != SnmpPriv.None ? "/" + Priv : "")})";
}

/// <summary>
/// Who made an SNMP agent, from its SNMPv3 engine ID: the first four bytes carry the maker's IANA enterprise number
/// (RFC 3411; the older format, RFC 1910, the same without the top bit). Engine discovery answers it to anyone.
/// </summary>
public static class SnmpEngine
{
    private static readonly Dictionary<int, string> Makers = new()
    {
        [2] = "IBM", [9] = "Cisco", [11] = "HP", [171] = "D-Link", [248] = "Hirschmann", [311] = "Microsoft", [674] = "Dell",
        [890] = "Zyxel", [1916] = "Extreme Networks", [2636] = "Juniper", [4329] = "Siemens", [4526] = "Netgear",
        [8072] = "Net-SNMP", [8691] = "Moxa", [10642] = "Zebra", [11863] = "TP-Link", [14823] = "Aruba", [14988] = "MikroTik",
        [41112] = "Ubiquiti",
    };

    /// <summary>Makers of switches and access points (an agent of theirs that speaks only SNMPv3 is likely one).</summary>
    public static readonly HashSet<string> NetworkMakers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Cisco", "HP", "HPE / Aruba", "Aruba", "D-Link", "Hirschmann", "Zyxel", "Extreme Networks", "Juniper", "Siemens",
        "Netgear", "Moxa", "TP-Link", "MikroTik", "Routerboard / MikroTik", "Ubiquiti", "Phoenix Contact", "Westermo",
    };

    public static int? Enterprise(byte[] engineId) =>
        engineId.Length >= 5 ? (int)(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(engineId) & 0x7FFFFFFF) : null;

    /// <summary>The maker's name, or null when the engine ID names none this table knows (or none at all: 0).</summary>
    public static string? Maker(byte[] engineId) =>
        Enterprise(engineId) is { } e and > 0 && Makers.TryGetValue(e, out var name) ? name : null;
}

/// <summary>A USM report (RFC 3414 3.2): why the agent refused a request.</summary>
public static class UsmReport
{
    public const string UnsupportedSecLevels = "1.3.6.1.6.3.15.1.1.1.0", NotInTimeWindows = "1.3.6.1.6.3.15.1.1.2.0",
        UnknownUserNames = "1.3.6.1.6.3.15.1.1.3.0", UnknownEngineIds = "1.3.6.1.6.3.15.1.1.4.0",
        WrongDigests = "1.3.6.1.6.3.15.1.1.5.0", DecryptionErrors = "1.3.6.1.6.3.15.1.1.6.0";

    public static string Text(string? oid) => oid switch
    {
        UnsupportedSecLevels => "the security level (authentication / privacy) is not allowed for this user",
        NotInTimeWindows => "out of the agent's time window",
        UnknownUserNames => "unknown user name",
        UnknownEngineIds => "unknown engine id",
        WrongDigests => "wrong authentication password or protocol",
        DecryptionErrors => "wrong privacy password or protocol",
        _ => $"refused ({oid ?? "no reason given"})",
    };
}

/// <summary>The User-based Security Model's keys, digests and AES-CFB (RFC 3414, RFC 3826, RFC 7860).</summary>
public static class Usm
{
    private static readonly ConcurrentDictionary<string, byte[]> Localized = new();

    /// <summary>The digest's length in a message: HMAC-MD5-96 and HMAC-SHA-96 12 bytes, HMAC-SHA-256-192 24.</summary>
    public static int MacLength(SnmpAuth auth) => auth == SnmpAuth.Sha256 ? 24 : auth == SnmpAuth.None ? 0 : 12;

    private static HashAlgorithm Hash(SnmpAuth auth) => auth switch
    {
        SnmpAuth.Md5 => MD5.Create(),
        SnmpAuth.Sha1 => SHA1.Create(),
        SnmpAuth.Sha256 => SHA256.Create(),
        _ => throw new ArgumentException("No authentication protocol."),
    };

    /// <summary>Password to key (1 MB of the password, hashed), RFC 3414 A.2.</summary>
    public static byte[] PasswordToKey(SnmpAuth auth, string password)
    {
        byte[] pw = Encoding.UTF8.GetBytes(password);
        if (pw.Length == 0) throw new ArgumentException("An empty password.");
        var buffer = new byte[1 << 20];
        for (int i = 0; i < buffer.Length; i++) buffer[i] = pw[i % pw.Length];
        using var h = Hash(auth);
        return h.ComputeHash(buffer);
    }

    /// <summary>The key localized to one engine: H(Ku | engineID | Ku). Cached per protocol, password and engine.</summary>
    public static byte[] LocalizedKey(SnmpAuth auth, string password, byte[] engineId)
    {
        string cacheKey = $"{auth}\n{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password)))}\n{Convert.ToHexString(engineId)}";
        return Localized.GetOrAdd(cacheKey, _ =>
        {
            byte[] ku = PasswordToKey(auth, password);
            using var h = Hash(auth);
            return h.ComputeHash([.. ku, .. engineId, .. ku]);
        });
    }

    public static byte[] Digest(SnmpAuth auth, byte[] key, byte[] message)
    {
        byte[] mac = auth switch
        {
            SnmpAuth.Md5 => HMACMD5.HashData(key, message),
            SnmpAuth.Sha1 => HMACSHA1.HashData(key, message),
            SnmpAuth.Sha256 => HMACSHA256.HashData(key, message),
            _ => throw new ArgumentException("No authentication protocol."),
        };
        return mac[..MacLength(auth)];
    }

    /// <summary>
    /// AES-128 in CFB-128 (RFC 3826), any length: CFB is a stream mode, so the data is padded to whole blocks and the
    /// result cut back to its length.
    /// </summary>
    public static byte[] AesCfb(bool encrypt, byte[] key, byte[] iv, byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = key[..16];
        var whole = new byte[(data.Length + 15) / 16 * 16];
        data.CopyTo(whole, 0);
        byte[] result = encrypt
            ? aes.EncryptCfb(whole, iv, PaddingMode.None, 128)
            : aes.DecryptCfb(whole, iv, PaddingMode.None, 128);
        return result[..data.Length];
    }

    /// <summary>The AES IV: engineBoots, engineTime (both 32-bit, big-endian) and the 64-bit salt.</summary>
    public static byte[] AesIv(int boots, int time, byte[] salt)
    {
        var iv = new byte[16];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(iv, boots);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(iv.AsSpan(4), time);
        salt.AsSpan(0, 8).CopyTo(iv.AsSpan(8));
        return iv;
    }
}

/// <summary>An SNMPv3 message as read: its header, the USM parameters and the PDU (decrypted).</summary>
public sealed record SnmpV3Message(int MessageId, byte Flags, byte[] EngineId, int Boots, int Time, string User,
    byte[] AuthParams, byte[] PrivParams, byte PduTag, SnmpResponse? Pdu, bool Authentic)
{
    /// <summary>
    /// A v3 message (request or answer). <paramref name="pdu"/> is the whole PDU TLV (tag included). With
    /// authentication the digest is computed over the whole message and put in place; with privacy the scoped PDU is
    /// encrypted with <paramref name="salt"/>.
    /// </summary>
    public static byte[] Build(int messageId, SnmpV3Credentials? user, byte flags, byte[] engineId, int boots, int time,
        byte[] pdu, byte[]? authKey, byte[]? privKey, byte[] salt)
    {
        bool auth = (flags & 1) != 0, priv = (flags & 2) != 0;
        byte[] scoped = Ber.Sequence(0x30, Ber.Tlv(SnmpValue.TagOctetString, engineId), Ber.Tlv(SnmpValue.TagOctetString, []), pdu);
        byte[] privParams = [];
        byte[] data = scoped;
        if (priv)
        {
            privParams = salt;
            data = Ber.Tlv(SnmpValue.TagOctetString, Usm.AesCfb(true, privKey!, Usm.AesIv(boots, time, salt), scoped));
        }
        int macLength = auth ? Usm.MacLength(user!.Auth) : 0;
        byte[] engine = Ber.Tlv(SnmpValue.TagOctetString, engineId), bootsTlv = Ber.Integer(boots), timeTlv = Ber.Integer(time),
            userTlv = Ber.Tlv(SnmpValue.TagOctetString, Encoding.UTF8.GetBytes(user?.User ?? "")),
            authTlv = Ber.Tlv(SnmpValue.TagOctetString, new byte[macLength]), privTlv = Ber.Tlv(SnmpValue.TagOctetString, privParams);
        byte[] usmContent = [.. engine, .. bootsTlv, .. timeTlv, .. userTlv, .. authTlv, .. privTlv];
        byte[] usm = Ber.Tlv(0x30, usmContent);
        byte[] secParams = Ber.Tlv(SnmpValue.TagOctetString, usm);
        byte[] version = Ber.Integer(3);
        byte[] global = Ber.Sequence(0x30, Ber.Integer(messageId), Ber.Integer(65507), Ber.Tlv(SnmpValue.TagOctetString, [flags]), Ber.Integer(3));
        byte[] content = [.. version, .. global, .. secParams, .. data];
        byte[] message = Ber.Tlv(0x30, content);
        if (auth)
        {
            // where the digest goes: past the message's header, the version, the header data, the two headers of the
            // security parameters, engine, boots, time and user, and the digest's own tag and length
            int at = (message.Length - content.Length) + version.Length + global.Length
                     + (secParams.Length - usm.Length) + (usm.Length - usmContent.Length)
                     + engine.Length + bootsTlv.Length + timeTlv.Length + userTlv.Length + (authTlv.Length - macLength);
            Usm.Digest(user!.Auth, authKey!, message).CopyTo(message, at);
        }
        return message;
    }

    /// <summary>
    /// Reads a v3 message. <paramref name="keys"/> gives the user's authentication and privacy keys for the engine the
    /// message names (null: not known - an unauthenticated report); the digest is checked, the PDU decrypted.
    /// </summary>
    public static SnmpV3Message Read(byte[] message, Func<string, byte[], (SnmpV3Credentials User, byte[] AuthKey, byte[]? PrivKey)?> keys)
    {
        int at = 0;
        var (tag, body) = Ber.Read(message, ref at);
        if (tag != 0x30) throw new FormatException("SNMP: not a message");
        int b = 0;
        if (Ber.ReadInteger(Ber.Read(body, ref b).Content) != 3) throw new FormatException("SNMP: not version 3");
        var (_, global) = Ber.Read(body, ref b);
        int g = 0;
        int messageId = (int)Ber.ReadInteger(Ber.Read(global, ref g).Content);
        Ber.Read(global, ref g); // max size
        var flagBytes = Ber.Read(global, ref g).Content;
        byte flags = flagBytes.Length > 0 ? flagBytes[0] : (byte)0;
        var (_, secParams) = Ber.Read(body, ref b);
        int s = 0;
        var (_, usm) = Ber.Read(secParams, ref s);
        int u = 0;
        byte[] engineId = Ber.Read(usm, ref u).Content;
        int boots = (int)Ber.ReadInteger(Ber.Read(usm, ref u).Content);
        int time = (int)Ber.ReadInteger(Ber.Read(usm, ref u).Content);
        string user = Encoding.UTF8.GetString(Ber.Read(usm, ref u).Content);
        byte[] authParams = Ber.Read(usm, ref u).Content;
        byte[] privParams = Ber.Read(usm, ref u).Content;
        var (dataTag, data) = Ber.Read(body, ref b);

        var key = (flags & 1) != 0 ? keys(user, engineId) : null;
        bool authentic = false;
        if ((flags & 1) != 0 && key is { } k && authParams.Length == Usm.MacLength(k.User.Auth))
        {
            // the digest is over the message with its own place zeroed
            int place = message.AsSpan().IndexOf(authParams);
            if (place >= 0)
            {
                var zeroed = (byte[])message.Clone();
                Array.Clear(zeroed, place, authParams.Length);
                authentic = CryptographicOperations.FixedTimeEquals(Usm.Digest(k.User.Auth, k.AuthKey, zeroed), authParams);
            }
        }

        byte[] scoped;
        if ((flags & 2) != 0)
        {
            if (dataTag != SnmpValue.TagOctetString || key is not { PrivKey: { } privKey } || privParams.Length != 8)
                return new SnmpV3Message(messageId, flags, engineId, boots, time, user, authParams, privParams, 0, null, authentic);
            scoped = Usm.AesCfb(false, privKey, Usm.AesIv(boots, time, privParams), data);
            int x = 0;
            (_, scoped) = Ber.Read(scoped, ref x);
        }
        else scoped = data;
        int c = 0;
        Ber.Read(scoped, ref c); // contextEngineID
        Ber.Read(scoped, ref c); // contextName
        var (pduTag, pdu) = Ber.Read(scoped, ref c);
        return new SnmpV3Message(messageId, flags, engineId, boots, time, user, authParams, privParams, pduTag, Ber.ReadPdu(pdu), authentic);
    }
}
