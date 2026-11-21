using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using EthernetTools.Pn;

namespace EthernetTools;

// SNMPv3 (USM keys and digests against RFC 3414's vectors, AES-CFB against NIST's, and a whole exchange with a fake v3
// agent on 127.0.0.1) and Profinet's own records (a Read Implicit of PDPortDataReal answered by a fake device).
internal static partial class SelfTest
{
    private static string HexOf(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static void SnmpV3()
    {
        Section("snmpv3");
        byte[] engine = Convert.FromHexString("000000000000000000000002");
        Check("password to key, MD5 (RFC 3414 A.3.1: \"maplesyrup\")",
            HexOf(Usm.PasswordToKey(SnmpAuth.Md5, "maplesyrup")) == "9faf3283884e92834ebc9847d8edd963"
            && HexOf(Usm.LocalizedKey(SnmpAuth.Md5, "maplesyrup", engine)) == "526f5eed9fcce26f8964c2930787d82b");
        Check("password to key, SHA-1 (RFC 3414 A.3.2)",
            HexOf(Usm.PasswordToKey(SnmpAuth.Sha1, "maplesyrup")) == "9fb5cc0381497b3793528939ff788d5d79145211"
            && HexOf(Usm.LocalizedKey(SnmpAuth.Sha1, "maplesyrup", engine)) == "6695febc9288e36282235fc7151f128497b38f3f");
        // NIST SP 800-38A F.3.13, CFB128-AES128, first block - cut to 10 bytes (CFB is a stream: any length)
        byte[] key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c"), iv = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
        byte[] plain = Convert.FromHexString("6bc1bee22e409f96e93d");
        byte[] cipher = Usm.AesCfb(true, key, iv, plain);
        Check("AES-128-CFB (NIST SP 800-38A), any length, and back",
            HexOf(cipher) == "3b3fd92eb72dad203334" && Usm.AesCfb(false, key, iv, cipher).AsSpan().SequenceEqual(plain));
        Check("digest lengths: HMAC-MD5-96 and HMAC-SHA-96 12 bytes, HMAC-SHA-256-192 24",
            Usm.Digest(SnmpAuth.Sha1, key, plain).Length == 12 && Usm.Digest(SnmpAuth.Md5, key, plain).Length == 12
            && Usm.Digest(SnmpAuth.Sha256, key, plain).Length == 24);
        var user = new SnmpV3Credentials("ops", SnmpAuth.Sha1, "authpassword1", SnmpPriv.Aes128, "privpassword1");
        Check("the user's text leaves the passwords out", !user.ToString().Contains("password1"));

        using (var dialog = new SnmpV3Form(null))
        {
            bool defaults = dialog.AuthText == "SHA-1" && dialog.PrivText == "AES-128";
            dialog.Fill("ops", SnmpAuth.Sha256, "short", SnmpPriv.Aes128, "privpassword1");
            dialog.PressOk();
            bool refusedShort = dialog.Credentials is null && dialog.ErrorText.Contains("at least 8");
            dialog.Fill("ops", SnmpAuth.Sha256, "authpassword1", SnmpPriv.Aes128, "privpassword1");
            dialog.PressOk();
            Check("SNMPv3 dialog: SHA-1 / AES-128 to begin with; a short password refused; the user as entered",
                defaults && refusedShort && dialog.Credentials == new SnmpV3Credentials("ops", SnmpAuth.Sha256, "authpassword1", SnmpPriv.Aes128, "privpassword1"));
        }
        using (var dialog = new SnmpV3Form(user))
        {
            dialog.PressClear();
            Check("SNMPv3 dialog: \"Don't use SNMPv3\" clears the user", dialog.Credentials is null && dialog.DialogResult == DialogResult.OK);
        }

        // the maker from the engine ID (engine IDs as real agents on the office LAN give them)
        byte[] E(string hex) => Convert.FromHexString(hex);
        Check("engine ID -> maker: Aruba (14823), HP (11, the old format), Net-SNMP (8072); a bare 0000000001 names none",
            SnmpEngine.Maker(E("000039E7000020A6CDC20458")) == "Aruba" && SnmpEngine.Maker(E("0000000B0000EC0273376E20")) == "HP"
            && SnmpEngine.Maker(E("80001F88030021B77FC7FB")) == "Net-SNMP" && SnmpEngine.Maker(E("0000000001")) is null);
        Check("a network maker: by the engine ID first (a Linux agent is not one, whatever its MAC), else by the MAC prefix",
            TopologyDiscovery.NetworkMaker(E("000039E7000020A6CDC20458"), "20:A6:CD:C2:04:58") == "Aruba"
            && TopologyDiscovery.NetworkMaker(E("80001F8804286E6F6E6529"), "00:8E:73:00:00:01") is null
            && TopologyDiscovery.NetworkMaker(E("0000000001"), "00:8E:73:2A:18:06") == "Cisco"
            && TopologyDiscovery.NetworkMaker(E("0000000001"), "02:AA:00:00:00:01") is null);

        var table = Enumerable.Range(1, 30).Select(i => Int($"{TopologyDiscovery.Dot1dTpFdbPort}.0.1.2.3.4.{i}", i))
            .Append(Str(TopologyDiscovery.SysName, "core-v3")).ToList();
        (string? Name, string? Error, int Rows) Ask(SnmpV3Credentials agentUser, SnmpV3Credentials clientUser)
        {
            using var agent = new FakeV3Agent(table, agentUser);
            var client = new SnmpClient(IPAddress.Loopback, clientUser, TimeSpan.FromMilliseconds(300), retries: 0, port: agent.Port);
            return Task.Run(async () =>
            {
                var sys = await client.GetAsync([TopologyDiscovery.SysName], CancellationToken.None);
                string? error = client.LastError;
                var rows = sys is null ? null : await client.WalkAsync(TopologyDiscovery.Dot1dTpFdbPort, CancellationToken.None, 1000);
                return (sys?[0].Value.AsText(), error, rows?.Count ?? -1);
            }).GetAwaiter().GetResult();
        }
        var priv = Ask(user, user);
        Check("v3 authPriv (SHA-1, AES-128): discovery, the agent's clock (time window) learned, GET and a GETBULK walk",
            priv is { Name: "core-v3", Error: null, Rows: 30 });
        var sha256 = new SnmpV3Credentials("ops", SnmpAuth.Sha256, "authpassword2", SnmpPriv.None, "");
        Check("v3 authNoPriv (SHA-256)", Ask(sha256, sha256) is { Name: "core-v3", Rows: 30 });
        var wrong = Ask(user, user with { AuthPassword = "not-the-password" });
        Check("v3 with a wrong password: refused, and why", wrong.Name is null && wrong.Error?.Contains("wrong authentication password") == true);
        var stranger = Ask(user, user with { User = "someone" });
        Check("v3 with an unknown user: refused, and why", stranger.Name is null && stranger.Error?.Contains("unknown user name") == true);
    }

    /// <summary>A fake SNMPv3 agent (USM) on 127.0.0.1 with one user; its discovery report gives time 0 (as some
    /// switches do), so the client must learn the clock from a notInTimeWindow report.</summary>
    private sealed class FakeV3Agent : IDisposable
    {
        private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly CancellationTokenSource _stop = new();
        private readonly List<SnmpVarBind> _rows;
        private readonly SnmpV3Credentials _user;
        private readonly byte[] _engine = Convert.FromHexString("80001F8804656E67696E65");
        private readonly byte[]? _authKey, _privKey;
        private const int Boots = 7, Time = 4242;
        public int Port => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;

        public FakeV3Agent(IEnumerable<SnmpVarBind> rows, SnmpV3Credentials user)
        {
            _rows = rows.OrderBy(r => r.Oid, Comparer<string>.Create(SnmpClient.CompareOid)).ToList();
            _user = user;
            if (user.Auth != SnmpAuth.None) _authKey = Usm.LocalizedKey(user.Auth, user.AuthPassword, _engine);
            if (user.Priv != SnmpPriv.None) _privKey = Usm.LocalizedKey(user.Auth, user.PrivPassword, _engine);
            _ = Task.Run(ServeAsync);
        }

        private async Task ServeAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                UdpReceiveResult received;
                try { received = await _udp.ReceiveAsync(_stop.Token); }
                catch (Exception) { return; }
                byte[]? answer;
                try { answer = Answer(received.Buffer); } catch (Exception) { answer = null; }
                if (answer is not null) await _udp.SendAsync(answer, received.RemoteEndPoint);
            }
        }

        private byte[] Report(int id, string oid, byte flags, int time) =>
            SnmpV3Message.Build(id, (flags & 1) != 0 ? _user : null, flags, _engine, Boots, time,
                Ber.Sequence(Ber.PduReport, Ber.Integer(id), Ber.Integer(0), Ber.Integer(0),
                    Ber.Sequence(0x30, Ber.Sequence(0x30, Ber.Oid(oid), Ber.Tlv(SnmpValue.TagCounter32, [1])))),
                _authKey, _privKey, new byte[8]);

        private byte[]? Answer(byte[] request)
        {
            var m = SnmpV3Message.Read(request, (u, e) => u == _user.User && e.AsSpan().SequenceEqual(_engine) && _authKey is not null
                ? (_user, _authKey, _privKey) : null);
            if (m.EngineId.Length == 0) return Report(m.MessageId, UsmReport.UnknownEngineIds, 0, 0);
            if (m.User != _user.User) return Report(m.MessageId, UsmReport.UnknownUserNames, 0, Time);
            if ((m.Flags & 1) != 0 && !m.Authentic) return Report(m.MessageId, UsmReport.WrongDigests, 0, Time);
            if (Math.Abs(m.Time - Time) > 150) return Report(m.MessageId, UsmReport.NotInTimeWindows, (byte)(m.Flags & 1), Time);
            if (m.Pdu is not { } pdu) return Report(m.MessageId, UsmReport.DecryptionErrors, 0, Time);

            var found = new List<SnmpVarBind>();
            string oid = pdu.VarBinds[0].Oid;
            var after = _rows.Where(r => SnmpClient.CompareOid(r.Oid, oid) > 0);
            if (m.PduTag == Ber.PduGet)
                found.AddRange(pdu.VarBinds.Select(v => _rows.FirstOrDefault(r => r.Oid == v.Oid) ?? new SnmpVarBind(v.Oid, new SnmpValue(SnmpValue.TagNoSuchObject, []))));
            else if (m.PduTag == Ber.PduGetBulk) found.AddRange(after.Take(pdu.ErrorIndex));
            else if (after.FirstOrDefault() is { } next) found.Add(next);
            if (found.Count == 0) found.Add(new SnmpVarBind(oid, new SnmpValue(SnmpValue.TagEndOfMibView, [])));
            byte[][] binds = found.Select(f => Ber.Sequence(0x30, Ber.Oid(f.Oid), Ber.Tlv(f.Value.Tag, f.Value.Data))).ToArray();
            byte[] response = Ber.Sequence(Ber.PduResponse, Ber.Integer(pdu.RequestId), Ber.Integer(0), Ber.Integer(0), Ber.Sequence(0x30, binds));
            byte[] salt = new byte[8];
            Random.Shared.NextBytes(salt);
            return SnmpV3Message.Build(m.MessageId, _user, (byte)(m.Flags & 3), _engine, Boots, Time, response, _authKey, _privKey, salt);
        }

        public void Dispose() { _stop.Cancel(); _udp.Dispose(); }
    }

    // ---- Profinet records ------------------------------------------------------------------------------------------

    /// <summary>A PDPortDataReal block: one port, its peers (port id, chassis id, MAC), 32-bit aligned from the block's start.</summary>
    private static byte[] PortDataReal(ushort subslot, string ownPort, params (string Port, string Chassis, byte[] Mac)[] peers)
    {
        var b = new List<byte> { 0x02, 0x0F, 0, 0, 1, 0, 0, 0, 0, 0, (byte)(subslot >> 8), (byte)subslot };
        void Text(string s) { b.Add((byte)s.Length); b.AddRange(Encoding.ASCII.GetBytes(s)); }
        void Align() { while (b.Count % 4 != 0) b.Add(0); }
        Text(ownPort);
        b.Add((byte)peers.Length);
        Align();
        foreach (var (port, chassis, mac) in peers)
        {
            Text(port);
            Text(chassis);
            Align();
            b.AddRange([0, 0, 0, 10]); // line delay
            b.AddRange(mac);
            Align();
        }
        b.AddRange([0, 0x10, 0, 0]); // MAU type, padding
        BinaryPrimitives.WriteUInt16BigEndian(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(b)[2..], (ushort)(b.Count - 4));
        return b.ToArray();
    }

    /// <summary>A fake Profinet device on 127.0.0.1: answers Read Implicit of PDPortDataReal for the ports it has, and a
    /// PNIO error for the rest.</summary>
    private sealed class FakePnDevice : IDisposable
    {
        private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly CancellationTokenSource _stop = new();
        private readonly Dictionary<ushort, byte[]> _ports;
        public Guid? LastObject;
        public int Port => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;

        public FakePnDevice(Dictionary<ushort, byte[]> ports) { _ports = ports; _ = Task.Run(ServeAsync); }

        private async Task ServeAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                UdpReceiveResult r;
                try { r = await _udp.ReceiveAsync(_stop.Token); } catch (Exception) { return; }
                byte[] q = r.Buffer;
                if (q.Length < 164 || q[1] != 0 || BinaryPrimitives.ReadUInt16LittleEndian(q.AsSpan(68)) != ProfinetRpc.OpReadImplicit) continue;
                LastObject = new Guid(q.AsSpan(8, 16));
                ushort subslot = BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(100 + 30));
                ushort index = BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(100 + 34));
                bool have = index == ProfinetRpc.IndexPdPortDataReal && _ports.ContainsKey(subslot);
                byte[] record = have ? _ports[subslot] : [];
                var res = new byte[64];
                BinaryPrimitives.WriteUInt16BigEndian(res, ProfinetRpc.BlockReadResHeader);
                BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(2), 60);
                res[4] = 1;
                BinaryPrimitives.WriteUInt32BigEndian(res.AsSpan(36), (uint)record.Length);
                var data = have ? res.Concat(record).ToArray() : [];
                var body = new byte[20 + data.Length];
                if (!have) body[0] = 0xDE; body[1] = have ? (byte)0 : (byte)0x80; body[2] = have ? (byte)0 : (byte)0xB0; // PNIO status
                BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(4), (uint)data.Length);
                BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(8), (uint)data.Length);
                BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(16), (uint)data.Length);
                data.CopyTo(body, 20);
                var a = new byte[80 + body.Length];
                q.AsSpan(0, 80).CopyTo(a);
                a[1] = 2; // response
                BinaryPrimitives.WriteUInt16LittleEndian(a.AsSpan(74), (ushort)body.Length);
                body.CopyTo(a, 80);
                await _udp.SendAsync(a, r.RemoteEndPoint);
            }
        }

        public void Dispose() { _stop.Cancel(); _udp.Dispose(); }
    }

    private static void ProfinetRecords()
    {
        Section("profinet records");
        var obj = ProfinetRpc.ObjectUuid(0x002A, 0x0313);
        Check("a device's object UUID: DEA00000-6C97-11D1-8271-<instance><device id><vendor id>",
            obj == new Guid("DEA00000-6C97-11D1-8271-00010313002A"));
        var act = Guid.NewGuid();
        byte[] q = ProfinetRpc.BuildReadImplicit(obj, act, 3, 0, 0x8002, ProfinetRpc.IndexPdPortDataReal);
        Check("Read Implicit: RPC v4 request, little-endian, the PNIO device interface, opnum 5, the IODReadReqHeader for slot 0 / 0x8002 / 0x802A",
            q[0] == 4 && q[1] == 0 && q[4] == 0x10 && new Guid(q.AsSpan(24, 16)) == ProfinetRpc.DeviceInterface && new Guid(q.AsSpan(40, 16)) == act
            && BinaryPrimitives.ReadUInt16LittleEndian(q.AsSpan(68)) == 5 && BinaryPrimitives.ReadUInt16LittleEndian(q.AsSpan(74)) == q.Length - 80
            && BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(100)) == 0x0009 && BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(102)) == 60
            && BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(130)) == 0x8002 && BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(134)) == 0x802A);

        byte[] peerMac = [0x02, 0xAA, 0, 0, 0x0C, 0x02];
        var p = ProfinetRpc.ReadPortDataReal(PortDataReal(0x8002, "port-002", ("port-001.pn-c", "pn-c", peerMac)));
        Check("PDPortDataReal: own port, a peer's port id, chassis id (name of station) and MAC",
            p is { Subslot: 0x8002, PortId: "port-002", Peers: [{ PortId: "port-001.pn-c", ChassisId: "pn-c" } peer] } && peer.Mac.SequenceEqual(peerMac));
        var swapped = ProfinetRpc.ReadPortDataReal(PortDataReal(0x8001, "port-001", ("pn-c", "port-003.pn-c", peerMac)));
        Check("a peer written chassis first is still read right (by the port id's shape)",
            swapped is { Peers: [{ PortId: "port-003.pn-c", ChassisId: "pn-c" }] });

        // pn-a's port 1 to switch sw-a port 3 (by chassis MAC), port 2 to pn-b's port 1; port 3 not there
        byte[] swMac = [0x02, 0xAA, 0, 0, 0, 2];
        using var device = new FakePnDevice(new()
        {
            [0x8001] = PortDataReal(0x8001, "port-001", ("3", "02-AA-00-00-00-02", swMac)),
            [0x8002] = PortDataReal(0x8002, "port-002", ("port-001.pn-b", "pn-b", [0x02, 0xAA, 0, 0, 0x0B, 1])),
        });
        var ports = Task.Run(() => ProfinetRpc.ReadPortsAsync(IPAddress.Loopback, 0x002A, 0x0313, TimeSpan.FromMilliseconds(300),
            CancellationToken.None, device.Port)).GetAwaiter().GetResult();
        Check("Read Implicit over UDP: the ports a device has, stopping at the first it refuses; its object UUID asked",
            ports.Select(x => x.PortId).SequenceEqual(["port-001", "port-002"]) && device.LastObject == ProfinetRpc.ObjectUuid(0x002A, 0x0313));

        var devices = new List<NetDevice> { Dev(2, "sw-a"), Dev(41, "pn-a", profinet: true), Dev(42, "pn-b", profinet: true) };
        var pnA = devices[1];
        var sw = new SnmpAgentData { Ip = IPAddress.Parse("10.0.0.2"), LocalChassis = ChassisMac(2), Services = 2 };
        for (int i = 1; i <= 4; i++) sw.LocalPorts[i] = i.ToString();
        var g = TopologyBuilder.Build(devices, new ThisPcInfo("this-pc", Ms(99), "10.0.0.99", "Ethernet"), [], [sw, ProfinetRpc.ToAgent(pnA, ports)], null);
        bool Linked(string x, string px, string y, string py) => g.Links.Count(l =>
            (l.A.Name == x && l.PortA == px && l.B.Name == y && l.PortB == py) || (l.A.Name == y && l.PortA == py && l.B.Name == x && l.PortB == px)) == 1;
        Check("on the map: pn-a's records link it to the switch (sw-a port 3) and to pn-b (port-001), said to be read through Profinet",
            Linked("pn-a", "port-001", "sw-a", "3") && Linked("pn-a", "port-002", "pn-b", "port-001")
            && g.Nodes.Single(n => n.Name == "pn-a").Detail?.Contains("Profinet") == true);
    }
}
