using System.Net;
using System.Net.NetworkInformation;
using SharpPcap;
using SharpPcap.LibPcap;

namespace EthernetTools.Pn;

/// <summary>
/// Active + passive network discovery on a single Ethernet adapter:
///   • Profinet DCP Identify-All (Layer-2, finds PN devices in any subnet)
///   • ARP sweep of the adapter's local IPv4 subnet (finds Windows PCs etc.)
///   • Passive ARP / IPv4 snooping (devices in foreign subnets emitting traffic)
///   • NBNS + reverse-DNS hostname enrichment for discovered IPv4 hosts
/// </summary>
public sealed class NetworkScanner
{
    public event Action<NetDevice>? DeviceDiscoveredOrUpdated;

    /// <summary>An LLDP frame heard on the adapter: the neighbour it is plugged into (for the topology map).</summary>
    public event Action<LldpNeighbor>? LldpHeard;

    public async Task<IReadOnlyList<NetDevice>> ScanAsync(
        AdapterInfo adapter,
        TimeSpan timeout,
        IProgress<string>? status = null,
        CancellationToken ct = default)
    {
        var pcap = adapter.PcapDevice
            ?? throw new InvalidOperationException(
                $"'{adapter.FriendlyName}' is not bound to Npcap and cannot be captured on. " +
                "Install/repair Npcap and ensure the adapter's NPF driver binding is enabled.");
        var srcMac = adapter.MacAddress;

        var devices = new Dictionary<string, NetDevice>(StringComparer.OrdinalIgnoreCase);
        var dcpXid = (uint)Random.Shared.Next(1, int.MaxValue);

        // Local IPv4 + mask (for ARP sweep + sender IP in ARP requests).
        IPAddress? localIp = null, localMask = null;
        foreach (var ua in adapter.NetworkInterface.GetIPProperties().UnicastAddresses)
        {
            if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                localIp = ua.Address;
                localMask = ua.IPv4Mask;
                break;
            }
        }

        pcap.Open(new DeviceConfiguration
        {
            Mode = DeviceModes.Promiscuous,
            ReadTimeout = 100,
        });

        try
        {
            // BPF: ARP, Profinet DCP, or any IPv4 (for passive MAC/IP learning) - and DCP behind an 802.1Q tag:
            // Profinet devices often answer priority-tagged. ("vlan" shifts the offsets of what follows it, so it is last.)
            // LLDP too: who the adapter is plugged into, for the topology map.
            try { pcap.Filter = "arp or (ether proto 0x8892) or (ether proto 0x88cc) or ip or (vlan and ether proto 0x8892)"; } catch { }

            pcap.OnPacketArrival += OnPacket;
            pcap.StartCapture();

            // 1. Send Profinet DCP Identify-All.
            var dcpFrame = DcpProtocol.BuildIdentifyAllRequest(srcMac, dcpXid);
            try { pcap.SendPacket(dcpFrame); } catch { }
            await Task.Delay(150, ct).ConfigureAwait(false);
            try { pcap.SendPacket(dcpFrame); } catch { }

            // 2. ARP sweep the local IPv4 subnet. ARP requests are tiny (60 bytes) so
            //    even /16 (65k hosts) finishes in a few seconds with batching. We hard-cap
            //    at /15 (~131k) to protect against absurd masks.
            if (localIp is not null && localMask is not null)
            {
                int hostCount = ArpProtocol.CountSubnetHosts(localMask);
                if (hostCount > 0 && hostCount <= 131_072)
                {
                    status?.Report($"ARP sweep: {hostCount:N0} addresses in local subnet...");
                    int sent = 0;
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    foreach (var target in ArpProtocol.EnumerateSubnetHosts(localIp, localMask))
                    {
                        if (ct.IsCancellationRequested) break;
                        if (target.Equals(localIp)) continue;
                        var frame = ArpProtocol.BuildRequest(srcMac, localIp, target);
                        try { pcap.SendPacket(frame); } catch { }
                        sent++;

                        // Yield to capture thread every 256 packets; throttle large sweeps
                        // every 1024 packets so the NIC ring buffer doesn't overflow.
                        if ((sent & 0xFF) == 0)
                        {
                            await Task.Yield();
                            if ((sent & 0x3FF) == 0)
                            {
                                status?.Report($"ARP sweep: {sent:N0}/{hostCount:N0} sent...");
                                await Task.Delay(5, ct).ConfigureAwait(false);
                            }
                        }
                    }
                    sw.Stop();
                    status?.Report($"ARP sweep: {sent:N0} sent in {sw.ElapsedMilliseconds} ms; collecting replies...");
                }
                else if (hostCount > 131_072)
                {
                    status?.Report($"Subnet too large for ARP sweep ({hostCount:N0} hosts); passive only.");
                }
            }

            // 3. Wait for responses + passive traffic.
            try { await Task.Delay(timeout, ct).ConfigureAwait(false); }
            catch (TaskCanceledException) { }
        }
        finally
        {
            try { pcap.StopCapture(); } catch { }
            try { pcap.Close(); } catch { }
        }

        // 4. Hostname enrichment (NBNS + reverse DNS) for every device with an IP.
        //    Skip if the user already aborted.
        var toResolve = ct.IsCancellationRequested
            ? new List<NetDevice>()
            : devices.Values
                .Where(d => d.IPAddress is not null && string.IsNullOrEmpty(d.Hostname))
                .ToList();

        if (toResolve.Count > 0)
        {
            status?.Report($"Resolving hostnames for {toResolve.Count} device(s)...");
            var resolveTimeout = TimeSpan.FromMilliseconds(800);
            var resolveTasks = toResolve.Select(async d =>
            {
                var name = await NameResolver.ResolveAsync(d.IPAddress!, resolveTimeout, ct)
                                             .ConfigureAwait(false);
                if (!string.IsNullOrEmpty(name))
                {
                    d.Hostname = name;
                    DeviceDiscoveredOrUpdated?.Invoke(d);
                }
            });
            try { await Task.WhenAll(resolveTasks).ConfigureAwait(false); } catch { }
        }

        return devices.Values
                      .OrderBy(d => d.IPAddress?.GetAddressBytes() is { } b
                                       ? ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | b[3]
                                       : long.MaxValue)
                      .ToList();

        // ---- packet handler -------------------------------------------------

        void OnPacket(object sender, PacketCapture e)
        {
            try
            {
                var raw = e.GetPacket();
                var data = raw.Data;
                if (data.Length < 14) return;

                ushort etherType = (ushort)((data[12] << 8) | data[13]);
                if (etherType == DcpProtocol.EtherTypeVlan && DcpProtocol.ProfinetOffset(data) > 0)
                    etherType = DcpProtocol.EtherTypeProfinet; // a priority-tagged DCP answer

                // Source MAC for any frame.
                var srcMacBytes = data.AsSpan(6, 6).ToArray();
                var srcAddr = new PhysicalAddress(srcMacBytes);

                if (srcAddr.Equals(srcMac)) return; // ignore our own outgoing frames

                switch (etherType)
                {
                    case DcpProtocol.EtherTypeProfinet:
                        {
                            var dev = GetOrAdd(srcAddr);
                            if (DcpProtocol.TryParseIdentifyResponse(data, dcpXid, dev))
                            {
                                dev.Sources |= DiscoverySource.Profinet;
                                DeviceDiscoveredOrUpdated?.Invoke(dev);
                            }
                            break;
                        }

                    case Lldp.EtherType:
                        {
                            if (Lldp.Read(data) is { } neighbor) LldpHeard?.Invoke(neighbor);
                            break;
                        }

                    case ArpProtocol.EtherTypeArp:
                        {
                            if (ArpProtocol.TryParse(data, out var arpMac, out var arpIp, out _))
                            {
                                if (arpMac.Equals(srcMac)) return;
                                if (arpIp.Equals(IPAddress.Any)) return;
                                var dev = GetOrAdd(arpMac);
                                dev.IPAddress ??= arpIp;
                                dev.Sources |= DiscoverySource.Arp;
                                DeviceDiscoveredOrUpdated?.Invoke(dev);
                            }
                            break;
                        }

                    case 0x0800: // IPv4
                        {
                            if (data.Length < 14 + 20) return;
                            var ipBytes = data.AsSpan(14 + 12, 4).ToArray(); // source IPv4
                            var ip = new IPAddress(ipBytes);
                            if (ip.Equals(IPAddress.Any) || IPAddress.IsLoopback(ip)) return;
                            var dev = GetOrAdd(srcAddr);
                            dev.IPAddress ??= ip;
                            dev.Sources |= DiscoverySource.Passive;
                            DeviceDiscoveredOrUpdated?.Invoke(dev);
                            break;
                        }
                }
            }
            catch { /* never throw out of the capture callback */ }
        }

        NetDevice GetOrAdd(PhysicalAddress mac)
        {
            var key = string.Join(":", mac.GetAddressBytes().Select(b => b.ToString("X2")));
            lock (devices)
            {
                if (!devices.TryGetValue(key, out var dev))
                {
                    dev = new NetDevice
                    {
                        MacAddress = mac,
                        VendorName = OuiLookup.Lookup(mac), // OUI fallback; PN response can override
                    };
                    devices[key] = dev;
                }
                dev.LastSeenUtc = DateTime.UtcNow;
                return dev;
            }
        }
    }
}
