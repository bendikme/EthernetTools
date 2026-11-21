namespace EthernetTools.Pn;

/// <summary>
/// Addresses and names that must be unique and are not: an IPv4 address that two or more MACs claim in ARP (a
/// duplicate address, or a router answering for others - proxy ARP), and a Profinet name of station on two or more
/// devices. Each becomes a problem on every device it concerns.
/// </summary>
public static class Conflicts
{
    /// <param name="ipClaims">Every MAC (AA:BB:..) seen claiming each IPv4 address in ARP (requests and answers).</param>
    /// <returns>device -> what is wrong (several problems joined by "; ").</returns>
    public static Dictionary<NetDevice, string> Find(IEnumerable<NetDevice> devices, IReadOnlyDictionary<string, HashSet<string>> ipClaims)
    {
        var list = devices.ToList();
        var byMac = list.GroupBy(d => d.MacString, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        var found = new Dictionary<NetDevice, List<string>>();
        void Note(NetDevice d, string text)
        {
            if (!found.TryGetValue(d, out var texts)) found[d] = texts = new List<string>();
            texts.Add(text);
        }

        foreach (var (ip, macs) in ipClaims.Where(c => c.Value.Count > 1).OrderBy(c => c.Key, StringComparer.Ordinal))
            foreach (string mac in macs)
                if (byMac.TryGetValue(mac, out var d))
                    Note(d, $"IP {ip} is also claimed by {string.Join(", ", macs.Where(m => !string.Equals(m, mac, StringComparison.OrdinalIgnoreCase)))} " +
                            "(a duplicate IP address, or proxy ARP)");

        foreach (var same in list.Where(d => d.Sources.HasFlag(DiscoverySource.Profinet) && !string.IsNullOrWhiteSpace(d.NameOfStation))
                     .GroupBy(d => d.NameOfStation!, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
            foreach (var d in same)
                Note(d, $"name of station \"{same.Key}\" is also on {string.Join(", ", same.Where(x => !ReferenceEquals(x, d)).Select(x => x.MacString))}");

        return found.ToDictionary(kv => kv.Key, kv => string.Join("; ", kv.Value));
    }
}
