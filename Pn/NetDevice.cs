using System.Net;
using System.Net.NetworkInformation;

namespace EthernetTools.Pn;

[Flags]
public enum DiscoverySource
{
    None = 0,
    Arp = 1 << 0,  // answered our ARP probe (host is alive on this subnet)
    Passive = 1 << 1,  // observed in passing traffic
    Profinet = 1 << 2,  // answered Profinet DCP Identify
}

/// <summary>
/// Unified network device discovered on the wire (Profinet, Windows PC, printer, etc.).
/// </summary>
public sealed class NetDevice
{
    public PhysicalAddress MacAddress { get; init; } = PhysicalAddress.None;

    public IPAddress? IPAddress { get; set; }
    public IPAddress? SubnetMask { get; set; }
    public IPAddress? Gateway { get; set; }

    public string? Hostname { get; set; } // NBNS or reverse DNS
    public string? NameOfStation { get; set; } // Profinet
    public string? VendorName { get; set; } // Profinet TypeOfStation or MAC OUI
    public ushort VendorId { get; set; }
    public ushort DeviceId { get; set; }
    public ushort DeviceRole { get; set; }

    public DiscoverySource Sources { get; set; }
    public DateTime DiscoveredUtc { get; init; } = DateTime.UtcNow;
    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;

    /// <summary>Round-trip time of the most recent ping/ARP reply, in milliseconds.</summary>
    public long? RttMs { get; set; }

    public string MacString =>
        string.Join(":", MacAddress.GetAddressBytes().Select(b => b.ToString("X2")));

    public string LastSeenText => $"{(int)(DateTime.UtcNow - LastSeenUtc).TotalSeconds} s ago";

    public string RttText => RttMs is { } v ? $"{v} ms" : "";

    /// <summary>Best-effort display name for the device.</summary>
    public string DisplayName =>
        NameOfStation
            ?? Hostname
            ?? (Sources.HasFlag(DiscoverySource.Profinet) ? "<Profinet device>" : "");

    public string SourcesText
    {
        get
        {
            var parts = new List<string>(3);
            if (Sources.HasFlag(DiscoverySource.Profinet)) parts.Add("PN-DCP");
            if (Sources.HasFlag(DiscoverySource.Arp)) parts.Add("ARP");
            if (Sources.HasFlag(DiscoverySource.Passive)) parts.Add("Passive");
            return string.Join(", ", parts);
        }
    }
}
