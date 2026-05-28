using System.Net.NetworkInformation;
using System.Text;
using SharpPcap.LibPcap;

namespace EthernetTools.Pn;

/// <summary>
/// Pairs an OS-level NetworkInterface with its SharpPcap capture device (when
/// available — some virtual adapters, e.g. Tosibox TAP, aren't bound to Npcap
/// and so cannot be captured on; they're still listed for visibility).
/// </summary>
public sealed record AdapterInfo(
    LibPcapLiveDevice? PcapDevice,
    NetworkInterface NetworkInterface,
    string FriendlyName,
    string Description,
    PhysicalAddress MacAddress)
{
    public bool CanCapture => PcapDevice is not null;

    public override string ToString() =>
        CanCapture
            ? $"{FriendlyName}  [{Description}]"
            : $"{FriendlyName}  [{Description}]  (no Npcap binding)";

    /// <summary>
    /// Enumerate Ethernet-style adapters visible to the OS. Includes virtual
    /// adapters (Hyper-V vEthernet, VMware, VirtualBox, Docker, WSL, TAP,
    /// Tosibox, etc.) regardless of whether Npcap can capture on them. Wi-Fi,
    /// PPP, software loopback, and tunnels are excluded.
    /// </summary>
    public static IReadOnlyList<AdapterInfo> EnumerateEthernet()
    {
        // Force a fresh enumeration so new Npcap bindings are visible without restarting.
        LibPcapLiveDeviceList.Instance.Refresh();
        var pcapDevices = new List<LibPcapLiveDevice>();
        try { foreach (var p in LibPcapLiveDeviceList.Instance) pcapDevices.Add(p); }
        catch { /* ignore — pcap may be unavailable */ }

        var result = new List<AdapterInfo>();

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var t = nic.NetworkInterfaceType;
            if (t == NetworkInterfaceType.Wireless80211
                || t == NetworkInterfaceType.Ppp
                || t == NetworkInterfaceType.Loopback
                || t == NetworkInterfaceType.Tunnel) continue;

            // Skip Bluetooth PAN — reports as Ethernet but isn't useful here.
            var desc = nic.Description ?? "";
            if (desc.Contains("Bluetooth", StringComparison.OrdinalIgnoreCase)) continue;

            // Find pcap device by GUID embedded in \Device\NPF_{GUID} (optional).
            LibPcapLiveDevice? pcap = null;
            foreach (var p in pcapDevices)
            {
                if (p.Loopback) continue;
                if (p.Name.IndexOf(nic.Id, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    pcap = p;
                    break;
                }
            }

            var nicMac = nic.GetPhysicalAddress();
            PhysicalAddress mac = (nicMac is not null && nicMac.GetAddressBytes().Length > 0)
                ? nicMac
                : PhysicalAddress.None;

            result.Add(new AdapterInfo(pcap, nic, nic.Name, nic.Description ?? "", mac));
        }

        // Show capturable adapters first, then the rest.
        result.Sort((a, b) =>
        {
            int byCap = b.CanCapture.CompareTo(a.CanCapture);
            return byCap != 0 ? byCap : string.Compare(a.FriendlyName, b.FriendlyName, StringComparison.OrdinalIgnoreCase);
        });

        return result;
    }

    /// <summary>
    /// Side-by-side dump of every pcap device and every OS NIC, with whatever
    /// match this class found. Used to diagnose why an adapter isn't appearing.
    /// </summary>
    public static string Diagnose()
    {
        var sb = new StringBuilder();

        sb.AppendLine("=== pcap devices (LibPcapLiveDeviceList) ===");
        try
        {
            int i = 0;
            foreach (var p in LibPcapLiveDeviceList.Instance)
            {
                sb.AppendLine($"[{i++}] Name:       {p.Name}");
                sb.AppendLine($"    Description: {p.Description}");
                sb.AppendLine($"    Loopback:    {p.Loopback}");
                try { sb.AppendLine($"    MAC:         {p.MacAddress}"); }
                catch (Exception ex) { sb.AppendLine($"    MAC:         <error: {ex.Message}>"); }
                try { sb.AppendLine($"    FriendlyName:{p.Interface?.FriendlyName}"); } catch { }
                sb.AppendLine();
            }
        }
        catch (Exception ex)
        {
            sb.AppendLine("pcap enumeration failed: " + ex.Message);
        }

        sb.AppendLine("=== OS NICs (NetworkInterface.GetAllNetworkInterfaces) ===");
        try
        {
            int i = 0;
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                sb.AppendLine($"[{i++}] Name:        {nic.Name}");
                sb.AppendLine($"    Description: {nic.Description}");
                sb.AppendLine($"    Id (GUID):   {nic.Id}");
                sb.AppendLine($"    Type:        {nic.NetworkInterfaceType}");
                sb.AppendLine($"    Status:      {nic.OperationalStatus}");
                try { sb.AppendLine($"    MAC:         {nic.GetPhysicalAddress()}"); } catch { }
                sb.AppendLine();
            }
        }
        catch (Exception ex)
        {
            sb.AppendLine("NIC enumeration failed: " + ex.Message);
        }

        sb.AppendLine("=== Matched (what EnumerateEthernet would return) ===");
        try
        {
            foreach (var a in EnumerateEthernet())
                sb.AppendLine($"  {a.FriendlyName}  [{a.Description}]  MAC={a.MacAddress}");
        }
        catch (Exception ex)
        {
            sb.AppendLine("Match enumeration failed: " + ex.Message);
        }

        return sb.ToString();
    }
}
