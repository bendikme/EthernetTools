using System.Net.NetworkInformation;
using SharpPcap;

namespace EthernetTools.Pn;

/// <summary>
/// Sends a one-shot Profinet DCP "Set Signal" (Flash LED) request to a target device.
/// </summary>
public static class DcpFlash
{
    public static void Flash(AdapterInfo adapter, PhysicalAddress targetMac)
    {
        var pcap = adapter.PcapDevice
            ?? throw new InvalidOperationException(
                $"'{adapter.FriendlyName}' is not bound to Npcap; cannot send DCP frame.");
        var xid = (uint)Random.Shared.Next(1, int.MaxValue);
        var frame = DcpProtocol.BuildFlashRequest(adapter.MacAddress, targetMac, xid);

        pcap.Open(new DeviceConfiguration { Mode = DeviceModes.Promiscuous, ReadTimeout = 100 });
        try
        {
            pcap.SendPacket(frame);
            // Send twice for reliability across managed switches.
            System.Threading.Thread.Sleep(50);
            pcap.SendPacket(frame);
        }
        finally
        {
            try { pcap.Close(); } catch { }
        }
    }
}
