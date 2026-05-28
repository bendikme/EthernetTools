using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace EthernetTools.Pn;

/// <summary>Sends a Wake-on-LAN magic packet to a target MAC.</summary>
public static class WakeOnLan
{
    public static void Send(PhysicalAddress mac, IPAddress? broadcastIp = null)
    {
        var macBytes = mac.GetAddressBytes();
        if (macBytes.Length != 6) throw new ArgumentException("MAC must be 6 bytes.");

        // Magic packet: 6x 0xFF + 16x MAC = 102 bytes.
        var packet = new byte[6 + 16 * 6];
        for (int i = 0; i < 6; i++) packet[i] = 0xFF;
        for (int i = 0; i < 16; i++) Buffer.BlockCopy(macBytes, 0, packet, 6 + i * 6, 6);

        broadcastIp ??= IPAddress.Broadcast;

        using var udp = new UdpClient { EnableBroadcast = true };
        udp.Send(packet, packet.Length, new IPEndPoint(broadcastIp, 9));
    }
}
