using System.Diagnostics;
using System.Net.NetworkInformation;
using SharpPcap;
using SharpPcap.LibPcap;

namespace EthernetTools.Pn;

/// <summary>What a DCP Set came to.</summary>
/// <param name="Done">The device answered that it did it.</param>
/// <param name="Answered">False when the device did not answer within <see cref="DcpSet.AnswerTimeout"/>.</param>
/// <param name="Message">The device's answer in words ("done", or why not).</param>
public sealed record DcpSetOutcome(bool Done, bool Answered, string Message);

/// <summary>
/// Profinet DCP Set requests to one device - Flash LED (Control ▸ Signal) and Set NameOfStation - sent through Npcap,
/// and the device's answer read back.
/// <para>
/// Each request opens a capture handle of its own on the adapter, never <see cref="AdapterInfo.PcapDevice"/>: a running
/// scan has that one open and capturing, and closing it would end the scan's capture. One request at a time, so two
/// cannot read each other's answers.
/// </para>
/// </summary>
public static class DcpSet
{
    /// <summary>How long a device has to answer.</summary>
    public static readonly TimeSpan AnswerTimeout = TimeSpan.FromSeconds(3);

    // The frames DCP comes in, with or without an 802.1Q tag. ("vlan" shifts the offsets of what follows it.)
    private const string CaptureFilter = "ether proto 0x8892 or (vlan and ether proto 0x8892)";

    private static readonly SemaphoreSlim Gate = new(1, 1);

    /// <summary>Make <paramref name="device"/> flash its LED (about three seconds on most devices).</summary>
    public static Task<DcpSetOutcome> FlashAsync(AdapterInfo adapter, PhysicalAddress device, CancellationToken ct = default) =>
        SetAsync(adapter, device, xid => DcpProtocol.BuildFlashRequest(adapter.MacAddress, device, xid), ct);

    /// <summary>Give <paramref name="device"/> the name of station <paramref name="name"/>, permanently.</summary>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a Profinet name (nothing is sent).</exception>
    public static Task<DcpSetOutcome> SetNameAsync(AdapterInfo adapter, PhysicalAddress device, string name, CancellationToken ct = default)
    {
        if (StationName.Problem(name) is string problem) throw new ArgumentException(problem, nameof(name));
        return SetAsync(adapter, device, xid => DcpProtocol.BuildSetNameRequest(adapter.MacAddress, device, xid, name), ct);
    }

    private static async Task<DcpSetOutcome> SetAsync(AdapterInfo adapter, PhysicalAddress device, Func<uint, byte[]> request, CancellationToken ct)
    {
        string npcapName = adapter.PcapDevice?.Name
            ?? throw new InvalidOperationException($"'{adapter.FriendlyName}' is not bound to Npcap; cannot send DCP frames.");
        if (adapter.MacAddress.GetAddressBytes().Length != 6)
            throw new InvalidOperationException($"'{adapter.FriendlyName}' has no Ethernet address.");
        if (adapter.NetworkInterface.OperationalStatus != OperationalStatus.Up)
            throw new InvalidOperationException($"'{adapter.FriendlyName}' has no link. Connect its cable to the Profinet network.");

        await Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await Task.Run(() =>
            {
                using LibPcapLiveDevice pcap = OpenOwnHandle(npcapName);
                uint xid = (uint)Random.Shared.Next(1, int.MaxValue);
                pcap.SendPacket(request(xid));

                var clock = Stopwatch.StartNew();
                while (clock.Elapsed < AnswerTimeout && !ct.IsCancellationRequested)
                {
                    GetPacketStatus status = pcap.GetNextPacket(out PacketCapture capture);
                    if (status == GetPacketStatus.PacketRead)
                    {
                        if (DcpProtocol.TryReadSetResponse(capture.Data, xid, device, out byte error))
                            return new DcpSetOutcome(error == 0, true, DcpProtocol.SetErrorText(error));
                    }
                    else if (status == GetPacketStatus.Error)
                    {
                        throw new InvalidOperationException($"Npcap stopped reading the adapter: {pcap.LastError}");
                    }
                }
                ct.ThrowIfCancellationRequested();
                return new DcpSetOutcome(false, false,
                    $"no answer within {AnswerTimeout.TotalSeconds:0} s. Is the device on this adapter's network, and powered?");
            }, ct).ConfigureAwait(false);
        }
        finally
        {
            Gate.Release();
        }
    }

    /// <summary>A new SharpPcap device object for the adapter, opened: independent of the one a scan may have open.</summary>
    private static LibPcapLiveDevice OpenOwnHandle(string npcapName)
    {
        LibPcapLiveDevice pcap = LibPcapLiveDeviceList.New()
            .FirstOrDefault(d => string.Equals(d.Name, npcapName, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("The adapter is not there any more. Press Refresh and choose it again.");
        try
        {
            // Not promiscuous: the answer is addressed to this adapter. Immediate mode hands each frame over as it comes.
            pcap.Open(new DeviceConfiguration { Mode = DeviceModes.MaxResponsiveness, ReadTimeout = 50, Immediate = true });
            pcap.Filter = CaptureFilter;
            return pcap;
        }
        catch
        {
            pcap.Dispose();
            throw;
        }
    }
}
