# EthernetTools

Finds the devices on an Ethernet network — **Profinet** devices in any subnet, PCs, PLCs, printers — and gives
the everyday tools for them in one window: ping, traceroute, port scan, Wake-on-LAN, Profinet *Flash LED* and
*Set Name* (name of station), open the web page, copy and export. **Topology...** draws a map of the network:
switches and devices, with the physical port at each end of every cable.

No installer and no .NET to install: `EthernetTools.exe` is a single file with its runtime inside. It needs
**Npcap** to send and capture raw Ethernet frames.

![EthernetTools icon](app.png)

---

## Download

The newest release is on the DYNATEC Portal's Applications page (For Windows ▸ EthernetTools) and on this
repository's Releases page: `EthernetTools-<version>-windows-x64.zip`. Unzip it anywhere and run
`EthernetTools.exe`.

**Npcap** must be installed once: <https://npcap.com> (the free installer, default options; administrator
rights needed). Without it the window opens and says so, and only ping, traceroute and port scan work.

---

## The window

```
┌ EthernetTools v26.11.2 – Ethernet / Profinet Device Discovery ─────────────────────────────┐
│ Adapter: [Ethernet  [Intel(R) Ethernet Connection]       ▾]  Refresh  Timeout (s): 5  Scan  Stop │
│ Ping  Traceroute  Port Scan  Open Web  Wake-on-LAN  Flash LED  Set Name... │ Copy IP  Copy MAC … │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│ MAC Address  IP Address  Name  Vendor  Subnet Mask  Gateway  Source  RTT  Last Seen          │
│ …                                                                                            │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│ 12 Ethernet adapter(s) found.                                               PN: 3 │ Devices: 17 │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Scan

Pick the adapter that is cabled to the network and press **Scan** (Enter). For the time set under
*Timeout* the scan:

- sends a **Profinet DCP Identify-All** — every Profinet device answers with its name of station, type,
  IP address, mask and gateway, *whatever subnet it is set to*;
- **ARP-sweeps** the adapter's own IPv4 subnet (up to a /15) — finds everything with an address there;
- **listens** to ARP and IPv4 traffic — finds devices in foreign subnets as soon as they send something;
- then looks up **host names** (NetBIOS, then reverse DNS) for the devices it found.

Devices appear while the scan runs. Profinet devices are tinted orange, devices without an IP address
are grey. The *Source* column says how each was found (Profinet, ARP, Passive). The vendor comes from the
Profinet answer or, failing that, from the MAC address. **Stop** ends the scan early.

The filter box (top right of the toolbar) narrows the list by MAC, IP, name or vendor.

### Tools for the selected device

From the toolbar or the grid's right-click menu (a double-click pings):

| Tool | What it does |
| ---- | ------------ |
| Ping | 8 echo requests, with round-trip times and loss |
| Traceroute | the route, hop by hop, up to 30 hops |
| Port Scan | TCP connect to 24 common IT and industrial ports (FTP, SSH, HTTP(S), S7 102, Modbus 502, EtherNet/IP 2222 / 44818, OPC UA 4840, MQTT, RDP, VNC …) |
| Open Web | opens `http://<ip>` in the default browser |
| Wake-on-LAN | sends a magic packet to the device's MAC |
| Flash LED | Profinet DCP *Signal*: the device blinks its LED, to find it in the cabinet |
| Set Name... | Profinet DCP *Set NameOfStation*: gives the device its name of station, kept after a power cycle (see below) |
| Copy IP / MAC / Row | to the clipboard |
| Export CSV | the devices in the list, to a `.csv` file |

Flash LED and Set Name wait up to 3 s for the device's answer and say what it answered: done, refused (and
why), or no answer. They can be used while a scan runs.

### Set Name

Select the device and press **Set Name...** (or **F2**, or right-click it). Type the name of station the controller's
configuration expects. The dialog checks it as you type, with the same Profinet rules as ProfinetTools:
- small letters a–z, digits, hyphens and dots;
- at most 240 characters, and at most 63 between dots;
- no part that starts or ends with a hyphen;
- not an IP address, and not `port-xyz`.

Capitals become small letters. If another device in the list already has that name, EthernetTools asks
before giving it, because two devices with one name stop the PLC from reaching either. A device that is
connected to its controller (in operation) refuses a new name; EthernetTools shows the refusal.

### Topology map

**Topology...** (toolbar) draws the scanned network as a tree from This PC down: switches, routers and devices,
with the port at each end of every cable, for example `23 ↔ gi1/0/31`. Scan first; the map is built from the
devices the scan found.

Traceroute sees only routers, never switches or ports. So, as in PRONETA or TIA Portal, the map is built from:

| Source | What it gives |
| ------ | ------------- |
| **LLDP heard on the adapter** | the switch and port This PC is plugged into (switches send LLDP every 5-30 s; the window listens for 35 s) |
| **SNMP, LLDP-MIB** | each device's neighbour on each of its ports (Profinet devices and managed switches carry it) |
| **SNMP, BRIDGE-MIB** | a switch's MAC address table: places the devices that don't speak LLDP (PCs, printers) on their port |
| **Profinet records** | a Profinet device that doesn't answer SNMP: each port's neighbour from its own PDPortDataReal record (as PRONETA reads it) |
| **The default gateway** | shown as a router |

SNMP is read-only, v2c with a fallback to v1, community `public` unless you type another one in the window.
**SNMPv3...** on the window's toolbar takes an SNMPv3 user (authentication MD5, SHA-1 or SHA-256; privacy AES-128),
asked before v2c and v1. The user is kept in memory until EthernetTools closes, never saved. A switch that only
speaks SNMPv3 is named in the status bar's warning when no user is given; one that refuses the user says why
(unknown user name, wrong password ...).
Without a user, every device that stays silent on v1/v2c is asked whether it speaks SNMPv3. The maker in the
SNMPv3 engine ID it gives anyone (or else its MAC prefix) tells switches and access points from printers and
servers. Those made by a network maker (Cisco, HPE/Aruba, Netgear, ...) are drawn as **SWITCH?** boxes, named in
the warning, and a v3 user would let the map read their tables too.
Tables are read with GETBULK. A device that answers GETBULK with an error, or not at all (some small embedded
agents do), is read again with fewer rows per request, then with GETNEXT.
The window asks every scanned device, then follows LLDP: the management address a neighbour announces is asked
too, even when the scan didn't find it (a switch on a management subnet of its own, say). It repeats this until
no new address turns up.

**Which switch first, then the port.** Just before reading the MAC tables, the window asks every device once
more (ARP, and a DCP Identify). Each answer passes the switches on its way to This PC, so their tables are fresh.
A device that answered but is missing from a switch's table didn't send its answer through that switch: it is on
This PC's side of it, behind the port This PC is on. So every device that answers is placed behind the right switch,
with its port where a table or LLDP tells it. The same refresh adds devices the scan missed (the default gateway,
say) when they answer now.

When the map can't be complete, the status bar says why in orange. Hover it for the details:
- **No SNMP from switches:** switches that didn't answer SNMP, or had no address to ask, by name. Their ports
  and MAC tables stay unknown. Enabling read-only SNMP on them completes the map.
- **No LLDP heard:** nothing told which switch port This PC is on. The port may not send LLDP, or the network
  card keeps LLDP to itself (the firmware LLDP agent of some Intel X710, XL710 and E810 cards).

Reading the map:
- **Solid line:** a cable known from LLDP.
- **Dotted line:** a device placed by a switch's MAC table.
- **Orange dashed line:** a link that closes a ring (a Profinet MRP ring) or a second path.
- **"Unmanaged switch?":** several MAC addresses on one switch port with no LLDP neighbour there. It may also
  be a hub, an access point or a virtual-machine host.
- **"port ?":** a device the tables show somewhere behind a switch that doesn't answer SNMP, so its port is not
  known. More than six such devices are drawn as one group box; hover it for the list.
- **"Not located":** devices neither LLDP nor any readable MAC table places. This includes devices two switches
  each place behind the other (their tables are of different ages).

Using the map:
- **Move and zoom:** drag to move; the mouse wheel, **+** and **-** zoom; **Fit** (or F) shows the whole map.
- **Details:** hover a box for its details (system description, MAC, members of a group).
- **Select:** double-click a box to select that device in the list.
- **Save:** **Export PNG...** saves the whole map as a picture.
- **Refresh:** **Discover again** asks again, for example with another SNMP community.

### Adapters

All wired adapters are listed, also virtual ones (Hyper-V, VMware, TAP, Tosibox …); those Npcap cannot
capture on are marked *(no Npcap binding)* and sorted last. **Refresh** reads the list again;
**Shift+Refresh** shows a diagnosis of every Npcap device and network interface — for an adapter that does
not show up.

---

## Build

| Tool    | Version                  |
| ------- | ------------------------ |
| .NET SDK | 10                      |
| Target  | `net10.0-windows`, WinForms |
| Packages | SharpPcap, PacketDotNet |

```powershell
dotnet build EthernetTools.csproj -c Release
```

or open `EthernetTools.sln` in Visual Studio. The release build is a self-contained single file:

```powershell
.\scripts\release.ps1
```

publishes `bin\Release\publish-win-x64\EthernetTools.exe` (win-x64, the .NET runtime inside, compressed),
runs the start-up check and writes `dist\EthernetTools-<version>-windows-x64.zip`.

### Start-up check

```powershell
.\Test\SmokeTest.ps1 -Exe bin\Release\publish-win-x64\EthernetTools.exe -Version 26.11.2
```

first runs `EthernetTools.exe --selftest` (`SelfTest.cs`, no network needed). The self-test checks:
- the Profinet DCP frames, byte by byte;
- the reading of the devices' answers, with and without an 802.1Q tag;
- the station-name rules, on ProfinetTools' cases (`Test/station-names.json`);
- the Set Name dialog;
- the SNMP encoding, LLDP frames, and the LLDP-MIB and BRIDGE-MIB tables;
- a whole topology map built and laid out from an example network.

Then it starts the exe and reads its window through UI Automation:
- the window opens with the version in its title;
- the toolbar offers Flash LED, Set Name and Topology;
- the adapters are listed through Npcap (on a machine without Npcap, the window says Npcap is missing);
- Refresh answers;
- the program closes cleanly.

To see the self-test's lines by hand, run `.\EthernetTools.exe --selftest | Out-Host` in PowerShell.

### Release

Push a tag `v<version>`: `.github/workflows/release.yml` runs `scripts\release.ps1` (build, check, package)
and publishes the GitHub release with `docs/release-notes/v<version>.md`. To sign the exe, add the
repository secrets `ETHTOOLS_SIGN_PFX_BASE64` (the code-signing certificate as a base64 `.pfx`) and
`ETHTOOLS_SIGN_PFX_PASSWORD`; locally, `scripts\release.ps1 -SignThumbprint <thumbprint>`.

### Version

The version is in `EthernetTools.csproj` only (`<Version>`, `year.month.patch`); a release is tagged
`v<version>`.

### Icon

`app.ico` (16–256 px) and `app.png` (256 px, for the Portal tile) are drawn by `scripts/make-icon.ps1`.

---

## Source layout

| Path | What |
| ---- | ---- |
| `Program.cs` | entry point |
| `MainForm.cs`, `MainForm.Designer.cs` | the window: adapter choice, scan, device grid, toolbar actions |
| `ToolOutputForm.cs` | the output window of ping, traceroute, port scan and the adapter diagnosis |
| `SetNameForm.cs` | the Set Name dialog |
| `TopologyForm.cs`, `TopologyView.cs` | the topology window and the drawing of the map |
| `AppInfo.cs` | the version and the icon |
| `SelfTest.cs`, `SelfTest.Topology.cs` | `EthernetTools.exe --selftest` |
| `Pn/NetworkScanner.cs` | the scan: DCP Identify-All, ARP sweep, passive listening, name lookup |
| `Pn/DcpProtocol.cs` | Profinet DCP frames: Identify, Signal, Set NameOfStation, and the devices' answers |
| `Pn/DcpSet.cs` | Flash LED and Set Name: send, and read the device's answer |
| `Pn/StationName.cs` | the rules of a Profinet name of station |
| `Pn/Lldp.cs`, `Pn/Snmp.cs`, `Pn/SnmpV3.cs` | LLDP frames; a small read-only SNMP client (v1, v2c, and v3 with USM: MD5/SHA keys and digests, AES-128) |
| `Pn/ProfinetRpc.cs` | Profinet's own records over PNIO RPC: Read Implicit of PDPortDataReal (a port's neighbour) |
| `SnmpV3Form.cs` | the SNMPv3 user dialog of the topology window |
| `Pn/TopologyDiscovery.cs` | reads LLDP-MIB and BRIDGE-MIB from the devices, following LLDP to switches the scan missed; listens for LLDP on the adapter |
| `Pn/Topology.cs`, `Pn/TopologyLayout.cs` | builds the map from what was found; lays it out as a tree |
| `Pn/ArpProtocol.cs`, `Pn/NameResolver.cs` | ARP frames; NetBIOS and reverse-DNS names |
| `Pn/AdapterInfo.cs` | adapters: Windows interfaces paired with their Npcap devices |
| `Pn/PortScanner.cs`, `Pn/WakeOnLan.cs`, `Pn/OuiLookup.cs` | port scan, magic packet, vendor by MAC |
| `Test/SmokeTest.ps1` | start-up check |
| `Test/station-names.json` | the station-name cases (a copy of ProfinetTools'), embedded for the self-test |
| `scripts/` | `release.ps1`, `make-icon.ps1` |

---

## Third-party components

The exe contains the .NET runtime (MIT, <https://github.com/dotnet/runtime>),
SharpPcap (MIT, <https://github.com/dotpcap/sharppcap>) and PacketDotNet (MPL-2.0,
<https://github.com/dotpcap/packetnet>). Npcap is not included; it is installed separately under its own
license.

---

## Issues

Bugs, features and tasks are tracked in DYNATEC Project (product `ETHTOOLS`), see `AGENTS.md`.
