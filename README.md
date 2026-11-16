# EthernetTools

Finds the devices on an Ethernet network — **Profinet** devices in any subnet, PCs, PLCs, printers — and gives
the everyday tools for them in one window: ping, traceroute, port scan, Wake-on-LAN, Profinet *Flash LED*,
open the web page, copy and export.

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
┌ EthernetTools v26.11.0 – Ethernet / Profinet Device Discovery ─────────────────────────────┐
│ Adapter: [Ethernet  [Intel(R) Ethernet Connection]       ▾]  Refresh  Timeout (s): 5  Scan  Stop │
│ Ping  Traceroute  Port Scan  Open Web  Wake-on-LAN  Flash LED │ Copy IP  Copy MAC  Copy Row │ … │
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
| Copy IP / MAC / Row | to the clipboard |
| Export CSV | the devices in the list, to a `.csv` file |

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
.\Test\SmokeTest.ps1 -Exe bin\Release\publish-win-x64\EthernetTools.exe -Version 26.11.0
```

starts the exe and reads its window through UI Automation: the window opens with the version in its title,
the adapters are listed through Npcap (on a machine without Npcap: the window says Npcap is missing),
Refresh answers, and the program closes cleanly.

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
| `AppInfo.cs` | the version and the icon |
| `Pn/NetworkScanner.cs` | the scan: DCP Identify-All, ARP sweep, passive listening, name lookup |
| `Pn/DcpProtocol.cs`, `Pn/DcpFlash.cs` | Profinet DCP frames (Identify, Signal) |
| `Pn/ArpProtocol.cs`, `Pn/NameResolver.cs` | ARP frames; NetBIOS and reverse-DNS names |
| `Pn/AdapterInfo.cs` | adapters: Windows interfaces paired with their Npcap devices |
| `Pn/PortScanner.cs`, `Pn/WakeOnLan.cs`, `Pn/OuiLookup.cs` | port scan, magic packet, vendor by MAC |
| `Test/SmokeTest.ps1` | start-up check |
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
