using System.Net.NetworkInformation;

namespace EthernetTools.Pn;

/// <summary>
/// Tiny built-in OUI (MAC prefix → vendor) lookup.
/// Covers common industrial-automation, networking and PC vendors. Not exhaustive —
/// extend the table as needed.
/// </summary>
public static class OuiLookup
{
    // Keys are the upper-case 6-hex-digit OUI (first 24 bits of the MAC).
    private static readonly Dictionary<string, string> _table = new(StringComparer.OrdinalIgnoreCase)
    {
        // ---- Industrial automation -----------------------------------------
        ["000E8C"] = "Siemens",
        ["001B1B"] = "Siemens",
        ["0001A6"] = "Siemens",
        ["002016"] = "Siemens",
        ["080006"] = "Siemens",
        ["20B7C0"] = "Siemens",
        ["28630E"] = "Siemens",
        ["8CF319"] = "Siemens",
        ["B85A4C"] = "Siemens",
        ["E04CA5"] = "Siemens",

        ["0030DE"] = "WAGO",
        ["0008E1"] = "WAGO",
        ["00A040"] = "WAGO",

        ["0007EE"] = "Beckhoff",
        ["00010C"] = "Beckhoff",

        ["0008E3"] = "Phoenix Contact",
        ["A8741D"] = "Phoenix Contact",
        ["00A045"] = "Phoenix Contact",

        ["00603E"] = "Hilscher",
        ["0002A2"] = "Hilscher",

        ["000FBB"] = "Nokia / NSN",
        ["00B0AE"] = "Symmetricom",

        ["0000BC"] = "Rockwell / Allen-Bradley",
        ["001D9C"] = "Rockwell Automation",
        ["E4901F"] = "Rockwell Automation",

        ["00306D"] = "Lucent / OPC",
        ["00802F"] = "Pepperl+Fuchs",
        ["003056"] = "Pepperl+Fuchs",

        ["001D40"] = "B&R Industrial Automation",
        ["00603C"] = "B&R Industrial Automation",

        ["003011"] = "Schneider Electric",
        ["0080F4"] = "Schneider Electric",
        ["08001F"] = "Schneider Electric",

        ["000ACD"] = "Sunny Computer / SMA",
        ["004F6B"] = "ABB",
        ["AC64DD"] = "ABB",
        ["00248C"] = "ABB",

        ["00125F"] = "Endress+Hauser",
        ["0007F8"] = "Endress+Hauser",

        ["00177A"] = "Mitsubishi Electric",
        ["00800F"] = "Mitsubishi Electric",

        ["7C667A"] = "Omron",
        ["00000E"] = "Omron",

        ["A4B197"] = "Hirschmann",
        ["00806A"] = "Hirschmann",

        // ---- Networking ----------------------------------------------------
        ["00000C"] = "Cisco",
        ["000142"] = "Cisco",
        ["001A2F"] = "Cisco",
        ["001CF6"] = "Cisco",
        ["F4CFE2"] = "Cisco",

        ["00112B"] = "MikroTik",
        ["4C5E0C"] = "MikroTik",
        ["E48D8C"] = "Routerboard / MikroTik",

        ["B827EB"] = "Raspberry Pi Foundation",
        ["DCA632"] = "Raspberry Pi Trading",
        ["E45F01"] = "Raspberry Pi Trading",

        ["001517"] = "Intel",
        ["001B21"] = "Intel",
        ["001E67"] = "Intel",
        ["A0369F"] = "Intel",
        ["B4969A"] = "Intel",

        ["005056"] = "VMware",
        ["000C29"] = "VMware",
        ["001C14"] = "VMware",

        ["000569"] = "VMware",
        ["00155D"] = "Microsoft / Hyper-V",
        ["7C1E52"] = "Microsoft",

        ["F0DEF1"] = "Wistron InfoComm",
        ["0026B9"] = "Dell",
        ["B083FE"] = "Dell",
        ["F8B156"] = "Dell",
        ["D481D7"] = "Dell",

        ["3C5282"] = "HP",
        ["3CD92B"] = "HP",
        ["6CC217"] = "HP",
        ["B499BA"] = "HP",
        ["941882"] = "HP",

        ["F40F24"] = "Apple",
        ["A8667F"] = "Apple",
        ["A4B805"] = "Apple",

        ["FC183C"] = "Samsung",
        ["E8508B"] = "Samsung",
    };

    public static string? Lookup(PhysicalAddress mac)
    {
        var bytes = mac.GetAddressBytes();
        if (bytes.Length < 3) return null;
        var key = $"{bytes[0]:X2}{bytes[1]:X2}{bytes[2]:X2}";
        return _table.TryGetValue(key, out var v) ? v : null;
    }
}
