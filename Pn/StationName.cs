using System.Text.RegularExpressions;

namespace EthernetTools.Pn;

/// <summary>
/// The rules a Profinet NameOfStation follows (IEC 61158-6-10, DNS-like): 1–240 characters; labels of 1–63 characters
/// separated by dots; only a–z, 0–9 and the hyphen; a label never starts or ends with a hyphen; the name is not an IP
/// address (n.n.n.n); and the first label is not "port-xyz" or "port-xyz-abcde" (those name ports).
/// The same rules, in the same words, as ProfinetTools' StationName; the self-test holds them to the same cases
/// (Test/station-names.json).
/// </summary>
public static partial class StationName
{
    public const int MaxLength = 240;
    public const int MaxLabelLength = 63;

    /// <summary>Why <paramref name="name"/> is not a Profinet name, or null when it is one.</summary>
    public static string? Problem(string? name)
    {
        if (string.IsNullOrEmpty(name)) return "A station name is required.";
        if (name.Length > MaxLength) return $"A station name has at most {MaxLength} characters.";
        if (name.Any(char.IsUpper)) return "A station name is written in small letters.";
        if (!AllowedCharacters().IsMatch(name)) return "A station name has only the letters a–z, the digits 0–9, hyphens and dots.";
        foreach (string label in name.Split('.'))
        {
            if (label.Length == 0) return "A station name has no empty part between dots, nor a dot first or last.";
            if (label.Length > MaxLabelLength) return $"Each part between dots has at most {MaxLabelLength} characters.";
            if (label.StartsWith('-') || label.EndsWith('-')) return "No part between dots starts or ends with a hyphen.";
        }
        if (IpAddressLike().IsMatch(name)) return "A station name is not an IP address.";
        if (PortLike().IsMatch(name.Split('.')[0])) return "A station name does not start with port-xyz (that names a port).";
        return null;
    }

    [GeneratedRegex(@"^[a-z0-9.\-]+$")]
    private static partial Regex AllowedCharacters();

    [GeneratedRegex(@"^\d+\.\d+\.\d+\.\d+$")]
    private static partial Regex IpAddressLike();

    [GeneratedRegex(@"^port-\d{3}(-\d{5})?$")]
    private static partial Regex PortLike();
}
