using System.Reflection;

namespace EthernetTools;

/// <summary>The program's version (from the project's &lt;Version&gt;) and its icon.</summary>
internal static class AppInfo
{
    public static string Version { get; } =
        (typeof(AppInfo).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? "0.0.0").Split('+')[0];

    public static Icon? Icon { get; } = LoadIcon();

    private static Icon? LoadIcon()
    {
        using var stream = typeof(AppInfo).Assembly.GetManifestResourceStream("EthernetTools.app.ico");
        return stream is null ? null : new Icon(stream);
    }
}
