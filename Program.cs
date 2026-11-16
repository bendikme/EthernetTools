namespace EthernetTools;

internal static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();

        // EthernetTools.exe --selftest: the checks of SelfTest.cs, written to standard output; exit code 0 when all pass.
        if (args.Any(a => string.Equals(a, "--selftest", StringComparison.OrdinalIgnoreCase)))
            return SelfTest.Run();

        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.Run(new MainForm());
        return 0;
    }
}
