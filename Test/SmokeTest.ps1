# =============================================================================
#  SmokeTest.ps1  --  starts EthernetTools.exe and checks that it comes up
#
#    Test\SmokeTest.ps1 -Exe <path to EthernetTools.exe> [-Version 26.11.0]
#
#  Checks, through UI Automation on the real window:
#    - the window opens, its title carries the version
#    - the adapter list is filled when the window loads (the status line
#      leaves "Ready."); with Npcap on this machine it must say
#      "<n> Ethernet adapter(s) found." - so the single-file build really loads
#      Npcap's wpcap.dll; without Npcap (a build server) it must say so
#    - Refresh works and the window keeps answering
#    - the window closes cleanly (exit code 0)
#
#  Exit code 0 when every check passes, 1 otherwise.
# =============================================================================

param(
    [Parameter(Mandatory = $true)] [string] $Exe,
    [string] $Version = "",
    [int]    $TimeoutSec = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

$script:failures = 0
function Check([string]$name, [bool]$ok, [string]$detail = "") {
    if ($ok) { Write-Host ("  PASS  {0}" -f $name) -ForegroundColor Green }
    else     { Write-Host ("  FAIL  {0}  {1}" -f $name, $detail) -ForegroundColor Red; $script:failures++ }
}

function Wait-Until([scriptblock]$condition, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $condition) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return [bool](& $condition)
}

$UIA = [System.Windows.Automation.AutomationElement]
$TS  = [System.Windows.Automation.TreeScope]
$CT  = [System.Windows.Automation.ControlType]

function Find-All($root, $controlType) {
    $cond = New-Object System.Windows.Automation.PropertyCondition ($UIA::ControlTypeProperty), $controlType
    return $root.FindAll($TS::Descendants, $cond)
}

# The status line is the first text of the status bar.
function Get-StatusText($window) {
    foreach ($bar in (Find-All $window $CT::StatusBar)) {
        foreach ($t in (Find-All $bar $CT::Text)) { return $t.Current.Name }
    }
    return $null
}

$Exe = (Resolve-Path $Exe).Path
$npcap = Test-Path (Join-Path $env:SystemRoot "System32\Npcap\wpcap.dll")
Write-Host ("Smoke test: {0}  (Npcap on this machine: {1})" -f $Exe, $(if ($npcap) { "yes" } else { "no" })) -ForegroundColor Cyan

$proc = Start-Process -FilePath $Exe -PassThru
try {
    # ---- The window opens -----------------------------------------------------
    $opened = Wait-Until { $proc.Refresh(); $proc.HasExited -or $proc.MainWindowHandle -ne [IntPtr]::Zero } $TimeoutSec
    $opened = $opened -and -not $proc.HasExited -and $proc.MainWindowHandle -ne [IntPtr]::Zero
    Check "window opens" $opened $(if ($proc.HasExited) { "process exited with code $($proc.ExitCode)" } else { "no window after $TimeoutSec s" })
    if (-not $opened) { throw "EthernetTools did not open its window" }

    $window = $UIA::FromHandle($proc.MainWindowHandle)
    $title  = $window.Current.Name
    $want   = if ($Version) { "EthernetTools v$Version " } else { "EthernetTools v" }
    Check "title carries the version ('$title')" ($title.StartsWith($want)) "expected it to start with '$want'"

    # ---- Adapters are listed when the window loads ------------------------------
    $status = $null
    $loaded = Wait-Until { $script:status = Get-StatusText $window; $script:status -and $script:status -ne "Ready." } $TimeoutSec
    Write-Host ("        status: {0}" -f $status)
    if ($npcap) {
        Check "adapters listed through Npcap" ($loaded -and $status -match '^\d+ Ethernet adapter\(s\) found\.$') "status: '$status'"
    } else {
        Check "no Npcap is reported as such" ($loaded -and $status -match 'Npcap') "status: '$status'"
    }

    # ---- Refresh, and the window keeps answering --------------------------------
    $refresh = $null
    foreach ($b in (Find-All $window $CT::Button)) { if ($b.Current.Name -eq "Refresh") { $refresh = $b; break } }
    Check "Refresh button found" ($null -ne $refresh)
    if ($refresh) {
        $refresh.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
        Start-Sleep -Milliseconds 500
        $proc.Refresh()
        $after = Get-StatusText $window
        Check "window answers after Refresh" ($proc.Responding -and $after -and $after -ne "Ready.") "status: '$after'"
    }

    # ---- Clean exit ---------------------------------------------------------------
    [void]$proc.CloseMainWindow()
    $exited = $proc.WaitForExit($TimeoutSec * 1000)
    Check "closes cleanly" ($exited -and $proc.ExitCode -eq 0) $(if ($exited) { "exit code $($proc.ExitCode)" } else { "still running after $TimeoutSec s" })
}
catch {
    Write-Host ("  ERROR {0}" -f $_.Exception.Message) -ForegroundColor Red
    $script:failures++
}
finally {
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}

if ($script:failures -gt 0) {
    Write-Host ("{0} check(s) failed" -f $script:failures) -ForegroundColor Red
    exit 1
}
Write-Host "All checks passed" -ForegroundColor Green
exit 0
