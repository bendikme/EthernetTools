# =============================================================================
#  release.ps1  --  builds, tests and packages an EthernetTools release
#
#    scripts\release.ps1                 publish win-x64 (self-contained, one
#                                        file), run the start-up check, write
#                                        dist\EthernetTools-<version>-windows-x64.zip
#    scripts\release.ps1 -SkipTests      the same without the start-up check
#    scripts\release.ps1 -SignThumbprint <thumbprint>
#                                        ... and sign EthernetTools.exe (see "Sign" below)
#    scripts\release.ps1 -Publish        ... and create the GitHub release
#                                        v<version> with the zip (needs `gh`,
#                                        logged in; the tag must be pushed)
#
#  The version comes from <Version> in EthernetTools.csproj. The GitHub workflow
#  .github\workflows\release.yml runs this script when a tag v* is pushed, so
#  pushing the tag is normally all a release takes.
#
#  Needs the .NET 10 SDK. The exe carries its own .NET runtime; the only thing
#  a user installs is Npcap (https://npcap.com).
# =============================================================================

param(
    [switch] $SkipTests,
    [switch] $Publish,
    [string] $SignThumbprint = "",  # sign with this certificate of the user's store
    [int]    $TimeoutSec = 30       # passed to the start-up check (slower machines: raise it)
)

$script:Signed = $false

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

# ---- Version ----------------------------------------------------------------
$project = Join-Path $root "EthernetTools.csproj"
$m = Select-String -Path $project -Pattern '<Version>([^<]+)</Version>'
if (-not $m) { throw "<Version> not found in EthernetTools.csproj" }
$version = $m.Matches[0].Groups[1].Value.Trim()
$tag     = "v$version"
Write-Host "EthernetTools $version" -ForegroundColor Cyan

# ---- .NET SDK -----------------------------------------------------------------
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnet) { throw "dotnet not found - install the .NET 10 SDK" }
$sdks = & dotnet --list-sdks
if (-not ($sdks | Where-Object { $_ -match '^(\d+)\.' -and [int]$Matches[1] -ge 10 })) {
    throw "The .NET 10 SDK (or newer) is needed; installed: $($sdks -join ', ')"
}

# ---- Build (publish) ----------------------------------------------------------
# A clean, self-contained, single-file build for win-x64: one EthernetTools.exe
# with the .NET runtime inside. Nothing else is needed next to it.
$publishDir = Join-Path $root "bin\Release\publish-win-x64"
foreach ($d in @($publishDir,
                 (Join-Path $root "bin\Release\net10.0-windows\win-x64"),
                 (Join-Path $root "obj\Release\net10.0-windows\win-x64"))) {
    if (Test-Path $d) { Remove-Item $d -Recurse -Force }
}

Write-Host "Publishing Release win-x64 (self-contained, single file) ..." -ForegroundColor Cyan
& dotnet publish $project -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true -p:DebugType=none `
    -o $publishDir -nologo -v:minimal
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed ($LASTEXITCODE)" }

$exe = Join-Path $publishDir "EthernetTools.exe"
if (-not (Test-Path $exe)) { throw "EthernetTools.exe was not published" }

# One file, nothing beside it - that is what the zip promises.
$extra = @(Get-ChildItem $publishDir | Where-Object { $_.Name -ne "EthernetTools.exe" })
if ($extra.Count -gt 0) { throw "The publish folder holds more than the exe: $($extra.Name -join ', ')" }

# The exe must carry the version it is released as.
$fileVersion = (Get-Item $exe).VersionInfo.ProductVersion
if ($fileVersion -ne $version) { throw "EthernetTools.exe says version '$fileVersion', the project says '$version'" }

# ---- Tests ----------------------------------------------------------------------
# Before signing and packaging: the file that is tested is the file that ships
# (signing only adds the signature).
if (-not $SkipTests) {
    Write-Host "Running the start-up check ..." -ForegroundColor Cyan
    & (Join-Path $root "Test\SmokeTest.ps1") -Exe $exe -Version $version -TimeoutSec $TimeoutSec
    if ($LASTEXITCODE -ne 0) { throw "Start-up check failed ($LASTEXITCODE)" }
}

# ---- Sign (when a certificate is given) ---------------------------------------------
# Either  -SignThumbprint <thumbprint of a code-signing certificate in the user's store>
# or the environment variables ETHTOOLS_SIGN_PFX_BASE64 (a .pfx, base64) and
# ETHTOOLS_SIGN_PFX_PASSWORD - the release workflow fills them from the repository
# secrets of the same names. Without a certificate the exe stays unsigned and
# Windows SmartScreen asks before its first start.
$pfxFile = $null
try {
    $signArgs = $null
    if ($SignThumbprint) {
        $signArgs = @("/sha1", $SignThumbprint)
    } elseif ($env:ETHTOOLS_SIGN_PFX_BASE64) {
        $pfxFile = Join-Path ([System.IO.Path]::GetTempPath()) ("ethtools-sign-" + [Guid]::NewGuid().ToString("N") + ".pfx")
        [System.IO.File]::WriteAllBytes($pfxFile, [Convert]::FromBase64String($env:ETHTOOLS_SIGN_PFX_BASE64))
        $signArgs = @("/f", $pfxFile)
        if ($env:ETHTOOLS_SIGN_PFX_PASSWORD) { $signArgs += @("/p", $env:ETHTOOLS_SIGN_PFX_PASSWORD) }
    }
    if ($signArgs) {
        $signtool = Get-ChildItem (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin") -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -match "\\x64\\" } | Sort-Object FullName -Descending | Select-Object -First 1
        if (-not $signtool) { throw "signtool.exe not found (Windows SDK)" }
        Write-Host "Signing EthernetTools.exe ..." -ForegroundColor Cyan
        & $signtool.FullName sign /fd SHA256 /td SHA256 /tr "http://timestamp.digicert.com" /d "EthernetTools" @signArgs $exe
        if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }
        & $signtool.FullName verify /pa $exe
        if ($LASTEXITCODE -ne 0) { throw "The signature does not verify ($LASTEXITCODE)" }
        $script:Signed = $true
    } else {
        Write-Host "No signing certificate given: EthernetTools.exe is NOT signed." -ForegroundColor Yellow
    }
} finally {
    if ($pfxFile -and (Test-Path $pfxFile)) { Remove-Item $pfxFile -Force }
}

# ---- Package ----------------------------------------------------------------------
$dist  = Join-Path $root "dist"
$stage = Join-Path $dist "EthernetTools-$version"
$zip   = Join-Path $dist "EthernetTools-$version-windows-x64.zip"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
Copy-Item $exe                              $stage
Copy-Item (Join-Path $root "README.md")     $stage
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -CompressionLevel Optimal
Remove-Item $stage -Recurse -Force

$hash = (Get-FileHash $zip -Algorithm SHA256).Hash
Write-Host ("{0}  ({1:N0} bytes)" -f $zip, (Get-Item $zip).Length) -ForegroundColor Green
Write-Host "SHA256 $hash"

# ---- Publish (optional) -------------------------------------------------------------
if ($Publish) {
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $gh) {
        $candidate = Join-Path $env:ProgramFiles "GitHub CLI\gh.exe"
        if (Test-Path $candidate) { $gh = $candidate } else { throw "GitHub CLI (gh) not found" }
    } else { $gh = $gh.Source }

    $notes = Join-Path $root "docs\release-notes\$tag.md"
    $ghArgs = @("release", "create", $tag, $zip, "--title", "EthernetTools $version", "--verify-tag")
    if (Test-Path $notes) { $ghArgs += @("--notes-file", $notes) } else { $ghArgs += "--generate-notes" }
    Write-Host "Creating GitHub release $tag ..." -ForegroundColor Cyan
    & $gh @ghArgs
    if ($LASTEXITCODE -ne 0) { throw "gh release create failed ($LASTEXITCODE)" }
}
