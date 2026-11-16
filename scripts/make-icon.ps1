# =============================================================================
#  make-icon.ps1  --  draws the EthernetTools icon and writes
#     app.ico   (16 ... 256 px; 256 px as PNG, the rest as 32-bit bitmaps)
#     app.png   (256 px, for the DYNATEC Portal tile)
#
#  The icon: a green-teal rounded square with a small network - one node at
#  the top, a trunk down to a bus, three nodes on the bus. Every size is
#  drawn at its own resolution, not scaled down from a big bitmap; up to
#  48 px the boxes and lines are snapped to whole pixels so they stay crisp.
#
#  Usage:  powershell -ExecutionPolicy Bypass -File scripts\make-icon.ps1
# =============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$root    = Split-Path $PSScriptRoot -Parent
$icoPath = Join-Path $root "app.ico"
$pngPath = Join-Path $root "app.png"

function New-RoundedRect([single]$x, [single]$y, [single]$w, [single]$h, [single]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $p.AddArc($x,           $y,           $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y,           $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d,   0, 90)
    $p.AddArc($x,           $y + $h - $d, $d, $d,  90, 90)
    $p.CloseFigure()
    return $p
}

# A filled box; snapped to whole pixels at the small sizes (round half up, so
# equal widths stay equal), with rounded corners when there is room for them.
function Add-Box($g, $brush, [double]$x, [double]$y, [double]$w, [double]$h, [double]$r, [bool]$snap) {
    if ($snap) {
        $x2 = [Math]::Floor($x + $w + 0.5); $y2 = [Math]::Floor($y + $h + 0.5)
        $x  = [Math]::Floor($x + 0.5);      $y  = [Math]::Floor($y + 0.5)
        $w  = [Math]::Max(1, $x2 - $x);     $h  = [Math]::Max(1, $y2 - $y)
    }
    if ($r -ge 1) {
        $p = New-RoundedRect ([single]$x) ([single]$y) ([single]$w) ([single]$h) ([single]$r)
        $g.FillPath($brush, $p)
        $p.Dispose()
    } else {
        $g.FillRectangle($brush, [single]$x, [single]$y, [single]$w, [single]$h)
    }
}

function New-IconBitmap([int]$s) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode   = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)

    # Background: rounded square, green-teal gradient (lighter at the top).
    $inset  = [single]($s * 0.03)
    $side   = [single]($s - 2 * $inset)
    $radius = [single]($s * 0.22)
    $bg     = New-RoundedRect $inset $inset $side $side $radius
    $rect   = New-Object System.Drawing.RectangleF 0, 0, $s, $s
    $brush  = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect,
                  ([System.Drawing.Color]::FromArgb(255, 34, 184, 140)),
                  ([System.Drawing.Color]::FromArgb(255, 10, 112,  96)), 90.0
    $g.FillPath($brush, $bg)

    # The network, in white: a node at the top, a trunk down to the bus,
    # three drops to three nodes.
    $snap  = $s -le 48
    $white = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
    $t     = [Math]::Max(1.0, $s * 0.065)                 # line width
    $rTop  = if ($s -ge 32) { $s * 0.045 } else { 0 }     # corner radius of the nodes
    $rBot  = if ($s -ge 32) { $s * 0.035 } else { 0 }

    $cx = $s * 0.5
    $tw = $s * 0.38; $th = $s * 0.22; $ty = $s * 0.16     # top node
    $busY = $s * 0.52                                     # bus (top edge)
    $bw = $s * 0.18; $bh = $s * 0.17; $by = $s * 0.66     # bottom nodes
    $xs = @(($s * 0.23), $cx, ($s * 0.77))                # their centres

    Add-Box $g $white ($cx - $t / 2) ($ty + $th / 2) $t ($busY - $ty - $th / 2) 0 $snap           # trunk
    Add-Box $g $white ($xs[0] - $t / 2) $busY ($xs[2] - $xs[0] + $t) $t 0 $snap                    # bus
    foreach ($x in $xs) {
        Add-Box $g $white ($x - $t / 2) $busY $t ($by - $busY + $bh / 2) 0 $snap                  # drop
        Add-Box $g $white ($x - $bw / 2) $by $bw $bh $rBot $snap                                  # node
    }
    Add-Box $g $white ($cx - $tw / 2) $ty $tw $th $rTop $snap                                     # top node

    $white.Dispose(); $brush.Dispose(); $bg.Dispose(); $g.Dispose()
    return $bmp
}

function Get-PngBytes($bmp) {
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bytes = $ms.ToArray()
    $ms.Dispose()
    return ,$bytes
}

# Classic icon image: BITMAPINFOHEADER + 32-bit BGRA rows (bottom-up) + an
# all-zero 1-bit AND mask. Every icon reader understands it; PNG entries are
# only reliable for the 256 px image.
function Get-DibBytes($bmp) {
    $s    = $bmp.Width
    $rect = New-Object System.Drawing.Rectangle 0, 0, $s, $s
    $data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
                          [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $pixels = New-Object byte[] ($s * $s * 4)
    for ($y = 0; $y -lt $s; $y++) {
        $src = [IntPtr]::Add($data.Scan0, $y * $data.Stride)
        [System.Runtime.InteropServices.Marshal]::Copy($src, $pixels, ($s - 1 - $y) * $s * 4, $s * 4)
    }
    $bmp.UnlockBits($data)

    $maskStride = [int]([Math]::Ceiling($s / 32.0) * 4)
    $ms = New-Object System.IO.MemoryStream
    $w  = New-Object System.IO.BinaryWriter $ms
    $w.Write([uint32]40); $w.Write([int32]$s); $w.Write([int32]($s * 2))   # height counts XOR + AND
    $w.Write([uint16]1);  $w.Write([uint16]32); $w.Write([uint32]0)
    $w.Write([uint32]($pixels.Length + $maskStride * $s))
    $w.Write([int32]0); $w.Write([int32]0); $w.Write([uint32]0); $w.Write([uint32]0)
    $w.Write($pixels)
    $w.Write((New-Object byte[] ($maskStride * $s)))
    $w.Flush()
    $bytes = $ms.ToArray()
    $w.Dispose()
    return ,$bytes
}

# ---- Build the .ico (ICONDIR + ICONDIRENTRY[] + images) -----------------------
$sizes  = 16, 20, 24, 32, 40, 48, 64, 128, 256
$images = @()
foreach ($s in $sizes) {
    $bmp = New-IconBitmap $s
    if ($s -ge 256) { $images += ,(Get-PngBytes $bmp) } else { $images += ,(Get-DibBytes $bmp) }
    if ($s -eq 256) { $bmp.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png) }
    $bmp.Dispose()
}

$out = New-Object System.IO.MemoryStream
$bw  = New-Object System.IO.BinaryWriter $out
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]
    $dim = if ($s -ge 256) { 0 } else { $s }          # 0 means 256 in an ICONDIRENTRY
    $bw.Write([byte]$dim); $bw.Write([byte]$dim)        # width, height
    $bw.Write([byte]0);    $bw.Write([byte]0)           # palette, reserved
    $bw.Write([uint16]1);  $bw.Write([uint16]32)        # planes, bits per pixel
    $bw.Write([uint32]$images[$i].Length)
    $bw.Write([uint32]$offset)
    $offset += $images[$i].Length
}
foreach ($img in $images) { $bw.Write($img) }
$bw.Flush()
[System.IO.File]::WriteAllBytes($icoPath, $out.ToArray())
$bw.Dispose()

"{0}  ({1} sizes, {2} bytes)" -f $icoPath, $sizes.Count, (Get-Item $icoPath).Length
"{0}  ({1} bytes)" -f $pngPath, (Get-Item $pngPath).Length
