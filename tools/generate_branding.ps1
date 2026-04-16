Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = 'Stop'

function New-Canvas($width, $height) {
    $bmp = New-Object System.Drawing.Bitmap($width, $height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    return @{ Bitmap = $bmp; Graphics = $g }
}

function New-RoundedPath([System.Drawing.RectangleF]$rect, [float]$radius) {
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $diameter = $radius * 2
    $path.AddArc($rect.X, $rect.Y, $diameter, $diameter, 180, 90)
    $path.AddArc($rect.Right - $diameter, $rect.Y, $diameter, $diameter, 270, 90)
    $path.AddArc($rect.Right - $diameter, $rect.Bottom - $diameter, $diameter, $diameter, 0, 90)
    $path.AddArc($rect.X, $rect.Bottom - $diameter, $diameter, $diameter, 90, 90)
    $path.CloseFigure()
    return $path
}

function Save-PngIco($bitmap, $path) {
    $pngStream = New-Object System.IO.MemoryStream
    $bitmap.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngBytes = $pngStream.ToArray()
    $pngStream.Dispose()

    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $bw = New-Object System.IO.BinaryWriter($fs)
    $bw.Write([UInt16]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]1)
    $bw.Write([Byte]0)
    $bw.Write([Byte]0)
    $bw.Write([Byte]0)
    $bw.Write([Byte]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]32)
    $bw.Write([UInt32]$pngBytes.Length)
    $bw.Write([UInt32]22)
    $bw.Write($pngBytes)
    $bw.Flush()
    $bw.Dispose()
    $fs.Dispose()
}

function Draw-BrandBadge($width, $height, [string]$primaryText, [string]$secondaryText = $null) {
    $canvas = New-Canvas $width $height
    $bmp = $canvas.Bitmap
    $g = $canvas.Graphics

    $bgRect = New-Object System.Drawing.RectangleF(0, 0, $width, $height)
    $gradient = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $bgRect,
        [System.Drawing.Color]::FromArgb(255, 12, 45, 72),
        [System.Drawing.Color]::FromArgb(255, 32, 120, 104),
        45
    )
    $g.FillRectangle($gradient, 0, 0, $width, $height)

    $shadowBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(40, 255, 255, 255))
    $g.FillEllipse($shadowBrush, $width * 0.10, $height * 0.08, $width * 0.80, $height * 0.45)

    $panelBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(220, 4, 22, 36))
    $cardRect = [System.Drawing.RectangleF]::new($width * 0.12, $height * 0.14, $width * 0.76, $height * 0.72)
    $cardPath = New-RoundedPath $cardRect ($width * 0.12)
    $g.FillPath($panelBrush, $cardPath)

    $borderPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(210, 182, 234, 218), [Math]::Max(2, $width * 0.03))
    $g.DrawPath($borderPen, $cardPath)

    $fontSize = [Math]::Max(12, $width * 0.28)
    $font = New-Object System.Drawing.Font("Segoe UI Semibold", $fontSize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $smallFont = New-Object System.Drawing.Font("Segoe UI", [Math]::Max(8, $width * 0.08), [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)

    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = [System.Drawing.StringAlignment]::Center
    $sf.LineAlignment = [System.Drawing.StringAlignment]::Center

    $textBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 239, 248, 244))
    $accentBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 183, 255, 236))
    $g.DrawString($primaryText, $font, $textBrush, [System.Drawing.RectangleF]::new(0, $height * 0.16, $width, $height * 0.42), $sf)
    if ($secondaryText) {
        $g.DrawString($secondaryText, $smallFont, $accentBrush, [System.Drawing.RectangleF]::new(0, $height * 0.58, $width, $height * 0.14), $sf)
    }

    $gradient.Dispose()
    $shadowBrush.Dispose()
    $panelBrush.Dispose()
    $cardPath.Dispose()
    $borderPen.Dispose()
    $font.Dispose()
    $smallFont.Dispose()
    $sf.Dispose()
    $textBrush.Dispose()
    $accentBrush.Dispose()
    $g.Dispose()
    return $bmp
}

function Draw-Banner($width, $height, [string]$title, [string]$subtitle) {
    $canvas = New-Canvas $width $height
    $bmp = $canvas.Bitmap
    $g = $canvas.Graphics

    $bgRect = New-Object System.Drawing.RectangleF(0, 0, $width, $height)
    $gradient = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $bgRect,
        [System.Drawing.Color]::FromArgb(255, 7, 29, 51),
        [System.Drawing.Color]::FromArgb(255, 30, 98, 103),
        0
    )
    $g.FillRectangle($gradient, 0, 0, $width, $height)

    $overlay = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(36, 255, 255, 255))
    for ($i = 0; $i -lt 6; $i++) {
        $g.FillEllipse($overlay, $width * (0.08 + $i * 0.16), $height * (0.10 + ($i % 2) * 0.12), $height * 0.55, $height * 0.55)
    }

    $titleFont = New-Object System.Drawing.Font("Segoe UI Semibold", [Math]::Max(16, $height * 0.55), [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $subtitleFont = New-Object System.Drawing.Font("Segoe UI", [Math]::Max(8, $height * 0.18), [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
    $titleBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 243, 249, 247))
    $subBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 189, 240, 228))

    $g.DrawString($title, $titleFont, $titleBrush, 20, $height * 0.08)
    $g.DrawString($subtitle, $subtitleFont, $subBrush, 22, $height * 0.68)

    $gradient.Dispose()
    $overlay.Dispose()
    $titleFont.Dispose()
    $subtitleFont.Dispose()
    $titleBrush.Dispose()
    $subBrush.Dispose()
    $g.Dispose()
    return $bmp
}

[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null

$repo = Split-Path -Parent $PSScriptRoot

$icon = Draw-BrandBadge 256 256 "EPS" "ExamPrepSec"
$iconTargets = @(
    "src\Common\VeraCrypt.ico",
    "src\Common\VeraCrypt_mounted.ico",
    "src\Common\VeraCrypt_Volume.ico",
    "src\Setup\Setup.ico",
    "src\SetupDLL\Setup.ico"
)
foreach ($target in $iconTargets) {
    Save-PngIco $icon (Join-Path $repo $target)
}

$logo96 = Draw-BrandBadge 96 96 "EPS"
$logo288 = Draw-BrandBadge 288 288 "EPS" "Secure Workspace"
$text96 = Draw-Banner 420 96 "ExamPrepSec" "Derived VeraCrypt build"
$text288 = Draw-Banner 1260 288 "ExamPrepSec" "Derived VeraCrypt build"
$bgText = Draw-Banner 620 110 "ExamPrepSec" "Secure exam workspace"
$setupBanner = Draw-Banner 493 58 "ExamPrepSec" "Desktop encryption toolkit"
$setupDialog = Draw-Banner 493 312 "ExamPrepSec" "Portable and installer branding"
$wizard = Draw-Banner 164 233 "EPS" "Volume wizard"

$bmpTargets = @{
    "src\Mount\Logo_96dpi.bmp" = $logo96
    "src\Mount\Logo_288dpi.bmp" = $logo288
    "src\ExpandVolume\Logo_96dpi.bmp" = $logo96
    "src\ExpandVolume\Logo_288dpi.bmp" = $logo288
    "src\Common\Textual_logo_96dpi.bmp" = $text96
    "src\Common\Textual_logo_288dpi.bmp" = $text288
    "src\Common\Textual_logo_background.bmp" = $bgText
    "src\Setup\VeraCrypt_setup.bmp" = $setupBanner
    "src\Setup\VeraCrypt_setup_background.bmp" = $setupDialog
    "src\SetupDLL\VeraCrypt_setup.bmp" = $setupBanner
    "src\SetupDLL\VeraCrypt_setup_background.bmp" = $setupDialog
    "src\Format\VeraCrypt_Wizard.bmp" = $wizard
}

foreach ($entry in $bmpTargets.GetEnumerator()) {
    $entry.Value.Save((Join-Path $repo $entry.Key), [System.Drawing.Imaging.ImageFormat]::Bmp)
}

$pngSizes = 16, 22, 24, 32, 48, 64, 128, 256, 512, 1024
foreach ($size in $pngSizes) {
    $png = Draw-BrandBadge $size $size "EPS"
    $png.Save((Join-Path $repo ("src\Resources\Icons\VeraCrypt-{0}x{0}.png" -f $size)), [System.Drawing.Imaging.ImageFormat]::Png)
    $png.Dispose()
}

$icon.Dispose()
$logo96.Dispose()
$logo288.Dispose()
$text96.Dispose()
$text288.Dispose()
$bgText.Dispose()
$setupBanner.Dispose()
$setupDialog.Dispose()
$wizard.Dispose()

Write-Host "Branding assets generated."
