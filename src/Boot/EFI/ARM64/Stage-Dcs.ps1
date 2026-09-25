[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $BuildOutput,

    [string] $Destination
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = $PSScriptRoot
}

$files = [ordered]@{
    "DcsBml.efi"        = "DcsBml.efi"
    "DcsBoot.efi"       = "DcsBoot.efi"
    "DcsCfg.efi"        = "DcsCfg.dcs"
    "DcsInfo.efi"       = "DcsInfo.dcs"
    "DcsInt.efi"        = "DcsInt.dcs"
    "DcsRe.efi"         = "DcsRe.efi"
    "LegacySpeaker.efi" = "LegacySpeaker.dcs"
}

function Assert-AArch64PeImage {
    param([Parameter(Mandatory = $true)][string] $Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if (($bytes.Length -lt 64) -or ($bytes[0] -ne 0x4d) -or ($bytes[1] -ne 0x5a)) {
        throw "'$Path' is not a PE image."
    }

    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if (($peOffset -lt 0) -or (($peOffset + 6) -gt $bytes.Length) -or ($bytes[$peOffset] -ne 0x50) -or ($bytes[$peOffset + 1] -ne 0x45) -or ($bytes[$peOffset + 2] -ne 0) -or ($bytes[$peOffset + 3] -ne 0)) {
        throw "'$Path' has an invalid PE header."
    }

    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    if ($machine -ne 0xaa64) {
        throw "'$Path' targets PE machine 0x$($machine.ToString('x4')), not AArch64 (0xaa64)."
    }
}

$buildOutputPath = (Resolve-Path -LiteralPath $BuildOutput).Path
New-Item -ItemType Directory -Force -Path $Destination | Out-Null

foreach ($entry in $files.GetEnumerator()) {
    $source = Join-Path $buildOutputPath $entry.Key
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Missing VeraCrypt-DCS output '$source'."
    }

    Assert-AArch64PeImage -Path $source
    $target = Join-Path $Destination $entry.Value
    Copy-Item -LiteralPath $source -Destination $target -Force

    $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    Write-Host "$($entry.Value)  $hash"
}
