<#
.SYNOPSIS
    Create a VeraCrypt container just large enough for the supplied file or
    directory and copy the data into it.

.DESCRIPTION
    • Chooses an exFAT cluster size (auto or explicit).
    • Calculates the minimum container size using an iterative approach for FAT/Bitmap sizing, plus safety margin.
    • Creates, mounts, copies, verifies, and dismounts – all guarded by -WhatIf/-Confirm (SupportsShouldProcess).
    • Finds VeraCrypt automatically or takes a -VeraCryptDir override.
    • Encryption and hash algorithms are parameters.
    • Password can be passed via SecureString prompt or pipeline.
    • Enhanced parameterization for safety margins and VeraCrypt overhead.

.PARAMETER InputPath        File or directory to store in the container.
.PARAMETER ContainerPath    Dest *.hc* file. Default: InputPath + '.hc'.
.PARAMETER ClusterSizeKB    4–512 KiB or 'Auto' (default 32).
.PARAMETER VeraCryptDir     Optional folder containing VeraCrypt *.exe* files.
.PARAMETER EncryptionAlg    Any algorithm VeraCrypt accepts (default AES).
.PARAMETER HashAlg          VeraCrypt hash (default SHA512).
.PARAMETER SafetyPercent    Safety margin as percentage of calculated size (default 1.0 for small, 0.1 for large).
.PARAMETER VCOverheadMiB    VeraCrypt overhead in MiB (default varies by size).
.PARAMETER Force            If specified, allows overwriting the output container if it already exists.
.PARAMETER Password         Optional SecureString password for automation (prompts if not provided).

.EXAMPLE
    .\EncryptData.ps1 -InputPath C:\Data -ContainerPath C:\EncryptedData.hc -ClusterSizeKB Auto
.NOTES
    Author: Mounir IDRASSI
    Email: mounir.idrassi@amcrypto.jp
    Date: 30 April 2025
    License: This script is licensed under the Apache License 2.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$InputPath,
    [string]$ContainerPath,
    [ValidateSet('Auto','4','8','16','32','64','128','256','512')]
    [string]$ClusterSizeKB = '32',
    [string]$VeraCryptDir,
    [string]$EncryptionAlg = 'AES',
    [string]$HashAlg = 'SHA512',
    # 0 ⇒ use built-in logic; otherwise 0–100 %  
    [ValidateRange(0.0,100.0)]  
    [double]$SafetyPercent = 0,  
    # 0 ⇒ auto. 1-8192 MiB accepted.  
    [ValidateRange(0,8192)]  
    [int]$VCOverheadMiB    = 0,
    [Parameter(ValueFromPipeline = $true)][System.Security.SecureString]$Password,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AbsolutePath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    } else {
        $combined = Join-Path -Path (Get-Location) -ChildPath $Path
        return [System.IO.Path]::GetFullPath($combined)
    }
}

# Helper creates a temp file, registers it for secure deletion in finally  
function New-VcErrFile {  
    $tmp = [System.IO.Path]::GetTempFileName()  
    # Pre-allocate 0-byte file; caller overwrites  
    return $tmp  
}

# Constants for exFAT sizing
$EXFAT_MIN_CLUSTERS = 2
$EXFAT_PRACTICAL_MIN_CLUSTERS = 65533
$INITIAL_VBR_SIZE = 32KB
$BACKUP_VBR_SIZE = 32KB
$RAW_UPCASE_BYTES = 128KB

#----------------------- Locate VeraCrypt executables --------------------------
if (-not $VeraCryptDir) {
    $candidates = @(Join-Path $env:ProgramFiles 'VeraCrypt')
    $VeraCryptDir = $candidates |
        Where-Object { Test-Path (Join-Path $_ 'VeraCrypt.exe') } |
        Select-Object -First 1
    if (-not $VeraCryptDir) {
        $cmd = Get-Command 'VeraCrypt.exe' -ErrorAction SilentlyContinue
        if ($cmd) { $VeraCryptDir = Split-Path $cmd.Path }
    }
    if (-not $VeraCryptDir) { throw 'VeraCrypt executables not found – specify -VeraCryptDir.' }
}

$VeraCryptExe = Join-Path $VeraCryptDir 'VeraCrypt.exe'
$VeraCryptFormatExe = Join-Path $VeraCryptDir 'VeraCrypt Format.exe'
if (-not (Test-Path $VeraCryptExe) -or -not (Test-Path $VeraCryptFormatExe)) {
    throw 'VeraCrypt executables missing.'
}

#--------------------------- Input / Output Paths ------------------------------
$InputPath = Get-AbsolutePath $InputPath
if (-not (Test-Path $InputPath)) { throw "InputPath '$InputPath' does not exist." }

if (-not $ContainerPath) {
    $ContainerPath = ($InputPath.TrimEnd('\') + '.hc')
} else {
    $ContainerPath = Get-AbsolutePath $ContainerPath
}
if (Test-Path $ContainerPath) {
    if ($Force) {
        Write-Verbose "Container '$ContainerPath' already exists and will be overwritten."
        if ($PSCmdlet.ShouldProcess("File '$ContainerPath'", "Remove existing container")) {
            Remove-Item $ContainerPath -Force
        } else {
            throw "Operation cancelled by user. Cannot overwrite '$ContainerPath'."
        }
    } else {
        throw "Container '$ContainerPath' already exists. Use -Force to overwrite."
    }
}

#----------------------------- Cluster Size -------------------------------------
[UInt32]$ClusterSize = if ($ClusterSizeKB -eq 'Auto') { $null } else { [int]$ClusterSizeKB * 1KB }

#--------------------------- exFAT Size Helpers --------------------------------
function Get-DirectoryStats {
    param([string]$Path)

    $fileLengths = [System.Collections.Generic.List[UInt64]]::new()
    $dirLengths  = [System.Collections.Generic.List[UInt64]]::new()
    [UInt64]$metaSum = 0

    function WalkDir {
        param([System.IO.DirectoryInfo]$Dir)

        [UInt64]$thisDirBytes = 0

        # Use -ErrorAction SilentlyContinue for potentially inaccessible items (like system junctions)
        Get-ChildItem -LiteralPath $Dir.FullName -Force -ErrorAction SilentlyContinue | ForEach-Object {

            $nameLen   = $_.Name.Length
            $nameSlots = [math]::Ceiling($nameLen / 15)          # name entries
            $dirSlots  = 2 + $nameSlots                          # File + Stream + Names
            $entryBytes = $dirSlots * 32

            $metaSum      += $entryBytes
            $thisDirBytes += $entryBytes

            if ($_.PSIsContainer) {
                WalkDir $_
            } else {
                # Handle potential errors reading length (e.g., locked files)
                try {
                    $fileLengths.Add([UInt64]$_.Length)
                } catch {
                    Write-Warning "Could not get length for file: $($_.FullName). Error: $($_.Exception.Message)"
                }
            }
        }

        # At least one 32-byte entry so the directory is not “empty”
        if ($thisDirBytes -lt 32) { $thisDirBytes = 32 }

        $dirLengths.Add($thisDirBytes)
    }

    $startItem = Get-Item -LiteralPath $Path -Force
    if ($startItem -isnot [System.IO.DirectoryInfo]) {
        # Handle case where InputPath is a single file
        $nameLen   = $startItem.Name.Length
        $nameSlots = [math]::Ceiling($nameLen / 15)
        $dirSlots  = 2 + $nameSlots
        $entryBytes = $dirSlots * 32
        $metaSum = $entryBytes
        $fileLengths.Add([UInt64]$startItem.Length)
        $dirLengths.Add(32) # Minimal directory entry size for the root
    } else {
        WalkDir $startItem
    }

    [PSCustomObject]@{
        MetadataSum = $metaSum      # pure 32-byte entry bytes (used for info, not size calc)
        FileLengths = $fileLengths  # payload of regular files
        DirLengths  = $dirLengths   # payload of *directory files* (containing entries)
    }
}

function Compute-ExFatSize {
    param(
        [Parameter(Mandatory)][UInt64[]] $FileLengths,
        [Parameter(Mandatory)][UInt64[]] $DirLengths,
        [Parameter(Mandatory)][UInt32]   $Cluster
    )

    # --- Calculate base size (VBR, UpCase Table, File Payloads, Directory Payloads) ---
    # These parts don't depend on the total cluster count directly.
    [UInt64]$baseSize = $INITIAL_VBR_SIZE + $BACKUP_VBR_SIZE
    $baseSize += [math]::Ceiling($RAW_UPCASE_BYTES / $Cluster) * $Cluster  # up-case tbl aligned

    foreach ($len in $FileLengths) { $baseSize += [math]::Ceiling($len / $Cluster) * $Cluster }
    foreach ($len in $DirLengths ) { $baseSize += [math]::Ceiling($len / $Cluster) * $Cluster }

    # --- Iterative FAT/Bitmap Calculation ---
    # The size of FAT and Bitmap depends on the total cluster count, which depends on the total size (including FAT/Bitmap).
    # We iterate until the calculated total size stabilizes.

    [UInt64]$currentTotalSize = $baseSize # Initial guess: size without FAT/Bitmap
    [UInt64]$previousTotalSize = 0
    $maxIterations = 10 # Safety break to prevent infinite loops
    $iteration = 0

    while ($currentTotalSize -ne $previousTotalSize -and $iteration -lt $maxIterations) {
        $previousTotalSize = $currentTotalSize
        $iteration++
        Write-Verbose "Compute-ExFatSize Iteration '$iteration': Starting size = '$previousTotalSize' bytes"

        # Calculate cluster count based on the size from the *start* of this iteration
        $clusterCount = [math]::Ceiling($previousTotalSize / $Cluster)
        # Ensure minimum cluster count if needed (exFAT has minimums, though usually covered by VBR etc.)
        if ($clusterCount -lt $EXFAT_PRACTICAL_MIN_CLUSTERS) { $clusterCount = $EXFAT_PRACTICAL_MIN_CLUSTERS } # Practical minimum for FAT entries > sector size

        # Allocation bitmap (1 bit per cluster, aligned to cluster size)
        $bitmapBytes = [math]::Ceiling($clusterCount / 8)
        $bitmapBytesAligned = [math]::Ceiling($bitmapBytes / $Cluster) * $Cluster
        Write-Verbose "  Clusters: '$clusterCount', Bitmap Bytes: '$bitmapBytes', Aligned Bitmap: '$bitmapBytesAligned'"

        # FAT (4 bytes per cluster, +2 reserved entries, aligned to cluster size)
        $fatBytes = ([UInt64]$clusterCount + 2) * 4 # Use UInt64 to avoid overflow on large volumes
        $fatBytesAligned = [math]::Ceiling($fatBytes / $Cluster) * $Cluster
        Write-Verbose "  FAT Bytes: '$fatBytes', Aligned FAT: '$fatBytesAligned'"

        # Calculate the new total size estimate including FAT and Bitmap
        $currentTotalSize = $baseSize + $bitmapBytesAligned + $fatBytesAligned
        Write-Verbose "  New Estimated Total Size: '$currentTotalSize' bytes"
    }

    if ($iteration -ge $maxIterations) {
        Write-Warning "FAT/Bitmap size calculation did not converge after '$maxIterations' iterations. Using last calculated size ('$currentTotalSize' bytes). This might indicate an issue or extremely large dataset."
    }

    Write-Verbose "Compute-ExFatSize Converged Size: '$currentTotalSize' bytes after '$iteration' iterations."
    return [PSCustomObject]@{
        TotalSize = $currentTotalSize
        ClusterCount = $clusterCount
        IterationHistory = @()
    }
}

function Get-RecommendedCluster {
    param([UInt64]$VolumeBytes)
    switch ($VolumeBytes) {
        { $_ -le 256MB } { return 4KB }
        { $_ -le 32GB } { return 32KB }
        { $_ -le 256TB } { return 128KB }
        default { return 512KB }
    }
}

#----------------------------------------------- Drive the two-pass logic
Write-Host "Calculating required size for '$InputPath'..."
$stats = Get-DirectoryStats -Path $InputPath
Write-Verbose "Stats: $($stats.FileLengths.Count) files, $($stats.DirLengths.Count) directories, Metadata: $($stats.MetadataSum) bytes."

if (-not $ClusterSize) {
    Write-Verbose "Cluster size set to 'Auto'. Performing first pass calculation with 4KB cluster..."
    $firstPassResult = Compute-ExFatSize -FileLengths $stats.FileLengths -DirLengths $stats.DirLengths -Cluster 4KB
    $firstPassSize = $firstPassResult.TotalSize
    Write-Verbose "First pass estimated size: '$firstPassSize' bytes"

    $ClusterSize = Get-RecommendedCluster -VolumeBytes $firstPassSize
    Write-Host "Auto-selected Cluster size: $($ClusterSize / 1KB) KiB based on estimated size."
    Write-Verbose "Performing second pass calculation with selected cluster size ($($ClusterSize / 1KB) KiB)..."
    $sizeResult = Compute-ExFatSize -FileLengths $stats.FileLengths -DirLengths $stats.DirLengths -Cluster $ClusterSize
    $rawSize = $sizeResult.TotalSize
} else {
    Write-Host "Using specified Cluster size: $($ClusterSize / 1KB) KiB."
    Write-Verbose "Performing calculation with specified cluster size..."
    $sizeResult = Compute-ExFatSize -FileLengths $stats.FileLengths -DirLengths $stats.DirLengths -Cluster $ClusterSize
    $rawSize = $sizeResult.TotalSize
}

#---------------------------- Container Sizing ---------------------------------
$safetyPercentUsed = if ($SafetyPercent -gt 0.0) { $SafetyPercent } else { if ($rawSize -lt 100MB) { 1.0 } else { 0.1 } }
$safety = if ($rawSize -lt 100MB) { [math]::Max(64KB, [math]::Ceiling($rawSize * $safetyPercentUsed / 100)) }
          else { [math]::Max(1MB, [math]::Ceiling($rawSize * $safetyPercentUsed / 100)) }
$contBytes = $rawSize + [UInt64]$safety
$contMiB = [int][math]::Ceiling($contBytes / 1MB)
if ($contMiB -lt 2) { $contMiB = 2 }

$vcOverheadMiBUsed = if ($VCOverheadMiB -gt 0) { $VCOverheadMiB } else {
    if ($contMiB -lt 10) { 1 } elseif ($contMiB -lt 100) { 2 } else { [math]::Ceiling($contMiB * 0.01) }
}
$finalContMiB = $contMiB + $vcOverheadMiBUsed

Write-Host ("Cluster Size  : {0} KiB`nCalculated FS: {1:N0} bytes`nSafety Margin: {2:N0} bytes ({3}%)`nVC Overhead  : {4} MiB`nFinal Size   : {5} MiB" -f
    ($ClusterSize/1KB), $rawSize, $safety, $safetyPercentUsed, $vcOverheadMiBUsed, $finalContMiB)

#---- Secure Password Prompt ----
if (-not $Password) {
    $Password = Read-Host -AsSecureString -Prompt "Enter container password"
}
$cred = New-Object System.Management.Automation.PSCredential ("VeraCryptUser", $Password)
$plainPassword = $cred.GetNetworkCredential().Password

if ([string]::IsNullOrWhiteSpace($plainPassword)) {
    Write-Host "Error: Password cannot be empty. Please provide a non-empty password." -ForegroundColor Red
    exit 1
}

#---- Main Action ----
$mounted = $false
$driveLetter = $null

$errFile   = New-VcErrFile  
$mountFile = New-VcErrFile

try {
    #--- Create Container ----
    if ($PSCmdlet.ShouldProcess("File '$ContainerPath'", "Create VeraCrypt container ($finalContMiB MiB)")) {
        $formatArgs = @(
            '/create', $ContainerPath,
            '/size', "$($finalContMiB)M",
            '/password', $plainPassword,
            '/encryption', $EncryptionAlg,
            '/hash', $HashAlg,
            '/filesystem', 'exFAT',
            '/quick', '/silent',
            '/force'
        )
        $maskedArgs = $formatArgs.Clone()
        $pwIndex = [array]::IndexOf($maskedArgs, '/password')
        if ($pwIndex -ge 0 -and $pwIndex + 1 -lt $maskedArgs.Length) { $maskedArgs[$pwIndex+1] = '********' }
        Write-Verbose "Executing: `"$VeraCryptFormatExe`" $($maskedArgs -join ' ')"

        $proc = Start-Process -FilePath $VeraCryptFormatExe -ArgumentList $formatArgs -NoNewWindow -Wait -PassThru -RedirectStandardError $errFile
        if ($proc.ExitCode -ne 0) {
            $errMsg = if (Test-Path $errFile) { Get-Content $errFile -Raw } else { "No error output captured." }
            throw "VeraCrypt Format failed (code $($proc.ExitCode)). Error: $errMsg"
        }
        Write-Verbose "VeraCrypt Format completed successfully."
    } else {
        Write-Host "Container creation skipped due to -WhatIf."
        exit
    }

    #--- Choose Drive Letter ----
    $used = (Get-PSDrive -PSProvider FileSystem).Name
    $driveLetter = (67..90 | ForEach-Object {[char]$_}) |
        Where-Object { $_ -notin $used } |
        Select-Object -First 1
    if (-not $driveLetter) { throw 'No free drive letters found (C-Z).' }
    Write-Verbose "Selected drive letter: $driveLetter"

    #--- Mount ----
    if ($PSCmdlet.ShouldProcess("Drive $driveLetter", "Mount VeraCrypt volume '$ContainerPath'")) {
        $mountArgs = @(
            '/volume', $ContainerPath,
            '/letter', $driveLetter,
            '/m', 'rm',
            '/password', $plainPassword,
            '/quit', '/silent'
        )
        $maskedArgs = $mountArgs.Clone()
        $pwIndex = [array]::IndexOf($maskedArgs, '/password')
        if ($pwIndex -ge 0 -and $pwIndex + 1 -lt $maskedArgs.Length) { $maskedArgs[$pwIndex+1] = '********' }
        Write-Verbose "Executing: `"$VeraCryptExe`" $($maskedArgs -join ' ')"

        $mountProc = Start-Process -FilePath $VeraCryptExe -ArgumentList $mountArgs -NoNewWindow -Wait -PassThru -RedirectStandardError $mountFile
        if ($mountProc.ExitCode -ne 0) {
            $errMsg = if (Test-Path $mountFile) { Get-Content $mountFile -Raw } else { "No error output captured." }
            throw "VeraCrypt mount failed (code $($mountProc.ExitCode)). Error: $errMsg"
        }

        $root = "$($driveLetter):\"
        Write-Verbose "Waiting for drive $root to become available..."
        $mountTimeoutSeconds = 30
        $mountCheckInterval = 0.5
        $elapsed = 0
        while (-not (Test-Path $root) -and $elapsed -lt $mountTimeoutSeconds) {
            Start-Sleep -Seconds $mountCheckInterval
            $elapsed += $mountCheckInterval
        }

        if (-not (Test-Path $root)) { throw "Drive $driveLetter did not appear within $mountTimeoutSeconds seconds." }
        $mounted = $true
        Write-Verbose "Drive $root mounted successfully."
    } else {
        Write-Host "Mounting skipped due to -WhatIf."
        exit
    }

    #--- Copy Data ----
    $destinationPath = "$($driveLetter):\"
    if ($PSCmdlet.ShouldProcess("'$InputPath' -> '$destinationPath'", "Copy input data into container")) {
        Write-Verbose "Starting data copy..."
        if (Test-Path $InputPath -PathType Container) {
            Copy-Item -Path "$InputPath\*" -Destination $destinationPath -Recurse -Force -ErrorAction Stop
            Write-Verbose "Copied directory contents recursively."
        } else {
            Copy-Item -Path $InputPath -Destination $destinationPath -Force -ErrorAction Stop
            Write-Verbose "Copied single file."
        }
        try {
            $driveInfo = Get-PSDrive $driveLetter -ErrorAction Stop
            $freeSpace = $driveInfo.Free
            Write-Verbose "Free space after copy: $freeSpace bytes."
            if ($freeSpace -lt 0) {
                Write-Warning 'Reported free space is negative. This might indicate an issue, but the copy might still be okay.'
            } elseif ($freeSpace -lt 1MB) {
                Write-Warning "Very low free space remaining ($freeSpace bytes). The container might be too small if data changes slightly."
            }
        } catch {
            Write-Warning "Could not verify free space on drive $driveLetter after copy. Error: $($_.Exception.Message)"
        }
        Write-Host "Data copy completed."
    } else {
        Write-Host "Data copy skipped due to -WhatIf."
    }
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
} finally {
    if (Test-Path variable:plainPassword) { Clear-Variable plainPassword -ErrorAction SilentlyContinue }
    if ($mounted) {
        if ($PSCmdlet.ShouldProcess("Drive $driveLetter", "Dismount VeraCrypt volume")) {
            Write-Verbose "Dismounting drive $driveLetter..."
            $dismountArgs = @('/dismount', $driveLetter, '/force', '/quit', '/silent')
            Start-Process -FilePath $VeraCryptExe -ArgumentList $dismountArgs -NoNewWindow -Wait -ErrorAction SilentlyContinue
            Write-Verbose "Dismount command issued."
        } else {
            Write-Host "Dismount skipped due to -WhatIf."
        }
    }
    foreach($f in @($errFile,$mountFile) | Where-Object { $_ }) {  
        if(Test-Path $f){  
            try { Set-Content -Path $f -Value ($null) -Encoding Byte -Force } catch{}  
            Remove-Item $f -Force -ErrorAction SilentlyContinue  
        }  
    }
}

if ($PSCmdlet.ShouldProcess("File '$ContainerPath'", "Create VeraCrypt container ($finalContMiB MiB)")) {
    Write-Host ("Script finished. VeraCrypt container created at '{0}' ({1} MiB)." -f $ContainerPath, $finalContMiB)
} else {
    Write-Host ("Script finished (simulation mode).")
}
