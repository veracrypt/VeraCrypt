<#
.SYNOPSIS
This PowerShell script is used to create a VeraCrypt container with minimal size to hold a copy of the given input file or directory.

.DESCRIPTION
This script takes as input a file path or directory path and a container path.
If the container path is not specified, it defaults to the same as the input path with a ".hc" extension.
The script calculates the minimal size needed to hold the input file or directory in a VeraCrypt container.
It then creates a VeraCrypt container with the specified path and the calculated size using exFAT filesystem.
Finally, the container is mounted, the input file or directory is copied to the container and the container is dismounted.

.PARAMETER inputPath
The file path or directory path to be encrypted in the VeraCrypt container.

.PARAMETER containerPath
The desired path for the VeraCrypt container. If not specified, it defaults to the same as the input path with a ".hc" extension.

.EXAMPLE
.\EncryptData.ps1 -inputPath "C:\MyFolder" -containerPath "D:\MyContainer.hc"
.\EncryptData.ps1 "C:\MyFolder" "D:\MyContainer.hc"
.\EncryptData.ps1 "C:\MyFolder"

.NOTES
Author: Mounir IDRASSI
Email: mounir.idrassi@idrix.fr
Date: 26 July 2024
License: This script is licensed under the Apache License 2.0
#>

# parameters
param(
    [Parameter(Mandatory=$true)]
    [string]$inputPath,
    [string]$containerPath
)
function ConvertTo-AbsolutePath {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    
    return Join-Path -Path (Get-Location) -ChildPath $Path
}

# Convert input path to fully qualified path
$inputPath = ConvertTo-AbsolutePath -Path $inputPath

# Check if input path exists
if (-not (Test-Path $inputPath)) {
    Write-Host "The specified input path does not exist. Please provide a valid input path."
    exit 1
}

$inputPath = (Resolve-Path -Path $inputPath).Path

# Set container path if not specified
if ([string]::IsNullOrWhiteSpace($containerPath)) {
    $containerPath = "${inputPath}.hc"
} else {
    $containerPath = ConvertTo-AbsolutePath -Path $containerPath
}

# Check if container path already exists
if (Test-Path $containerPath) {
    Write-Host "The specified container path already exists. Please provide a unique path for the new container."
    exit 1
}

# Full path to VeraCrypt executables
$veracryptPath = "C:\Program Files\VeraCrypt"  # replace with your actual path
$veraCryptExe = Join-Path $veracryptPath "VeraCrypt.exe"
$veraCryptFormatExe = Join-Path $veracryptPath "VeraCrypt Format.exe"

# Constants used to calculate the size of the exFAT filesystem
$InitialVBRSize = 32KB
$BackupVBRSize = 32KB
$InitialFATSize = 128KB
$ClusterSize = 32KB # TODO : make this configurable
$UpCaseTableSize = 128KB # Typical size

function Get-ExFATSizeRec {
    param(
        [string]$Path,
        [uint64] $TotalSize
    )

    # Constants
    $BaseMetadataSize = 32
    $DirectoryEntrySize = 32

    try {
        # Get the item (file or directory) at the provided path
        $item = Get-Item -Path $Path -ErrorAction Stop

        # Calculate metadata size
        $fileNameLength = $item.Name.Length
        $metadataSize = $BaseMetadataSize + ($fileNameLength * 2)

        # Calculate directory entries
        if ($fileNameLength -gt 15) {
            $numDirEntries = [math]::Ceiling($fileNameLength / 15) + 1
        } else {
            $numDirEntries = 2
        }
        $dirEntriesSize = $numDirEntries * $DirectoryEntrySize

        # Add metadata, file size, and directory entries size to $TotalSize
        $TotalSize += $metadataSize + $dirEntriesSize


        if ($item.PSIsContainer) {
            # It's a directory
            $childItems = Get-ChildItem -Path $Path -ErrorAction Stop

            foreach ($childItem in $childItems) {
                # Recursively call this function for each child item
                $TotalSize = Get-ExFATSizeRec -Path $childItem.FullName -TotalSize $TotalSize
            }
        } else {
            # It's a file

            # Calculate actual file size and round it up to the nearest multiple of $ClusterSize
            $fileSize = $item.Length
            $totalFileSize = [math]::Ceiling($fileSize / $ClusterSize) * $ClusterSize

            # Add metadata, file size, and directory entries size to $TotalSize
            $TotalSize += $totalFileSize
        }
    } catch {
        Write-Error "Error processing item at path ${Path}: $_"
    }

    return $TotalSize
}

function Get-ExFATSize {
    param(
        [string]$Path
    )

    try {
        # Initialize total size
        $totalSize = $InitialVBRSize + $BackupVBRSize + $InitialFATSize + $UpCaseTableSize

        # Call the recursive function
        $totalSize = Get-ExFATSizeRec -Path $Path -TotalSize $totalSize

        # Add the root directory to $totalSize
        $totalSize += $ClusterSize

        # Calculate the size of the Bitmap Allocation Table
        $numClusters = [math]::Ceiling($totalSize / $ClusterSize)
        $bitmapSize = [math]::Ceiling($numClusters / 8)
        $totalSize += $bitmapSize

        # Adjust the size of the FAT
        $fatSize = $numClusters * 4
        $totalSize += $fatSize - $InitialFATSize
		
        # Add safety factor to account for potential filesystem overhead
        # For smaller datasets (<100MB), we add 1% or 64KB (whichever is larger)
        # For larger datasets (>=100MB), we add 0.1% or 1MB (whichever is larger)
        # This scaled approach ensures adequate extra space without excessive overhead
        $safetyFactor = if ($totalSize -lt 100MB) {
            [math]::Max(64KB, $totalSize * 0.01)
        } else {
            [math]::Max(1MB, $totalSize * 0.001)
        }
        $totalSize += $safetyFactor

        # Return the minimum disk size needed to store the exFAT filesystem
        return $totalSize

    } catch {
        Write-Error "Error calculating exFAT size for path ${Path}: $_"
        return 0
    }
}

# Calculate size of the container
$containerSize = Get-ExFATSize -Path $inputPath

# Convert to MB and round up to the nearest MB
$containerSize = [math]::Ceiling($containerSize / 1MB)

# Add extra space for VeraCrypt headers, reserved areas, and potential alignment requirements
# We use a sliding scale to balance efficiency for small datasets and adequacy for large ones:
# - For very small datasets (<10MB), add 1MB
# - For small to medium datasets (10-100MB), add 2MB
# - For larger datasets (>100MB), add 1% of the total size
# This approach ensures sufficient space across a wide range of dataset sizes
if ($containerSize -lt 10) {
    $containerSize += 1  # Add 1 MB for very small datasets
} elseif ($containerSize -lt 100) {
    $containerSize += 2  # Add 2 MB for small datasets
} else {
    $containerSize += [math]::Ceiling($containerSize * 0.01)  # Add 1% for larger datasets
}

# Ensure a minimum container size of 2 MB
$containerSize = [math]::Max(2, $containerSize)

# Specify encryption algorithm, and hash algorithm
$encryption = "AES"
$hash = "sha512"

# Create a SecureString password
$password = Read-Host -AsSecureString -Prompt "Enter your password"

# Create a PSCredential object
$cred = New-Object System.Management.Automation.PSCredential ("username", $password)

Write-Host "Creating VeraCrypt container `"$containerPath`" ..."

# Create file container using VeraCrypt Format
# TODO: Add a switch to VeraCrypt Format to allow specifying the cluster size to use for the container
$veraCryptFormatArgs = "/create `"$containerPath`" /size `"${containerSize}M`" /password $($cred.GetNetworkCredential().Password) /encryption $encryption /hash $hash /filesystem `"exFAT`" /quick /silent"
Start-Process $veraCryptFormatExe -ArgumentList $veraCryptFormatArgs -NoNewWindow -Wait

# Check that the container was successfully created
if (-not (Test-Path $containerPath)) {
    Write-Host "An error occurred while creating the VeraCrypt container."
    exit 1
}

# Get a list of currently used drive letters
$driveLetter = Get-Volume | Where-Object { $_.DriveLetter -ne $null } | Select-Object -ExpandProperty DriveLetter

# Find the first available drive letter
$unusedDriveLetter = (70..90 | ForEach-Object { [char]$_ } | Where-Object { $_ -notin $driveLetter })[0]

# If no available drive letter was found, print an error message and exit the script
if ($null -eq $unusedDriveLetter) {
    # delete the file container that was created
    Remove-Item -Path $containerPath -Force
    Write-Error "No available drive letters found. Please free up a drive letter and try again."
    exit 1
}

Write-Host "Mounting the newly created VeraCrypt container..."

# Mount the container to the chosen drive letter as removable media
Start-Process $veraCryptExe -ArgumentList "/volume `"$containerPath`" /letter $unusedDriveLetter /m rm /password $($cred.GetNetworkCredential().Password) /quit" -NoNewWindow -Wait

# Check if the volume has been mounted successfully
$mountedDriveRoot = "${unusedDriveLetter}:\"
if (-not (Test-Path -Path $mountedDriveRoot)) {
    # Volume mount failed
    Write-Error "Failed to mount the volume. Please make sure VeraCrypt.exe is working correctly."
    # delete the file container that was created
    Remove-Item -Path $containerPath -Force
    exit 1
}

Write-Host "Copying data to the mounted VeraCrypt container..."

# Copy the file or directory to the mounted drive
if (Test-Path -Path $inputPath -PathType Container) {
    # For directories
    Copy-Item -Path $inputPath -Destination "$($unusedDriveLetter):\" -Recurse
} else {
    # For files
    Copy-Item -Path $inputPath -Destination "$($unusedDriveLetter):\"
}

Write-Host "Copying completed. Dismounting the VeraCrypt container..."

# give some time for the file system to flush the data to the disk
Start-Sleep -Seconds 5

# Dismount the volume
Start-Process $veraCryptExe -ArgumentList "/dismount $unusedDriveLetter /quit" -NoNewWindow -Wait

Write-Host "VeraCrypt container created successfully."
