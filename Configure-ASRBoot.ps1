# Configure-ASRBoot.ps1
# Script to configure boot to ASR Windows for Azure UEFI VMs
# Version 11.0 - Simplified back to core working functionality

param(
    [switch]$NoReboot
)

# Diagnostic: Prove script is running
"Script started at $(Get-Date)" | Out-File C:\temp\configure_asrboot_ran.txt -Force
"Running as: $env:USERNAME" | Out-File C:\temp\configure_asrboot_ran.txt -Append
"Computer: $env:COMPUTERNAME" | Out-File C:\temp\configure_asrboot_ran.txt -Append

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ASR BOOT CONFIGURATION SCRIPT (v11.0)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check if running as admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

# Create temp directory
if (!(Test-Path "C:\temp")) {
    New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null
}

# Set up logging
$logFile = "C:\temp\ASRBootConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Write-Log {
    param($Message, $Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logFile -Append
    Write-Host $Message -ForegroundColor $Color
}

Write-Log "Starting ASR Boot Configuration Script v11.0" "Cyan"

# Azure Gen2 VMs are always UEFI
$bootType = "UEFI"
Write-Log "Boot Type: UEFI (Azure Gen2)" "Green"

# Bring all disks online
Write-Log "`nBringing all disks online..." "Yellow"
$allDisks = Get-Disk
foreach ($disk in $allDisks) {
    if ($disk.OperationalStatus -eq 'Offline') {
        Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction SilentlyContinue
    }
    if ($disk.IsReadOnly) {
        Set-Disk -Number $disk.Number -IsReadOnly $false -ErrorAction SilentlyContinue
    }
}

# Find the ASR disk (non-boot disk with Windows)
Write-Log "`nFinding ASR disk..." "Yellow"
$asrDisk = $null
$bootDisk = Get-Disk | Where-Object { $_.IsBoot }

foreach ($disk in $allDisks) {
    if (-not $disk.IsBoot) {
        # Check if this disk has Windows
        $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
        foreach ($partition in $partitions) {
            if ($partition.DriveLetter -and $partition.Size -gt 10GB) {
                if (Test-Path "$($partition.DriveLetter):\Windows\System32\ntoskrnl.exe") {
                    $asrDisk = $disk
                    $asrDrive = $partition.DriveLetter
                    Write-Log "Found ASR Windows on Disk $($disk.Number), Drive $asrDrive" "Green"
                    break
                }
            }
        }
    }
    if ($asrDisk) { break }
}

# If no drive letter, assign one
if (!$asrDisk) {
    Write-Log "No ASR Windows found with drive letter, checking unlettered partitions..." "Yellow"
    
    foreach ($disk in $allDisks) {
        if (-not $disk.IsBoot) {
            $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
            foreach ($partition in $partitions) {
                if (!$partition.DriveLetter -and $partition.Size -gt 100GB) {
                    # Assign drive letter
                    $availableLetters = 70..90 | ForEach-Object { [char]$_ } | Where-Object { 
                        $_ -notin (Get-Volume | Where-Object {$_.DriveLetter} | Select-Object -ExpandProperty DriveLetter)
                    }
                    
                    if ($availableLetters.Count -gt 0) {
                        $newLetter = $availableLetters[0]
                        Write-Log "Assigning drive letter $newLetter to partition..." "Yellow"
                        
                        $diskpartScript = @"
select disk $($disk.Number)
select partition $($partition.PartitionNumber)
assign letter=$newLetter
"@
                        $diskpartScript | Out-File "C:\temp\assign.txt" -Encoding ASCII -Force
                        $null = & diskpart /s "C:\temp\assign.txt" 2>&1
                        Remove-Item "C:\temp\assign.txt" -Force
                        
                        Start-Sleep -Seconds 2
                        
                        if (Test-Path "${newLetter}:\Windows\System32\ntoskrnl.exe") {
                            $asrDisk = $disk
                            $asrDrive = $newLetter
                            Write-Log "Found ASR Windows on Disk $($disk.Number), Drive $asrDrive" "Green"
                            break
                        }
                    }
                }
            }
        }
        if ($asrDisk) { break }
    }
}

if (!$asrDisk) {
    Write-Log "ERROR: Could not find ASR Windows installation!" "Red"
    exit 1
}

Write-Log "`nASR Windows found on drive $asrDrive" "Cyan"

# Find and mount EFI partition from ASR disk
Write-Log "`nLooking for EFI partition on ASR disk..." "Yellow"
$efiPartition = Get-Partition -DiskNumber $asrDisk.Number | Where-Object { 
    $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' 
}

if (!$efiPartition) {
    Write-Log "ERROR: No EFI partition found on ASR disk!" "Red"
    exit 1
}

# Mount EFI partition if not already mounted
$efiDrive = $efiPartition.DriveLetter
if (!$efiDrive) {
    $efiDrive = "S"
    Write-Log "Mounting EFI partition as ${efiDrive}:" "Yellow"
    
    $diskpartScript = @"
select disk $($efiPartition.DiskNumber)
select partition $($efiPartition.PartitionNumber)
assign letter=$efiDrive
"@
    $diskpartScript | Out-File "C:\temp\mount_efi.txt" -Encoding ASCII -Force
    $null = & diskpart /s "C:\temp\mount_efi.txt" 2>&1
    Remove-Item "C:\temp\mount_efi.txt" -Force
    Start-Sleep -Seconds 2
}

Write-Log "EFI partition mounted as ${efiDrive}:" "Green"

# Backup current BCD
Write-Log "`nBacking up current BCD..." "Yellow"
$backupFile = "C:\temp\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$null = & cmd /c "bcdedit /export `"$backupFile`"" 2>&1
Write-Log "BCD backed up to: $backupFile" "Green"

# Create UEFI boot files on ASR disk's EFI partition
Write-Log "`nCreating UEFI boot files..." "Yellow"
Write-Log "Running: bcdboot ${asrDrive}:\Windows /s ${efiDrive}: /f UEFI" "Gray"

$result = & cmd /c "bcdboot ${asrDrive}:\Windows /s ${efiDrive}: /f UEFI" 2>&1 | Out-String
Write-Log $result

if ($result -match "successfully created") {
    Write-Log "Boot files created successfully!" "Green"
} else {
    Write-Log "WARNING: Boot file creation may have failed" "Yellow"
}

# Update the Windows Boot Manager to use ASR Windows
Write-Log "`nUpdating Windows Boot Manager..." "Yellow"

# Make sure the boot manager points to the correct EFI partition
$null = & cmd /c "bcdedit /set {bootmgr} device partition=${efiDrive}:" 2>&1
$null = & cmd /c "bcdedit /set {bootmgr} path \EFI\Microsoft\Boot\bootmgfw.efi" 2>&1

# Set default boot entry
$null = & cmd /c "bcdedit /set {default} device partition=${asrDrive}:" 2>&1
$null = & cmd /c "bcdedit /set {default} osdevice partition=${asrDrive}:" 2>&1
$null = & cmd /c "bcdedit /set {default} path \Windows\system32\boot\winload.efi" 2>&1
$null = & cmd /c "bcdedit /set {default} systemroot \Windows" 2>&1
$null = & cmd /c "bcdedit /set {default} description `"ASR Windows`"" 2>&1

# Set timeout to 0
$null = & cmd /c "bcdedit /timeout 0" 2>&1

# If there's a BCD on the EFI partition, update it too
if (Test-Path "${efiDrive}:\EFI\Microsoft\Boot\BCD") {
    Write-Log "Updating EFI BCD store..." "Yellow"
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /set {default} device partition=${asrDrive}:" 2>&1
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /set {default} osdevice partition=${asrDrive}:" 2>&1
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /set {default} path \Windows\system32\boot\winload.efi" 2>&1
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /set {default} systemroot \Windows" 2>&1
}

# Show final configuration
Write-Log "`n========================================" "Cyan"
Write-Log "CONFIGURATION COMPLETE" "Cyan"
Write-Log "========================================" "Cyan"
Write-Log "ASR Windows: ${asrDrive}:\Windows" "Green"
Write-Log "EFI Partition: ${efiDrive}:" "Green"
Write-Log "Boot Type: UEFI" "Green"

# Save configuration
$config = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ASRDrive = $asrDrive
    ASRDiskNumber = $asrDisk.Number
    EFIDrive = $efiDrive
    Version = "v11.0"
    BootType = "UEFI"
    Success = $true
}
$config | ConvertTo-Json | Out-File "C:\temp\ASRBootConfig.json" -Force

Write-Log "`nConfiguration saved to: C:\temp\ASRBootConfig.json" "Gray"
Write-Log "Log saved to: $logFile" "Gray"

# Handle reboot
if (-not $NoReboot) {
    $isAutomated = ($env:USERNAME -eq "SYSTEM") -or 
                   ($env:COMPUTERNAME -match "bootproxy") -or 
                   (Get-Process -Name "RunCommandExtension" -ErrorAction SilentlyContinue)
    
    if ($isAutomated) {
        Write-Log "`nAutomated execution - rebooting in 10 seconds..." "Yellow"
        Start-Sleep -Seconds 10
        & shutdown /r /t 0 /f
    } else {
        Write-Log "`nManual execution - please reboot when ready:" "Yellow"
        Write-Log "  Restart-Computer -Force" "Cyan"
    }
} else {
    Write-Log "`nReboot skipped (NoReboot parameter specified)" "Yellow"
}