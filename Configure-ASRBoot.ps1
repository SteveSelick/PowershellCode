# Configure-ASRBoot.ps1
# Script to configure boot to ASR Windows for Azure UEFI VMs
# Version 13.0 - More aggressive BCD replacement to force ASR boot

param(
    [switch]$NoReboot
)

# Diagnostic: Prove script is running
"Script started at $(Get-Date)" | Out-File C:\temp\configure_asrboot_ran.txt -Force
"Running as: $env:USERNAME" | Out-File C:\temp\configure_asrboot_ran.txt -Append
"Computer: $env:COMPUTERNAME" | Out-File C:\temp\configure_asrboot_ran.txt -Append

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ASR BOOT CONFIGURATION SCRIPT (v13.0)" -ForegroundColor Cyan
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

Write-Log "Starting ASR Boot Configuration Script v13.0" "Cyan"

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
Write-Log "Boot disk is Disk $($bootDisk.Number)" "Gray"

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

# Find and mount EFI partition from BOOT DISK
Write-Log "`n========================================" "Yellow"
Write-Log "Looking for EFI partition on BOOT disk (Disk $($bootDisk.Number))..." "Yellow"
Write-Log "========================================" "Yellow"

$efiPartition = Get-Partition -DiskNumber $bootDisk.Number | Where-Object { 
    $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' 
}

if (!$efiPartition) {
    Write-Log "ERROR: No EFI partition found on boot disk!" "Red"
    exit 1
}

Write-Log "Found EFI partition on boot disk: Partition $($efiPartition.PartitionNumber)" "Green"

# Mount EFI partition if not already mounted
$efiDrive = $efiPartition.DriveLetter
if (!$efiDrive) {
    $efiDrive = "S"
    Write-Log "Mounting BOOT DISK's EFI partition as ${efiDrive}:" "Yellow"
    
    $diskpartScript = @"
select disk $($bootDisk.Number)
select partition $($efiPartition.PartitionNumber)
assign letter=$efiDrive
"@
    $diskpartScript | Out-File "C:\temp\mount_efi.txt" -Encoding ASCII -Force
    $null = & diskpart /s "C:\temp\mount_efi.txt" 2>&1
    Remove-Item "C:\temp\mount_efi.txt" -Force
    Start-Sleep -Seconds 2
}

Write-Log "Boot disk's EFI partition mounted as ${efiDrive}:" "Green"

# Backup current BCD
Write-Log "`nBacking up current BCD..." "Yellow"
$backupFile = "C:\temp\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$null = & cmd /c "bcdedit /export `"$backupFile`"" 2>&1
Write-Log "BCD backed up to: $backupFile" "Green"

# AGGRESSIVE APPROACH: Delete existing boot files and create fresh ones
Write-Log "`n========================================" "Yellow"
Write-Log "AGGRESSIVE BCD REPLACEMENT" "Yellow"
Write-Log "========================================" "Yellow"

# Delete the old BCD store completely
$bcdPath = "${efiDrive}:\EFI\Microsoft\Boot\BCD"
if (Test-Path $bcdPath) {
    Write-Log "Deleting existing BCD store at $bcdPath..." "Yellow"
    Remove-Item $bcdPath -Force -ErrorAction SilentlyContinue
    Remove-Item "${efiDrive}:\EFI\Microsoft\Boot\BCD.LOG*" -Force -ErrorAction SilentlyContinue
}

# Create fresh boot files from ASR Windows
Write-Log "Creating fresh UEFI boot files on ${efiDrive}: from ${asrDrive}:\Windows..." "Yellow"
$result = & cmd /c "bcdboot ${asrDrive}:\Windows /s ${efiDrive}: /f UEFI" 2>&1 | Out-String
Write-Log $result

if ($result -match "successfully created") {
    Write-Log "Boot files created successfully!" "Green"
}

# Force BCD configuration to ONLY boot from ASR Windows
Write-Log "`nForcing BCD configuration to ASR Windows ONLY..." "Yellow"
$bcdStore = "${efiDrive}:\EFI\Microsoft\Boot\BCD"

if (Test-Path $bcdStore) {
    # Delete ALL existing OS loader entries except {default}
    Write-Log "Cleaning up existing boot entries..." "Yellow"
    $entries = & bcdedit /store $bcdStore /enum osloader 2>&1 | Out-String
    $guids = [regex]::Matches($entries, '{[\w-]+}') | ForEach-Object { $_.Value } | Where-Object { $_ -ne '{default}' -and $_ -ne '{bootmgr}' }
    
    foreach ($guid in $guids) {
        Write-Log "Deleting boot entry: $guid" "Gray"
        $null = & bcdedit /store $bcdStore /delete $guid /f 2>&1
    }
    
    # Set all the properties for {default}
    $null = & bcdedit /store $bcdStore /set {default} device partition=${asrDrive}: 2>&1
    $null = & bcdedit /store $bcdStore /set {default} osdevice partition=${asrDrive}: 2>&1
    $null = & bcdedit /store $bcdStore /set {default} path \Windows\system32\boot\winload.efi 2>&1
    $null = & bcdedit /store $bcdStore /set {default} systemroot \Windows 2>&1
    $null = & bcdedit /store $bcdStore /set {default} description "ASR Windows" 2>&1
    
    # Set boot manager settings
    $null = & bcdedit /store $bcdStore /set {bootmgr} default {default} 2>&1
    $null = & bcdedit /store $bcdStore /timeout 0 2>&1
    $null = & bcdedit /store $bcdStore /set {bootmgr} displaybootmenu No 2>&1
    
    Write-Log "BCD store configuration completed" "Green"
}

# Show final configuration
Write-Log "`n========================================" "Cyan"
Write-Log "CONFIGURATION COMPLETE" "Cyan"
Write-Log "========================================" "Cyan"
Write-Log "ASR Windows: ${asrDrive}:\Windows (Disk $($asrDisk.Number))" "Green"
Write-Log "Boot Disk: Disk $($bootDisk.Number)" "Green"
Write-Log "EFI Partition: ${efiDrive}: (on Boot Disk)" "Green"

# Save configuration
$config = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ASRDrive = $asrDrive
    ASRDiskNumber = $asrDisk.Number
    BootDiskNumber = $bootDisk.Number
    EFIDrive = $efiDrive
    Version = "v13.0"
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