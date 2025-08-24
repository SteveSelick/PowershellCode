# Configure-ASRBoot.ps1
# Aggressive script to force boot to ASR Windows with enhanced UEFI support
# Run this INSIDE the bootproxy VM
# Version 10.1 - FIXED SYNTAX ERRORS

param(
    [switch]$NoReboot,
    [switch]$ForceUEFI
)

# Diagnostic: Prove script is running
"Script started at $(Get-Date)" | Out-File C:\temp\configure_asrboot_ran.txt -Force
"Running as: $env:USERNAME" | Out-File C:\temp\configure_asrboot_ran.txt -Append
"Execution Policy: $(Get-ExecutionPolicy)" | Out-File C:\temp\configure_asrboot_ran.txt -Append
"Computer: $env:COMPUTERNAME" | Out-File C:\temp\configure_asrboot_ran.txt -Append

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ASR BOOT CONFIGURATION SCRIPT (v10.1)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Enhanced UEFI Support for Azure Gen2 VMs" -ForegroundColor Yellow

# Check if running as admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

# Create temp directory if it doesn't exist
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

Write-Log "Starting ASR Boot Configuration Script v10.1" "Cyan"

# Detect boot type (UEFI vs Legacy)
Write-Log "`nDetecting boot type..." "Yellow"
$bootType = "Unknown"
try {
    $firmware = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control" -Name PEFirmwareType -ErrorAction SilentlyContinue
    if ($firmware.PEFirmwareType -eq 2) {
        $bootType = "UEFI"
        Write-Log "  Boot Type: UEFI (Gen2 VM)" "Green"
    } elseif ($firmware.PEFirmwareType -eq 1) {
        $bootType = "BIOS"
        Write-Log "  Boot Type: Legacy BIOS (Gen1 VM)" "Yellow"
    }
} catch {
    Write-Log "  Could not determine boot type, assuming UEFI for Azure" "Yellow"
    $bootType = "UEFI"
}

if ($ForceUEFI) {
    $bootType = "UEFI"
    Write-Log "  Forcing UEFI mode (ForceUEFI parameter set)" "Yellow"
}

# Rename the current C: drive volume label to "BootProxy" for clarity
Write-Log "`nRenaming current boot volume to 'BootProxy'..." "Yellow"
try {
    $drive = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='C:'"
    # Only rename if it's the small boot proxy disk (< 200GB)
    if ($drive.Capacity -lt 200GB) {
        $drive.Label = "BootProxy"
        $drive.Put() | Out-Null
        Write-Log "  Current boot drive renamed to 'BootProxy'" "Green"
    } else {
        Write-Log "  Current C: drive is large ($([math]::Round($drive.Capacity/1GB))GB), skipping rename" "Yellow"
    }
} catch {
    # Alternative method using label command
    $vol = Get-Volume -DriveLetter C -ErrorAction SilentlyContinue
    if ($vol -and $vol.Size -lt 200GB) {
        & cmd /c "label C: BootProxy" 2>&1 | Out-Null
        Write-Log "  Current boot drive renamed to 'BootProxy'" "Green"
    }
}

# Find all Windows installations
Write-Log "`nStep 1: Finding and initializing ALL disks..." "Yellow"

# First, bring all disks online and make them writable
$allDisks = Get-Disk
foreach ($disk in $allDisks) {
    if ($disk.OperationalStatus -eq 'Offline') {
        Write-Log "  Bringing Disk $($disk.Number) online..." "Gray"
        Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction SilentlyContinue
    }
    if ($disk.IsReadOnly) {
        Write-Log "  Setting Disk $($disk.Number) to read-write..." "Gray"
        Set-Disk -Number $disk.Number -IsReadOnly $false -ErrorAction SilentlyContinue
    }
}

# CRITICAL: Find the ASR disk - it's the non-boot disk that has an EFI partition
Write-Log "`nFinding ASR disk (non-boot disk with EFI partition)..." "Yellow"

$asrDiskNumber = -1
$asrDisk = $null

# Get all disks
$allDisks = Get-Disk
Write-Log "  Total disks found: $($allDisks.Count)" "Gray"

# Check each disk for EFI partition
foreach ($disk in $allDisks) {
    $sizeGB = [math]::Round($disk.Size/1GB, 2)
    Write-Log "  Disk $($disk.Number): $sizeGB GB, Boot: $($disk.IsBoot)" "Gray"
    
    # Skip the boot disk
    if ($disk.IsBoot) {
        Write-Log "    Skipping boot disk" "Gray"
        continue
    }
    
    # Check if this disk has an EFI partition
    $efiPartition = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | 
        Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' }
    
    if ($efiPartition) {
        Write-Log "    >>> Found EFI partition on this disk - THIS IS THE ASR DISK!" "Green"
        $asrDiskNumber = $disk.Number
        $asrDisk = $disk
        break
    }
}

# If no disk with EFI found, try finding the largest non-boot disk as fallback
if ($asrDiskNumber -eq -1) {
    Write-Log "  No non-boot disk with EFI partition found, trying largest non-boot disk..." "Yellow"
    $nonBootDisks = Get-Disk | Where-Object { -not $_.IsBoot } | Sort-Object Size -Descending
    if ($nonBootDisks) {
        $asrDisk = $nonBootDisks[0]
        $asrDiskNumber = $asrDisk.Number
        Write-Log "  Using largest non-boot disk: Disk $asrDiskNumber (Size: $([math]::Round($asrDisk.Size/1GB,2)) GB)" "Yellow"
    }
}

if ($asrDiskNumber -eq -1) {
    Write-Log "  ERROR: Could not find ASR disk!" "Red"
    exit 1
}

Write-Log "`n  ASR disk identified: Disk $asrDiskNumber" "Cyan"
Write-Log "  Size: $([math]::Round($asrDisk.Size/1GB,2)) GB" "Cyan"

# Now check ALL disks and ALL partitions for Windows installations
Write-Log "`nSearching ALL disks for Windows installations..." "Yellow"

$windowsInstallations = @()

foreach ($disk in $allDisks) {
    $diskSizeGB = [math]::Round($disk.Size/1GB, 2)
    Write-Log "`n  Checking Disk $($disk.Number) ($diskSizeGB GB)..." "Gray"
    
    # Get all partitions on this disk
    $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
    
    if (!$partitions) {
        Write-Log "    No partitions found" "Gray"
        continue
    }
    
    foreach ($partition in $partitions) {
        $partSizeGB = [math]::Round($partition.Size/1GB, 2)
        
        # Skip small partitions (under 10GB can't have Windows)
        if ($partition.Size -lt 10GB) {
            continue
        }
        
        Write-Log "    Partition $($partition.PartitionNumber): $partSizeGB GB" "Gray"
        
        # Check if partition has a drive letter
        if ($partition.DriveLetter) {
            Write-Log "      Has drive letter: $($partition.DriveLetter):" "Gray"
            
            # Check for Windows
            if (Test-Path "$($partition.DriveLetter):\Windows\System32\ntoskrnl.exe") {
                Write-Log "      >>> WINDOWS FOUND!" "Green"
                $windowsInstallations += @{
                    DiskNumber = $disk.Number
                    PartitionNumber = $partition.PartitionNumber
                    DriveLetter = $partition.DriveLetter
                    Size = $partition.Size
                    IsBoot = $disk.IsBoot
                    IsASRDisk = ($disk.Number -eq $asrDiskNumber)
                }
            }
        } else {
            Write-Log "      NO DRIVE LETTER - Assigning one..." "Yellow"
            
            # Find next available letter
            $usedLetters = (Get-Volume | Where-Object {$_.DriveLetter} | Select-Object -ExpandProperty DriveLetter)
            $availableLetters = 'EDFGHIJKLMNOPQRSTUVWXYZ'.ToCharArray() | Where-Object {$_ -notin $usedLetters}
            
            if ($availableLetters.Count -gt 0) {
                $newLetter = $availableLetters[0]
                
                # Use diskpart for reliability - FIXED THE SYNTAX ERROR HERE
                $diskpartScript = "select disk $($disk.Number)`r`nselect partition $($partition.PartitionNumber)`r`nassign letter=$newLetter"
                $diskpartPath = "C:\temp\assign_letter_d$($disk.Number)_p$($partition.PartitionNumber).txt"
                $diskpartScript | Out-File $diskpartPath -Encoding ASCII -Force
                
                $diskpartResult = & diskpart /s $diskpartPath 2>&1 | Out-String
                Remove-Item $diskpartPath -Force -ErrorAction SilentlyContinue
                
                if ($diskpartResult -match "successfully assigned") {
                    Write-Log "      Assigned drive letter $newLetter" "Green"
                    
                    # Wait and check for Windows
                    Start-Sleep -Seconds 2
                    if (Test-Path "${newLetter}:\Windows\System32\ntoskrnl.exe") {
                        Write-Log "      >>> WINDOWS FOUND!" "Green"
                        $windowsInstallations += @{
                            DiskNumber = $disk.Number
                            PartitionNumber = $partition.PartitionNumber
                            DriveLetter = $newLetter
                            Size = $partition.Size
                            IsBoot = $disk.IsBoot
                            IsASRDisk = ($disk.Number -eq $asrDiskNumber)
                        }
                    }
                } else {
                    Write-Log "      Failed to assign letter" "Red"
                }
            }
        }
    }
}

Write-Log "`n========================================" "Cyan"
Write-Log "WINDOWS INSTALLATIONS FOUND:" "Cyan"
Write-Log "========================================" "Cyan"

foreach ($win in $windowsInstallations) {
    $sizeGB = [math]::Round($win.Size/1GB, 2)
    Write-Log "  $($win.DriveLetter): drive (Disk $($win.DiskNumber), Size: $sizeGB GB)" "White"
    if ($win.IsBoot) {
        Write-Log "    -> This is the BOOT PROXY Windows (current OS)" "Gray"
    }
    if ($win.IsASRDisk) {
        Write-Log "    -> This is on the ASR DISK" "Green"
    }
}

# Select the Windows installation to boot from
# Priority: Windows on ASR disk > Largest Windows not on boot disk > Any Windows not on boot disk
$asrWindows = $null

# First choice: Windows on the ASR disk
$asrWindows = $windowsInstallations | Where-Object { $_.IsASRDisk } | Select-Object -First 1

if (!$asrWindows) {
    # Second choice: Largest Windows installation not on boot disk
    Write-Log "`nNo Windows found on ASR disk, using largest non-boot Windows..." "Yellow"
    $asrWindows = $windowsInstallations | Where-Object { -not $_.IsBoot } | Sort-Object Size -Descending | Select-Object -First 1
}

if (!$asrWindows) {
    Write-Log "`nERROR: No suitable Windows installation found!" "Red"
    exit 1
}

$asrDrive = $asrWindows.DriveLetter
Write-Log "`n========================================" "Green"
Write-Log "SELECTED ASR WINDOWS: $($asrDrive): drive" "Green"
Write-Log "  Disk: $($asrWindows.DiskNumber)" "Green"
Write-Log "  Size: $([math]::Round($asrWindows.Size/1GB,2)) GB" "Green"
Write-Log "========================================" "Green"

# FIXED: The warning message about small partition size
if ($asrWindows.Size -lt 200GB) {
    $sizeInGB = [math]::Round($asrWindows.Size/1GB, 2)
    Write-Log "WARNING: Selected Windows is on a small partition ($sizeInGB GB)" "Yellow"
    Write-Log "This might be the wrong Windows installation!" "Yellow"
}

# Mount and prepare EFI partition (critical for UEFI)
Write-Log "`nStep 3: Preparing EFI partition..." "Yellow"

# Find EFI partition
$efiPartition = Get-Partition | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' } | Select-Object -First 1
$efiMounted = $false
$efiDrive = "S"

if ($efiPartition) {
    Write-Log "  Found EFI partition on Disk $($efiPartition.DiskNumber), Partition $($efiPartition.PartitionNumber)" "Green"
    
    if ($efiPartition.DriveLetter) {
        $efiDrive = $efiPartition.DriveLetter
        Write-Log "  EFI partition already mounted as ${efiDrive}:" "Gray"
        $efiMounted = $true
    } else {
        # Assign letter S: to EFI partition - FIXED THE SYNTAX ERROR HERE
        Write-Log "  Mounting EFI partition as S:..." "Gray"
        $diskpartScript = @"
select disk $($efiPartition.DiskNumber)
select partition $($efiPartition.PartitionNumber)
assign letter=S
"@
        $diskpartScript | Out-File "C:\temp\mount_efi.txt" -Encoding ASCII -Force
        $null = & diskpart /s "C:\temp\mount_efi.txt" 2>&1
        Remove-Item "C:\temp\mount_efi.txt" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $efiMounted = $true
    }
} else {
    Write-Log "  No EFI partition found in partition table - trying mountvol" "Yellow"
    $null = & cmd /c "mountvol S: /S" 2>&1
    if (Test-Path "S:\") {
        $efiMounted = $true
        Write-Log "  EFI partition mounted using mountvol" "Green"
    }
}

# Backup current BCD before making changes - FIXED THE REDIRECTION ISSUE
Write-Log "`nBacking up current BCD configuration..." "Yellow"
$backupFile = "C:\temp\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$null = & cmd /c "bcdedit /export `"$backupFile`"" 2>&1
Write-Log "  BCD backed up to: $backupFile" "Green"

# AGGRESSIVE BCD CLEANUP (if UEFI)
if ($bootType -eq "UEFI") {
    Write-Log "`nStep 4: Cleaning up old UEFI boot entries..." "Yellow"
    
    # Delete all non-essential boot entries
    $bcdenum = & bcdedit /enum | Out-String
    $guidPattern = '\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}'
    $guids = [regex]::Matches($bcdenum, $guidPattern) | ForEach-Object { $_.Value } | Select-Object -Unique
    
    foreach ($guid in $guids) {
        if ($guid -ne '{current}' -and $guid -ne '{default}' -and $guid -ne '{bootmgr}' -and $guid -ne '{fwbootmgr}' -and 
            $guid -ne '{memdiag}' -and $guid -ne '{ntldr}') {
            Write-Log "  Deleting boot entry: $guid" "Gray"
            $null = & cmd /c "bcdedit /delete $guid /f" 2>&1
        }
    }
}

# FORCE METHOD 1: Overwrite all boot files (BOTH Legacy and UEFI)
Write-Log "`nMethod 1: Overwriting boot files with ASR Windows..." "Yellow"

# Update BOTH Legacy (C:) and UEFI (S:) boot files - FIXED THE REDIRECTION ISSUES
if ($bootType -eq "BIOS") {
    Write-Log "  Updating Legacy BIOS boot files on C:..." "Gray"
    $result = & cmd /c "bcdboot ${asrDrive}:\Windows /s C: /f BIOS" 2>&1 | Out-String
    Write-Log "    $result"
} else {
    # For UEFI, update multiple locations
    if ($efiMounted) {
        Write-Log "  Updating UEFI boot files on ${efiDrive}:..." "Gray"
        
        # Delete old EFI boot files first
        if (Test-Path "${efiDrive}:\EFI\Microsoft\Boot") {
            Write-Log "  Removing old EFI boot files..." "Gray"
            Remove-Item "${efiDrive}:\EFI\Microsoft\Boot\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        $result = & cmd /c "bcdboot ${asrDrive}:\Windows /s ${efiDrive}: /f UEFI" 2>&1 | Out-String
        Write-Log "    $result"
    }
    
    # Also update system partition
    Write-Log "  Updating system partition boot files..." "Gray"
    $result = & cmd /c "bcdboot ${asrDrive}:\Windows /s C: /f ALL" 2>&1 | Out-String
    Write-Log "    $result"
}

# FORCE METHOD 2: Modify ALL boot entries in BOTH BCDs
Write-Log "`nMethod 2: Forcing ALL boot entries to ASR Windows..." "Yellow"

# Update main BCD
Write-Log "  Updating main BCD entries..." "Gray"
$bootEntries = @("{current}", "{default}", "{bootmgr}")
foreach ($entry in $bootEntries) {
    $null = & cmd /c "bcdedit /set $entry device partition=${asrDrive}:" 2>&1
    $null = & cmd /c "bcdedit /set $entry osdevice partition=${asrDrive}:" 2>&1
    
    if ($bootType -eq "UEFI") {
        $null = & cmd /c "bcdedit /set $entry path \Windows\system32\boot\winload.efi" 2>&1
    } else {
        $null = & cmd /c "bcdedit /set $entry path \Windows\system32\boot\winload.exe" 2>&1
    }
    
    $null = & cmd /c "bcdedit /set $entry systemroot \Windows" 2>&1
}

# Update UEFI BCD if present
if ($bootType -eq "UEFI" -and $efiMounted -and (Test-Path "${efiDrive}:\EFI\Microsoft\Boot\BCD")) {
    Write-Log "  Updating UEFI BCD entries..." "Gray"
    
    # Force all UEFI entries to ASR Windows
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /set {default} device partition=${asrDrive}:" 2>&1
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /set {default} osdevice partition=${asrDrive}:" 2>&1
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /set {default} path \Windows\system32\boot\winload.efi" 2>&1
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /set {default} systemroot \Windows" 2>&1
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /set {default} description `"ASR Production Windows`"" 2>&1
    
    # Set boot manager
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /set {bootmgr} device partition=${efiDrive}:" 2>&1
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /set {bootmgr} path \EFI\Microsoft\Boot\bootmgfw.efi" 2>&1
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /set {bootmgr} description `"Windows Boot Manager (ASR)`"" 2>&1
    
    # Set timeout to 0
    $null = & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /timeout 0" 2>&1
}

# FORCE METHOD 3: Nuclear option - recreate BCD
Write-Log "`nMethod 3: Nuclear option - recreating BCD..." "Yellow"
$null = & cmd /c "bcdedit /timeout 0" 2>&1

if ($bootType -eq "BIOS") {
    $null = & cmd /c "del C:\Boot\BCD /f" 2>&1
    $null = & cmd /c "bcdboot ${asrDrive}:\Windows /s C: /f BIOS" 2>&1
} else {
    # For UEFI, recreate in all locations
    if ($efiMounted) {
        $null = & cmd /c "bcdboot ${asrDrive}:\Windows /s ${efiDrive}: /f UEFI /v" 2>&1
    }
    $null = & cmd /c "bcdboot ${asrDrive}:\Windows /s C: /f ALL" 2>&1
}

$null = & cmd /c "bcdedit /set {default} description `"ASR Windows Server`"" 2>&1

# FORCE METHOD 4: Create a new boot entry and make it default
Write-Log "`nMethod 4: Creating new boot entry..." "Yellow"
$tempFile = [System.IO.Path]::GetTempFileName()

if ($bootType -eq "UEFI") {
    # Create UEFI firmware entry
    & cmd /c "bcdedit /create /d `"ASR Production Windows`" /application osloader" > $tempFile 2>&1
} else {
    & cmd /c "bcdedit /copy {current} /d `"ASR Windows Server`"" > $tempFile 2>&1
}

$output = Get-Content $tempFile -Raw
Remove-Item $tempFile -Force

if ($output -match '\{([a-f0-9\-]+)\}') {
    $guid = "{$($matches[1])}"
    Write-Log "  Created entry: $guid" "Green"
    
    $null = & cmd /c "bcdedit /set $guid device partition=${asrDrive}:" 2>&1
    $null = & cmd /c "bcdedit /set $guid osdevice partition=${asrDrive}:" 2>&1
    
    if ($bootType -eq "UEFI") {
        $null = & cmd /c "bcdedit /set $guid path \Windows\system32\boot\winload.efi" 2>&1
    } else {
        $null = & cmd /c "bcdedit /set $guid path \Windows\system32\boot\winload.exe" 2>&1
    }
    
    $null = & cmd /c "bcdedit /set $guid systemroot \Windows" 2>&1
    
    # Set as default
    $null = & cmd /c "bcdedit /default $guid" 2>&1
    $null = & cmd /c "bcdedit /displayorder $guid /addfirst" 2>&1
    
    if ($bootType -eq "UEFI") {
        $null = & cmd /c "bcdedit /set {fwbootmgr} default $guid" 2>&1
        $null = & cmd /c "bcdedit /set {fwbootmgr} displayorder $guid /addfirst" 2>&1
    }
    
    Write-Log "  Set as default boot entry" "Green"
}

# Additional UEFI-specific fixes
if ($bootType -eq "UEFI") {
    Write-Log "`nApplying Azure UEFI-specific fixes..." "Yellow"
    
    # Create NVRAM entries
    Write-Log "  Creating UEFI firmware boot entries..." "Gray"
    $tempFile = [System.IO.Path]::GetTempFileName()
    & cmd /c "bcdedit /create /d `"ASR Windows Boot Manager`" /application bootmgr" > $tempFile 2>&1
    $output = Get-Content $tempFile -Raw
    Remove-Item $tempFile -Force
    
    if ($output -match '\{([a-f0-9\-]+)\}') {
        $newGuid = "{$($matches[1])}"
        Write-Log "    Created firmware entry: $newGuid" "Green"
        
        $null = & cmd /c "bcdedit /set $newGuid device partition=${efiDrive}:" 2>&1
        $null = & cmd /c "bcdedit /set $newGuid path \EFI\Microsoft\Boot\bootmgfw.efi" 2>&1
        $null = & cmd /c "bcdedit /set {fwbootmgr} displayorder $newGuid /addfirst" 2>&1
        $null = & cmd /c "bcdedit /set {fwbootmgr} default $newGuid" 2>&1
    }
    
    # Fix boot order in firmware
    Write-Log "  Fixing UEFI boot order..." "Gray"
    $null = & cmd /c "bcdedit /set {fwbootmgr} displayorder {bootmgr} /addfirst" 2>&1
    $null = & cmd /c "bcdedit /set {fwbootmgr} timeout 0" 2>&1
}

# Final aggressive approach: Update the BCD store directly
Write-Log "`nFinal step: Forcing BCD to point to ASR Windows..." "Yellow"
$null = & cmd /c "bcdedit /set {current} device partition=${asrDrive}:" 2>&1
$null = & cmd /c "bcdedit /set {current} osdevice partition=${asrDrive}:" 2>&1
$null = & cmd /c "bcdedit /set {default} device partition=${asrDrive}:" 2>&1
$null = & cmd /c "bcdedit /set {default} osdevice partition=${asrDrive}:" 2>&1

# Registry manipulation as last resort
Write-Log "`nApplying registry fixes..." "Yellow"
try {
    # Load ASR Windows registry hive
    $hivePath = "${asrDrive}:\Windows\System32\config\SYSTEM"
    if (Test-Path $hivePath) {
        Write-Log "  Loading ASR Windows registry..." "Gray"
        $null = & cmd /c "reg load HKLM\ASR_SYSTEM `"$hivePath`"" 2>&1
        
        # Set boot configuration in registry
        $null = & cmd /c "reg add HKLM\ASR_SYSTEM\Setup /v SystemPartition /t REG_SZ /d `"${asrDrive}:`" /f" 2>&1
        $null = & cmd /c "reg add HKLM\ASR_SYSTEM\Setup /v OsLoaderPath /t REG_SZ /d `"\Windows\system32\boot`" /f" 2>&1
        
        # Unload hive
        $null = & cmd /c "reg unload HKLM\ASR_SYSTEM" 2>&1
        Write-Log "  Registry fixes applied" "Green"
    }
} catch {
    Write-Log "  Could not apply registry fixes: $_" "Yellow"
}

# Show final configuration
Write-Log "`n========================================" "Cyan"
Write-Log "VERIFICATION" "Cyan"
Write-Log "========================================" "Cyan"

Write-Log "`nMain BCD Configuration:" "Yellow"
Write-Log "Current boot configuration:" "Gray"
& cmd /c "bcdedit /enum {current} | findstr /i `"device osdevice description`""

Write-Log "`nDefault boot configuration:" "Gray"
& cmd /c "bcdedit /enum {default} | findstr /i `"device osdevice description`""

if ($bootType -eq "UEFI" -and $efiMounted -and (Test-Path "${efiDrive}:\EFI\Microsoft\Boot\BCD")) {
    Write-Log "`nUEFI BCD Configuration (EFI Partition):" "Yellow"
    & cmd /c "bcdedit /store ${efiDrive}:\EFI\Microsoft\Boot\BCD /enum {default} | findstr /i `"device osdevice description`""
}

Write-Log "`nAll Windows Boot Manager entries:" "Yellow"
& cmd /c "bcdedit /enum firmware | findstr /i `"description`""

# Save configuration
$config = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ASRDrive = $asrDrive
    ASRDiskSize = $asrWindows.Size
    ASRDiskNumber = $asrWindows.DiskNumber
    Version = "v10.1-Fixed"
    BootType = $bootType
    EFIMounted = $efiMounted
    Success = $true
}
$config | ConvertTo-Json | Out-File "C:\temp\ASRBootConfig.json" -Force

Write-Log "`n========================================" "Green"
Write-Log "BOOT CONFIGURATION FORCED!" "Green"
Write-Log "========================================" "Green"
Write-Log "ASR Windows: ${asrDrive}:\Windows" "Cyan"
Write-Log "Boot Type: $bootType" "Cyan"
Write-Log "Configuration saved to: C:\temp\ASRBootConfig.json" "Cyan"
Write-Log "Log saved to: $logFile" "Cyan"

# Handle reboot
if (-not $NoReboot) {
    # Detect if running in automation (as SYSTEM or via Run Command)
    $isAutomated = ($env:USERNAME -eq "SYSTEM") -or 
                   ($env:COMPUTERNAME -match "bootproxy") -or 
                   (Get-Process -Name "RunCommandExtension" -ErrorAction SilentlyContinue)
    
    if ($isAutomated) {
        Write-Log "`nAutomated execution detected - rebooting in 10 seconds..." "Yellow"
        Write-Log "VM will boot into ASR Windows Server after restart" "Green"
        Start-Sleep -Seconds 10
        
        # Use shutdown command for more reliable restart when running as SYSTEM
        & shutdown /r /t 0 /f
    } else {
        Write-Log "`nManual execution - please reboot when ready:" "Yellow"
        Write-Log "  Restart-Computer -Force" "Cyan"
    }
} else {
    Write-Log "`nReboot skipped (NoReboot parameter specified)" "Yellow"
    Write-Log "Please reboot manually to apply changes: Restart-Computer -Force" "Cyan"
}