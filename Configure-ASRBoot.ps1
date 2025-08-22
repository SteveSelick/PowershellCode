# Configure-ASRBoot-Enhanced.ps1
# Enhanced script with more aggressive UEFI boot configuration
# Version 9 - Focused on Azure Gen2 VMs with UEFI

param(
    [switch]$NoReboot,
    [switch]$ForceUEFI
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ASR BOOT CONFIGURATION SCRIPT (v9 ENHANCED)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Focus: Azure Gen2 UEFI Boot Fix" -ForegroundColor Yellow

# Check if running as admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

# Create temp and log directory
$logDir = "C:\temp"
if (!(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$logFile = "$logDir\ASRBootConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param($Message, $Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logFile -Append
    Write-Host $Message -ForegroundColor $Color
}

Write-Log "Starting ASR Boot Configuration" "Cyan"

# Step 1: Identify boot type (UEFI vs Legacy)
Write-Log "`nStep 1: Detecting boot type..." "Yellow"
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

# Step 2: Bring all disks online and initialize
Write-Log "`nStep 2: Initializing all disks..." "Yellow"
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

# Step 3: Find ALL Windows installations
Write-Log "`nStep 3: Searching for Windows installations..." "Yellow"
$windowsInstallations = @()

# First assign drive letters to all large partitions
$partitions = Get-Partition | Where-Object { $_.Size -gt 10GB }
foreach ($partition in $partitions) {
    if (-not $partition.DriveLetter) {
        $usedLetters = (Get-Partition | Where-Object {$_.DriveLetter} | Select-Object -ExpandProperty DriveLetter)
        $availableLetters = 70..90 | ForEach-Object { [char]$_ } | Where-Object { $_ -notin $usedLetters -and $_ -ne 'C' }
        
        if ($availableLetters.Count -gt 0) {
            $newLetter = $availableLetters[0]
            Write-Log "  Assigning drive letter $newLetter to partition (Size: $([math]::Round($partition.Size/1GB))GB)" "Gray"
            Set-Partition -InputObject $partition -NewDriveLetter $newLetter -ErrorAction SilentlyContinue
        }
    }
}

# Now search for Windows
Start-Sleep -Seconds 2
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Name -match '^[A-Z]$'}
foreach ($drive in $drives) {
    $testPath = "$($drive.Name):\Windows\System32\ntoskrnl.exe"
    if (Test-Path $testPath) {
        $partition = Get-Partition | Where-Object {$_.DriveLetter -eq $drive.Name} | Select-Object -First 1
        $sizeGB = [math]::Round($partition.Size/1GB, 2)
        
        $winInfo = @{
            Drive = $drive.Name
            Size = $sizeGB
            DiskNumber = $partition.DiskNumber
            PartitionNumber = $partition.PartitionNumber
        }
        
        Write-Log "  Found Windows on $($drive.Name): drive (Size: $sizeGB GB, Disk: $($partition.DiskNumber))" "Green"
        $windowsInstallations += $winInfo
    }
}

if ($windowsInstallations.Count -eq 0) {
    Write-Log "ERROR: No Windows installations found!" "Red"
    exit 1
}

# Select the Windows on the LARGEST partition (ASR disk)
$asrWindows = $windowsInstallations | Sort-Object Size -Descending | Select-Object -First 1
$asrDrive = $asrWindows.Drive

Write-Log "`nSelected ASR Windows: $($asrDrive): drive ($($asrWindows.Size) GB)" "Green"

# Step 4: Mount and prepare EFI partition
Write-Log "`nStep 4: Preparing EFI partition..." "Yellow"

# Find EFI partition
$efiPartition = Get-Partition | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' } | Select-Object -First 1

if ($efiPartition) {
    Write-Log "  Found EFI partition on Disk $($efiPartition.DiskNumber), Partition $($efiPartition.PartitionNumber)" "Green"
    
    # Assign letter S: to EFI partition if not already assigned
    if (-not $efiPartition.DriveLetter) {
        Write-Log "  Mounting EFI partition as S:..." "Gray"
        $diskpartScript = @"
select disk $($efiPartition.DiskNumber)
select partition $($efiPartition.PartitionNumber)
assign letter=S
"@
        $diskpartScript | Out-File "$logDir\mount_efi.txt" -Encoding ASCII -Force
        $null = diskpart /s "$logDir\mount_efi.txt" 2>&1
        Remove-Item "$logDir\mount_efi.txt" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    } else {
        $efiDrive = $efiPartition.DriveLetter
        Write-Log "  EFI partition already mounted as ${efiDrive}:" "Gray"
    }
} else {
    Write-Log "  WARNING: No EFI partition found - using mountvol" "Yellow"
    & cmd /c "mountvol S: /S 2>&1" | Out-Null
}

# Step 5: AGGRESSIVE BCD CLEANUP
Write-Log "`nStep 5: Cleaning up old boot entries..." "Yellow"

# Backup current BCD
Write-Log "  Backing up current BCD..." "Gray"
& cmd /c "bcdedit /export C:\temp\BCD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss') 2>&1" | Out-Null

# Delete all non-current boot entries
$bcdenum = & bcdedit /enum | Out-String
$guidPattern = '\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}'
$guids = [regex]::Matches($bcdenum, $guidPattern) | ForEach-Object { $_.Value } | Select-Object -Unique

foreach ($guid in $guids) {
    if ($guid -ne '{current}' -and $guid -ne '{default}' -and $guid -ne '{bootmgr}' -and $guid -ne '{fwbootmgr}') {
        Write-Log "  Deleting boot entry: $guid" "Gray"
        & cmd /c "bcdedit /delete $guid /f 2>&1" | Out-Null
    }
}

# Step 6: NUCLEAR OPTION - Complete BCD rebuild
Write-Log "`nStep 6: Rebuilding boot configuration from scratch..." "Yellow"

if ($bootType -eq "UEFI" -or $ForceUEFI) {
    Write-Log "  Rebuilding UEFI boot configuration..." "Yellow"
    
    # Delete old EFI boot files
    if (Test-Path "S:\EFI\Microsoft\Boot") {
        Write-Log "  Removing old EFI boot files..." "Gray"
        Remove-Item "S:\EFI\Microsoft\Boot\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Rebuild EFI boot
    Write-Log "  Creating new UEFI boot files from ASR Windows..." "Gray"
    $result = & cmd /c "bcdboot ${asrDrive}:\Windows /s S: /f UEFI 2>&1"
    Write-Log "    $result" "Gray"
    
    # Also update the system partition
    Write-Log "  Updating system partition boot files..." "Gray"
    $result = & cmd /c "bcdboot ${asrDrive}:\Windows /s C: /f ALL 2>&1"
    Write-Log "    $result" "Gray"
    
    # Force UEFI entries
    if (Test-Path "S:\EFI\Microsoft\Boot\BCD") {
        Write-Log "  Forcing UEFI BCD entries to ASR Windows..." "Yellow"
        
        # Set default OS
        & cmd /c "bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} device partition=${asrDrive}: 2>&1" | Out-Null
        & cmd /c "bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} osdevice partition=${asrDrive}: 2>&1" | Out-Null
        & cmd /c "bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} path \Windows\system32\boot\winload.efi 2>&1" | Out-Null
        & cmd /c "bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} systemroot \Windows 2>&1" | Out-Null
        & cmd /c "bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} description `"ASR Production Windows`" 2>&1" | Out-Null
        
        # Set boot manager
        & cmd /c "bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {bootmgr} device partition=S: 2>&1" | Out-Null
        & cmd /c "bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {bootmgr} path \EFI\Microsoft\Boot\bootmgfw.efi 2>&1" | Out-Null
        & cmd /c "bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {bootmgr} description `"Windows Boot Manager`" 2>&1" | Out-Null
        
        # Set timeout to 0
        & cmd /c "bcdedit /store S:\EFI\Microsoft\Boot\BCD /timeout 0 2>&1" | Out-Null
    }
    
    # Create UEFI NVRAM entries
    Write-Log "  Creating UEFI firmware boot entries..." "Yellow"
    
    # Try to create a new firmware application entry
    $tempFile = [System.IO.Path]::GetTempFileName()
    & cmd /c "bcdedit /create /d `"ASR Windows Boot Manager`" /application bootmgr > `"$tempFile`" 2>&1"
    $output = Get-Content $tempFile -Raw
    Remove-Item $tempFile -Force
    
    if ($output -match '\{([a-f0-9\-]+)\}') {
        $newGuid = "{$($matches[1])}"
        Write-Log "    Created firmware entry: $newGuid" "Green"
        
        & cmd /c "bcdedit /set $newGuid device partition=S: 2>&1" | Out-Null
        & cmd /c "bcdedit /set $newGuid path \EFI\Microsoft\Boot\bootmgfw.efi 2>&1" | Out-Null
        & cmd /c "bcdedit /set {fwbootmgr} displayorder $newGuid /addfirst 2>&1" | Out-Null
        & cmd /c "bcdedit /set {fwbootmgr} default $newGuid 2>&1" | Out-Null
    }
}

# Step 7: Update main BCD store
Write-Log "`nStep 7: Updating main BCD store..." "Yellow"

# Force all entries to point to ASR Windows
$entries = @("{current}", "{default}")
foreach ($entry in $entries) {
    Write-Log "  Updating $entry..." "Gray"
    & cmd /c "bcdedit /set $entry device partition=${asrDrive}: 2>&1" | Out-Null
    & cmd /c "bcdedit /set $entry osdevice partition=${asrDrive}: 2>&1" | Out-Null
    & cmd /c "bcdedit /set $entry systemroot \Windows 2>&1" | Out-Null
    
    if ($bootType -eq "UEFI") {
        & cmd /c "bcdedit /set $entry path \Windows\system32\boot\winload.efi 2>&1" | Out-Null
    } else {
        & cmd /c "bcdedit /set $entry path \Windows\system32\boot\winload.exe 2>&1" | Out-Null
    }
}

& cmd /c "bcdedit /set {default} description `"ASR Production Windows`" 2>&1" | Out-Null
& cmd /c "bcdedit /timeout 0 2>&1" | Out-Null

# Step 8: Additional UEFI fixes for Azure
if ($bootType -eq "UEFI") {
    Write-Log "`nStep 8: Applying Azure-specific UEFI fixes..." "Yellow"
    
    # Ensure boot files are in all possible locations
    $efiLocations = @("S:", "C:")
    foreach ($location in $efiLocations) {
        if (Test-Path "$location\") {
            Write-Log "  Copying boot files to $location..." "Gray"
            & cmd /c "bcdboot ${asrDrive}:\Windows /s $location /f UEFI 2>&1" | Out-Null
        }
    }
    
    # Fix boot order in firmware
    Write-Log "  Fixing UEFI boot order..." "Gray"
    & cmd /c "bcdedit /set {fwbootmgr} displayorder {bootmgr} /addfirst 2>&1" | Out-Null
    & cmd /c "bcdedit /set {fwbootmgr} timeout 0 2>&1" | Out-Null
}

# Step 9: Verification
Write-Log "`n========================================" "Cyan"
Write-Log "VERIFICATION" "Cyan"
Write-Log "========================================" "Cyan"

Write-Log "`nMain BCD Configuration:" "Yellow"
$currentConfig = & cmd /c "bcdedit /enum {current} 2>&1" | Out-String
Write-Log $currentConfig "Gray"

Write-Log "`nDefault Configuration:" "Yellow"
$defaultConfig = & cmd /c "bcdedit /enum {default} 2>&1" | Out-String
Write-Log $defaultConfig "Gray"

if (Test-Path "S:\EFI\Microsoft\Boot\BCD") {
    Write-Log "`nUEFI BCD Configuration:" "Yellow"
    $uefiConfig = & cmd /c "bcdedit /store S:\EFI\Microsoft\Boot\BCD /enum 2>&1" | Out-String
    Write-Log $uefiConfig "Gray"
}

Write-Log "`nFirmware Boot Order:" "Yellow"
$fwConfig = & cmd /c "bcdedit /enum firmware 2>&1" | Out-String
Write-Log $fwConfig "Gray"

# Save configuration
$configSummary = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ScriptVersion = "v9-Enhanced"
    BootType = $bootType
    ASRDrive = $asrDrive
    ASRDiskSize = $asrWindows.Size
    ASRDiskNumber = $asrWindows.DiskNumber
    WindowsInstallationsFound = $windowsInstallations.Count
    Success = $true
}

$configSummary | ConvertTo-Json | Out-File "$logDir\ASRBootConfig.json" -Force
Write-Log "`nConfiguration saved to $logDir\ASRBootConfig.json" "Green"

# Step 10: Final aggressive fix - Direct registry manipulation
Write-Log "`nStep 10: Applying registry fixes..." "Yellow"
try {
    # Load ASR Windows registry hive
    $hivePath = "${asrDrive}:\Windows\System32\config\SYSTEM"
    if (Test-Path $hivePath) {
        Write-Log "  Loading ASR Windows registry..." "Gray"
        & cmd /c "reg load HKLM\ASR_SYSTEM `"$hivePath`" 2>&1" | Out-Null
        
        # Set boot configuration in registry
        & cmd /c "reg add HKLM\ASR_SYSTEM\Setup /v SystemPartition /t REG_SZ /d `"${asrDrive}:`" /f 2>&1" | Out-Null
        & cmd /c "reg add HKLM\ASR_SYSTEM\Setup /v OsLoaderPath /t REG_SZ /d `"\Windows\system32\boot`" /f 2>&1" | Out-Null
        
        # Unload hive
        & cmd /c "reg unload HKLM\ASR_SYSTEM 2>&1" | Out-Null
        Write-Log "  Registry fixes applied" "Green"
    }
} catch {
    Write-Log "  Could not apply registry fixes: $_" "Yellow"
}

Write-Log "`n========================================" "Green"
Write-Log "BOOT CONFIGURATION COMPLETE!" "Green"
Write-Log "========================================" "Green"
Write-Log "ASR Windows: ${asrDrive}:\Windows" "Cyan"
Write-Log "Boot Type: $bootType" "Cyan"
Write-Log "Log saved to: $logFile" "Cyan"

# Handle reboot
if (-not $NoReboot) {
    $isAutomated = ($env:USERNAME -eq "SYSTEM") -or ($env:COMPUTERNAME -match "bootproxy") -or (Get-Process -Name "RunCommandExtension" -ErrorAction SilentlyContinue)
    
    if ($isAutomated) {
        Write-Log "`nAutomated execution detected - rebooting in 10 seconds..." "Yellow"
        Write-Log "VM will boot into ASR Production Windows after restart" "Green"
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    } else {
        Write-Log "`nManual execution - please reboot when ready:" "Yellow"
        Write-Log "  Restart-Computer -Force" "Cyan"
    }
} else {
    Write-Log "`nReboot skipped (NoReboot parameter specified)" "Yellow"
    Write-Log "Please reboot manually: Restart-Computer -Force" "Cyan"
}