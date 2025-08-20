# Configure-ASRBoot.ps1
# Script to run INSIDE the boot proxy VM to configure dual-boot with ASR disk
# This automates the manual diskpart and bcdboot steps

param(
    [switch]$AutoReboot,  # Manual reboot by default, use -AutoReboot to enable
    [int]$ASRDiskSizeGB = 3300  # Default 3.3TB for ASR disk identification
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ASR BOOT CONFIGURATION SCRIPT" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

# Ensure running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "This script must be run as Administrator. Relaunching..." -ForegroundColor Red
    Start-Process PowerShell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`" $($MyInvocation.UnboundArguments)"
    exit
}

# Step 1: Identify the ASR disk (looking for disk > 3TB)
Write-Host "`nStep 1: Identifying ASR disk..." -ForegroundColor Yellow
$asrDisk = Get-Disk | Where-Object {$_.Size -gt ($ASRDiskSizeGB * 1GB)} | Select-Object -First 1

if (-not $asrDisk) {
    Write-Host "ERROR: No disk larger than $ASRDiskSizeGB GB found!" -ForegroundColor Red
    Write-Host "Available disks:" -ForegroundColor Yellow
    Get-Disk | Format-Table Number,FriendlyName,Size,PartitionStyle,OperationalStatus
    exit 1
}

$diskNumber = $asrDisk.Number
$diskSizeGB = [math]::Round($asrDisk.Size / 1GB, 2)
Write-Host "Found ASR disk: Disk $diskNumber (Size: $diskSizeGB GB)" -ForegroundColor Green

# Step 2: Get partition information
Write-Host "`nStep 2: Analyzing disk partitions..." -ForegroundColor Yellow

# Create temp directory if it doesn't exist
if (!(Test-Path "C:\temp")) {
    New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null
}

# Get partition details using diskpart
$diskpartScript1 = @"
select disk $diskNumber
list partition
"@
$diskpartScript1 | Out-File -FilePath "C:\temp\listpart.txt" -Encoding ASCII -Force
$partitionInfo = diskpart /s "C:\temp\listpart.txt"

# Display partition information
Write-Host "Partition layout:" -ForegroundColor Cyan
$partitionInfo | Where-Object {$_ -match "Partition"} | ForEach-Object {Write-Host $_ -ForegroundColor Gray}

# Step 3: Identify EFI and Windows partitions
Write-Host "`nStep 3: Identifying EFI and Windows partitions..." -ForegroundColor Yellow

# Get partitions programmatically
$partitions = Get-Partition -DiskNumber $diskNumber

# Find EFI partition (usually ~100MB, FAT32)
$efiPartition = $partitions | Where-Object {
    $_.Size -gt 50MB -and $_.Size -lt 500MB -and $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
}

# Find Windows partition (largest NTFS partition)
$windowsPartition = $partitions | Where-Object {
    $_.Size -gt 100GB
} | Sort-Object Size -Descending | Select-Object -First 1

if (-not $efiPartition) {
    Write-Host "WARNING: Could not automatically identify EFI partition" -ForegroundColor Yellow
    $efiPartNum = Read-Host "Enter EFI partition number (usually 2)"
} else {
    $efiPartNum = $efiPartition.PartitionNumber
    Write-Host "Found EFI partition: Partition $efiPartNum (Size: $([math]::Round($efiPartition.Size / 1MB, 2)) MB)" -ForegroundColor Green
}

if (-not $windowsPartition) {
    Write-Host "WARNING: Could not automatically identify Windows partition" -ForegroundColor Yellow
    $winPartNum = Read-Host "Enter Windows partition number (usually 4)"
} else {
    $winPartNum = $windowsPartition.PartitionNumber
    Write-Host "Found Windows partition: Partition $winPartNum (Size: $([math]::Round($windowsPartition.Size / 1GB, 2)) GB)" -ForegroundColor Green
}

# Step 4: Assign drive letters
Write-Host "`nStep 4: Assigning drive letters..." -ForegroundColor Yellow

# Check if letters are already assigned
$existingEFI = Get-Partition -DiskNumber $diskNumber -PartitionNumber $efiPartNum -ErrorAction SilentlyContinue
$existingWin = Get-Partition -DiskNumber $diskNumber -PartitionNumber $winPartNum -ErrorAction SilentlyContinue

$efiLetter = if ($existingEFI.DriveLetter) {$existingEFI.DriveLetter} else {"S"}
$winLetter = if ($existingWin.DriveLetter) {$existingWin.DriveLetter} else {"G"}

# Create diskpart script for drive letter assignment
$diskpartScript2 = @"
select disk $diskNumber
select partition $efiPartNum
$(if (!$existingEFI.DriveLetter) {"assign letter=$efiLetter"} else {"rem EFI already has letter $($existingEFI.DriveLetter)"})
select partition $winPartNum
$(if (!$existingWin.DriveLetter) {"assign letter=$winLetter"} else {"rem Windows already has letter $($existingWin.DriveLetter)"})
"@

$diskpartScript2 | Out-File -FilePath "C:\temp\assignletters.txt" -Encoding ASCII -Force
$assignResult = diskpart /s "C:\temp\assignletters.txt"

Write-Host "Drive letters assigned:" -ForegroundColor Green
Write-Host "  EFI Partition: ${efiLetter}:" -ForegroundColor Gray
Write-Host "  Windows Partition: ${winLetter}:" -ForegroundColor Gray

# Step 5: Verify Windows installation exists
Write-Host "`nStep 5: Verifying Windows installation..." -ForegroundColor Yellow
$windowsPath = "${winLetter}:\Windows"
if (Test-Path $windowsPath) {
    Write-Host "Windows installation found at $windowsPath" -ForegroundColor Green
    $winVersion = Get-ItemProperty "$windowsPath\System32\ntoskrnl.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty VersionInfo
    if ($winVersion) {
        Write-Host "  Version: $($winVersion.FileDescription)" -ForegroundColor Gray
    }
} else {
    Write-Host "ERROR: Windows installation not found at $windowsPath!" -ForegroundColor Red
    Write-Host "Please verify the correct partition was selected." -ForegroundColor Yellow
    exit 1
}

# Step 6: Configure UEFI boot
Write-Host "`nStep 6: Configuring UEFI boot..." -ForegroundColor Yellow
Write-Host "Running: bcdboot ${winLetter}:\Windows /s ${efiLetter}: /f UEFI" -ForegroundColor Cyan

$bcdResult = & bcdboot "${winLetter}:\Windows" /s "${efiLetter}:" /f UEFI 2>&1
Write-Host $bcdResult -ForegroundColor Gray

if ($LASTEXITCODE -eq 0) {
    Write-Host "Boot files successfully created!" -ForegroundColor Green
} else {
    Write-Host "WARNING: bcdboot returned exit code $LASTEXITCODE" -ForegroundColor Yellow
    Write-Host "Attempting alternative configuration..." -ForegroundColor Yellow
    
    # Try with current system EFI as fallback
    $altResult = & bcdboot "${winLetter}:\Windows" /s C: /f UEFI 2>&1
    Write-Host $altResult -ForegroundColor Gray
}

# Step 7: Verify boot configuration
Write-Host "`nStep 7: Verifying boot configuration..." -ForegroundColor Yellow
$bootEntries = bcdedit /enum firmware | Out-String

if ($bootEntries -match "Windows Boot Manager") {
    Write-Host "Boot configuration verified successfully!" -ForegroundColor Green
    
    # Show boot entries
    Write-Host "`nCurrent boot entries:" -ForegroundColor Cyan
    bcdedit /enum firmware | Where-Object {$_ -match "identifier|device|path|description"} | ForEach-Object {
        Write-Host $_ -ForegroundColor Gray
    }
} else {
    Write-Host "WARNING: Could not verify boot configuration" -ForegroundColor Yellow
}

# Step 8: Cleanup
Write-Host "`nStep 8: Cleaning up..." -ForegroundColor Yellow
Remove-Item "C:\temp\*.txt" -Force -ErrorAction SilentlyContinue
Write-Host "Temporary files removed" -ForegroundColor Green

# Summary and reboot option
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CONFIGURATION COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ASR Disk: Disk $diskNumber" -ForegroundColor White
Write-Host "EFI Partition: Partition $efiPartNum (${efiLetter}:)" -ForegroundColor White
Write-Host "Windows Partition: Partition $winPartNum (${winLetter}:)" -ForegroundColor White
Write-Host "Boot Configuration: UEFI" -ForegroundColor White

if ($AutoReboot) {
    Write-Host "`nRebooting in 10 seconds..." -ForegroundColor Yellow
    Write-Host "Press Ctrl+C to cancel reboot" -ForegroundColor Gray
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "`nMANUAL REBOOT REQUIRED:" -ForegroundColor Yellow
    Write-Host "Review the configuration above for any errors." -ForegroundColor Cyan
    Write-Host "If everything looks correct, restart the VM:" -ForegroundColor Cyan
    Write-Host "  shutdown /r /t 0" -ForegroundColor White
    Write-Host "`nConfiguration details saved to C:\ASRBootConfig.json" -ForegroundColor Gray
}

# Create result file for verification
$resultInfo = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ASRDisk = $diskNumber
    DiskSizeGB = $diskSizeGB
    EFIPartition = $efiPartNum
    EFILetter = $efiLetter
    WindowsPartition = $winPartNum
    WindowsLetter = $winLetter
    BCDResult = $LASTEXITCODE -eq 0
}
$resultInfo | ConvertTo-Json | Out-File -FilePath "C:\ASRBootConfig.json" -Force
Write-Host "`nConfiguration saved to C:\ASRBootConfig.json" -ForegroundColor Gray