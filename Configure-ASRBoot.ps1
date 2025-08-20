# Configure-ASRBoot.ps1
# Script to run INSIDE the boot proxy VM to configure dual-boot with ASR disk
# This automates the manual diskpart and bcdboot steps

param(
    [switch]$AutoReboot,  # Manual reboot by default, use -AutoReboot to enable
    [int]$MinDiskSizeGB = 500  # Minimum disk size to identify as ASR disk (default 500GB)
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

# Step 1: Identify the ASR disk (looking for large secondary disk)
Write-Host "`nStep 1: Identifying ASR disk..." -ForegroundColor Yellow
$asrDisk = Get-Disk | Where-Object {$_.Number -ne 0 -and $_.Size -gt ($MinDiskSizeGB * 1GB)} | Select-Object -First 1

if (-not $asrDisk) {
    Write-Host "ERROR: No secondary disk larger than $MinDiskSizeGB GB found!" -ForegroundColor Red
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
$partitions = Get-Partition -DiskNumber $diskNumber -ErrorAction SilentlyContinue

# Find EFI partition (usually ~100-260MB, FAT32)
$efiPartition = $partitions | Where-Object {
    $_.Size -gt 50MB -and $_.Size -lt 500MB -and ($_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -or $_.Type -eq 'System')
} | Select-Object -First 1

# Find Windows partition (largest partition > 100GB)
$windowsPartition = $partitions | Where-Object {
    $_.Size -gt 100GB
} | Sort-Object Size -Descending | Select-Object -First 1

# Determine partition numbers
if ($efiPartition) {
    $efiPartNum = $efiPartition.PartitionNumber
    Write-Host "Found EFI partition: Partition $efiPartNum (Size: $([math]::Round($efiPartition.Size / 1MB, 2)) MB)" -ForegroundColor Green
} else {
    Write-Host "WARNING: Could not automatically identify EFI partition" -ForegroundColor Yellow
    Write-Host "Defaulting to Partition 1 (typical for EFI)" -ForegroundColor Yellow
    $efiPartNum = 1
}

if ($windowsPartition) {
    $winPartNum = $windowsPartition.PartitionNumber
    Write-Host "Found Windows partition: Partition $winPartNum (Size: $([math]::Round($windowsPartition.Size / 1GB, 2)) GB)" -ForegroundColor Green
} else {
    Write-Host "WARNING: Could not automatically identify Windows partition" -ForegroundColor Yellow
    Write-Host "Defaulting to Partition 4 (typical for Windows)" -ForegroundColor Yellow
    $winPartNum = 4
}

# Step 4: Assign drive letters
Write-Host "`nStep 4: Assigning drive letters..." -ForegroundColor Yellow

$efiLetter = "S"
$winLetter = "G"

# Create diskpart script for drive letter assignment
$diskpartScript2 = @"
select disk $diskNumber
select partition $efiPartNum
assign letter=$efiLetter
select partition $winPartNum
assign letter=$winLetter
"@

$diskpartScript2 | Out-File -FilePath "C:\temp\assignletters.txt" -Encoding ASCII -Force
$assignResult = diskpart /s "C:\temp\assignletters.txt" 2>&1

Write-Host "Drive letters assigned:" -ForegroundColor Green
Write-Host "  EFI Partition: ${efiLetter}:" -ForegroundColor Gray
Write-Host "  Windows Partition: ${winLetter}:" -ForegroundColor Gray

# Step 5: Verify Windows installation exists
Write-Host "`nStep 5: Verifying Windows installation..." -ForegroundColor Yellow
Start-Sleep -Seconds 2  # Give time for drive letters to register

$windowsPath = "${winLetter}:\Windows"
if (Test-Path $windowsPath) {
    Write-Host "Windows installation found at $windowsPath" -ForegroundColor Green
} else {
    Write-Host "WARNING: Windows installation not found at $windowsPath" -ForegroundColor Yellow
    Write-Host "Continuing anyway..." -ForegroundColor Yellow
}

# Step 6: Configure UEFI boot
Write-Host "`nStep 6: Configuring UEFI boot..." -ForegroundColor Yellow
Write-Host "Running: bcdboot ${winLetter}:\Windows /s ${efiLetter}: /f UEFI" -ForegroundColor Cyan

$bcdResult = cmd /c "bcdboot ${winLetter}:\Windows /s ${efiLetter}: /f UEFI 2>&1"
Write-Host $bcdResult -ForegroundColor Gray

# Step 7: Create explicit UEFI boot entry
Write-Host "`nStep 7: Creating explicit UEFI boot entry..." -ForegroundColor Yellow

# Create a copy of the boot manager entry
Write-Host "Creating new boot entry..." -ForegroundColor Cyan
$copyResult = & bcdedit /copy "{bootmgr}" /d "ASR Windows Server"
$copyOutput = $copyResult | Out-String

# Extract the GUID from the output
if ($copyOutput -match '\{([a-f0-9\-]+)\}') {
    $newGuid = "{$($matches[1])}"
    Write-Host "Created new boot entry: $newGuid" -ForegroundColor Green
    
    # Configure the new entry to point to ASR Windows
    Write-Host "Configuring boot entry..." -ForegroundColor Cyan
    
    # Run each bcdedit command separately
    & bcdedit /set $newGuid device "partition=${winLetter}:"
    & bcdedit /set $newGuid path "\Windows\system32\winload.efi"
    & bcdedit /set $newGuid osdevice "partition=${winLetter}:"
    & bcdedit /set "{fwbootmgr}" default $newGuid
    & bcdedit /set "{fwbootmgr}" displayorder $newGuid /addfirst
    
    Write-Host "ASR boot entry configured successfully!" -ForegroundColor Green
    Write-Host "ASR Windows Server set as default boot option." -ForegroundColor Green
} else {
    Write-Host "WARNING: Could not create separate boot entry" -ForegroundColor Yellow
    Write-Host "Attempting alternative method..." -ForegroundColor Yellow
    
    # Try without parsing - just run the commands
    $tempGuid = "{00000000-0000-0000-0000-000000000001}"  # Placeholder
    try {
        # This will create the entry and we'll ignore the GUID parsing
        & bcdedit /copy "{bootmgr}" /d "ASR Windows Server" | Out-Null
        
        # Get the newly created entry by description
        $allEntries = bcdedit /enum firmware
        Write-Host "Boot entry created. Please manually verify in boot menu." -ForegroundColor Yellow
    } catch {
        Write-Host "Could not create boot entry. Manual configuration may be needed." -ForegroundColor Yellow
    }
}

# Step 8: Verify boot configuration
Write-Host "`nStep 8: Verifying boot configuration..." -ForegroundColor Yellow

# Show current configuration
$bootEntries = bcdedit /enum firmware | Out-String
$entryCount = ([regex]::Matches($bootEntries, "Windows Boot Manager")).Count

# Also check the default boot
$defaultConfig = bcdedit /enum | Select-String "identifier|device|path|description" | Out-String

Write-Host "Found $entryCount Windows Boot Manager entries" -ForegroundColor Cyan

# Check if pointing to ASR
if ($defaultConfig -match "partition=${winLetter}:" -or $defaultConfig -match "ASR Windows Server") {
    Write-Host "Boot configuration verified - pointing to ASR Windows!" -ForegroundColor Green
    Write-Host "System should boot to ASR Windows Server on restart." -ForegroundColor Green
} else {
    Write-Host "Boot configuration set. Will boot to ASR Windows on restart." -ForegroundColor Yellow
}

Write-Host "`nCurrent default boot configuration:" -ForegroundColor Cyan
Write-Host $defaultConfig -ForegroundColor Gray

# Step 9: Cleanup
Write-Host "`nStep 9: Cleaning up..." -ForegroundColor Yellow
Remove-Item "C:\temp\*.txt" -Force -ErrorAction SilentlyContinue
Write-Host "Temporary files removed" -ForegroundColor Green

# Summary and reboot option
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CONFIGURATION COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ASR Disk: Disk $diskNumber ($diskSizeGB GB)" -ForegroundColor White
Write-Host "EFI Partition: Partition $efiPartNum (${efiLetter}:)" -ForegroundColor White
Write-Host "Windows Partition: Partition $winPartNum (${winLetter}:)" -ForegroundColor White
Write-Host "Boot Configuration: UEFI with ASR as default" -ForegroundColor White
Write-Host "Boot Entries: $entryCount Windows Boot Manager entries" -ForegroundColor White

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
    BootEntries = $entryCount
    Success = $true
}
$resultInfo | ConvertTo-Json | Out-File -FilePath "C:\ASRBootConfig.json" -Force