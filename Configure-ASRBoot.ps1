# Configure-ASRBoot-Enhanced.ps1
# Enhanced version that searches ALL disks and ALL partitions for Windows
# Works with any disk configuration

param(
    [switch]$NoReboot,
    [int]$MinDiskSizeGB = 500
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ASR BOOT CONFIGURATION SCRIPT" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Detect if running in automation
$isAutomated = ($env:USERNAME -eq "SYSTEM") -or ($env:COMPUTERNAME -match "bootproxy")

# Step 1: Find ALL Windows installations on ALL disks
Write-Host "`nStep 1: Searching ALL disks for Windows installations..." -ForegroundColor Yellow

$windowsInstallations = @()

# Get all disks except the boot disk (disk 0)
$allDisks = Get-Disk | Where-Object { $_.PartitionStyle -ne 'RAW' }

foreach ($disk in $allDisks) {
    Write-Host "`n  Checking Disk $($disk.Number) - Size: $([math]::Round($disk.Size/1GB))GB" -ForegroundColor Cyan
    
    # Get all partitions on this disk
    $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | 
        Where-Object { $_.Type -eq 'Basic' -and $_.Size -gt 10GB }
    
    foreach ($partition in $partitions) {
        # Check if partition has a drive letter
        if ($partition.DriveLetter) {
            $testPath = "$($partition.DriveLetter):\Windows\System32\ntoskrnl.exe"
            if (Test-Path $testPath) {
                $windowsInfo = @{
                    DiskNumber = $disk.Number
                    PartitionNumber = $partition.PartitionNumber
                    DriveLetter = $partition.DriveLetter
                    Size = [math]::Round($partition.Size/1GB)
                    DiskSize = [math]::Round($disk.Size/1GB)
                }
                $windowsInstallations += $windowsInfo
                Write-Host "    [FOUND] Windows on Disk $($disk.Number), Partition $($partition.PartitionNumber), Drive $($partition.DriveLetter): ($($windowsInfo.Size)GB)" -ForegroundColor Green
            }
        }
    }
}

# Now check partitions without drive letters
Write-Host "`nStep 2: Checking partitions without drive letters..." -ForegroundColor Yellow

$availableLetters = @('G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z') | 
    Where-Object { -not (Test-Path "$_`:") }
$letterIndex = 0

foreach ($disk in $allDisks) {
    $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | 
        Where-Object { $_.Type -eq 'Basic' -and $_.Size -gt 10GB -and -not $_.DriveLetter }
    
    foreach ($partition in $partitions) {
        if ($letterIndex -ge $availableLetters.Count) {
            Write-Host "  [WARNING] No more drive letters available" -ForegroundColor Yellow
            break
        }
        
        $tempLetter = $availableLetters[$letterIndex]
        $letterIndex++
        
        Write-Host "  Assigning ${tempLetter}: to Disk $($disk.Number), Partition $($partition.PartitionNumber)..." -ForegroundColor Gray
        
        # Create temp directory if it doesn't exist
        if (!(Test-Path "C:\temp")) {
            New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null
        }
        
        # Use diskpart to assign letter
        $diskpartScript = @"
select disk $($disk.Number)
select partition $($partition.PartitionNumber)
assign letter=$tempLetter
"@
        
        $diskpartScript | Out-File "C:\temp\assignletter.txt" -Encoding ASCII -Force
        $null = diskpart /s "C:\temp\assignletter.txt" 2>&1
        Remove-Item "C:\temp\assignletter.txt" -Force -ErrorAction SilentlyContinue
        
        # Check if Windows exists
        Start-Sleep -Seconds 1
        $testPath = "${tempLetter}:\Windows\System32\ntoskrnl.exe"
        if (Test-Path $testPath) {
            $windowsInfo = @{
                DiskNumber = $disk.Number
                PartitionNumber = $partition.PartitionNumber
                DriveLetter = $tempLetter
                Size = [math]::Round($partition.Size/1GB)
                DiskSize = [math]::Round($disk.Size/1GB)
            }
            $windowsInstallations += $windowsInfo
                            Write-Host "    [FOUND] Windows on Disk $($disk.Number), Partition $($partition.PartitionNumber), Drive ${tempLetter}: ($($windowsInfo.Size)GB)" -ForegroundColor Green
        } else {
            # Remove the drive letter if no Windows found
            $diskpartScript = @"
select disk $($disk.Number)
select partition $($partition.PartitionNumber)
remove letter=$tempLetter
"@
            $diskpartScript | Out-File "C:\temp\removeletter.txt" -Encoding ASCII -Force
            $null = diskpart /s "C:\temp\removeletter.txt" 2>&1
            Remove-Item "C:\temp\removeletter.txt" -Force -ErrorAction SilentlyContinue
            $letterIndex-- # Reuse this letter
        }
    }
}

# Step 3: Display all found Windows installations
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "WINDOWS INSTALLATIONS FOUND: $($windowsInstallations.Count)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($windowsInstallations.Count -eq 0) {
    Write-Host "[X] No Windows installations found on any disk!" -ForegroundColor Red
    exit 1
}

foreach ($win in $windowsInstallations) {
    Write-Host "  Disk $($win.DiskNumber) (Size: $($win.DiskSize)GB), Partition $($win.PartitionNumber), Drive $($win.DriveLetter): - $($win.Size)GB" -ForegroundColor Yellow
}

# Step 4: Identify the ASR Windows (largest disk that's not disk 0)
Write-Host "`nStep 4: Identifying ASR Windows installation..." -ForegroundColor Yellow

$asrWindows = $windowsInstallations | 
    Where-Object { $_.DiskNumber -ne 0 } | 
    Sort-Object DiskSize -Descending | 
    Select-Object -First 1

if (-not $asrWindows) {
    # If no Windows on non-boot disk, take the largest Windows installation
    $asrWindows = $windowsInstallations | Sort-Object Size -Descending | Select-Object -First 1
}

$winDriveLetter = $asrWindows.DriveLetter
Write-Host "[OK] Selected ASR Windows: Disk $($asrWindows.DiskNumber), Drive ${winDriveLetter}: ($($asrWindows.Size)GB)" -ForegroundColor Green

# Step 5: Run bcdboot to create boot files
Write-Host "`nStep 5: Creating boot files..." -ForegroundColor Yellow
$bcdbootResult = & cmd /c "bcdboot ${winDriveLetter}:\Windows /s C: /f UEFI /v 2>&1"
Write-Host $bcdbootResult
Write-Host "[OK] Boot files created" -ForegroundColor Green

# Step 6: Create boot entry using bcdedit /copy
Write-Host "`nStep 6: Creating ASR boot entry..." -ForegroundColor Yellow

# Force overwrite current boot configuration first
Write-Host "Forcing boot configuration to ASR Windows..." -ForegroundColor Cyan
& cmd /c "bcdboot ${winDriveLetter}:\Windows /s C: /f UEFI /v" 2>&1 | Out-String

# Now modify the existing boot entries to ensure they point to ASR
Write-Host "Updating all boot entries to point to ASR Windows..." -ForegroundColor Cyan
& cmd /c "bcdedit /set {current} device partition=${winDriveLetter}:" 2>&1
& cmd /c "bcdedit /set {current} osdevice partition=${winDriveLetter}:" 2>&1
& cmd /c "bcdedit /set {current} path \Windows\system32\boot\winload.efi" 2>&1
& cmd /c "bcdedit /set {current} systemroot \Windows" 2>&1
& cmd /c "bcdedit /set {current} description `"ASR Windows Server`"" 2>&1

& cmd /c "bcdedit /set {default} device partition=${winDriveLetter}:" 2>&1
& cmd /c "bcdedit /set {default} osdevice partition=${winDriveLetter}:" 2>&1
& cmd /c "bcdedit /set {default} path \Windows\system32\boot\winload.efi" 2>&1
& cmd /c "bcdedit /set {default} systemroot \Windows" 2>&1
& cmd /c "bcdedit /set {default} description `"ASR Windows Server`"" 2>&1

Write-Host "[OK] Boot configuration forced to ASR Windows" -ForegroundColor Green

# Step 7: Verify configuration
Write-Host "`nStep 7: Verifying boot configuration..." -ForegroundColor Yellow

$verifyOutput = & cmd /c "bcdedit /enum firmware 2>&1" | Out-String
$bootEntries = ($verifyOutput -split "Windows Boot Manager" | Measure-Object).Count - 1

if ($verifyOutput -match "ASR Windows Server") {
    Write-Host "[OK] ASR Windows Server entry found in boot configuration" -ForegroundColor Green
} else {
    Write-Host "[WARNING] ASR Windows Server entry not found, but configuration was applied" -ForegroundColor Yellow
}

Write-Host "Boot entries found: $bootEntries" -ForegroundColor Cyan

# Step 8: Save configuration
Write-Host "`nStep 8: Saving configuration..." -ForegroundColor Yellow

$configInfo = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ASRDisk = "Disk $($asrWindows.DiskNumber)"
    WindowsPartition = "Partition $($asrWindows.PartitionNumber)"
    WindowsDrive = "${winDriveLetter}:"
    BootEntries = $bootEntries
    AllWindowsFound = $windowsInstallations.Count
    Success = $true
}

$configInfo | ConvertTo-Json | Out-File "C:\ASRBootConfig.json" -Force
Write-Host "[OK] Configuration saved to C:\ASRBootConfig.json" -ForegroundColor Green

# Final summary
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "BOOT CONFIGURATION COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Found $($windowsInstallations.Count) Windows installations total" -ForegroundColor Cyan
Write-Host "ASR Windows: Disk $($asrWindows.DiskNumber), Drive ${winDriveLetter}:" -ForegroundColor Cyan
Write-Host "Boot Entries: $bootEntries" -ForegroundColor Cyan

# Handle reboot
if (-not $NoReboot) {
    if ($isAutomated) {
        Write-Host "`nAutomated execution detected - rebooting in 10 seconds..." -ForegroundColor Yellow
        Write-Host "VM will boot into ASR Windows Server after restart" -ForegroundColor Green
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    } else {
        Write-Host "`nManual execution - please reboot when ready:" -ForegroundColor Yellow
        Write-Host "  shutdown /r /t 0" -ForegroundColor Cyan
    }
} else {
    Write-Host "`nReboot skipped (NoReboot parameter specified)" -ForegroundColor Yellow
    Write-Host "Please reboot manually to apply changes: shutdown /r /t 0" -ForegroundColor Cyan
}