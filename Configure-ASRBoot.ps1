# Configure-ASRBoot.ps1 (v8)
# Aggressive script to force boot to ASR Windows
# Run this INSIDE the bootproxy VM

param(
    [switch]$NoReboot
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ASR BOOT CONFIGURATION SCRIPT (v8)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Find all Windows installations
Write-Host "`nSearching for Windows installations..." -ForegroundColor Yellow

$windowsFound = @()

# Check all possible drive letters
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Name -match '^[A-Z]$'}

foreach ($drive in $drives) {
    $testPath = "$($drive.Name):\Windows\System32\ntoskrnl.exe"
    if (Test-Path $testPath) {
        $size = (Get-ChildItem "$($drive.Name):\" -Force | Measure-Object -Property Length -Sum).Sum / 1GB
        Write-Host "  Found Windows on $($drive.Name): drive (Size: $([math]::Round($size, 2)) GB)" -ForegroundColor Green
        $windowsFound += @{
            Drive = $drive.Name
            Size = $size
        }
    }
}

if ($windowsFound.Count -eq 0) {
    Write-Host "ERROR: No Windows installations found!" -ForegroundColor Red
    exit 1
}

# Select the ASR Windows (not C:)
$asrWindows = $windowsFound | Where-Object {$_.Drive -ne 'C'} | Sort-Object Size -Descending | Select-Object -First 1

if (!$asrWindows) {
    Write-Host "ERROR: No ASR Windows found (only found Windows on C:)" -ForegroundColor Red
    exit 1
}

$asrDrive = $asrWindows.Drive
Write-Host "`nSelected ASR Windows on $asrDrive`: drive" -ForegroundColor Green

# FORCE METHOD 1: Overwrite all boot files
Write-Host "`nMethod 1: Overwriting boot files with ASR Windows..." -ForegroundColor Yellow
$result = & cmd /c "bcdboot ${asrDrive}:\Windows /s C: /f UEFI 2>&1"
Write-Host $result

# FORCE METHOD 2: Modify ALL boot entries to point to ASR
Write-Host "`nMethod 2: Forcing ALL boot entries to ASR Windows..." -ForegroundColor Yellow

$bootEntries = @("{current}", "{default}", "{bootmgr}")
foreach ($entry in $bootEntries) {
    Write-Host "  Updating $entry..." -ForegroundColor Gray
    & cmd /c "bcdedit /set $entry device partition=${asrDrive}: 2>&1" | Out-Null
    & cmd /c "bcdedit /set $entry osdevice partition=${asrDrive}: 2>&1" | Out-Null
    & cmd /c "bcdedit /set $entry path \Windows\system32\boot\winload.efi 2>&1" | Out-Null
    & cmd /c "bcdedit /set $entry systemroot \Windows 2>&1" | Out-Null
}

# FORCE METHOD 3: Delete and recreate BCD
Write-Host "`nMethod 3: Nuclear option - recreating BCD..." -ForegroundColor Yellow
& cmd /c "bcdedit /timeout 0 2>&1" | Out-Null
& cmd /c "del C:\Boot\BCD /f 2>&1" | Out-Null
& cmd /c "bcdboot ${asrDrive}:\Windows /s C: /f ALL 2>&1" | Out-Null
& cmd /c "bcdedit /set {default} description `"ASR Windows Server`" 2>&1" | Out-Null

# FORCE METHOD 4: Create a new boot entry and make it default
Write-Host "`nMethod 4: Creating new boot entry..." -ForegroundColor Yellow
$tempFile = [System.IO.Path]::GetTempFileName()
& cmd /c "bcdedit /copy {bootmgr} /d `"ASR Windows Server`" > `"$tempFile`" 2>&1"
$output = Get-Content $tempFile -Raw
Remove-Item $tempFile -Force

if ($output -match '\{([a-f0-9\-]+)\}') {
    $guid = "{$($matches[1])}"
    Write-Host "  Created entry: $guid" -ForegroundColor Green
    
    & cmd /c "bcdedit /set $guid device partition=${asrDrive}: 2>&1" | Out-Null
    & cmd /c "bcdedit /set $guid osdevice partition=${asrDrive}: 2>&1" | Out-Null
    & cmd /c "bcdedit /set $guid path \Windows\system32\winload.efi 2>&1" | Out-Null
    & cmd /c "bcdedit /set $guid systemroot \Windows 2>&1" | Out-Null
    
    # Try both ways to set as default
    & cmd /c "bcdedit /default $guid 2>&1" | Out-Null
    & cmd /c "bcdedit /set {fwbootmgr} default $guid 2>&1" | Out-Null
    & cmd /c "bcdedit /set {fwbootmgr} displayorder $guid /addfirst 2>&1" | Out-Null
    
    Write-Host "  Set as default boot entry" -ForegroundColor Green
}

# Show final configuration
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "VERIFICATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nCurrent boot configuration:" -ForegroundColor Yellow
& cmd /c "bcdedit /enum {current} | findstr /i `"device osdevice description`""

Write-Host "`nDefault boot configuration:" -ForegroundColor Yellow
& cmd /c "bcdedit /enum {default} | findstr /i `"device osdevice description`""

Write-Host "`nAll Windows Boot Manager entries:" -ForegroundColor Yellow
& cmd /c "bcdedit /enum firmware | findstr /i `"description`""

# Save configuration
$config = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ASRDrive = $asrDrive
    Version = "v8"
    Success = $true
}
$config | ConvertTo-Json | Out-File "C:\ASRBootConfig.json" -Force

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "BOOT CONFIGURATION FORCED!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "ASR Windows: ${asrDrive}:\Windows" -ForegroundColor Cyan

# Handle reboot
if (-not $NoReboot) {
    # Detect if running in automation (as SYSTEM or via Run Command)
    $isAutomated = ($env:USERNAME -eq "SYSTEM") -or ($env:COMPUTERNAME -match "bootproxy")
    
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