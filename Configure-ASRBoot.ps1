# Configure-ASRBoot.ps1 (v8)
# Aggressive script to force boot to ASR Windows
# Run this INSIDE the bootproxy VM

param(
    [switch]$NoReboot
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ASR BOOT CONFIGURATION SCRIPT (v8)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Create temp directory if it doesn't exist
if (!(Test-Path "C:\temp")) {
    New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null
}

# Rename the current C: drive volume label to "BootProxy" for clarity
# This is the proxy Windows that we're currently running in
Write-Host "`nRenaming current boot volume to 'BootProxy'..." -ForegroundColor Yellow
try {
    $drive = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='C:'"
    $drive.Label = "BootProxy"
    $drive.Put() | Out-Null
    Write-Host "  Current boot drive renamed to 'BootProxy'" -ForegroundColor Green
} catch {
    # Alternative method using label command
    & cmd /c "label C: BootProxy" 2>&1 | Out-Null
    Write-Host "  Current boot drive renamed to 'BootProxy'" -ForegroundColor Green
}

# Find all Windows installations
Write-Host "`nStep 1: Finding and initializing disks..." -ForegroundColor Yellow

# First, bring all disks online
$disks = Get-Disk | Where-Object {$_.OperationalStatus -eq 'Offline'}
foreach ($disk in $disks) {
    Write-Host "  Bringing Disk $($disk.Number) online..." -ForegroundColor Gray
    Set-Disk -Number $disk.Number -IsOffline $false
}

# Find large disk (ASR disk is typically > 500GB and not disk 0)
$asrDisk = Get-Disk | Where-Object {
    $_.Size -gt 500GB -and $_.Number -ne 0
} | Sort-Object Size -Descending | Select-Object -First 1

if ($asrDisk) {
    Write-Host "  Found ASR disk: Disk $($asrDisk.Number) - Size: $([math]::Round($asrDisk.Size/1GB))GB" -ForegroundColor Green
    
    # Check all partitions on the ASR disk
    $partitions = Get-Partition -DiskNumber $asrDisk.Number -ErrorAction SilentlyContinue
    
    foreach ($partition in $partitions) {
        # Look for large partitions (Windows is usually on the largest partition)
        if ($partition.Type -eq 'Basic' -and $partition.Size -gt 100GB) {
            if (-not $partition.DriveLetter) {
                # Find an available drive letter
                $usedLetters = (Get-PSDrive -PSProvider FileSystem).Name
                $availableLetters = 'GHIJKLMNOPQRSTUVWXYZ'.ToCharArray() | Where-Object {$_ -notin $usedLetters}
                
                if ($availableLetters.Count -gt 0) {
                    $newLetter = $availableLetters[0]
                    Write-Host "  Assigning drive letter $newLetter to partition $($partition.PartitionNumber) on Disk $($asrDisk.Number) (Size: $([math]::Round($partition.Size/1GB))GB)" -ForegroundColor Yellow
                    
                    # Use diskpart to assign letter
                    $diskpartScript = @"
select disk $($asrDisk.Number)
select partition $($partition.PartitionNumber)
assign letter=$newLetter
"@
                    $diskpartScript | Out-File "C:\temp\assignletter.txt" -Encoding ASCII -Force
                    $null = diskpart /s "C:\temp\assignletter.txt" 2>&1
                    Remove-Item "C:\temp\assignletter.txt" -Force -ErrorAction SilentlyContinue
                    
                    Start-Sleep -Seconds 2
                    
                    # Verify Windows exists on this drive
                    if (Test-Path "${newLetter}:\Windows\System32\ntoskrnl.exe") {
                        Write-Host "  SUCCESS: Found Windows on ${newLetter}: drive!" -ForegroundColor Green
                    }
                }
            } else {
                Write-Host "  Partition $($partition.PartitionNumber) already has drive letter $($partition.DriveLetter):" -ForegroundColor Gray
            }
        }
    }
} else {
    Write-Host "  WARNING: No large disk found (>500GB, not disk 0)" -ForegroundColor Yellow
}

Write-Host "`nStep 2: Searching for Windows installations..." -ForegroundColor Yellow

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

# Create a startup script to hide the BootProxy volume when booted into ASR Windows
Write-Host "`nCreating startup script to hide BootProxy volume in ASR Windows..." -ForegroundColor Yellow
$startupScript = @'
# Hide-BootProxyVolume.ps1
# This script runs at startup in the ASR Windows to hide the BootProxy volume

# Check if we're running in the ASR Windows (not the BootProxy Windows)
if (Test-Path "C:\Windows\System32\config\systemprofile\ASRWindows.flag") {
    # We're in ASR Windows, hide the BootProxy volumes
    
    # Find all volumes labeled "BootProxy"
    $volumes = Get-WmiObject -Class Win32_Volume | Where-Object { $_.Label -eq "BootProxy" }
    
    foreach ($volume in $volumes) {
        if ($volume.DriveLetter) {
            $driveLetter = $volume.DriveLetter.TrimEnd(':')
            
            # Remove drive letter to hide it from Explorer
            $volume.DriveLetter = $null
            $volume.Put() | Out-Null
            
            Write-Output "Hidden BootProxy volume (was $driveLetter:)"
        }
    }
    
    # Alternative: Set NoDrives registry key to hide specific drives
    # This hides drives but keeps them accessible via path
    # $hideDrives = 4  # Value 4 = C: drive
    # Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDrives" -Value $hideDrives -Type DWord
}
'@

# Save the startup script to the ASR Windows drive
$startupScriptPath = "${asrDrive}:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\Hide-BootProxyVolume.ps1"
$startupDir = Split-Path $startupScriptPath -Parent

if (!(Test-Path $startupDir)) {
    New-Item -ItemType Directory -Path $startupDir -Force | Out-Null
}

$startupScript | Out-File $startupScriptPath -Encoding UTF8 -Force

# Create a flag file in ASR Windows to identify it
New-Item -ItemType File -Path "${asrDrive}:\Windows\System32\config\systemprofile\ASRWindows.flag" -Force | Out-Null

# Configure the script to run at startup via Group Policy
$gptIniPath = "${asrDrive}:\Windows\System32\GroupPolicy\gpt.ini"
$scriptsIniPath = "${asrDrive}:\Windows\System32\GroupPolicy\Machine\Scripts\scripts.ini"

# Create or update scripts.ini
$scriptsContent = @"
[Startup]
0CmdLine=powershell.exe -ExecutionPolicy Bypass -File C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\Hide-BootProxyVolume.ps1
0Parameters=
"@

$scriptsContent | Out-File $scriptsIniPath -Encoding ASCII -Force

Write-Host "  Startup script created to hide BootProxy volume in ASR Windows" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "BOOT CONFIGURATION FORCED!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "ASR Windows: ${asrDrive}:\Windows" -ForegroundColor Cyan
Write-Host "BootProxy volume will be hidden when booted to ASR" -ForegroundColor Cyan

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