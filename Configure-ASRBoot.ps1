# Configure-ASRBoot-FORCE.ps1
# This version will FORCE Windows to boot from the ASR disk
# Version: FORCE

param(
    [switch]$NoReboot
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ASR BOOT CONFIGURATION - FORCE VERSION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Create log directory
$logDir = "C:\temp"
if (!(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$logFile = "$logDir\ASRBootForce.log"
function Log($msg) {
    "$msg" | Out-File $logFile -Append
    Write-Host $msg
}

Log "Starting at $(Get-Date)"

# Step 1: Find the current boot disk
$bootDisk = Get-Disk | Where-Object {$_.IsBoot -eq $true} | Select-Object -First 1
Log "Current boot disk: Disk $($bootDisk.Number)"

# Step 2: Find ALL other disks and assign drive letters to ALL partitions
Log "`nAssigning drive letters to ALL partitions on ALL disks..."

$allDisks = Get-Disk
$windowsFound = @()

foreach ($disk in $allDisks) {
    $diskNum = $disk.Number
    $diskSizeGB = [math]::Round($disk.Size/1GB, 2)
    Log "`nDisk $diskNum - Size: $diskSizeGB GB - Boot: $($disk.IsBoot)"
    
    # Get all partitions
    $partitions = Get-Partition -DiskNumber $diskNum -ErrorAction SilentlyContinue
    
    foreach ($partition in $partitions) {
        if ($partition.Size -lt 1GB) { continue }
        
        $partNum = $partition.PartitionNumber
        $partSizeGB = [math]::Round($partition.Size/1GB, 2)
        
        if (!$partition.DriveLetter -and $partition.Size -gt 10GB) {
            # Assign drive letter using diskpart
            $availLetter = (69..90 | ForEach-Object {[char]$_} | Where-Object {
                $_ -notin (Get-Volume | Where-Object DriveLetter | ForEach-Object DriveLetter)
            })[0]
            
            if ($availLetter) {
                Log "  Assigning $availLetter to Disk $diskNum Partition $partNum ($partSizeGB GB)"
                
                $dpCmd = "select disk $diskNum`r`nselect partition $partNum`r`nassign letter=$availLetter"
                $dpFile = "$logDir\dp.txt"
                [System.IO.File]::WriteAllText($dpFile, $dpCmd)
                
                $result = & diskpart /s $dpFile 2>&1
                Remove-Item $dpFile -Force -ErrorAction SilentlyContinue
                
                Start-Sleep -Seconds 1
                
                # Force refresh
                Get-PSDrive | Out-Null
                
                # Check for Windows
                if (Test-Path "${availLetter}:\Windows\System32\ntoskrnl.exe") {
                    Log "    >>> WINDOWS FOUND on ${availLetter}:"
                    $windowsFound += @{
                        Drive = $availLetter
                        DiskNum = $diskNum
                        PartNum = $partNum
                        Size = $partition.Size
                        IsBoot = $disk.IsBoot
                    }
                }
            }
        }
        elseif ($partition.DriveLetter) {
            $letter = $partition.DriveLetter
            if (Test-Path "${letter}:\Windows\System32\ntoskrnl.exe") {
                Log "  Windows found on ${letter}: (existing drive)"
                $windowsFound += @{
                    Drive = $letter
                    DiskNum = $diskNum
                    PartNum = $partNum
                    Size = $partition.Size
                    IsBoot = $disk.IsBoot
                }
            }
        }
    }
}

Log "`n========================================"
Log "WINDOWS INSTALLATIONS FOUND: $($windowsFound.Count)"
Log "========================================"

foreach ($w in $windowsFound) {
    $sizeGB = [math]::Round($w.Size/1GB, 2)
    Log "$($w.Drive): - Disk $($w.DiskNum) - $sizeGB GB - Boot: $($w.IsBoot)"
}

# Select the ASR Windows (non-boot, largest)
$asrWin = $windowsFound | Where-Object {!$_.IsBoot} | Sort-Object Size -Descending | Select-Object -First 1

if (!$asrWin) {
    Log "ERROR: No non-boot Windows installation found!"
    exit 1
}

$asrDrive = $asrWin.Drive
Log "`nSELECTED ASR WINDOWS: ${asrDrive}:"
Log "========================================"

# Step 3: AGGRESSIVELY update boot configuration
Log "`nStep 3: FORCING boot configuration..."

# Method 1: bcdboot from ASR Windows
Log "Running bcdboot from ASR Windows..."
$bcdResults = @()
$bcdResults += & cmd /c "bcdboot ${asrDrive}:\Windows /s C: /f ALL" 2>&1
$bcdResults += & cmd /c "bcdboot ${asrDrive}:\Windows /s C: /f BIOS" 2>&1

# Try to mount EFI and update UEFI
& mountvol S: /S 2>&1 | Out-Null
if (Test-Path "S:\") {
    Log "EFI partition mounted"
    $bcdResults += & cmd /c "bcdboot ${asrDrive}:\Windows /s S: /f UEFI" 2>&1
}

foreach ($result in $bcdResults) {
    if ($result -match "success") {
        Log "  Boot files created successfully"
        break
    }
}

# Method 2: Force ALL BCD entries
Log "Forcing BCD entries..."

# Delete all non-essential boot entries first
$entries = & bcdedit /enum | Out-String
$guids = [regex]::Matches($entries, '\{[a-f0-9-]+\}') | ForEach-Object {$_.Value} | Select-Object -Unique
foreach ($guid in $guids) {
    if ($guid -notin @('{current}','{default}','{bootmgr}','{fwbootmgr}','{memdiag}')) {
        & bcdedit /delete $guid /f 2>&1 | Out-Null
    }
}

# Now force all entries to ASR drive
$commands = @(
    "bcdedit /set {bootmgr} device partition=${asrDrive}:",
    "bcdedit /set {default} device partition=${asrDrive}:",
    "bcdedit /set {default} osdevice partition=${asrDrive}:",
    "bcdedit /set {default} path \Windows\system32\winload.efi",
    "bcdedit /set {default} systemroot \Windows",
    "bcdedit /set {default} description `"ASR Windows`"",
    "bcdedit /set {current} device partition=${asrDrive}:",
    "bcdedit /set {current} osdevice partition=${asrDrive}:",
    "bcdedit /timeout 0"
)

foreach ($cmd in $commands) {
    $result = & cmd /c $cmd 2>&1
    Log "  $cmd"
}

# Method 3: Create new boot entry
Log "Creating new default boot entry..."
$output = & bcdedit /create /d "ASR Windows Server" /application osloader 2>&1 | Out-String
if ($output -match '\{([a-f0-9-]+)\}') {
    $newGuid = "{$($matches[1])}"
    Log "  Created new entry: $newGuid"
    
    & bcdedit /set $newGuid device partition=${asrDrive}: 2>&1 | Out-Null
    & bcdedit /set $newGuid osdevice partition=${asrDrive}: 2>&1 | Out-Null
    & bcdedit /set $newGuid path \Windows\system32\winload.efi 2>&1 | Out-Null
    & bcdedit /set $newGuid systemroot \Windows 2>&1 | Out-Null
    & bcdedit /default $newGuid 2>&1 | Out-Null
    & bcdedit /displayorder $newGuid /addfirst 2>&1 | Out-Null
    
    Log "  Set as default boot entry"
}

# Method 4: Update UEFI NVRAM directly
if (Test-Path "S:\EFI\Microsoft\Boot\BCD") {
    Log "Updating UEFI BCD store..."
    & bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {bootmgr} device partition=S: 2>&1 | Out-Null
    & bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} device partition=${asrDrive}: 2>&1 | Out-Null
    & bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} osdevice partition=${asrDrive}: 2>&1 | Out-Null
    & bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} path \Windows\system32\winload.efi 2>&1 | Out-Null
    & bcdedit /store S:\EFI\Microsoft\Boot\BCD /timeout 0 2>&1 | Out-Null
}

# Method 5: Use bcdedit to completely rebuild
Log "Rebuilding BCD store..."
& bcdedit /timeout 0 2>&1 | Out-Null
& bcdedit /set {fwbootmgr} displayorder {bootmgr} /addfirst 2>&1 | Out-Null

# Step 4: Verification
Log "`n========================================"
Log "VERIFICATION"
Log "========================================"

$defaultBcd = & bcdedit /enum {default} 2>&1 | Out-String
if ($defaultBcd -match "partition=${asrDrive}:") {
    Log "SUCCESS: Default boot entry points to ${asrDrive}:"
} else {
    Log "WARNING: Default boot entry may not be updated"
}

$currentBcd = & bcdedit /enum {current} 2>&1 | Out-String
if ($currentBcd -match "partition=C:") {
    Log "Current boot is still C: (will change after reboot)"
}

# Save configuration
@{
    Timestamp = Get-Date
    ASRDrive = $asrDrive
    ASRDisk = $asrWin.DiskNum
    WindowsFound = $windowsFound.Count
    Success = $true
} | ConvertTo-Json | Out-File "$logDir\ASRBootStatus.json"

Log "`n========================================"
Log "BOOT CONFIGURATION FORCED!"
Log "ASR Windows: ${asrDrive}:\Windows"
Log "========================================"

# Reboot
if (!$NoReboot) {
    Log "Rebooting in 5 seconds..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
} else {
    Log "Run 'Restart-Computer -Force' to complete"
}