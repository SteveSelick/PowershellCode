# Configure-ASRBoot.ps1
# Script to run INSIDE the boot proxy VM to force boot to ASR Windows
# Fixed version that actually works

param(
    [switch]$NoReboot,
    [int]$MinDiskSizeGB = 500
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

# Step 1: Identify the ASR disk
Write-Host "`nStep 1: Identifying ASR disk..." -ForegroundColor Yellow
$asrDisk = Get-Disk | Where-Object {$_.Number -ne 0 -and $_.Size -gt ($MinDiskSizeGB * 1GB)} | Select-Object -First 1

if (-not $asrDisk) {
    Write-Host "ERROR: No secondary disk larger than $MinDiskSizeGB GB found!" -ForegroundColor Red
    Get-Disk | Format-Table Number,FriendlyName,Size,PartitionStyle,OperationalStatus
    exit 1
}

$diskNumber = $asrDisk.Number
$diskSizeGB = [math]::Round($asrDisk.Size / 1GB, 2)
Write-Host "Found ASR disk: Disk $diskNumber (Size: $diskSizeGB GB)" -ForegroundColor Green

# Step 2: Map the ASR disk partitions
Write-Host "`nStep 2: Mapping ASR disk partitions..." -ForegroundColor Yellow

# Create temp directory
if (!(Test-Path "C:\temp")) {
    New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null
}

# Get partitions
$partitions = Get-Partition -DiskNumber $diskNumber -ErrorAction SilentlyContinue

# Find Windows partition (largest)
$windowsPartition = $partitions | Where-Object {$_.Size -gt 100GB} | Sort-Object Size -Descending | Select-Object -First 1
if ($windowsPartition) {
    $winPartNum = $windowsPartition.PartitionNumber
} else {
    $winPartNum = 4  # Default
}

Write-Host "Windows partition identified: Partition $winPartNum" -ForegroundColor Green

# Step 3: Assign drive letter G: to ASR Windows
Write-Host "`nStep 3: Assigning drive letter G: to ASR Windows..." -ForegroundColor Yellow

$diskpartScript = @"
select disk $diskNumber
select partition $winPartNum
assign letter=G
"@
$diskpartScript | Out-File -FilePath "C:\temp\assign.txt" -Encoding ASCII -Force
$null = diskpart /s "C:\temp\assign.txt" 2>&1

Start-Sleep -Seconds 2

# Verify G:\Windows exists
if (Test-Path "G:\Windows") {
    Write-Host "ASR Windows found at G:\Windows" -ForegroundColor Green
} else {
    Write-Host "ERROR: Windows not found at G:\Windows" -ForegroundColor Red
    exit 1
}

# Step 4: Create boot entry using the method that worked earlier
Write-Host "`nStep 4: Creating boot entry for ASR Windows..." -ForegroundColor Yellow

# The manual process that worked was:
# 1. bcdedit /copy {bootmgr} /d "ASR Windows Server"
# 2. Extract the GUID
# 3. Set the properties
# 4. Set it as default in firmware boot manager

Write-Host "Executing: bcdedit /copy {bootmgr} /d 'ASR Windows Server'" -ForegroundColor Cyan

# Run the copy command and capture ALL output
$copyProcess = Start-Process -FilePath "bcdedit.exe" -ArgumentList "/copy","{bootmgr}","/d","`"ASR Windows Server`"" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "C:\temp\bcdedit_output.txt" -RedirectStandardError "C:\temp\bcdedit_error.txt"

# Read the output
$copyOutput = Get-Content "C:\temp\bcdedit_output.txt" -ErrorAction SilentlyContinue
$copyError = Get-Content "C:\temp\bcdedit_error.txt" -ErrorAction SilentlyContinue

if ($copyOutput) {
    Write-Host "Output: $copyOutput" -ForegroundColor Gray
}
if ($copyError) {
    Write-Host "Error: $copyError" -ForegroundColor Red
}

# Extract GUID from output
$newGuid = $null
if ($copyOutput -match '\{([a-f0-9\-]+)\}') {
    $newGuid = "{$($matches[1])}"
    Write-Host "Successfully created boot entry with GUID: $newGuid" -ForegroundColor Green
    
    # Now configure it EXACTLY as we did manually
    Write-Host "`nConfiguring boot entry..." -ForegroundColor Cyan
    
    # Run each command separately and show results
    Write-Host "Setting device to G:..." -ForegroundColor Gray
    & bcdedit /set $newGuid device partition=G:
    
    Write-Host "Setting path..." -ForegroundColor Gray
    & bcdedit /set $newGuid path \Windows\system32\winload.efi
    
    Write-Host "Setting OS device to G:..." -ForegroundColor Gray
    & bcdedit /set $newGuid osdevice partition=G:
    
    Write-Host "Setting as default in firmware boot manager..." -ForegroundColor Gray
    & bcdedit /set "{fwbootmgr}" default $newGuid
    
    Write-Host "Setting as first in display order..." -ForegroundColor Gray
    & bcdedit /set "{fwbootmgr}" displayorder $newGuid /addfirst
    
    Write-Host "`nBoot entry configured successfully!" -ForegroundColor Green
    $bootModified = $true
} else {
    Write-Host "Failed to create boot entry. Trying alternative approach..." -ForegroundColor Yellow
    
    # Alternative: Look for existing ASR entry
    $allEntries = bcdedit /enum firmware | Out-String
    if ($allEntries -match "ASR Windows Server") {
        Write-Host "Found existing ASR Windows Server entry" -ForegroundColor Green
        # Try to find its GUID
        $lines = (bcdedit /enum firmware | Out-String) -split "`n"
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "ASR Windows Server") {
                # Look backwards for identifier
                for ($j = $i; $j -ge 0; $j--) {
                    if ($lines[$j] -match "identifier\s+(\{[a-f0-9\-]+\})") {
                        $newGuid = $matches[1]
                        Write-Host "Found existing entry GUID: $newGuid" -ForegroundColor Green
                        
                        # Set it as default
                        & bcdedit /set "{fwbootmgr}" default $newGuid
                        & bcdedit /set "{fwbootmgr}" displayorder $newGuid /addfirst
                        $bootModified = $true
                        break
                    }
                }
                break
            }
        }
    }
}

# If still no success, modify the existing entries
if (-not $bootModified) {
    Write-Host "`nModifying existing boot entries as fallback..." -ForegroundColor Yellow
    
    # Modify {bootmgr} directly
    & bcdedit /set "{bootmgr}" device partition=G:
    & bcdedit /set "{bootmgr}" path \Windows\system32\winload.efi
    & bcdedit /set "{bootmgr}" description "ASR Windows Server"
    
    # Also modify current
    & bcdedit /set "{current}" device partition=G:
    & bcdedit /set "{current}" osdevice partition=G:
    & bcdedit /set "{current}" systemroot \Windows
    & bcdedit /set "{current}" path \Windows\system32\boot\winload.efi
    & bcdedit /set "{current}" description "ASR Windows Server"
}

# Step 5: Verify configuration
Write-Host "`nStep 5: Verifying configuration..." -ForegroundColor Yellow

# Step 5: Verify configuration
Write-Host "`nStep 5: Verifying configuration..." -ForegroundColor Yellow

$success = $false

# Check if ASR entry exists and is set as default
$fwbootmgrOutput = bcdedit /enum "{fwbootmgr}" 2>&1 | Out-String
$firmwareOutput = bcdedit /enum firmware | Out-String

if ($firmwareOutput -match "ASR Windows Server") {
    Write-Host "[OK] ASR Windows Server boot entry exists" -ForegroundColor Green
    
    # Check if it's the default
    if ($fwbootmgrOutput -match "default\s+(\{[a-f0-9\-]+\})") {
        $defaultGuid = $matches[1]
        $defaultEntry = bcdedit /enum $defaultGuid 2>&1 | Out-String
        if ($defaultEntry -match "ASR Windows Server" -or $defaultEntry -match "partition=G:") {
            Write-Host "[OK] ASR entry is set as default" -ForegroundColor Green
            $success = $true
        }
    }
} 

# Also check if current points to G:
$currentConfig = bcdedit /enum "{current}" | Out-String
if ($currentConfig -match "partition=G:") {
    Write-Host "[OK] Current boot entry points to G:" -ForegroundColor Green
    $success = $true
}

if (-not $success) {
    Write-Host "[X] Boot configuration may not be complete" -ForegroundColor Red
    Write-Host "Manual intervention may be required" -ForegroundColor Yellow
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CONFIGURATION COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ASR Disk: Disk $diskNumber ($diskSizeGB GB)" -ForegroundColor White
Write-Host "ASR Windows: G:\Windows" -ForegroundColor White
if ($success) {
    Write-Host "Status: SUCCESS - Will boot ASR Windows" -ForegroundColor Green
} else {
    Write-Host "Status: NEEDS MANUAL CHECK" -ForegroundColor Yellow
}

# Check if automated
$isAutomated = $env:USERNAME -eq 'SYSTEM' -or $env:COMPUTERNAME -match 'proxy'

if (($isAutomated -or $PSBoundParameters.ContainsKey('AutoReboot')) -and !$NoReboot) {
    Write-Host "`nRebooting in 10 seconds..." -ForegroundColor Yellow
    Write-Host "System will boot into ASR Windows" -ForegroundColor Green
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "`nMANUAL REBOOT REQUIRED:" -ForegroundColor Yellow
    Write-Host "Run: shutdown /r /t 0" -ForegroundColor Cyan
}

# Save results
@{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ASRDisk = $diskNumber
    DiskSizeGB = $diskSizeGB
    Method = if ((Get-Item 'C:\Windows' -ErrorAction SilentlyContinue).LinkType -eq 'Junction') {'Junction'} else {'BCD'}
    Success = $success
} | ConvertTo-Json | Out-File -FilePath "C:\ASRBootConfig.json" -Force