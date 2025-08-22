# Configure-ASRBoot.ps1
# Universal ASR Boot Configuration Script v2.1
# Configures boot from ASR replicated disk in Azure VMs
# Auto-handles SYSTEM context by scheduling task as local admin

param(
    [switch]$NoReboot,
    [switch]$ForceReboot,
    [switch]$Verbose,
    [string]$LogPath = "C:\temp\ASRBootConfig.log",
    [switch]$RunningFromTask  # Internal parameter to indicate task execution
)

# Initialize script
$ErrorActionPreference = "Stop"
$script:LogMessages = @()
$script:HasErrors = $false

# Ensure temp directory exists
New-Item -ItemType Directory -Path "C:\temp" -Force -ErrorAction SilentlyContinue | Out-Null

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    $script:LogMessages += $logEntry
    
    # Write to file immediately
    $logEntry | Out-File -FilePath $LogPath -Append -Force -ErrorAction SilentlyContinue
    
    # Console output with colors
    switch ($Level) {
        "Error" { 
            Write-Host $Message -ForegroundColor Red
            $script:HasErrors = $true
        }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Success" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor Gray }
    }
}

# Function to check if running as SYSTEM
function Test-RunningAsSystem {
    return $env:USERNAME -eq "SYSTEM"
}

# Function to handle SYSTEM context by creating scheduled task
function Handle-SystemContext {
    Write-Log "=========================================" -Level Info
    Write-Log "SYSTEM CONTEXT DETECTED" -Level Warning
    Write-Log "=========================================" -Level Info
    Write-Log "Running as SYSTEM - will create scheduled task for local admin" -Level Info
    
    try {
        # Known credentials for boot proxy VMs
        $adminUser = "bootadmin"
        $adminPassword = "TempP@ss2024!"
        
        Write-Log "Creating scheduled task to run as $adminUser" -Level Info
        
        # Create the task action - download and run the script with RunningFromTask flag
        $taskName = "ASRBootConfig_Admin"
        $scriptCommand = @"
powershell.exe -ExecutionPolicy Bypass -Command "& {
    # Ensure temp directory exists
    New-Item -ItemType Directory -Path 'C:\temp' -Force -ErrorAction SilentlyContinue | Out-Null
    
    # Download the script
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    `$url = 'https://raw.githubusercontent.com/SteveSelick/PowershellCode/main/Configure-ASRBoot.ps1'
    `$scriptPath = 'C:\temp\Configure-ASRBoot.ps1'
    
    Write-Host 'Downloading Configure-ASRBoot.ps1...'
    Invoke-WebRequest -Uri `$url -OutFile `$scriptPath -UseBasicParsing
    
    # Run the script with RunningFromTask flag
    Write-Host 'Executing Configure-ASRBoot.ps1 as $adminUser...'
    & `$scriptPath -RunningFromTask -NoReboot
}"
"@
        
        # Create scheduled task XML with credentials
        $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</Date>
    <Author>ASRBootConfig</Author>
    <Description>Run ASR Boot Configuration as local admin</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>$(Get-Date (Get-Date).AddSeconds(30) -Format 'yyyy-MM-ddTHH:mm:ss')</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$adminUser</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
    <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c $scriptCommand</Arguments>
    </Exec>
  </Actions>
</Task>
"@
        
        # Save XML to temp file
        $xmlPath = "C:\temp\ASRBootTask.xml"
        $taskXml | Out-File -FilePath $xmlPath -Encoding Unicode -Force
        
        # Register the task with credentials
        Write-Log "Registering scheduled task '$taskName'" -Level Info
        $registerResult = schtasks /create /tn "$taskName" /xml "$xmlPath" /ru "$adminUser" /rp "$adminPassword" /f 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Scheduled task created successfully" -Level Success
            Write-Log "Task will run in 30 seconds as $adminUser" -Level Info
            
            # Wait for the task to start and complete
            Write-Log "Waiting for task to start..." -Level Info
            Start-Sleep -Seconds 35  # Wait for task to trigger
            
            # Monitor task execution
            $maxWait = 120  # Max 2 minutes
            $waited = 0
            $taskCompleted = $false
            
            while ($waited -lt $maxWait) {
                $taskInfo = schtasks /query /tn "$taskName" /fo CSV | ConvertFrom-Csv
                $taskStatus = $taskInfo.Status
                
                if ($taskStatus -eq "Ready") {
                    # Task completed
                    Write-Log "Task completed successfully" -Level Success
                    $taskCompleted = $true
                    break
                } elseif ($taskStatus -eq "Running") {
                    Write-Log "Task is running... (waited $waited seconds)" -Level Info
                } else {
                    Write-Log "Task status: $taskStatus" -Level Info
                }
                
                Start-Sleep -Seconds 5
                $waited += 5
            }
            
            if (!$taskCompleted) {
                Write-Log "Warning: Task did not complete within expected time" -Level Warning
            }
            
            # Check if configuration was successful by looking for the config file
            if (Test-Path "C:\ASRBootConfig.json") {
                $config = Get-Content "C:\ASRBootConfig.json" | ConvertFrom-Json
                if ($config.Success) {
                    Write-Log "Boot configuration completed successfully!" -Level Success
                    
                    # Delete the scheduled task
                    Write-Log "Removing scheduled task" -Level Info
                    schtasks /delete /tn "$taskName" /f 2>&1 | Out-Null
                    
                    # Clean up XML file
                    Remove-Item -Path $xmlPath -Force -ErrorAction SilentlyContinue
                    
                    # Reboot the system
                    Write-Log "Initiating system reboot in 10 seconds..." -Level Info
                    shutdown /r /t 10 /f /c "ASR Boot Configuration Complete - Rebooting to apply changes"
                    
                    Write-Log "=========================================" -Level Info
                    Write-Log "SYSTEM WILL REBOOT IN 10 SECONDS" -Level Success
                    Write-Log "=========================================" -Level Info
                    
                    return $true
                } else {
                    Write-Log "Configuration failed: $($config.ErrorMessage)" -Level Error
                }
            } else {
                Write-Log "Configuration file not found - task may have failed" -Level Error
            }
            
            # Clean up task if still exists
            schtasks /delete /tn "$taskName" /f 2>&1 | Out-Null
            
        } else {
            Write-Log "Failed to create scheduled task: $registerResult" -Level Error
        }
        
        return $false
        
    } catch {
        Write-Log "Error handling SYSTEM context: $_" -Level Error
        return $false
    }
}

# Function to prepare disks
function Initialize-Disks {
    Write-Log "Initializing disk configuration..." -Level Info
    
    try {
        # Get all disks
        $disks = Get-Disk
        $disksPrepared = 0
        
        foreach ($disk in $disks) {
            $changes = @()
            
            # Check if disk needs to be brought online
            if ($disk.OperationalStatus -eq 'Offline') {
                try {
                    Set-Disk -Number $disk.Number -IsOffline $false
                    $changes += "brought online"
                    Write-Log "Disk $($disk.Number): Brought online" -Level Success
                } catch {
                    Write-Log "Disk $($disk.Number): Failed to bring online - $_" -Level Warning
                }
            }
            
            # Check if disk is read-only
            if ($disk.IsReadOnly) {
                try {
                    Set-Disk -Number $disk.Number -IsReadOnly $false
                    $changes += "read-only removed"
                    Write-Log "Disk $($disk.Number): Removed read-only flag" -Level Success
                } catch {
                    Write-Log "Disk $($disk.Number): Failed to remove read-only - $_" -Level Warning
                }
            }
            
            if ($changes.Count -gt 0) {
                $disksPrepared++
            }
        }
        
        if ($disksPrepared -gt 0) {
            Write-Log "Prepared $disksPrepared disk(s) for configuration" -Level Success
            Start-Sleep -Seconds 3  # Give disks time to fully initialize
        }
        
        return $true
    } catch {
        Write-Log "Error during disk initialization: $_" -Level Error
        return $false
    }
}

# Function to find ASR Windows installation
function Find-ASRWindows {
    Write-Log "Searching for ASR Windows installation..." -Level Info
    
    $windowsInstallations = @()
    
    # Get all volumes with drive letters
    $volumes = Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveLetter -ne 'C' }
    
    foreach ($volume in $volumes) {
        $driveLetter = $volume.DriveLetter
        $windowsPath = "${driveLetter}:\Windows"
        $systemPath = "${driveLetter}:\Windows\System32"
        
        if ((Test-Path $windowsPath) -and (Test-Path $systemPath)) {
            # Check if it's the ASR disk (usually larger than boot proxy disk)
            $sizeGB = [math]::Round($volume.Size / 1GB, 2)
            
            # Get more details about this Windows installation
            $buildInfo = $null
            $registryPath = "${driveLetter}:\Windows\System32\config\SOFTWARE"
            
            $installation = [PSCustomObject]@{
                DriveLetter = $driveLetter
                Volume = $volume
                SizeGB = $sizeGB
                WindowsPath = $windowsPath
                IsLikelyASR = $sizeGB -gt 150  # ASR disks are typically larger
            }
            
            $windowsInstallations += $installation
            
            Write-Log "Found Windows on drive $driveLetter (Size: $sizeGB GB)" -Level Info
        }
    }
    
    # Sort by size (largest first) and prefer likely ASR disks
    $windowsInstallations = $windowsInstallations | Sort-Object -Property IsLikelyASR, SizeGB -Descending
    
    if ($windowsInstallations.Count -eq 0) {
        Write-Log "No Windows installations found on attached disks" -Level Error
        return $null
    }
    
    if ($windowsInstallations.Count -eq 1) {
        Write-Log "Found single Windows installation on drive $($windowsInstallations[0].DriveLetter)" -Level Success
        return $windowsInstallations[0]
    }
    
    # Multiple installations found - select the most likely ASR disk
    $selected = $windowsInstallations[0]
    Write-Log "Multiple Windows installations found. Selecting drive $($selected.DriveLetter) (largest: $($selected.SizeGB) GB)" -Level Info
    
    return $selected
}

# Function to find and prepare EFI partition
function Prepare-EFIPartition {
    param(
        [Parameter(Mandatory=$true)]
        $ASRDisk
    )
    
    Write-Log "Preparing EFI partition..." -Level Info
    
    try {
        # Find the disk number for the ASR volume
        $partition = Get-Partition -DriveLetter $ASRDisk.DriveLetter -ErrorAction SilentlyContinue
        if (!$partition) {
            Write-Log "Could not find partition for drive $($ASRDisk.DriveLetter)" -Level Error
            return $null
        }
        
        $diskNumber = $partition.DiskNumber
        Write-Log "ASR disk identified as Disk $diskNumber" -Level Info
        
        # Find EFI partition on the same disk
        $efiPartition = Get-Partition -DiskNumber $diskNumber | Where-Object { $_.Type -eq 'System' }
        
        if (!$efiPartition) {
            # Try to find EFI on disk 0 (boot disk)
            Write-Log "No EFI partition on ASR disk, checking boot disk..." -Level Warning
            $efiPartition = Get-Partition -DiskNumber 0 | Where-Object { $_.Type -eq 'System' }
        }
        
        if (!$efiPartition) {
            Write-Log "No EFI partition found on any disk" -Level Error
            return $null
        }
        
        Write-Log "Found EFI partition: Disk $($efiPartition.DiskNumber), Partition $($efiPartition.PartitionNumber)" -Level Success
        
        # Check if EFI partition has a drive letter
        if (!$efiPartition.DriveLetter) {
            Write-Log "EFI partition needs drive letter assignment" -Level Info
            
            # Use diskpart to assign drive letter
            $diskpartScript = @"
select disk $($efiPartition.DiskNumber)
select partition $($efiPartition.PartitionNumber)
assign letter=S
exit
"@
            $scriptPath = "C:\temp\assign_efi.txt"
            $diskpartScript | Out-File -FilePath $scriptPath -Encoding ASCII -Force
            
            $result = Start-Process -FilePath "diskpart.exe" -ArgumentList "/s `"$scriptPath`"" -Wait -NoNewWindow -PassThru
            
            if ($result.ExitCode -eq 0) {
                Write-Log "Successfully assigned drive letter S to EFI partition" -Level Success
                Start-Sleep -Seconds 2
                
                # Refresh partition info
                $efiPartition = Get-Partition -DiskNumber $efiPartition.DiskNumber -PartitionNumber $efiPartition.PartitionNumber
            } else {
                Write-Log "Failed to assign drive letter to EFI partition using diskpart" -Level Error
                return $null
            }
        }
        
        return $efiPartition
        
    } catch {
        Write-Log "Error preparing EFI partition: $_" -Level Error
        return $null
    }
}

# Function to configure boot
function Set-BootConfiguration {
    param(
        [Parameter(Mandatory=$true)]
        $ASRDisk,
        [Parameter(Mandatory=$true)]
        $EFIPartition
    )
    
    Write-Log "Configuring boot for ASR Windows..." -Level Info
    
    try {
        $asrDriveLetter = $ASRDisk.DriveLetter
        $efiDriveLetter = if ($EFIPartition.DriveLetter) { $EFIPartition.DriveLetter } else { "S" }
        
        # Run bcdboot to create boot files
        Write-Log "Running bcdboot from ${asrDriveLetter}:\Windows to ${efiDriveLetter}:" -Level Info
        
        $bcdbootCmd = "bcdboot ${asrDriveLetter}:\Windows /s ${efiDriveLetter}: /f UEFI"
        Write-Log "Executing: $bcdbootCmd" -Level Info
        
        $result = Invoke-Expression $bcdbootCmd 2>&1
        $resultString = if ($result) { $result -join "`n" } else { "No output" }
        
        if ($LASTEXITCODE -eq 0 -or $resultString -like "*successfully*") {
            Write-Log "Boot files created successfully" -Level Success
            Write-Log "Output: $resultString" -Level Info
            
            # Verify boot files were created
            $bootFilePath = "${efiDriveLetter}:\EFI\Microsoft\Boot\BCD"
            if (Test-Path $bootFilePath) {
                Write-Log "Verified: Boot files exist at $bootFilePath" -Level Success
                return $true
            } else {
                Write-Log "Warning: Could not verify boot files at $bootFilePath" -Level Warning
                # Still return true as bcdboot reported success
                return $true
            }
        } else {
            Write-Log "bcdboot failed with exit code: $LASTEXITCODE" -Level Error
            Write-Log "Output: $resultString" -Level Error
            return $false
        }
        
    } catch {
        Write-Log "Error configuring boot: $_" -Level Error
        return $false
    }
}

# Function to save configuration status
function Save-ConfigurationStatus {
    param(
        [bool]$Success,
        [string]$ASRDriveLetter = "",
        [string]$ErrorMessage = ""
    )
    
    $config = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Success = $Success
        Status = if ($Success) { "Configured" } else { "Failed" }
        ASRDriveLetter = $ASRDriveLetter
        ComputerName = $env:COMPUTERNAME
        RunAsSystem = Test-RunningAsSystem
        RunFromTask = $RunningFromTask
        ErrorMessage = $ErrorMessage
        LogPath = $LogPath
    }
    
    $configPath = "C:\ASRBootConfig.json"
    $config | ConvertTo-Json | Out-File -FilePath $configPath -Force
    
    Write-Log "Configuration status saved to $configPath" -Level Info
    
    return $config
}

# Main execution
try {
    Write-Log "=========================================" -Level Info
    Write-Log "ASR Boot Configuration Script v2.1" -Level Info
    Write-Log "=========================================" -Level Info
    Write-Log "Computer: $env:COMPUTERNAME" -Level Info
    Write-Log "User: $env:USERNAME" -Level Info
    Write-Log "Running as SYSTEM: $(Test-RunningAsSystem)" -Level Info
    Write-Log "Running from Task: $RunningFromTask" -Level Info
    Write-Log "Script Parameters: NoReboot=$NoReboot, ForceReboot=$ForceReboot" -Level Info
    
    # Check if running as SYSTEM and not from a scheduled task
    if ((Test-RunningAsSystem) -and !$RunningFromTask) {
        # Handle SYSTEM context by creating scheduled task
        $handled = Handle-SystemContext
        if ($handled) {
            Write-Log "Configuration delegated to scheduled task successfully" -Level Success
            exit 0
        } else {
            Write-Log "Failed to handle SYSTEM context via scheduled task" -Level Error
            exit 1
        }
    }
    
    # If we get here, we're either running as a user or from the scheduled task
    Write-Log "Proceeding with boot configuration..." -Level Info
    
    # Step 1: Initialize disks
    if (!(Initialize-Disks)) {
        throw "Failed to initialize disks"
    }
    
    # Step 2: Find ASR Windows
    $asrDisk = Find-ASRWindows
    if (!$asrDisk) {
        throw "No ASR Windows installation found"
    }
    
    # Step 3: Prepare EFI partition
    $efiPartition = Prepare-EFIPartition -ASRDisk $asrDisk
    if (!$efiPartition) {
        throw "Failed to prepare EFI partition"
    }
    
    # Step 4: Configure boot
    $bootConfigured = Set-BootConfiguration -ASRDisk $asrDisk -EFIPartition $efiPartition
    if (!$bootConfigured) {
        throw "Failed to configure boot"
    }
    
    # Step 5: Save configuration status
    $config = Save-ConfigurationStatus -Success $true -ASRDriveLetter $asrDisk.DriveLetter
    
    Write-Log "=========================================" -Level Info
    Write-Log "CONFIGURATION COMPLETED SUCCESSFULLY" -Level Success
    Write-Log "=========================================" -Level Info
    Write-Log "ASR Windows: Drive $($asrDisk.DriveLetter)" -Level Success
    Write-Log "Boot files configured on EFI partition" -Level Success
    
    # Handle reboot (don't reboot if we're running from task - let SYSTEM context handle it)
    if ($RunningFromTask) {
        Write-Log "Configuration complete - returning to SYSTEM context for reboot" -Level Info
        # Create success marker
        "Boot configuration completed at $(Get-Date)" | Out-File -FilePath "C:\temp\ASRBootSuccess.txt" -Force
    } elseif ($ForceReboot -or !$NoReboot) {
        Write-Log "Initiating system reboot in 10 seconds..." -Level Info
        Write-Log "To cancel reboot, run: shutdown /a" -Level Warning
        
        # Create success marker before reboot
        "Boot configuration completed at $(Get-Date)" | Out-File -FilePath "C:\temp\ASRBootSuccess.txt" -Force
        
        shutdown /r /t 10 /f /c "ASR Boot Configuration Complete - Rebooting to apply changes"
        
        Write-Log "Reboot scheduled" -Level Success
    } else {
        Write-Log "Reboot suppressed by NoReboot parameter" -Level Warning
        Write-Log "Manual reboot required to complete configuration" -Level Warning
    }
    
} catch {
    $errorMsg = $_.Exception.Message
    Write-Log "CONFIGURATION FAILED: $errorMsg" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    
    # Save failure status
    Save-ConfigurationStatus -Success $false -ErrorMessage $errorMsg
    
    # If running interactively, provide troubleshooting steps
    if (!(Test-RunningAsSystem) -and !$RunningFromTask) {
        Write-Log "" -Level Info
        Write-Log "TROUBLESHOOTING STEPS:" -Level Warning
        Write-Log "1. Check disk status: Get-Disk | Format-Table" -Level Info
        Write-Log "2. Verify Windows installations: Get-Volume | Where DriveLetter" -Level Info
        Write-Log "3. Review log file: Get-Content $LogPath" -Level Info
        Write-Log "4. Run with -Verbose flag for more details" -Level Info
    }
    
    # Don't throw if running as SYSTEM or from task (to avoid RunCommand failures)
    if (!(Test-RunningAsSystem) -and !$RunningFromTask) {
        throw
    }
} finally {
    # Ensure log is saved
    if ($script:LogMessages.Count -gt 0) {
        $script:LogMessages | Out-File -FilePath $LogPath -Force
    }
    
    Write-Log "Log file saved to: $LogPath" -Level Info
    
    # Create summary file for easy checking
    $summaryPath = "C:\temp\ASRBootSummary.txt"
    $summary = @"
ASR Boot Configuration Summary
==============================
Timestamp: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Status: $(if (!$script:HasErrors) { "SUCCESS" } else { "FAILED" })
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Running from Task: $RunningFromTask
Log File: $LogPath

$(if ($asrDisk) { "ASR Windows Found: Drive $($asrDisk.DriveLetter)" } else { "ASR Windows: Not Found" })
$(if ($efiPartition) { "EFI Partition: Configured" } else { "EFI Partition: Not Configured" })
$(if ($bootConfigured) { "Boot Configuration: Complete" } else { "Boot Configuration: Failed" })

Next Step: $(if (!$script:HasErrors -and !$NoReboot) { "System will reboot automatically" } elseif (!$script:HasErrors) { "Manual reboot required" } else { "Review errors and retry" })
"@
    
    $summary | Out-File -FilePath $summaryPath -Force
    
    if ($Verbose) {
        Write-Host "`nSummary saved to: $summaryPath" -ForegroundColor Cyan
        Get-Content $summaryPath
    }
}