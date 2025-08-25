# BootProxyCreate.ps1 - v2.6 (With Server Names in Status Messages)
# Creates a boot proxy VM for ASR failover testing

param(
    [Parameter(Mandatory=$true)]
    [string[]]$ServerNames,
    
    [string]$ResourceGroup = "PinnacleAssociates-Migrate-rg",
    [string]$VNet = "",  # Will be auto-detected from test VM
    [string]$Subnet = "",  # Will be auto-detected from test VM
    [string]$ProxyNameSuffix = "bootproxy",
    [string]$TestNameSuffix = "test",
    [switch]$SkipAutoConfig,  # Skip automatic boot configuration
    [switch]$WhatIf
)

# Import required modules
Write-Host "Checking PowerShell modules..." -ForegroundColor Yellow
$requiredModules = @('Az.Compute', 'Az.Network', 'Az.Storage')
foreach ($module in $requiredModules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing module: $module" -ForegroundColor Yellow
        Install-Module -Name $module -Force -AllowClobber
    }
    Import-Module $module -ErrorAction SilentlyContinue
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "BOOT PROXY CREATION SCRIPT v2.6" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Processing $($ServerNames.Count) server(s): $($ServerNames -join ', ')" -ForegroundColor White
Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

# Connect to Azure if not already connected
$context = Get-AzContext
if (!$context) {
    Write-Host "Please login to Azure..." -ForegroundColor Yellow
    Connect-AzAccount
}

foreach ($ServerName in $ServerNames) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "PROCESSING: $ServerName" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $testVMName = "$ServerName-$TestNameSuffix"
    $proxyVMName = "$($ServerName.ToUpper())-$ProxyNameSuffix"
    
    # Generate computer name (max 15 chars)
    $computerName = $ServerName.ToUpper() -replace '[^A-Z0-9]', ''
    if ($computerName.Length -gt 15) {
        # Try to shorten intelligently
        $computerName = $computerName -replace 'SERVER', 'SRV'
        $computerName = $computerName -replace 'ADVENT', 'ADV'
        if ($computerName.Length -gt 15) {
            $computerName = $computerName.Substring(0, 15)
        }
    }
    
    Write-Host "$ServerName - Test VM: $testVMName" -ForegroundColor Gray
    Write-Host "$ServerName - Proxy VM: $proxyVMName" -ForegroundColor Gray
    Write-Host "$ServerName - Computer Name: $computerName" -ForegroundColor Gray
    
    if ($WhatIf) {
        Write-Host "[WHATIF] Would process $ServerName" -ForegroundColor Yellow
        continue
    }
    
    # Check if proxy VM already exists
    Write-Host "`n$ServerName - Checking for existing proxy VM..." -ForegroundColor Yellow
    $existingProxy = Get-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName -ErrorAction SilentlyContinue
    if ($existingProxy) {
        Write-Host "$ServerName - WARNING: Proxy VM $proxyVMName already exists!" -ForegroundColor Red
        $response = Read-Host "Do you want to delete it and recreate? (yes/no)"
        if ($response -ne 'yes') {
            Write-Host "$ServerName - Skipping..." -ForegroundColor Yellow
            continue
        }
        
        Write-Host "$ServerName - Removing existing proxy VM..." -ForegroundColor Yellow
        Stop-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName -Force
        Remove-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName -Force
        
        # Clean up associated resources
        Remove-AzNetworkInterface -ResourceGroupName $ResourceGroup -Name "$proxyVMName-nic" -Force -ErrorAction SilentlyContinue
        Remove-AzDisk -ResourceGroupName $ResourceGroup -Name "$proxyVMName-osdisk" -Force -ErrorAction SilentlyContinue
    }
    
    # Step 1: Get test VM details
    Write-Host "`n$ServerName - Step 1: Getting test VM details..." -ForegroundColor Yellow
    $testVM = Get-AzVM -ResourceGroupName $ResourceGroup -Name $testVMName -ErrorAction SilentlyContinue
    
    if (!$testVM) {
        Write-Host "$ServerName - ERROR: Test VM $testVMName not found!" -ForegroundColor Red
        continue
    }
    
    # Get VM size and priority from test VM
    $vmSize = $testVM.HardwareProfile.VmSize
    $vmPriority = $testVM.Priority  # Will be "Regular" for normal VMs
    Write-Host "$ServerName - Test VM size: $vmSize" -ForegroundColor Gray
    Write-Host "$ServerName - Test VM priority: $vmPriority" -ForegroundColor Gray
    
    # Get network configuration from test VM
    Write-Host "$ServerName - Getting network configuration from test VM..." -ForegroundColor Yellow
    $testNicId = $testVM.NetworkProfile.NetworkInterfaces[0].Id
    $testNic = Get-AzNetworkInterface -ResourceId $testNicId
    $testSubnetId = $testNic.IpConfigurations[0].Subnet.Id
    
    # Extract VNet and Subnet info from the subnet ID
    # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}
    $vnetName = $testSubnetId.Split('/')[8]
    $subnetName = $testSubnetId.Split('/')[10]
    $vnetRG = $testSubnetId.Split('/')[4]
    
    Write-Host "$ServerName - Test VM network config:" -ForegroundColor Gray
    Write-Host "$ServerName -   VNet: $vnetName (in RG: $vnetRG)" -ForegroundColor Gray
    Write-Host "$ServerName -   Subnet: $subnetName" -ForegroundColor Gray
    
    # Step 2: Stop and remove test VM (keep disks)
    Write-Host "`n$ServerName - Step 2: Stopping and removing test VM (keeping disks)..." -ForegroundColor Yellow
    Stop-AzVM -ResourceGroupName $ResourceGroup -Name $testVMName -Force
    Remove-AzVM -ResourceGroupName $ResourceGroup -Name $testVMName -Force
    
    # Wait for disks to be released
    Write-Host "$ServerName - Waiting for disks to be released..." -ForegroundColor Gray
    Start-Sleep -Seconds 10
    
    # Step 3: Find the ASR disks
    Write-Host "`n$ServerName - Step 3: Finding ASR disks from test VM..." -ForegroundColor Yellow
    
    # Find all disks that are from the test VM and are not attached
    # Handle both hyphen and underscore in names (apx-db3 vs apx_db3)
    $searchBase = $ServerName -replace "-", "[-_]"  # This makes "apx-db3" match both "apx-db3" and "apx_db3"
    
    $asrDisks = Get-AzDisk -ResourceGroupName $ResourceGroup | Where-Object {
        ($_.Name -like "*$searchBase*test*" -or $_.Name -like "*$testVMName*") -and 
        $_.ManagedBy -eq $null
    }
    
    if ($asrDisks.Count -eq 0) {
        Write-Host "$ServerName - ERROR: No unattached ASR disks found for $testVMName!" -ForegroundColor Red
        Write-Host "$ServerName - Looking for pattern: *$searchBase*test* or *$testVMName*" -ForegroundColor Yellow
        
        # Show all unattached disks for debugging
        $unattachedDisks = Get-AzDisk -ResourceGroupName $ResourceGroup | Where-Object { $_.ManagedBy -eq $null }
        if ($unattachedDisks) {
            Write-Host "$ServerName - Available unattached disks:" -ForegroundColor Yellow
            $unattachedDisks | ForEach-Object { Write-Host "$ServerName -   - $($_.Name)" -ForegroundColor Gray }
        }
        continue
    }
    
    # Identify OS disk (usually the first one or has specific naming)
    $asrOSDisk = $asrDisks | Where-Object { 
        $_.Name -like "PHYSICALDRIVE0*" -or 
        $_.Name -like "*OS*" -or 
        $_.OsType -ne $null 
    } | Select-Object -First 1
    
    if (!$asrOSDisk) {
        # If no obvious OS disk, take the first disk
        $asrOSDisk = $asrDisks | Select-Object -First 1
    }
    
    # Other disks are data disks
    $asrDataDisks = $asrDisks | Where-Object { $_.Id -ne $asrOSDisk.Id }
    
    Write-Host "$ServerName - Found ASR OS disk: $($asrOSDisk.Name) ($([math]::Round($asrOSDisk.DiskSizeGB, 0)) GB)" -ForegroundColor Green
    
    if ($asrDataDisks.Count -gt 0) {
        Write-Host "$ServerName - Found $($asrDataDisks.Count) additional data disk(s)" -ForegroundColor Green
        foreach ($disk in $asrDataDisks) {
            Write-Host "$ServerName -   - $($disk.Name) ($([math]::Round($disk.DiskSizeGB, 0)) GB)" -ForegroundColor Gray
        }
    }
    
    # Step 4: Create boot proxy VM
    Write-Host "`n$ServerName - Step 4: Creating Gen2 boot proxy VM..." -ForegroundColor Yellow
    
    # We already have the subnet ID from the test VM - just use it directly!
    $subnetId = $testSubnetId
    
    # Get the VNet object for location info
    $vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $vnetRG
    
    if (!$vnet) {
        Write-Host "$ServerName - ERROR: VNet '$vnetName' not found in resource group '$vnetRG'!" -ForegroundColor Red
        continue
    }
    
    Write-Host "$ServerName - Using network config from test VM:" -ForegroundColor Green
    Write-Host "$ServerName -   VNet: $vnetName" -ForegroundColor Gray
    Write-Host "$ServerName -   Subnet: $subnetName" -ForegroundColor Gray
    Write-Host "$ServerName -   Subnet ID: $subnetId" -ForegroundColor Gray
    
    # Create NIC for proxy VM
    $nicName = "$proxyVMName-nic"
    # Use the test VM's location instead of the vnet location
    $location = $testVM.Location
    $nic = New-AzNetworkInterface -Name $nicName -ResourceGroupName $ResourceGroup `
        -Location $location -SubnetId $subnetId -Force
    
    # Create VM config matching the test VM's configuration
    if ($vmPriority -eq "Spot" -or $vmPriority -eq "Low") {
        $bootProxyVM = New-AzVMConfig -VMName $proxyVMName -VMSize $vmSize -Priority "Spot" -MaxPrice -1
    } else {
        # Regular VM (same as test VM)
        $bootProxyVM = New-AzVMConfig -VMName $proxyVMName -VMSize $vmSize
    }
    
    # Set as Gen2 VM with standard credentials
    $adminUser = "bootadmin"
    $adminPassword = ConvertTo-SecureString "TempP@ss2024!" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($adminUser, $adminPassword)
    
    $bootProxyVM = Set-AzVMOperatingSystem -VM $bootProxyVM -Windows -ComputerName $computerName `
        -Credential $cred
    
    $bootProxyVM = Add-AzVMNetworkInterface -VM $bootProxyVM -Id $nic.Id
    
    # Use Windows Server 2022 Gen2 image
    $bootProxyVM = Set-AzVMSourceImage -VM $bootProxyVM `
        -PublisherName "MicrosoftWindowsServer" `
        -Offer "WindowsServer" `
        -Skus "2022-datacenter-g2" `
        -Version "latest"
    
    # Set OS disk (small 127GB disk for boot proxy)
    $bootProxyVM = Set-AzVMOSDisk -VM $bootProxyVM `
        -Name "$proxyVMName-osdisk" `
        -CreateOption FromImage `
        -DiskSizeInGB 127 `
        -StorageAccountType "Premium_LRS" `
        -Windows
    
    # Enable boot diagnostics with managed storage (no separate storage account needed)
    $bootProxyVM = Set-AzVMBootDiagnostic -VM $bootProxyVM -Enable
    
    # Create the VM
    Write-Host "$ServerName - Using VM size: $vmSize" -ForegroundColor Gray
    Write-Host "$ServerName - Creating VM..." -ForegroundColor Yellow
    New-AzVM -ResourceGroupName $ResourceGroup -Location $location -VM $bootProxyVM
    
    # Step 5: Wait for VM to be ready
    Write-Host "`n$ServerName - Step 5: Waiting for VM to be ready..." -ForegroundColor Yellow
    $maxWait = 60
    $waited = 0
    while ($waited -lt $maxWait) {
        $vm = Get-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName -Status
        if ($vm.Statuses[1].Code -eq "PowerState/running") {
            Write-Host "$ServerName - VM is running" -ForegroundColor Green
            break
        }
        Write-Host "." -NoNewline
        Start-Sleep -Seconds 5
        $waited += 5
    }
    
    # Step 6: Stop VM to attach disks
    Write-Host "`n`n$ServerName - Step 6: Stopping proxy VM to attach disks..." -ForegroundColor Yellow
    Stop-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName -Force
    
    # Step 7: Attach ASR disks
    Write-Host "`n$ServerName - Step 7: Attaching ASR disks..." -ForegroundColor Yellow
    
    # Get the VM object
    $bootProxyVM = Get-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName
    
    # Attach ASR OS disk as data disk at LUN 0
    Write-Host "$ServerName - Attaching ASR OS disk: $($asrOSDisk.Name) at LUN 0" -ForegroundColor Gray
    $bootProxyVM = Add-AzVMDataDisk -VM $bootProxyVM -Name $asrOSDisk.Name `
        -CreateOption Attach -ManagedDiskId $asrOSDisk.Id -Lun 0
    
    # Attach additional data disks
    $lun = 1
    foreach ($disk in $asrDataDisks) {
        Write-Host "$ServerName - Attaching data disk: $($disk.Name) at LUN $lun" -ForegroundColor Gray
        $bootProxyVM = Add-AzVMDataDisk -VM $bootProxyVM -Name $disk.Name `
            -CreateOption Attach -ManagedDiskId $disk.Id -Lun $lun
        $lun++
    }
    
    # Update the VM
    Update-AzVM -ResourceGroupName $ResourceGroup -VM $bootProxyVM
    
    # Step 8: Start the VM
    Write-Host "`n$ServerName - Step 8: Starting proxy VM..." -ForegroundColor Yellow
    Start-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName
    
    # Step 9: Configure boot (automated) - OPTIONAL
    if ($SkipAutoConfig) {
        Write-Host "`n$ServerName - Step 9: SKIPPING automatic boot configuration (SkipAutoConfig specified)" -ForegroundColor Yellow
        Write-Host "$ServerName - You will need to manually configure boot after connecting to the VM" -ForegroundColor Yellow
    } else {
        Write-Host "`n$ServerName - Step 9: Running boot configuration..." -ForegroundColor Yellow
        
        # Wait for VM Guest Agent to be ready
        Write-Host "$ServerName - Waiting for VM Guest Agent to be ready..." -ForegroundColor Gray
        $maxWait = 120  # Max 2 minutes
        $waited = 0
        $agentReady = $false
        
        while ($waited -lt $maxWait) {
            $vmStatus = Get-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName -Status
            $guestAgentStatus = $vmStatus.VMAgent.Statuses | Where-Object { $_.Code -like "ProvisioningState/succeeded" }
            
            if ($guestAgentStatus) {
                Write-Host "$ServerName - VM Guest Agent is ready!" -ForegroundColor Green
                $agentReady = $true
                break
            }
            
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 5
            $waited += 5
        }
        
        if (!$agentReady) {
            Write-Host "`n$ServerName - Warning: Guest Agent may not be ready, attempting anyway..." -ForegroundColor Yellow
        }
        
        # Additional brief wait to ensure extensions are ready
        Write-Host "`n$ServerName - Waiting 10 seconds for extensions to initialize..." -ForegroundColor Gray
        Start-Sleep -Seconds 10
        
        # Download and run configuration script
        $scriptUrl = "https://raw.githubusercontent.com/SteveSelick/PowershellCode/main/Configure-ASRBoot.ps1"
        
        # Create wrapper script that downloads and executes
        $wrapperScript = @'
# Boot configuration wrapper
$logFile = "C:\temp\bootproxy_autoconfig.log"
New-Item -ItemType Directory -Path C:\temp -Force | Out-Null

"=== Starting autoconfig at $(Get-Date) ===" | Out-File $logFile -Force
"Running as: $env:USERNAME" | Out-File $logFile -Append
"Computer: $env:COMPUTERNAME" | Out-File $logFile -Append

# Download configuration script
$scriptUrl = "https://raw.githubusercontent.com/SteveSelick/PowershellCode/main/Configure-ASRBoot.ps1"
$scriptPath = "C:\temp\Configure-ASRBoot.ps1"

try {
    "Downloading from: $scriptUrl" | Out-File $logFile -Append
    Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath -UseBasicParsing
    "Download successful" | Out-File $logFile -Append
    
    $fileSize = (Get-Item $scriptPath).Length
    "Script file size: $fileSize bytes" | Out-File $logFile -Append
    
    # Execute with bypass and capture output
    "Attempting Start-Process method..." | Out-File $logFile -Append
    $proc = Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`"" `
        -Wait -PassThru -RedirectStandardOutput "C:\temp\configure_output.txt" `
        -RedirectStandardError "C:\temp\configure_error.txt" `
        -WindowStyle Hidden
    
    "Process exit code: $($proc.ExitCode)" | Out-File $logFile -Append
    
    # Capture outputs
    "=== SCRIPT OUTPUT ===" | Out-File $logFile -Append
    if (Test-Path "C:\temp\configure_output.txt") {
        Get-Content "C:\temp\configure_output.txt" | Out-File $logFile -Append
    }
    
    "=== ERRORS ===" | Out-File $logFile -Append
    if (Test-Path "C:\temp\configure_error.txt") {
        Get-Content "C:\temp\configure_error.txt" | Out-File $logFile -Append
    }
    
} catch {
    "ERROR: $_" | Out-File $logFile -Append
    $_.Exception.Message | Out-File $logFile -Append
}

"=== Completed at $(Get-Date) ===" | Out-File $logFile -Append
'@
        
        Write-Host "$ServerName - Executing boot configuration via Run Command..." -ForegroundColor Yellow
        
        $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroup `
            -VMName $proxyVMName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $wrapperScript
        
        if ($result.Status -eq 'Succeeded') {
            Write-Host "$ServerName - Boot configuration initiated successfully!" -ForegroundColor Green
            Write-Host "$ServerName - The VM will reboot automatically to apply changes" -ForegroundColor Yellow
            
            # Wait and check if VM stopped instead of restarting
            Write-Host "$ServerName - Waiting 30 seconds for reboot..." -ForegroundColor Gray
            Start-Sleep -Seconds 30
            
            $vmStatus = Get-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName -Status
            if ($vmStatus.Statuses[1].Code -eq "PowerState/stopped" -or $vmStatus.Statuses[1].Code -eq "PowerState/deallocated") {
                Write-Host "$ServerName - VM stopped - starting it again..." -ForegroundColor Yellow
                Start-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName
            }
        } else {
            Write-Host "$ServerName - WARNING: Boot configuration may have failed" -ForegroundColor Red
            Write-Host "$ServerName - Status: $($result.Status)" -ForegroundColor Red
            Write-Host "$ServerName - Please check the VM manually" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "$ServerName - BOOT PROXY CREATED: $proxyVMName" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    # Get VM details for summary
    $vmDetails = Get-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName
    $nicDetails = Get-AzNetworkInterface -ResourceId $vmDetails.NetworkProfile.NetworkInterfaces[0].Id
    $privateIP = $nicDetails.IpConfigurations[0].PrivateIpAddress
    
    Write-Host "`n$ServerName - CONNECTION DETAILS:" -ForegroundColor Cyan
    Write-Host "$ServerName -   VM Name: $proxyVMName" -ForegroundColor White
    Write-Host "$ServerName -   Private IP: $privateIP" -ForegroundColor White
    Write-Host "$ServerName -   Username: bootadmin" -ForegroundColor White
    Write-Host "$ServerName -   Password: TempP@ss2024!" -ForegroundColor White
    Write-Host "`n$ServerName - The VM should reboot into ASR Windows automatically" -ForegroundColor Cyan
    Write-Host "`n$ServerName - To verify boot configuration:" -ForegroundColor Yellow
    Write-Host "$ServerName - 1. Wait 2-3 minutes for reboot to complete" -ForegroundColor Gray
    Write-Host "$ServerName - 2. RDP to: $privateIP (or $proxyVMName)" -ForegroundColor Gray
    Write-Host "$ServerName - 3. Check C:\temp\ for log files:" -ForegroundColor Gray
    Write-Host "$ServerName -    - bootproxy_autoconfig.log" -ForegroundColor Gray
    Write-Host "$ServerName -    - ASRBootConfig_*.log" -ForegroundColor Gray
    Write-Host "$ServerName -    - configure_asrboot_ran.txt" -ForegroundColor Gray
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "ALL OPERATIONS COMPLETED" -ForegroundColor Cyan
Write-Host "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan