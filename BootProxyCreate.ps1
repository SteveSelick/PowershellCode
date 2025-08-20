# BootProxyCreate.ps1
# Universal boot proxy creation script for ASR test failover fixes
# Works for APX-DB3, Advent-MoxySQL2, and Pinnacle-NY

param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({
        $validServers = @("APX-DB3", "Advent-MoxySQL2", "Pinnacle-NY")
        $inputServers = $_ -split ',' | ForEach-Object { $_.Trim() }
        $invalidServers = $inputServers | Where-Object { $_ -notin $validServers }
        if ($invalidServers) {
            throw "Invalid server name(s): $($invalidServers -join ', '). Valid options: $($validServers -join ', ')"
        }
        return $true
    })]
    [string]$ServerName,
    
    [string]$ResourceGroup = "PinnacleAssociates-Migrate-rg",
    [string]$Location = "eastus2",
    [switch]$SkipModuleCheck,
    [switch]$RunRemoteConfig,
    [switch]$AutoConfigureBoot
)

# Parse server names
$serverList = $ServerName -split ',' | ForEach-Object { $_.Trim() }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "BOOT PROXY CREATION SCRIPT" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Processing $($serverList.Count) server(s): $($serverList -join ', ')" -ForegroundColor Yellow
Write-Host ""

# Server configuration mapping
$serverConfigs = @{
    "APX-DB3" = @{
        TestVMName = "apx-db3-test"
        ProxyVMName = "APX-DB3-bootproxy"
        ComputerName = "APXDB3PROXY"
    }
    "Advent-MoxySQL2" = @{
        TestVMName = "advent-moxysql2-test"
        ProxyVMName = "ADVENT-bootproxy"
        ComputerName = "ADVENTPROXY"
    }
    "Pinnacle-NY" = @{
        TestVMName = "pinnacle-ny-test"
        ProxyVMName = "PINNACLE-bootproxy"
        ComputerName = "PINNACLEPROXY"
    }
}

# Module check (only once for all servers)
if (!$SkipModuleCheck) {
    Write-Host "Checking PowerShell modules..." -ForegroundColor Yellow
    $requiredModules = @("Az.Accounts", "Az.Compute", "Az.Network", "Az.Storage", "Az.RecoveryServices")
    foreach ($module in $requiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
        }
        Import-Module $module -Force
    }
}

# Connect to Azure (only once for all servers)
$context = Get-AzContext
if (!$context) {
    Write-Host "Connecting to Azure..." -ForegroundColor Yellow
    Connect-AzAccount -UseDeviceAuthentication
}
Set-AzContext -Subscription "a11ecd3f-d8b4-44be-90e0-66f792b468ee"

# Results collection
$results = @()

# Process each server
foreach ($server in $serverList) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "PROCESSING: $server" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Get configuration for current server
    $config = $serverConfigs[$server]
    $testVMName = $config.TestVMName
    $proxyVMName = $config.ProxyVMName
    $computerName = $config.ComputerName
    
    Write-Host "Test VM: $testVMName" -ForegroundColor Gray
    Write-Host "Proxy VM: $proxyVMName" -ForegroundColor Gray
    
    try {

        # Step 1: Get the test VM details (including size)
        Write-Host "`nStep 1: Getting test VM details..." -ForegroundColor Yellow
        $testVM = Get-AzVM -ResourceGroupName $ResourceGroup -Name $testVMName -ErrorAction SilentlyContinue

        if (!$testVM) {
            Write-Host "ERROR: Test VM '$testVMName' not found!" -ForegroundColor Red
            Write-Host "Skipping $server - Please ensure test failover has been initiated" -ForegroundColor Yellow
            $results += [PSCustomObject]@{
                ServerName = $server
                Status = "Failed - Test VM not found"
                Error = "Test VM '$testVMName' not found"
            }
            continue
        }

$vmSize = $testVM.HardwareProfile.VmSize
Write-Host "Test VM size: $vmSize" -ForegroundColor Green

# Step 2: Stop and remove the test VM (keep disks)
Write-Host "`nStep 2: Stopping and removing test VM (keeping disks)..." -ForegroundColor Yellow
Stop-AzVM -ResourceGroupName $ResourceGroup -Name $testVMName -Force -ErrorAction SilentlyContinue -Confirm:$false
Remove-AzVM -ResourceGroupName $ResourceGroup -Name $testVMName -Force -ErrorAction SilentlyContinue -Confirm:$false

# Step 3: Find all disks from the test VM
Write-Host "`nStep 3: Finding disks from test VM..." -ForegroundColor Yellow
$allDisks = Get-AzDisk -ResourceGroupName $ResourceGroup

# Find OS disk (largest unattached disk or by name pattern)
$osDisk = $allDisks | Where-Object {
    $_.DiskState -eq "Unattached" -and 
    ($_.Name -like "*$($testVMName.Replace('-test',''))*" -or
     $_.Name -like "*$(($testVMName.Replace('-test','')).Replace('-','_'))*" -or
     $_.Name -like "*$(($testVMName.Replace('-test','')).Replace('-',''))*")
} | Sort-Object DiskSizeGB -Descending | Select-Object -First 1

if (!$osDisk) {
    # Fallback: Get largest unattached disk
    $osDisk = $allDisks | Where-Object {$_.DiskState -eq "Unattached"} | 
              Sort-Object DiskSizeGB -Descending | Select-Object -First 1
}

        if (!$osDisk) {
            Write-Host "ERROR: No unattached OS disk found for $server!" -ForegroundColor Red
            $results += [PSCustomObject]@{
                ServerName = $server
                Status = "Failed - No OS disk found"
                Error = "No unattached OS disk found"
            }
            continue
        }

Write-Host "Found OS disk: $($osDisk.Name) (Size: $($osDisk.DiskSizeGB) GB)" -ForegroundColor Green

# Find data disks (other unattached disks)
$dataDisks = $allDisks | Where-Object {
    $_.DiskState -eq "Unattached" -and 
    $_.Id -ne $osDisk.Id
}

if ($dataDisks) {
    Write-Host "Found $($dataDisks.Count) data disk(s):" -ForegroundColor Green
    foreach ($disk in $dataDisks) {
        Write-Host "  - $($disk.Name) (Size: $($disk.DiskSizeGB) GB)" -ForegroundColor Gray
    }
} else {
    Write-Host "No additional data disks found" -ForegroundColor Gray
}

# Step 4: Create Gen2 boot proxy VM with same size as test VM
Write-Host "`nStep 4: Creating boot proxy VM..." -ForegroundColor Yellow
Write-Host "Using VM size: $vmSize (same as test VM)" -ForegroundColor Cyan

$subnetId = "/subscriptions/a11ecd3f-d8b4-44be-90e0-66f792b468ee/resourceGroups/PinnacleAssociates-VNet-rg/providers/Microsoft.Network/virtualNetworks/FailoverTest-VNet/subnets/FailoverTest-Subnet"

# Create VM configuration
$vmConfig = New-AzVMConfig -VMName $proxyVMName -VMSize $vmSize
$vmConfig = Set-AzVMSourceImage -VM $vmConfig -PublisherName "MicrosoftWindowsServer" -Offer "WindowsServer" -Skus "2022-datacenter-g2" -Version "latest"
$vmConfig = Set-AzVMOSDisk -VM $vmConfig -CreateOption "FromImage"

# Create network interface
$nic = New-AzNetworkInterface -Name "$proxyVMName-NIC" -ResourceGroupName $ResourceGroup -Location $Location -SubnetId $subnetId -Confirm:$false

$vmConfig = Add-AzVMNetworkInterface -VM $vmConfig -Id $nic.Id
$cred = New-Object PSCredential("bootadmin",(ConvertTo-SecureString "TempP@ss2024!" -AsPlainText -Force))
$vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -Windows -ComputerName $computerName -Credential $cred

Write-Host "Creating VM..." -ForegroundColor Yellow
New-AzVM -ResourceGroupName $ResourceGroup -Location $Location -VM $vmConfig -Confirm:$false

# Step 5: Wait for VM creation
Write-Host "`nStep 5: Waiting for VM to be ready..." -ForegroundColor Yellow
$timeout = 180
$timer = 0
while ($timer -lt $timeout) {
    $vm = Get-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName -Status -ErrorAction SilentlyContinue
    if ($vm.Statuses[1].Code -eq "PowerState/running") {
        Write-Host "VM is running" -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds 10
    $timer += 10
    Write-Host "." -NoNewline
}
Write-Host ""

# Step 6: Stop proxy VM to attach disks
Write-Host "`nStep 6: Stopping proxy VM to attach disks..." -ForegroundColor Yellow
Stop-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName -Force -Confirm:$false

# Step 7: Attach OS disk
Write-Host "`nStep 7: Attaching OS disk..." -ForegroundColor Yellow
$bootProxyVM = Get-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName

# Add OS disk as data disk (LUN 1)
$bootProxyVM.StorageProfile.DataDisks.Add((New-Object Microsoft.Azure.Management.Compute.Models.DataDisk -Property @{
    Lun = 1
    CreateOption = "Attach"
    ManagedDisk = (New-Object Microsoft.Azure.Management.Compute.Models.ManagedDiskParameters -Property @{Id = $osDisk.Id})
}))

# Step 8: Attach data disks if any
$lunNumber = 2
foreach ($dataDisk in $dataDisks) {
    Write-Host "Attaching data disk: $($dataDisk.Name) at LUN $lunNumber" -ForegroundColor Yellow
    $bootProxyVM.StorageProfile.DataDisks.Add((New-Object Microsoft.Azure.Management.Compute.Models.DataDisk -Property @{
        Lun = $lunNumber
        CreateOption = "Attach"
        ManagedDisk = (New-Object Microsoft.Azure.Management.Compute.Models.ManagedDiskParameters -Property @{Id = $dataDisk.Id})
    }))
    $lunNumber++
}

# Update VM with all attached disks
Update-AzVM -ResourceGroupName $ResourceGroup -VM $bootProxyVM

# Step 9: Start proxy VM
Write-Host "`nStep 9: Starting proxy VM..." -ForegroundColor Yellow
Start-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName -Confirm:$false

# Step 10: Optionally run remote configuration
if ($RunRemoteConfig -or $AutoConfigureBoot) {
    Write-Host "`nStep 10: Running remote boot configuration..." -ForegroundColor Yellow
    Start-Sleep -Seconds 45
    
    # Download and run Configure-ASRBoot.ps1 remotely
    $remoteScript = @'
# Download and run Configure-ASRBoot.ps1
$scriptUrl = "https://raw.githubusercontent.com/SteveSelick/PowershellCode/main/Configure-ASRBoot.ps1"
$scriptPath = "C:\temp\Configure-ASRBoot.ps1"

if (!(Test-Path "C:\temp")) {
    New-Item -ItemType Directory -Path "C:\temp" -Force
}

# Download the script
Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath -UseBasicParsing

# Run the script
Set-ExecutionPolicy Bypass -Scope Process -Force
& $scriptPath

Write-Output "Boot configuration completed"
'@
    
    try {
        $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroup -VMName $proxyVMName -CommandId 'RunPowerShellScript' -ScriptString $remoteScript
        Write-Host "Remote configuration result:" -ForegroundColor Green
        $result.Value[0].Message
        
        if ($AutoConfigureBoot) {
            Write-Host "`nWaiting 30 seconds before automatic reboot..." -ForegroundColor Yellow
            Start-Sleep -Seconds 30
            
            Write-Host "Rebooting VM to apply boot configuration..." -ForegroundColor Yellow
            Restart-AzVM -ResourceGroupName $ResourceGroup -Name $proxyVMName -Confirm:$false
        }
    } catch {
        Write-Host "Remote configuration failed. Manual configuration required." -ForegroundColor Yellow
    }
}

        # Display completion summary for this server
        $completionMessage = @"

========================================
COMPLETED: $server
========================================
Proxy VM: $proxyVMName
VM Size: $vmSize
OS Disk: $($osDisk.Name)
Data Disks: $(if ($dataDisks) { $dataDisks.Count } else { 0 })
Status: Success
========================================
"@
        Write-Host $completionMessage -ForegroundColor Green
        
        # Add to results
        $results += [PSCustomObject]@{
            ServerName = $server
            ProxyVMName = $proxyVMName
            ResourceGroup = $ResourceGroup
            VMSize = $vmSize
            OSDisk = $osDisk.Name
            DataDisks = $dataDisks | Select-Object -ExpandProperty Name
            Status = "Success"
            Username = "bootadmin"
            Password = "TempP@ss2024!"
        }
        
    } catch {
        Write-Host "ERROR processing $server : $_" -ForegroundColor Red
        $results += [PSCustomObject]@{
            ServerName = $server
            Status = "Failed"
            Error = $_.Exception.Message
        }
    }
}

# Final summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "FINAL SUMMARY" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

$successCount = ($results | Where-Object {$_.Status -eq "Success"}).Count
$failCount = ($results | Where-Object {$_.Status -ne "Success"}).Count

Write-Host "Total Servers Processed: $($results.Count)" -ForegroundColor White
Write-Host "Successful: $successCount" -ForegroundColor Green
if ($failCount -gt 0) {
    Write-Host "Failed: $failCount" -ForegroundColor Red
}

Write-Host "`nDetailed Results:" -ForegroundColor Yellow
$results | ForEach-Object {
    if ($_.Status -eq "Success") {
        Write-Host "  ✓ $($_.ServerName): $($_.ProxyVMName) created successfully" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $($_.ServerName): $($_.Error)" -ForegroundColor Red
    }
}

# Copy connection info for all successful servers to clipboard
if ($successCount -gt 0) {
    $clipboardText = @()
    $results | Where-Object {$_.Status -eq "Success"} | ForEach-Object {
        $clipboardText += @"
========================================
$($_.ServerName) - $($_.ProxyVMName)
========================================
RDP to $($_.ProxyVMName)
Username: $($_.Username)
Password: $($_.Password)

Quick boot fix:
Set-ExecutionPolicy Bypass -Force; iwr -useb https://raw.githubusercontent.com/SteveSelick/PowershellCode/main/Configure-ASRBoot.ps1 | iex

"@
    }
    $clipboardText -join "`n" | Set-Clipboard
    Write-Host "`nConnection info for all servers copied to clipboard!" -ForegroundColor Green
}

# Return results for pipeline use
return $results