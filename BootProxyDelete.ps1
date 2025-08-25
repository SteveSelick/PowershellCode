# Try to get VMs, authenticating only if needed
Write-Host "Searching for VMs ending with -bootproxy..."
try {
    $vms = Get-AzVM -ErrorAction Stop | Where-Object { $_.Name -like "*-bootproxy" }
} catch {
    if ($_.Exception.Message -like "*credentials*" -or $_.Exception.Message -like "*expired*" -or $_.Exception.Message -like "*not been set up*") {
        Write-Host "Azure credentials expired or not set. Authenticating..."
        Connect-AzAccount -UseDeviceAuthentication
        
        # Retry the operation
        $vms = Get-AzVM | Where-Object { $_.Name -like "*-bootproxy" }
    } else {
        # Some other error occurred
        Write-Host "Error: $_"
        exit 1
    }
}

if ($vms.Count -eq 0) {
    Write-Host "No VMs found ending with -bootproxy"
    "No VMs found ending with -bootproxy" | Set-Clipboard
    exit
}

Write-Host "Found $($vms.Count) VM(s) to delete:"
$vms | ForEach-Object { Write-Host "  - $($_.Name) in resource group $($_.ResourceGroupName)" }

$confirmation = Read-Host "Type 'YES' to confirm deletion of these VMs and all associated resources"
if ($confirmation -ne 'YES') {
    Write-Host "Operation cancelled"
    "Operation cancelled" | Set-Clipboard
    exit
}

# Create a script block for the deletion job
$deletionScriptBlock = {
    param($vmName, $resourceGroup)
    
    try {
        Write-Output "Processing VM: $vmName"
        
        # Get VM details before deletion to identify associated resources
        $vmDetail = Get-AzVM -ResourceGroupName $resourceGroup -Name $vmName
        
        # Store NIC IDs
        $nicIds = $vmDetail.NetworkProfile.NetworkInterfaces.Id
        
        # Store OS disk info
        $osDiskName = $vmDetail.StorageProfile.OsDisk.Name
        
        # Store data disk names
        $dataDiskNames = $vmDetail.StorageProfile.DataDisks.Name
        
        # Delete the VM
        Write-Output "  Deleting VM..."
        Remove-AzVM -ResourceGroupName $resourceGroup -Name $vmName -Force
        
        # Delete NICs
        foreach ($nicId in $nicIds) {
            $nicName = $nicId.Split('/')[-1]
            Write-Output "  Deleting NIC: $nicName"
            Remove-AzNetworkInterface -ResourceGroupName $resourceGroup -Name $nicName -Force
        }
        
        # Delete OS disk
        if ($osDiskName) {
            Write-Output "  Deleting OS disk: $osDiskName"
            Remove-AzDisk -ResourceGroupName $resourceGroup -DiskName $osDiskName -Force
        }
        
        # Delete data disks
        foreach ($dataDiskName in $dataDiskNames) {
            if ($dataDiskName) {
                Write-Output "  Deleting data disk: $dataDiskName"
                Remove-AzDisk -ResourceGroupName $resourceGroup -DiskName $dataDiskName -Force
            }
        }
        
        Write-Output "  Completed deletion of $vmName and associated resources"
        return "Success: $vmName"
    } catch {
        Write-Error "Failed to delete $vmName : $_"
        return "Failed: $vmName"
    }
}

# Start deletion jobs for each VM
$jobs = @()
foreach ($vm in $vms) {
    $jobName = "Delete-$($vm.Name)"
    Write-Host "Starting background job: $jobName"
    $job = Start-Job -Name $jobName -ScriptBlock $deletionScriptBlock -ArgumentList $vm.Name, $vm.ResourceGroupName
    $jobs += $job
}

Write-Host "`n========================================"
Write-Host "Started $($jobs.Count) background deletion job(s)"
Write-Host "========================================"
Write-Host "`nJobs are running in the background. You can:"
Write-Host "  - Check job status with: Get-Job"
Write-Host "  - View job output with: Receive-Job -Name 'Delete-*'"
Write-Host "  - Wait for all jobs: Wait-Job -Name 'Delete-*'"
Write-Host "  - Remove completed jobs: Remove-Job -Name 'Delete-*' -Force"
Write-Host "`nTo monitor all jobs in real-time, run:"
Write-Host "  Get-Job -Name 'Delete-*' | Wait-Job | Receive-Job"

# Store job information to clipboard for reference
$jobInfo = "Started deletion jobs: " + ($jobs | ForEach-Object { $_.Name }) -join ", "
$jobInfo | Set-Clipboard

Write-Host "`nJob names copied to clipboard. Script returning control to console..."

# Optionally, you can uncomment the following lines to show a quick status check
# Start-Sleep -Seconds 2
# Write-Host "`nQuick status check:"
# Get-Job -Name 'Delete-*' | Format-Table Name, State, HasMoreData -AutoSize