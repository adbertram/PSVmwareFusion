Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Centralized VMRun Configuration and Execution Function
function Invoke-VMRun {
    <#
    .SYNOPSIS
    Centralized function to invoke VMware vmrun command with proper platform detection and error handling.
    
    .DESCRIPTION
    This function provides a unified interface for executing vmrun commands across different platforms
    (VMware Fusion on macOS, VMware Workstation on Windows) with automatic path detection,
    comprehensive error handling, and returns the command output.
    
    .PARAMETER Arguments
    Array of arguments to pass to vmrun command
    
    .EXAMPLE
    Invoke-VMRun -Arguments @("list")
    
    .EXAMPLE
    Invoke-VMRun -Arguments @("start", $VMPath)
    
    .EXAMPLE
    $output = Invoke-VMRun -Arguments @("getGuestIPAddress", $VMPath)
    #>
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )
    
    # VMware Fusion vmrun path
    $vmRunPath = "/Applications/VMware Fusion.app/Contents/Public/vmrun"
    $vmRunType = "fusion"
    
    # Add platform type argument if not already specified and command supports it
    $finalArguments = $Arguments
    $needsPlatformType = @("checkToolsState", "getGuestIPAddress", "runProgramInGuest", "copyFileFromHostToGuest", "copyFileFromGuestToHost")
    
    if ($Arguments.Count -gt 0 -and $needsPlatformType -contains $Arguments[0] -and $Arguments -notcontains "-T") {
        $finalArguments = @("-T", $vmRunType) + $Arguments
    }
    
    try {
        # Execute vmrun command
        $output = & $vmRunPath @finalArguments 2>&1
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -ne 0) {
            $errorMsg = "vmrun command failed with exit code $exitCode"
            if ($output) {
                $errorMsg += ": $($output -join "`n")"
            }
            throw $errorMsg
        }
        
        return $output
        
    } catch {
        $errorMsg = "Error executing vmrun: $($_.Exception.Message)"
        throw $errorMsg
    }
}

# Function to get Fusion VMs and their status
function Get-FusionVm {
    param(
        [Parameter(Mandatory = $false)]
        [Alias("Name")]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Running", "Stopped", "Unknown")]
        [string]$Status
    )

    $vmFolderPath = "$HOME/Virtual Machines.localized"
    if (-not (Test-Path $vmFolderPath)) {
        throw "Error: VM directory not found."
    }
    
    # Find all .vmx files in the VM directory
    $VMFiles = Get-ChildItem -Path $vmFolderPath -Filter "*.vmx" -Recurse -ErrorAction SilentlyContinue
    
    if (-not $VMFiles) {
        Write-Verbose "No VMs found in $vmFolderPath"
        return $false
    }
    
    # If VMName is specified, filter to just that VM
    if ($VMName) {
        $VMFiles = $VMFiles | Where-Object { $_.BaseName -like "*$VMName*" }
        
        if (-not $VMFiles) {
            throw "VM '$VMName' not found"
        }
    }
    
    # Get list of running VMs
    $RunningVMs = $null
    try {
        $RunningVMs = Invoke-VMRun -Arguments @("list")
    } catch {
        throw "Error getting running VMs: $($_.Exception.Message)"
    }
    
    # Display VM information
    $result = @()
    foreach ($VMFile in $VMFiles) {
        $VMName = [System.IO.Path]::GetFileNameWithoutExtension($VMFile.Name)
        $VMPath = $VMFile.FullName
        
        # Determine VM status
        $VMStatus = "Stopped"
        $IPAddress = $null
        
        if ($RunningVMs -contains $VMPath) {
            $VMStatus = "Running"
            try {
                $IPAddress = Invoke-VMRun -Arguments @("getGuestIPAddress", $VMPath)
                if (-not $IPAddress -or $IPAddress -like "*Error*") {
                    $IPAddress = "Unknown"
                }
            } catch {
                $IPAddress = "Unknown"
            }
        }
        
        # Get current snapshot
        $CurrentSnapshot = $null
        $VMSDFile = [System.IO.Path]::ChangeExtension($VMPath, ".vmsd")
        
        if (Test-Path $VMSDFile) {
            try {
                $VMSDContent = Get-Content $VMSDFile
                
                # Get the current snapshot UID from snapshot.current
                $CurrentUIDLine = $VMSDContent | Where-Object { $_ -like "*snapshot.current*" }
                if ($CurrentUIDLine) {
                    $CurrentUID = ($CurrentUIDLine -split '=')[1].Trim(' "')
                    
                    if ($CurrentUID) {
                        # Find the snapshot entry with this UID
                        $UIDLine = $VMSDContent | Where-Object { $_ -like "*snapshot*.uid = `"$CurrentUID`"" }
                        if ($UIDLine) {
                            # Extract the snapshot number from the line
                            $SnapshotNum = ($UIDLine -split '\.')[0] -replace 'snapshot', ''
                            
                            # Get the display name for this snapshot number
                            $DisplayNameLine = $VMSDContent | Where-Object { $_ -like "*snapshot$SnapshotNum.displayName*" }
                            if ($DisplayNameLine) {
                                $CurrentSnapshot = ($DisplayNameLine -split '=')[1].Trim(' "')
                            }
                        }
                    }
                }
            } catch {
                # Silently ignore snapshot read errors
                $CurrentSnapshot = "Unknown"
            }
        }
        
        # Add to result object
        $vmObject = [PSCustomObject]@{
            Name = $VMName
            Path = $VMPath
            Status = $VMStatus
            CurrentSnapshot = $CurrentSnapshot
            IPAddress = $IPAddress
        }
        
        # Filter by status if specified
        if (-not $Status -or $vmObject.Status -eq $Status) {
            $result += $vmObject
        }
    }
    
    return $result
}

function Wait-FusionVmReady {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$FusionVM,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [int]$MaxAttempts = 20,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [int]$TimeoutSeconds = 60
    )
    
    process {
        $Attempt = 1
    
    Write-Verbose "Waiting for VM '$VMName' to be fully ready..."
    
    $timeWaited = 0
    while ((Get-FusionVm -Name $FusionVm.Name).Status -ne "Running" -and $timeWaited -lt $TimeoutSeconds) {
        try {
            Write-Verbose "Waiting for VM to start... (attempt $Attempt/$MaxAttempts)"
            Start-Sleep -Seconds 5
            $timeWaited += 5
            $Attempt++
            
            if ($timeWaited -gt $TimeoutSeconds) {
                throw "Timeout waiting for VM to start"
            }
        } catch {
            throw "Error checking if VM is running: $($_.Exception.Message)"
        }
    }
    
    # Now check if VMware Tools is running
    $Attempt = 1
    
    while ((Invoke-VMRun -Arguments @("checkToolsState", $FusionVM.Path)) -ne "running") {
        try {
            Write-Verbose "Waiting for VMware Tools... (attempt $Attempt/$MaxAttempts)"
            Start-Sleep -Seconds 5
            $timeWaited += 5
            $Attempt++
            
            if ($timeWaited -gt $TimeoutSeconds) {
                throw "Timeout waiting for VMware Tools"
            }
        } catch {
            throw "Error checking VMware Tools state: $($_.Exception.Message)"
        }
    }
    }
}

# Function to start a VM
function Start-FusionVm {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$FusionVM
    )
    
    process {
        $VMPath = $FusionVM.Path
    $VMName = $FusionVM.Name
    
    # Check if VM is already running
    try {
        $IsRunning = $FusionVM.Status -eq "Running"
        
        if ($IsRunning) {
            Write-Verbose "VM '$VMName' is already running"
        }
    } catch {
        throw "Error checking if VM is running: $($_.Exception.Message)"
    }
    
    Write-Verbose "Starting VM '$VMName'..."
    
    # Start VM with verbose output

    try {
        Invoke-VMRun -Arguments @("start", $VMPath)
        Write-Verbose "Start command successful"
    } catch {
        throw "Failed to start VM: $($_.Exception.Message)"
    }
    
    Write-Verbose "VM start command successful, waiting for VM to be ready..."
    
    # Wait for VM to be ready
    Wait-FusionVmReady $FusionVM
    }
}

# Function to stop a VM
function Stop-FusionVm {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$FusionVM
    )
    
    process {
        $VMPath = $FusionVM.Path
    $VMName = $FusionVM.Name
    
    try {
        $IsRunning = $FusionVM.Status -eq "Running"
        
        if (-not $IsRunning) {
            Write-Verbose "VM '$VMName' is not running"
        }
    } catch {
        throw "Error checking if VM is running: $($_.Exception.Message)"
    }
    
    Write-Verbose "Stopping VM: $VMName"
    
    try {
        Invoke-VMRun -Arguments @("stop", $VMPath, "soft")
        Write-Verbose "VM '$VMName' stopped successfully"
    } catch {
        throw "Failed to stop VM '$VMName': $($_.Exception.Message)"
    }
    }
}

# Function to list snapshots for a VM
function Get-FusionVmSnapshot {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$FusionVM,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    
    process {
        $VMPath = $FusionVM.Path
    $VMName = $FusionVM.Name
    $VMDir = Split-Path $VMPath -Parent
    
    Write-Verbose "Snapshots for VM: $VMName"
    
    try {
        $Snapshots = Invoke-VMRun -Arguments @("listSnapshots", $VMPath)

        Write-Verbose -Message "Snapshots: $Snapshots"
        
        # Check if there was an error
        if ($Snapshots -like "*Error*") {
            throw "Error listing snapshots: $Snapshots"
        }
        
        # Check if there are no snapshots
        $snapshots = $Snapshots | Where-Object { $_ -notlike "Total snapshots:*" }
        
        # Get snapshot files from filesystem for size information
        $snapshotFiles = @(Get-ChildItem -Path $VMDir -Filter "*.vmsd" -ErrorAction SilentlyContinue)
        $vmsnapFiles = @(Get-ChildItem -Path $VMDir -Filter "*.vmem" -ErrorAction SilentlyContinue)
        $vmsnapFiles += @(Get-ChildItem -Path $VMDir -Filter "*-Snapshot*.vmdk" -ErrorAction SilentlyContinue)
        
        $result = @()
        foreach ($snapshot in $snapshots) {
            $snapshotObj = [PSCustomObject]@{
                Name = $snapshot
                VMName = $VMName
                VMPath = $VMPath
                Size = 0
                Files = @()
            }
            
            # Calculate total size of snapshot-related files
            $totalSize = 0
            $relatedFiles = @()
            
            # Add vmsd file (snapshot metadata)
            foreach ($file in $snapshotFiles) {
                $totalSize += $file.Length
                $relatedFiles += [PSCustomObject]@{
                    Path = $file.FullName
                    Size = [math]::Round($file.Length / 1GB, 2)
                    SizeBytes = $file.Length
                    Type = "Metadata"
                }
            }
            
            # Add memory and disk snapshot files
            foreach ($file in $vmsnapFiles) {
                $totalSize += $file.Length
                $relatedFiles += [PSCustomObject]@{
                    Path = $file.FullName
                    Size = [math]::Round($file.Length / 1GB, 0)
                    SizeBytes = $file.Length
                    Type = if ($file.Extension -eq ".vmem") { "Memory" } else { "Disk" }
                }
            }
            
            $snapshotObj.Size = [math]::Round($totalSize / 1GB, 0)
            $snapshotObj | Add-Member -MemberType NoteProperty -Name "SizeBytes" -Value $totalSize
            $snapshotObj.Files = $relatedFiles
            
            $result += $snapshotObj
        }
        
        if ($Name) {
            $result | Where-Object { $_.Name -like "*$Name*" }
        } else {
            $result
        }
    } catch {
        throw "Error listing snapshots: $($_.Exception.Message)"
    }
    }
}

# Function to take a snapshot of a VM
function New-FusionVmSnapshot {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$FusionVM,
        [Parameter(Mandatory)]
        [string]$Name,
        [string]$Description,
        [switch]$Shutdown
    )
    
    process {
        $VMPath = $FusionVM.Path
    $VMName = $FusionVM.Name
    
    # Handle VM state based on Shutdown parameter
    $vmStarted = $false
    $vmWasRunning = $FusionVM.Status -eq "Running"
    Write-Verbose "VM Status: $($FusionVM.Status)"
    
    if ($Shutdown -and $vmWasRunning) {
        Write-Verbose "Shutdown parameter specified - stopping VM before snapshot..."
        Stop-FusionVm $FusionVM
        Write-Verbose "VM stopped successfully"
    } elseif ($vmWasRunning) {
        Write-Verbose "VM is already running - taking snapshot while running"
    } else {
        Write-Verbose "VM is stopped - taking snapshot while stopped"
    }
    
    Write-Verbose "Taking snapshot '$Name' for VM: $VMName"
    Write-Verbose "vmrun command: snapshot $VMPath $Name $(if($Description) { $Description })"
    
    try {
        Write-Verbose "Creating snapshot... This may take several minutes depending on VM memory and disk usage."
        
        if ($Description) {
            Write-Verbose "Calling vmrun with description..."
            Invoke-VMRun -Arguments @("snapshot", $VMPath, $Name, $Description)
        } else {
            Write-Verbose "Calling vmrun without description..."
            Invoke-VMRun -Arguments @("snapshot", $VMPath, $Name)
        }
        
        Write-Verbose "Snapshot '$Name' created successfully"
    } catch {
        # Extract just the vmrun error message, not the full exception chain
        $errorMessage = $_.Exception.Message
        if ($errorMessage -match "Error: (.+)$") {
            throw $matches[1]
        } else {
            throw "Failed to take snapshot: $errorMessage"
        }
    } finally {
        # Restore VM to original state if we changed it
        if ($Shutdown -and $vmWasRunning) {
            Write-Verbose "Restarting VM (was stopped for snapshot)..."
            Start-FusionVm $FusionVM
        }
    }
    }
}

# Function to restore a VM to a snapshot
function Restore-FusionVmSnapshot {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$Snapshot
    )
    
    process {
        $VMPath = $Snapshot.VMPath
    $VMName = $Snapshot.VMName
    
    $vMStarted = $false
    # Get current VM status
    $FusionVM = Get-FusionVm -VMName $VMName
    if ($FusionVM.Status -ne "Running") {
        Write-Verbose "Starting VM to check snapshots..."
        Start-FusionVm $FusionVM
        $vMStarted = $true
    }
    
    try {
        $Snapshots = Invoke-VMRun -Arguments @("listSnapshots", $VMPath)
        if ($Snapshots -notcontains $Snapshot.Name) {
            throw "Snapshot '$($Snapshot.Name)' not found"
        }
    } catch {
        throw "Error checking snapshots: $($_.Exception.Message)"
    }
    
    Write-Verbose "Restoring VM '$VMName' to snapshot '$($Snapshot.Name)'..."
    
    try {
        Invoke-VMRun -Arguments @("revertToSnapshot", $VMPath, $Snapshot.Name)
        Write-Verbose "VM '$VMName' restored to snapshot '$($Snapshot.Name)' successfully"
    } catch {
        throw "Failed to restore snapshot: $($_.Exception.Message)"
    } finally {
        if ($vMStarted) {
            Stop-FusionVm $FusionVM
        }
    }
    }
}

# Function to delete a VM snapshot
function Remove-FusionVmSnapshot {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$Snapshot
    )
    
    process {
        $VMPath = $Snapshot.VMPath
        $VMName = $Snapshot.VMName
        
        # Check if snapshot exists (no need to start VM for this)
        try {
            $Snapshots = Invoke-VMRun -Arguments @("listSnapshots", $VMPath)
            if ($Snapshots -notcontains $Snapshot.Name) {
                throw "Snapshot '$($Snapshot.Name)' not found"
            }
        } catch {
            throw "Error checking snapshots: $($_.Exception.Message)"
        }
        
        Write-Verbose "Deleting snapshot '$Snapshot.Name' for VM '$VMName'..."
        
        try {
            Invoke-VMRun -Arguments @("deleteSnapshot", $VMPath, $Snapshot.Name)
            Write-Verbose "Snapshot '$($Snapshot.Name)' deleted successfully"
        } catch {
            throw "Failed to delete snapshot: $($_.Exception.Message)"
        }
    }
}

