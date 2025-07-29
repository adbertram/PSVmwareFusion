Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Script scope credential for VM guest authentication
$Script:FusionVMCredential = $null

# Script scope storage for VM encryption passwords
$Script:FusionVMEncryptionPasswords = @{}

# Default output directory for command results
$OUTPUT_DIR = "$HOME/.vm_command_results"

# Ensure output directory exists
if (-not (Test-Path $OUTPUT_DIR)) {
    New-Item -ItemType Directory -Path $OUTPUT_DIR -Force | Out-Null
}

# Centralized VMRun Configuration and Execution Function
function Invoke-VMRun {
    <#
    .SYNOPSIS
    Centralized function to invoke VMware vmrun command with comprehensive parameter support and error handling.
    
    .DESCRIPTION
    This function provides a unified interface for executing vmrun commands with full support for all
    vmrun parameters including authentication, host configuration, and guest credentials.
    
    .PARAMETER HostType
    The host type for vmrun operations. Defaults to 'fusion' for VMware Fusion
    
    .PARAMETER HostName
    The host name for remote vmrun operations
    
    .PARAMETER HostPort
    The host port for remote vmrun operations
    
    .PARAMETER HostUser
    The host username for remote vmrun operations
    
    .PARAMETER HostPassword
    The host password for remote vmrun operations (SecureString)
    
    .PARAMETER VixPassword
    The VIX password for vmrun operations (SecureString)
    
    .PARAMETER GuestCredential
    PSCredential object containing guest username and password for guest operations
    
    .PARAMETER Command
    The vmrun command to execute (e.g., 'start', 'stop', 'list', 'snapshot')
    
    .PARAMETER VMPath
    Path to the VM's .vmx file
    
    .PARAMETER CommandParameters
    Additional parameters specific to the command being executed
    
    .PARAMETER ActiveWindow
    For runProgramInGuest command - run program in active window
    
    .PARAMETER Interactive
    For runProgramInGuest command - run program interactively
    
    .PARAMETER NoWait
    For runProgramInGuest command - do not wait for program to finish (useful for interactive programs)
    
    
    .PARAMETER Wait
    For getGuestIPAddress command - wait until IP address is available
    
    .PARAMETER ShowTree
    For listSnapshots command - display snapshots in tree format
    
    .PARAMETER AndDeleteChildren
    For deleteSnapshot command - delete snapshot and all its children
    
    .PARAMETER CloneType
    For clone command - specify 'full' or 'linked' clone type
    
    .PARAMETER SnapshotName
    For clone command - specify snapshot to clone from
    
    .PARAMETER CloneName
    For clone command - specify name for the cloned VM
    
    .PARAMETER PowerType
    For power commands (stop, reset, suspend) - specify 'hard' or 'soft' power operation
    
    .EXAMPLE
    Invoke-VMRun -Command "list"
    
    .EXAMPLE
    Invoke-VMRun -Command "start" -VMPath $VMPath
    
    .EXAMPLE
    Invoke-VMRun -Command "getGuestIPAddress" -VMPath $VMPath -Wait -GuestCredential $cred
    
    .EXAMPLE
    Invoke-VMRun -Command "runProgramInGuest" -VMPath $VMPath -GuestCredential $cred -CommandParameters @("cmd.exe", "/c", "dir") -Interactive
    
    .EXAMPLE
    Invoke-VMRun -Command "runProgramInGuest" -VMPath $VMPath -GuestCredential $cred -CommandParameters @("notepad.exe") -Interactive -NoWait
    
    
    .EXAMPLE
    Invoke-VMRun -Command "listSnapshots" -VMPath $VMPath -ShowTree
    
    .EXAMPLE
    Invoke-VMRun -Command "stop" -VMPath $VMPath -PowerType "soft"
    
    .EXAMPLE
    Invoke-VMRun -Command "clone" -VMPath $VMPath -CommandParameters @($destinationPath) -CloneType "full" -CloneName "MyClone"
    
    .EXAMPLE
    Invoke-VMRun -Command "deleteSnapshot" -VMPath $VMPath -CommandParameters @("SnapshotName") -AndDeleteChildren
    #>
    param(
        [Parameter()]
        [ValidateSet('fusion', 'ws', 'workstation', 'player', 'server')]
        [string]$HostType = 'fusion',
        
        [Parameter()]
        [string]$HostName,
        
        [Parameter()]
        [int]$HostPort,
        
        [Parameter()]
        [string]$HostUser,
        
        [Parameter()]
        [SecureString]$HostPassword,
        
        [Parameter()]
        [SecureString]$VixPassword,
        
        [Parameter()]
        [PSCredential]$GuestCredential,
        
        [Parameter(Mandatory)]
        [ValidateSet(
            # Power Commands
            'start', 'stop', 'reset', 'suspend', 'pause', 'unpause',
            # Snapshot Commands  
            'listSnapshots', 'snapshot', 'deleteSnapshot', 'revertToSnapshot',
            # Network Adapter Commands
            'listNetworkAdapters', 'addNetworkAdapter', 'setNetworkAdapter', 'deleteNetworkAdapter',
            # Host Network Commands
            'listHostNetworks', 'listPortForwardings', 'setPortForwarding', 'deletePortForwarding',
            # Guest Operating System Commands
            'runProgramInGuest', 'fileExistsInGuest', 'directoryExistsInGuest', 'setSharedFolderState',
            'addSharedFolder', 'removeSharedFolder', 'enableSharedFolders', 'disableSharedFolders',
            'listProcessesInGuest', 'killProcessInGuest', 'runScriptInGuest', 'deleteFileInGuest',
            'createDirectoryInGuest', 'deleteDirectoryInGuest', 'CreateTempfileInGuest', 'listDirectoryInGuest',
            'CopyFileFromHostToGuest', 'CopyFileFromGuestToHost', 'renameFileInGuest', 'connectNamedDevice',
            'disconnectNamedDevice', 'captureScreen', 'writeVariable', 'readVariable', 'getGuestIPAddress',
            # General Commands
            'list', 'upgradevm', 'installTools', 'checkToolsState', 'deleteVM', 'clone',
            # Template VM Commands
            'downloadPhotonVM'
        )]
        [string]$Command,
        
        [Parameter()]
        [string]$VMPath,
        
        [Parameter()]
        [string[]]$CommandParameters,
        
        # Additional vmrun flags and options
        [Parameter()]
        [switch]$ActiveWindow,
        
        [Parameter()]
        [switch]$Interactive,
        
        [Parameter()]
        [switch]$NoWait,
        
        
        [Parameter()]
        [switch]$Wait,
        
        [Parameter()]
        [switch]$ShowTree,
        
        [Parameter()]
        [switch]$AndDeleteChildren,
        
        # Clone-specific parameters
        [Parameter()]
        [ValidateSet('full', 'linked')]
        [string]$CloneType,
        
        [Parameter()]
        [string]$SnapshotName,
        
        [Parameter()]
        [string]$CloneName,
        
        # Power operation type
        [Parameter()]
        [ValidateSet('hard', 'soft')]
        [string]$PowerType
    )
    
    # VMware Fusion vmrun path
    $vmRunPath = "/Applications/VMware Fusion.app/Contents/Public/vmrun"
    
    # Get configuration if available
    $config = Get-FusionVMConfig
    
    # Handle VixPassword (encryption password) with config defaults
    if (-not $VixPassword -and $config -and $config.vmEncryption) {
        # Extract VM name from path if available
        $vmName = if ($VMPath) {
            $vmFile = Split-Path -Leaf $VMPath
            $vmName = [System.IO.Path]::GetFileNameWithoutExtension($vmFile)
            $vmName
        }
        
        # Check for VM-specific encryption password by path
        if ($VMPath -and $config.vmEncryption.byVMPath -and $config.vmEncryption.byVMPath.$VMPath) {
            $encryptionPass = $config.vmEncryption.byVMPath.$VMPath.encryptionPassword
            if ($encryptionPass) {
                $VixPassword = ConvertTo-SecureString $encryptionPass -AsPlainText -Force
                Write-Verbose "Using VM-specific encryption password from config for path: $VMPath"
            }
        }
        # Check for VM-specific encryption password by name
        elseif ($vmName -and $config.vmEncryption.byVMName -and $config.vmEncryption.byVMName.$vmName) {
            $encryptionPass = $config.vmEncryption.byVMName.$vmName.encryptionPassword
            if ($encryptionPass) {
                $VixPassword = ConvertTo-SecureString $encryptionPass -AsPlainText -Force
                Write-Verbose "Using VM-specific encryption password from config for VM: $vmName"
            }
        }
        # Use default encryption password
        elseif ($config.vmEncryption.default -and $config.vmEncryption.default.encryptionPassword) {
            $encryptionPass = $config.vmEncryption.default.encryptionPassword
            if ($encryptionPass) {
                $VixPassword = ConvertTo-SecureString $encryptionPass -AsPlainText -Force
                Write-Verbose "Using default encryption password from config"
            }
        }
    }
    
    # Handle GuestCredential with config defaults
    if (-not $GuestCredential -and $config -and $config.vmCredentials) {
        # Extract VM name from path if available
        $vmName = if ($VMPath) {
            $vmFile = Split-Path -Leaf $VMPath
            $vmName = [System.IO.Path]::GetFileNameWithoutExtension($vmFile)
            $vmName
        }
        
        # Check for VM-specific credentials
        if ($vmName -and $config.vmCredentials.byVMName -and $config.vmCredentials.byVMName.$vmName) {
            $vmCred = $config.vmCredentials.byVMName.$vmName
            if ($vmCred.guestUsername -and $vmCred.guestPassword) {
                $securePass = ConvertTo-SecureString $vmCred.guestPassword -AsPlainText -Force
                $GuestCredential = New-Object PSCredential($vmCred.guestUsername, $securePass)
                Write-Verbose "Using VM-specific guest credentials from config for VM: $vmName"
            }
        }
        # Use default credentials
        elseif ($config.vmCredentials.default -and $config.vmCredentials.default.guestUsername -and $config.vmCredentials.default.guestPassword) {
            $defaultCred = $config.vmCredentials.default
            $securePass = ConvertTo-SecureString $defaultCred.guestPassword -AsPlainText -Force
            $GuestCredential = New-Object PSCredential($defaultCred.guestUsername, $securePass)
            Write-Verbose "Using default guest credentials from config"
        }
    }
    
    # Build final arguments array from parameters
    $finalArguments = @()
    
    # Add host type parameter for commands that need it
    if ($HostType -and $HostType -ne 'fusion') {
        $finalArguments += @("-T", $HostType)
    } elseif ($Command -in @("checkToolsState", "getGuestIPAddress", "runProgramInGuest", "copyFileFromHostToGuest", "copyFileFromGuestToHost", "fileExistsInGuest", "directoryExistsInGuest", "listProcessesInGuest", "killProcessInGuest", "runScriptInGuest", "deleteFileInGuest", "createDirectoryInGuest", "deleteDirectoryInGuest", "CreateTempfileInGuest", "listDirectoryInGuest", "renameFileInGuest", "connectNamedDevice", "disconnectNamedDevice", "captureScreen", "writeVariable", "readVariable", "setSharedFolderState", "addSharedFolder", "removeSharedFolder", "enableSharedFolders", "disableSharedFolders")) {
        $finalArguments += @("-T", "fusion")
    }
    
    # Add host connection parameters
    if ($HostName) { $finalArguments += @("-h", $HostName) }
    if ($HostPort) { $finalArguments += @("-P", $HostPort) }
    if ($HostUser) { $finalArguments += @("-u", $HostUser) }
    if ($HostPassword) { 
        $plainHostPassword = ConvertFrom-SecureStringToPlainText -SecureString $HostPassword
        $finalArguments += @("-p", $plainHostPassword)
    }
    if ($VixPassword) { 
        $plainVixPassword = ConvertFrom-SecureStringToPlainText -SecureString $VixPassword
        $finalArguments += @("-vp", $plainVixPassword)
    }
    
    # Add guest credentials
    if ($GuestCredential) {
        $finalArguments += @("-gu", $GuestCredential.UserName)
        $plainGuestPassword = ConvertFrom-SecureStringToPlainText -SecureString $GuestCredential.Password
        $finalArguments += @("-gp", $plainGuestPassword)
    }
    
    # Add the command
    $finalArguments += $Command
    
    # Add VM path if provided
    if ($VMPath) { $finalArguments += $VMPath }
    
    # Add runProgramInGuest-specific flags BEFORE the program path
    if ($Command -eq 'runProgramInGuest') {
        if ($NoWait) {
            $finalArguments += '-noWait'
        }
        if ($Interactive) {
            $finalArguments += '-interactive'
        }
        if ($ActiveWindow -or $Interactive) {
            # Use activeWindow when explicitly requested or when running interactively
            $finalArguments += '-activeWindow'
        }
    }
    
    # Add command-specific parameters
    if ($CommandParameters) { $finalArguments += $CommandParameters }
    
    # Add additional flags based on command type and parameters
    if ($ShowTree -and $Command -eq 'listSnapshots') {
        $finalArguments += 'showtree'
    }
    
    if ($AndDeleteChildren -and $Command -eq 'deleteSnapshot') {
        $finalArguments += 'andDeleteChildren'
    }
    
    if ($Wait -and $Command -eq 'getGuestIPAddress') {
        $finalArguments += '-wait'
    }
    
    if ($PowerType -and $Command -in @('stop', 'reset', 'suspend')) {
        $finalArguments += $PowerType
    }
    
    # Add clone-specific parameters
    if ($Command -eq 'clone') {
        if ($CloneType) { $finalArguments += $CloneType }
        if ($SnapshotName) { $finalArguments += "-snapshot=$SnapshotName" }
        if ($CloneName) { $finalArguments += "-cloneName=$CloneName" }
    }
    
    try {
        # Execute vmrun command
        # Don't log passwords in arguments for security
        $safeArgs = $finalArguments.Clone()
        
        # Mask guest password
        if ($safeArgs -contains "-gp") {
            $gpIndex = [array]::IndexOf($safeArgs, "-gp")
            if ($gpIndex -ge 0 -and $gpIndex + 1 -lt $safeArgs.Length) {
                $safeArgs[$gpIndex + 1] = "***"
            }
        }
        
        # Mask host password  
        if ($safeArgs -contains "-p") {
            $pIndex = [array]::IndexOf($safeArgs, "-p")
            if ($pIndex -ge 0 -and $pIndex + 1 -lt $safeArgs.Length) {
                $safeArgs[$pIndex + 1] = "***"
            }
        }
        
        # Mask VIX password
        if ($safeArgs -contains "-vp") {
            $vpIndex = [array]::IndexOf($safeArgs, "-vp")
            if ($vpIndex -ge 0 -and $vpIndex + 1 -lt $safeArgs.Length) {
                $safeArgs[$vpIndex + 1] = "***"
            }
        }
        
        Write-Verbose "Executing vmrun with arguments: $($safeArgs -join ' ')"

        # Check if this is a cleanup operation that might produce "Access is denied"
        if ($Command -eq "runProgramInGuest" -and $CommandParameters -match "Remove-Item|del|delete") {
            Write-Verbose "Executing cleanup operation: $($CommandParameters -join ' ')"
        }

        $output = & $vmRunPath @finalArguments 2>&1
        $exitCode = $LASTEXITCODE
        
        # Check for specific error messages in output
        if ($output -match "Access is denied") {
            Write-Verbose "Access denied error detected for command: $Command with parameters: $($CommandParameters -join ' ')"
        }
        
        if ($exitCode -ne 0) {
            $errorMsg = "vmrun command failed with exit code $exitCode"
            if ($output) {
                $errorMsg += ": $($output -join "`n")"
            }
            throw $errorMsg
        }
        
        # Note: Process verification disabled for better compatibility with short-running commands like PowerShell scripts
        
        $output
        
    } catch {
        $errorMsg = "Error executing vmrun: $($_.Exception.Message)"
        throw $errorMsg
    }
}

# Helper function to securely convert SecureString to plain text
function ConvertFrom-SecureStringToPlainText {
    <#
    .SYNOPSIS
    Converts a SecureString to plain text with proper memory management.
    
    .PARAMETER SecureString
    The SecureString to convert
    
    .EXAMPLE
    $plainText = ConvertFrom-SecureStringToPlainText -SecureString $securePassword
    #>
    param(
        [Parameter(Mandatory)]
        [SecureString]$SecureString
    )
    
    try {
        $credential = New-Object System.Management.Automation.PSCredential('dummy', $SecureString)
        return $credential.GetNetworkCredential().Password
    } catch {
        # Fallback to BSTR method
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
    }
}

# Function to get configuration from config.json
function Get-FusionVMConfig {
    <#
    .SYNOPSIS
    Gets VM configuration from config.json file including credentials and encryption passwords.
    
    .DESCRIPTION
    Reads the config.json file from the module directory and returns configuration
    for VM credentials and encryption passwords. Returns null if config file doesn't exist.
    
    .EXAMPLE
    $config = Get-FusionVMConfig
    
    .EXAMPLE
    # Get config and use it to set credentials
    $config = Get-FusionVMConfig
    if ($config -and $config.vmCredentials.default) {
        $securePass = ConvertTo-SecureString $config.vmCredentials.default.guestPassword -AsPlainText -Force
        $cred = New-Object PSCredential($config.vmCredentials.default.guestUsername, $securePass)
        Set-FusionVMCredential -Credential $cred
    }
    #>
    
    # Get the module path
    $modulePath = $PSScriptRoot
    if (-not $modulePath) {
        # Try to get from module info
        $module = Get-Module PSVmwareFusion
        if ($module) {
            $modulePath = Split-Path -Parent $module.Path
        } else {
            # Fallback to the directory where this script is located
            $modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
        }
    }
    
    $configPath = Join-Path $modulePath "config.json"
    
    # Check if config file exists
    if (-not (Test-Path $configPath)) {
        Write-Verbose "Config file not found at: $configPath"
        return $null
    }
    
    try {
        # Read and parse the JSON config
        $configContent = Get-Content -Path $configPath -Raw
        $config = $configContent | ConvertFrom-Json
        
        Write-Verbose "Configuration loaded from: $configPath"
        return $config
        
    } catch {
        Write-Warning "Failed to read or parse config.json: $($_.Exception.Message)"
        return $null
    }
}

# Function to set script-level credential for VM guest authentication
function Set-FusionVMCredential {
    <#
    .SYNOPSIS
    Sets a default credential for VM guest authentication that all functions can use.
    
    .DESCRIPTION
    Stores a PSCredential object in script scope that other functions will use as a default
    when no explicit credential is provided. This allows you to set credentials once and
    use them across multiple function calls.
    
    .PARAMETER Credential
    PSCredential object to use for VM guest authentication
    
    .EXAMPLE
    $cred = Get-Credential
    Set-FusionVMCredential -Credential $cred
    
    .EXAMPLE
    Set-FusionVMCredential -Credential (Get-Credential)
    #>
    param(
        [Parameter(Mandatory)]
        [PSCredential]$Credential
    )
    
    $Script:FusionVMCredential = $Credential
    Write-Verbose "VM guest credential set for user: $($Credential.UserName)"
}

# Helper function to get credentials with config fallback
function Get-FusionVMCredentialWithFallback {
    <#
    .SYNOPSIS
    Internal helper to get VM credentials with fallback to config file.
    
    .DESCRIPTION
    Gets credentials in order of priority:
    1. Provided credential parameter
    2. Script-scoped credential
    3. Config file credential (VM-specific or default)
    
    .PARAMETER Credential
    Optional credential parameter
    
    .PARAMETER VMName
    Optional VM name for VM-specific config lookup
    #>
    param(
        [Parameter()]
        [PSCredential]$Credential,
        
        [Parameter()]
        [string]$VMName
    )
    
    # Return provided credential if available
    if ($Credential) {
        return $Credential
    }
    
    # Return script-scoped credential if available
    if ($Script:FusionVMCredential) {
        return $Script:FusionVMCredential
    }
    
    # Try to get from config
    $config = Get-FusionVMConfig
    if ($config -and $config.vmCredentials) {
        # Check for VM-specific credentials
        if ($VMName -and $config.vmCredentials.byVMName -and $config.vmCredentials.byVMName.$VMName) {
            $vmCred = $config.vmCredentials.byVMName.$VMName
            if ($vmCred.guestUsername -and $vmCred.guestPassword) {
                $securePass = ConvertTo-SecureString $vmCred.guestPassword -AsPlainText -Force
                Write-Verbose "Using VM-specific guest credentials from config for VM: $VMName"
                return New-Object PSCredential($vmCred.guestUsername, $securePass)
            }
        }
        
        # Use default credentials
        if ($config.vmCredentials.default -and $config.vmCredentials.default.guestUsername -and $config.vmCredentials.default.guestPassword) {
            $defaultCred = $config.vmCredentials.default
            $securePass = ConvertTo-SecureString $defaultCred.guestPassword -AsPlainText -Force
            Write-Verbose "Using default guest credentials from config"
            return New-Object PSCredential($defaultCred.guestUsername, $securePass)
        }
    }
    
    # No credentials found
    return $null
}

# Function to check the current credential status
function Get-FusionVMCredential {
    <#
    .SYNOPSIS
    Gets the current VM guest credential status.
    
    .DESCRIPTION
    Returns information about the currently set VM guest credential.
    
    .EXAMPLE
    Get-FusionVMCredential
    #>
    if ($Script:FusionVMCredential) {
        return [PSCustomObject]@{
            Username = $Script:FusionVMCredential.UserName
            IsSet = $true
        }
    } else {
        return [PSCustomObject]@{
            Username = $null
            IsSet = $false
        }
    }
}

# Function to get Fusion VMs and their status
function Get-FusionVm {
    <#
    .SYNOPSIS
    Gets VMware Fusion virtual machines.
    
    .DESCRIPTION
    Retrieves information about VMware Fusion VMs including their status.
    If you have encrypted VMs and don't want to be prompted for passwords,
    use the -SkipStatusCheck parameter.
    
    .PARAMETER VMName
    Optional VM name filter
    
    .PARAMETER Status
    Filter VMs by status (Running, Stopped, Unknown)
    
    .PARAMETER SkipStatusCheck
    Skip checking VM running status. Useful when you have encrypted VMs
    and don't want to be prompted for encryption passwords.
    
    .EXAMPLE
    Get-FusionVm
    
    .EXAMPLE
    Get-FusionVm -Name "TestVM"
    
    .EXAMPLE
    Get-FusionVm -SkipStatusCheck
    #>
    param(
        [Parameter(Mandatory = $false)]
        [Alias("Name")]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Running", "Stopped", "Unknown")]
        [string]$Status,
        
        [Parameter()]
        [switch]$SkipStatusCheck
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
    $RunningVMs = @()
    if (-not $SkipStatusCheck) {
        try {
            # Note: The "list" command may prompt for encryption passwords if encrypted VMs are present
            # This is a limitation of vmrun - it cannot use -vp flag with the list command
            $RunningVMs = Invoke-VMRun -Command "list"
        } catch {
            # If we fail to get running VMs (possibly due to encryption), continue without status info
            Write-Warning "Could not get list of running VMs. This may happen if you have encrypted VMs. Error: $($_.Exception.Message)"
            Write-Warning "VM status will be shown as 'Unknown' for all VMs."
            Write-Warning "Use -SkipStatusCheck parameter to avoid this prompt."
            $RunningVMs = @()
        }
    } else {
        Write-Verbose "Skipping VM status check as requested"
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
                $IPAddress = Invoke-VMRun -Command "getGuestIPAddress" -VMPath $VMPath
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
                        # Find the snapshot entry with this UID (handle both quoted and unquoted UIDs)
                        # Look specifically for snapshotN.uid lines, not mru entries
                        $UIDLine = $VMSDContent | Where-Object { $_ -match "^snapshot\d+\.uid = [`"]?$CurrentUID[`"]?$" } | Select-Object -First 1
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
    
    Write-Verbose "Waiting for VM '$($FusionVM.Name)' to be fully ready..."
    
    $timeWaited = 0
    while ((Get-FusionVm -Name $FusionVM.Name).Status -ne "Running" -and $timeWaited -lt $TimeoutSeconds) {
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
    
    while ((Invoke-VMRun -Command "checkToolsState" -VMPath $FusionVM.Path) -ne "running") {
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
        Invoke-VMRun -Command "start" -VMPath $VMPath
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
        Invoke-VMRun -Command "stop" -VMPath $VMPath -PowerType "soft"
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
        [string]$Name,
        
        [Parameter()]
        [switch]$ShowTree
    )
    
    process {
        $VMPath = $FusionVM.Path
    $VMName = $FusionVM.Name
    $VMDir = Split-Path $VMPath -Parent
    
    Write-Verbose "Snapshots for VM: $VMName"
    
    try {
        $Snapshots = Invoke-VMRun -Command "listSnapshots" -VMPath $VMPath -ShowTree:$ShowTree

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
            Invoke-VMRun -Command "snapshot" -VMPath $VMPath -CommandParameters @($Name, $Description)
        } else {
            Write-Verbose "Calling vmrun without description..."
            Invoke-VMRun -Command "snapshot" -VMPath $VMPath -CommandParameters @($Name)
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
        $Snapshots = Invoke-VMRun -Command "listSnapshots" -VMPath $VMPath
        if ($Snapshots -notcontains $Snapshot.Name) {
            throw "Snapshot '$($Snapshot.Name)' not found"
        }
    } catch {
        throw "Error checking snapshots: $($_.Exception.Message)"
    }
    
    Write-Verbose "Restoring VM '$VMName' to snapshot '$($Snapshot.Name)'..."
    
    try {
        Invoke-VMRun -Command "revertToSnapshot" -VMPath $VMPath -CommandParameters @($Snapshot.Name)
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
        [PSCustomObject]$Snapshot,
        
        [Parameter()]
        [switch]$AndDeleteChildren
    )
    
    process {
        $VMPath = $Snapshot.VMPath
        $VMName = $Snapshot.VMName
        
        # Check if snapshot exists (no need to start VM for this)
        try {
            $Snapshots = Invoke-VMRun -Command "listSnapshots" -VMPath $VMPath
            if ($Snapshots -notcontains $Snapshot.Name) {
                throw "Snapshot '$($Snapshot.Name)' not found"
            }
        } catch {
            throw "Error checking snapshots: $($_.Exception.Message)"
        }
        
        Write-Verbose "Deleting snapshot '$Snapshot.Name' for VM '$VMName'..."
        
        try {
            Invoke-VMRun -Command "deleteSnapshot" -VMPath $VMPath -CommandParameters @($Snapshot.Name) -AndDeleteChildren:$AndDeleteChildren
            Write-Verbose "Snapshot '$($Snapshot.Name)' deleted successfully"
        } catch {
            throw "Failed to delete snapshot: $($_.Exception.Message)"
        }
    }
}

function Optimize-PowerShellScript {
    <#
    .SYNOPSIS
    Optimizes PowerShell script content for remote execution.
    
    .DESCRIPTION
    Replaces Write-Host with Write-Information and removes color parameters for better remote execution.
    
    .PARAMETER PSCommand
    PowerShell command or script content to optimize
    
    .EXAMPLE
    Optimize-PowerShellScript -PSCommand "Write-Host 'Hello' -ForegroundColor Green"
    #>
    param(
        [Parameter(Mandatory)]
        [string]$PSCommand
    )
    
    # Replace Write-Host with Write-Information and remove -ForegroundColor parameters
    $cleanedCommand = $PSCommand -replace 'Write-Host', 'Write-Information'
    $cleanedCommand = $cleanedCommand -replace '-ForegroundColor \w+', ''
    $cleanedCommand = $cleanedCommand -replace 'Write-Information ([^-]*?)$', 'Write-Information $1 -InformationAction Continue'
    $cleanedCommand -replace 'Write-Information ([^-]*?) -InformationAction Continue -InformationAction Continue', 'Write-Information $1 -InformationAction Continue'
}

function Invoke-FusionVMGuestPowerShellCommand {
    <#
    .SYNOPSIS
    Executes PowerShell commands on a remote VM with comprehensive logging.
    
    .PARAMETER FusionVM
    VM object from Get-FusionVm or VM name string
    
    .PARAMETER Command
    PowerShell command or script content to execute
    
    .PARAMETER Credential
    PSCredential object for VM guest authentication
    
    .PARAMETER UsePwsh
    Use PowerShell 7+ (pwsh.exe) instead of Windows PowerShell (powershell.exe)
    
    .EXAMPLE
    Invoke-FusionVMGuestPowerShellCommand -FusionVM "TestVM" -Command "Get-Process"
    
    .EXAMPLE
    Invoke-FusionVMGuestPowerShellCommand -FusionVM "TestVM" -Command "Get-Process" -UsePwsh
    
    .EXAMPLE
    Invoke-FusionVMGuestPowerShellCommand -FusionVM "TestVM" -Command "Get-Process" -LogFilePath "C:\Users\user\my-course-20240101.log"
    #>
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [pscustomobject]$FusionVM,
        
        [Parameter(Mandatory)]
        [string]$Command,
        
        [Parameter()]
        [PSCredential]$Credential,
        
        [Parameter()]
        [string]$LogFilePath,
        
        [Parameter()]
        [switch]$UsePwsh
    )
    
    process {
        if ($FusionVM.Status -ne "Running") {
            throw "VM '$($FusionVM.Name)' is not running"
        }
        
        # Get credential with config fallback
        $cred = Get-FusionVMCredentialWithFallback -Credential $Credential -VMName $FusionVM.Name
        if (-not $cred) {
            throw "No credential provided. Use -Credential parameter, call Set-FusionVMCredential, or configure credentials in config.json"
        }
        
        # Determine PowerShell executable path
        $powershellPath = if ($UsePwsh) {
            "C:\Program Files\PowerShell\7\pwsh.exe"
        } else {
            "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        }
        
        $psType = if ($UsePwsh) { "PowerShell 7+" } else { "Windows PowerShell" }
        Write-Verbose "Executing $psType command on VM '$($FusionVM.Name)' as $($cred.UserName)..."
        
        # Wrap command with logging if LogFilePath is specified
        $finalCommand = $Command

        # Create a temporary log file path on the guest
        $guestLogPath = "C:\Windows\Temp\PSOutput_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').log"

        Write-Verbose "Logging output to guest file: $guestLogPath"
        # Create a wrapper script that logs all output
        $finalCommand = @"
# Execute the command and capture all output
try {
    `$output = & {
        $Command
    } *>&1
    
    # Log the output
    if (`$output) {
        `$output | Out-File -FilePath '$guestLogPath' -Encoding UTF8
    }
    
    # Also write to console (though vmrun won't capture it)
    if (`$output) {
        `$output
    }    
} catch {
    "ERROR: `$(`$_.Exception.Message)" | Out-File -FilePath '$guestLogPath' -Append -Encoding UTF8
}
"@
        
        # Generate a unique temporary file name on the guest
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
        $guestScriptPath = "C:\Windows\Temp\PSCommand_$timestamp.ps1"
        
        # Create a temporary local script file
        $localTempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
        
        try {
            # Write the command to the temporary local script file
            $finalCommand | Out-File -FilePath $localTempScript -Encoding UTF8
            Write-Verbose "Created temporary script file: $localTempScript"
            
            # Copy the script to the VM
            Copy-FileToFusionVMGuest -FusionVM $FusionVM -LocalFile $localTempScript -GuestFile $guestScriptPath -Credential $cred
            Write-Verbose "Copied script to VM at: $guestScriptPath"
            
            # Execute the script on the VM with execution policy bypass
            $output = Invoke-VMRun -Command "runProgramInGuest" -VMPath $FusionVM.Path -GuestCredential $cred -CommandParameters @($powershellPath, "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $guestScriptPath)
            
            # Clean up the temporary script file on the VM
            try {
                $cleanupCommand = "Remove-Item -Path '$guestScriptPath' -Force -ErrorAction SilentlyContinue"
                $cleanupScriptPath = "C:\Windows\Temp\Cleanup_$timestamp.ps1"
                $cleanupCommand | Out-File -FilePath $localTempScript -Encoding UTF8
                Copy-FileToFusionVMGuest -FusionVM $FusionVM -LocalFile $localTempScript -GuestFile $cleanupScriptPath -Credential $cred
                Invoke-VMRun -Command "runProgramInGuest" -VMPath $FusionVM.Path -GuestCredential $cred -CommandParameters @($powershellPath, "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $cleanupScriptPath)
                # Clean up the cleanup script too
                $finalCleanup = "Remove-Item -Path '$cleanupScriptPath' -Force -ErrorAction SilentlyContinue"
                $finalCleanup | Out-File -FilePath $localTempScript -Encoding UTF8
                Copy-FileToFusionVMGuest -FusionVM $FusionVM -LocalFile $localTempScript -GuestFile "C:\Windows\Temp\FinalCleanup_$timestamp.ps1" -Credential $cred
                Invoke-VMRun -Command "runProgramInGuest" -VMPath $FusionVM.Path -GuestCredential $cred -CommandParameters @($powershellPath, "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "C:\Windows\Temp\FinalCleanup_$timestamp.ps1")
                Write-Verbose "Cleaned up temporary script files on VM"
            } catch {
                Write-Verbose "Warning: Could not clean up temporary script files on VM: $($_.Exception.Message)"
            }
            
            # Now copy the log file back from the guest to read the output
            $localLogPath = [System.IO.Path]::GetTempFileName()
            try {
                Write-Verbose "Copying output log from guest..."
                Copy-FileFromFusionVmGuest -FusionVM $FusionVM -GuestFile $guestLogPath -LocalFile $localLogPath -Credential $cred
                
                # Read the output
                if (Test-Path $localLogPath) {
                    $capturedOutput = Get-Content $localLogPath -Raw
                    Write-Verbose "Retrieved output from guest log file"
                    
                    # Clean up guest log file
                    try {
                        $cleanupLogCmd = "Remove-Item -Path '$guestLogPath' -Force -ErrorAction SilentlyContinue"
                        $cleanupLogScript = "C:\Windows\Temp\CleanupLog_$timestamp.ps1"
                        $cleanupLogCmd | Out-File -FilePath $localTempScript -Encoding UTF8
                        Copy-FileToFusionVMGuest -FusionVM $FusionVM -LocalFile $localTempScript -GuestFile $cleanupLogScript -Credential $cred
                        Invoke-VMRun -Command "runProgramInGuest" -VMPath $FusionVM.Path -GuestCredential $cred -CommandParameters @($powershellPath, "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $cleanupLogScript)
                        Write-Verbose "Cleaned up guest log file"
                    } catch {
                        Write-Verbose "Warning: Could not clean up guest log file: $($_.Exception.Message)"
                    }
                    
                    # Return the captured output
                    Write-Output $capturedOutput
                } else {
                    Write-Verbose "No output captured from command"
                }
            } catch {
                Write-Verbose "Could not retrieve output log: $($_.Exception.Message)"
                # Still return the original output if any
                Write-Output $output
            } finally {
                # Clean up local log file
                if (Test-Path $localLogPath) {
                    Remove-Item $localLogPath -Force -ErrorAction SilentlyContinue
                }
            }
            
        } catch {
            throw "PowerShell execution failed on VM '$($FusionVM.Name)': $($_.Exception.Message)"
        } finally {
            # Clean up the local temporary script file
            if (Test-Path $localTempScript) {
                Remove-Item $localTempScript -Force -ErrorAction SilentlyContinue
                Write-Verbose "Cleaned up local temporary script file: $localTempScript"
            }
        }
    }
}

function Invoke-FusionVMGuestScript {
    <#
    .SYNOPSIS
    Executes a PowerShell script file on a remote VM.
    
    .DESCRIPTION
    Copies a local PowerShell script file to the VM and executes it remotely.
    This approach handles scripts of any size and complexity.
    
    .PARAMETER FusionVM
    VM object from Get-FusionVm or VM name string
    
    .PARAMETER ScriptPath
    Path to the local PowerShell script file to execute
    
    .PARAMETER Credential
    PSCredential object for VM guest authentication
    
    .PARAMETER LogFilePath
    Optional log file path on guest. If specified, all script output will be logged to this file
    
    .EXAMPLE
    Set-FusionVMCredential -Credential (Get-Credential)
    Invoke-FusionVMGuestScript -FusionVM "TestVM" -ScriptPath "/Users/adam/Scripts/test.ps1"
    
    .EXAMPLE
    $cred = Get-Credential
    Get-FusionVm -Name "TestVM" | Invoke-FusionVMGuestScript -ScriptPath "./deploy.ps1" -Credential $cred -LogFilePath "C:\Users\user\my-course-20240101.log"
    #>
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$FusionVM,
        
        [Parameter(Mandatory)]
        [string]$ScriptPath,
        
        [Parameter()]
        [PSCredential]$Credential,
        
        [Parameter()]
        [string]$LogFilePath
    )
    
    process {
        # Check if the script exists
        if (-not (Test-Path $ScriptPath)) {
            throw "Script '$ScriptPath' not found"
        }
        
        # Get credential with config fallback
        $Credential = Get-FusionVMCredentialWithFallback -Credential $Credential -VMName $FusionVM.Name
        if (-not $Credential) {
            throw "No credential provided. Use -Credential parameter, call Set-FusionVMCredential, or configure credentials in config.json"
        }
        
        Write-Verbose "Copying script '$ScriptPath' to VM and executing..."
        
        # Generate a unique temporary file name on the guest
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $scriptFileName = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)
        $guestScriptPath = "C:\Windows\Temp\${scriptFileName}_$timestamp.ps1"
        
        try {
            # Copy the script to the VM
            Copy-FileToFusionVMGuest -FusionVM $FusionVM -LocalFile $ScriptPath -GuestFile $guestScriptPath -Credential $Credential
            
            # Execute the script on the VM with execution policy bypass
            $executeCommand = "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force; & '$guestScriptPath'"
            $output = Invoke-FusionVMGuestPowerShellCommand -FusionVM $FusionVM -Command $executeCommand -Credential $Credential -LogFilePath $LogFilePath -UsePwsh
            
            # Clean up the temporary script file
            try {
                $cleanupCommand = "Remove-Item -Path '$guestScriptPath' -Force -ErrorAction SilentlyContinue"
                Invoke-FusionVMGuestPowerShellCommand -FusionVM $FusionVM -Command $cleanupCommand -Credential $Credential -UsePwsh
                Write-Verbose "Cleaned up temporary script file: $guestScriptPath"
            } catch {
                Write-Verbose "Warning: Could not clean up temporary script file: $($_.Exception.Message)"
            }
            
            return $output
            
        } catch {
            # Try to clean up on error
            try {
                $cleanupCommand = "Remove-Item -Path '$guestScriptPath' -Force -ErrorAction SilentlyContinue"
                Invoke-FusionVMGuestPowerShellCommand -FusionVM $FusionVM -Command $cleanupCommand -Credential $Credential -UsePwsh
            } catch {
                # Ignore cleanup errors during error handling
            }
            
            throw "Failed to execute script '$ScriptPath' on VM '$($FusionVM.Name)': $($_.Exception.Message)"
        }
    }
}

function Copy-FileToFusionVMGuest {
    <#
    .SYNOPSIS
    Copies a file from the host to a VM guest.
    
    .DESCRIPTION
    Copies a local file to a specified location on a VMware Fusion VM guest.
    
    .PARAMETER FusionVM
    VM object from Get-FusionVm or VM name string
    
    .PARAMETER LocalFile
    Path to the local file to copy
    
    .PARAMETER GuestFile
    Destination path on the VM guest
    
    .PARAMETER Credential
    PSCredential object for VM guest authentication
    
    .EXAMPLE
    Set-FusionVMCredential -Credential (Get-Credential)
    Copy-FileToFusionVMGuest -FusionVM "TestVM" -LocalFile "/Users/adam/file.txt" -GuestFile "C:\Users\user\file.txt"
    
    .EXAMPLE
    $cred = Get-Credential
    Get-FusionVm -Name "TestVM" | Copy-FileToFusionVMGuest -LocalFile "./script.ps1" -GuestFile "C:\temp\script.ps1" -Credential $cred
    #>
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$FusionVM,
        
        [Parameter(Mandatory)]
        [string]$LocalFile,
        
        [Parameter(Mandatory)]
        [string]$GuestFile,
        
        [Parameter()]
        [PSCredential]$Credential
    )
    
    process {
        # Resolve VM object if string was passed
        if ($FusionVM -is [string]) {
            $vmObject = Get-FusionVm -Name $FusionVM | Select-Object -First 1
            if (-not $vmObject) {
                throw "VM '$FusionVM' not found"
            }
        } else {
            $vmObject = $FusionVM
        }
        
        # Check if the local file exists
        if (-not (Test-Path $LocalFile)) {
            throw "Local file '$LocalFile' not found"
        }
        
        # Check if VM is running
        if ($vmObject.Status -ne "Running") {
            throw "VM '$($vmObject.Name)' is not running"
        }
        
        # Get credential with config fallback
        $Credential = Get-FusionVMCredentialWithFallback -Credential $Credential -VMName $vmObject.Name
        if (-not $Credential) {
            throw "No credential provided. Use -Credential parameter, call Set-FusionVMCredential, or configure credentials in config.json"
        }
        
        Write-Verbose "Copying file '$LocalFile' to VM '$($vmObject.Name)' at '$GuestFile'..."
        
        try {
            Invoke-VMRun -Command "copyFileFromHostToGuest" -VMPath $vmObject.Path -GuestCredential $Credential -CommandParameters @($LocalFile, $GuestFile)
            
            Write-Verbose "File copied successfully to '$GuestFile'"
            
        } catch {
            throw "Failed to copy file to VM '$($vmObject.Name)': $($_.Exception.Message)"
        }
    }
}

function Get-FusionVmScreenshot {
    <#
    .SYNOPSIS
    Captures a screenshot of a running VM and saves it to a local file.
    
    .DESCRIPTION
    Uses vmrun's captureScreen command to take a screenshot of the VM's current display
    and saves it as a PNG file on the host system.
    
    .PARAMETER FusionVM
    VM object from Get-FusionVm or VM name string
    
    .PARAMETER OutputPath
    Local path where the screenshot PNG file will be saved
    
    .PARAMETER Credential
    PSCredential object for VM guest authentication (required for captureScreen)
    
    .EXAMPLE
    Set-FusionVMCredential -Credential (Get-Credential)
    Get-FusionVmScreenshot -FusionVM "TestVM" -OutputPath "/Users/adam/screenshot.png"
    
    .EXAMPLE
    $cred = Get-Credential
    Get-FusionVm -Name "TestVM" | Get-FusionVmScreenshot -OutputPath "./vm_screenshot.png" -Credential $cred
    
    .EXAMPLE
    # Capture screenshot with timestamp
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    Get-FusionVmScreenshot -FusionVM "TestVM" -OutputPath "/Users/adam/screenshots/vm_$timestamp.png"
    #>
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$FusionVM,
        
        [Parameter(Mandatory)]
        [string]$OutputPath,
        
        [Parameter()]
        [PSCredential]$Credential
    )
    
    process {
        # Resolve VM object if string was passed
        if ($FusionVM -is [string]) {
            $vmObject = Get-FusionVm -Name $FusionVM | Select-Object -First 1
            if (-not $vmObject) {
                throw "VM '$FusionVM' not found"
            }
        } else {
            $vmObject = $FusionVM
        }
        
        # Check if VM is running
        if ($vmObject.Status -ne "Running") {
            throw "VM '$($vmObject.Name)' is not running. Screenshots can only be taken from running VMs."
        }
        
        # Get credential with config fallback
        $Credential = Get-FusionVMCredentialWithFallback -Credential $Credential -VMName $vmObject.Name
        if (-not $Credential) {
            throw "No credential provided. Use -Credential parameter, call Set-FusionVMCredential, or configure credentials in config.json"
        }
        
        Write-Verbose "Capturing screenshot of VM '$($vmObject.Name)' to '$OutputPath'..."
        
        # Create the directory for the output file if it doesn't exist
        $outputDir = Split-Path -Parent $OutputPath
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        
        # Ensure the output file has .png extension
        if (-not $OutputPath.EndsWith('.png', [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Warning "Screenshot will be saved as PNG format. Consider using .png extension."
        }
        
        try {
            Invoke-VMRun -Command "captureScreen" -VMPath $vmObject.Path -GuestCredential $Credential -CommandParameters @($OutputPath)
            
            # Verify the screenshot was created
            if (Test-Path $OutputPath) {
                $fileInfo = Get-Item $OutputPath
                Write-Verbose "Screenshot captured successfully: $($fileInfo.FullName) ($([math]::Round($fileInfo.Length / 1KB, 2)) KB)"
                
                # Return file info object
                return $fileInfo
            } else {
                throw "Screenshot file was not created at expected location: $OutputPath"
            }
            
        } catch {
            throw "Failed to capture screenshot from VM '$($vmObject.Name)': $($_.Exception.Message)"
        }
    }
}

function Copy-FileFromFusionVmGuest {
    <#
    .SYNOPSIS
    Copies a file from a VM guest to the host.
    
    .DESCRIPTION
    Copies a file from a VMware Fusion VM guest to a specified local location.
    
    .PARAMETER FusionVM
    VM object from Get-FusionVm or VM name string
    
    .PARAMETER GuestFile
    Path to the file on the VM guest
    
    .PARAMETER LocalFile
    Destination path on the local host
    
    .PARAMETER Credential
    PSCredential object for VM guest authentication
    
    .EXAMPLE
    Set-FusionVMCredential -Credential (Get-Credential)
    Copy-FileFromFusionVmGuest -FusionVM "TestVM" -GuestFile "C:\Users\user\output.txt" -LocalFile "/Users/adam/output.txt"
    
    .EXAMPLE
    $cred = Get-Credential
    Get-FusionVm -Name "TestVM" | Copy-FileFromFusionVmGuest -GuestFile "C:\temp\results.log" -LocalFile "./results.log" -Credential $cred
    #>
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$FusionVM,
        
        [Parameter(Mandatory)]
        [string]$GuestFile,
        
        [Parameter(Mandatory)]
        [string]$LocalFile,
        
        [Parameter()]
        [PSCredential]$Credential
    )
    
    process {
        # Resolve VM object if string was passed
        if ($FusionVM -is [string]) {
            $vmObject = Get-FusionVm -Name $FusionVM | Select-Object -First 1
            if (-not $vmObject) {
                throw "VM '$FusionVM' not found"
            }
        } else {
            $vmObject = $FusionVM
        }
        
        # Check if VM is running
        if ($vmObject.Status -ne "Running") {
            throw "VM '$($vmObject.Name)' is not running"
        }
        
        # Get credential with config fallback
        $Credential = Get-FusionVMCredentialWithFallback -Credential $Credential -VMName $vmObject.Name
        if (-not $Credential) {
            throw "No credential provided. Use -Credential parameter, call Set-FusionVMCredential, or configure credentials in config.json"
        }
        
        Write-Verbose "Copying file '$GuestFile' from VM '$($vmObject.Name)' to '$LocalFile'..."
        
        # Create the directory for the local file if it doesn't exist
        $localDir = Split-Path -Parent $LocalFile
        if (-not (Test-Path $localDir)) {
            New-Item -ItemType Directory -Path $localDir -Force | Out-Null
        }
        
        try {
            Invoke-VMRun -Command "copyFileFromGuestToHost" -VMPath $vmObject.Path -GuestCredential $Credential -CommandParameters @($GuestFile, $LocalFile)
            
            Write-Verbose "File copied successfully to '$LocalFile'"
            
        } catch {
            throw "Failed to copy file from VM '$($vmObject.Name)': $($_.Exception.Message)"
        }
    }
}

function Get-VMIPAddress {
    <#
    .SYNOPSIS
    Gets the IP address of a VM by running ipconfig inside the guest OS.
    
    .DESCRIPTION
    This function runs ipconfig inside a Windows VM guest and parses the output to extract
    the primary IP address. This is more reliable than vmrun getGuestIPAddress which often
    fails or hangs, especially in headless mode.
    
    .PARAMETER FusionVM
    VM object from Get-FusionVm or VM name string
    
    .PARAMETER Credential
    PSCredential object for VM guest authentication
    
    .PARAMETER AdapterName
    Optional network adapter name to get IP from (default: gets first IPv4 address)
    
    .EXAMPLE
    Get-VMIPAddress -FusionVM "DEMOVM"
    
    .EXAMPLE
    Get-FusionVm -Name "DEMOVM" | Get-VMIPAddress
    
    .EXAMPLE
    Get-VMIPAddress -FusionVM "DEMOVM" -AdapterName "Ethernet0"
    #>
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$FusionVM,
        
        [Parameter()]
        [PSCredential]$Credential,
        
        [Parameter()]
        [string]$AdapterName
    )
    
    process {
        # Resolve VM object if string was passed
        if ($FusionVM -is [string]) {
            $vmObject = Get-FusionVm -Name $FusionVM | Select-Object -First 1
            if (-not $vmObject) {
                throw "VM '$FusionVM' not found"
            }
        } else {
            $vmObject = $FusionVM
        }
        
        # Check if VM is running
        if ($vmObject.Status -ne "Running") {
            throw "VM '$($vmObject.Name)' is not running. VM must be running to get IP address."
        }
        
        # Get credential with config fallback
        $Credential = Get-FusionVMCredentialWithFallback -Credential $Credential -VMName $vmObject.Name
        if (-not $Credential) {
            throw "No credential provided. Use -Credential parameter, call Set-FusionVMCredential, or configure credentials in config.json"
        }
        
        Write-Verbose "Getting IP address from VM '$($vmObject.Name)'..."
        
        try {
            # Run ipconfig using the existing PowerShell command function and get all IPv4s
            $psCommand = @'
$ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { 
    $_.IPAddress -notlike "127.*" -and 
    $_.IPAddress -notlike "169.254.*" -and
    $_.InterfaceAlias -notlike "*Loopback*"
} | Select-Object -ExpandProperty IPAddress
if ($ips) {
    $ips -join ","
} else {
    # Fallback to ipconfig parsing
    $output = ipconfig
    $matches = [regex]::Matches($output, 'IPv4 Address[^:]*:\s*([\d\.]+)')
    $validIPs = $matches | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -notlike "169.254.*" }
    if ($validIPs) {
        $validIPs[0]
    } else {
        "NO_VALID_IP"
    }
}
'@
            $result = Invoke-FusionVMGuestPowerShellCommand -FusionVM $vmObject -Command $psCommand -Credential $Credential
            
            if ($result -and $result -ne "NO_VALID_IP") {
                # If multiple IPs, take the first one
                $ipAddress = ($result -split ',')[0].Trim()
                Write-Verbose "Found IP address: $ipAddress"
                return $ipAddress
            } else {
                throw "No valid IP address found"
            }
            
        } catch {
            throw "Failed to get IP address from VM '$($vmObject.Name)': $($_.Exception.Message)"
        }
    }
}

function Restart-FusionVM {
    <#
    .SYNOPSIS
    Restarts a VMware Fusion virtual machine and waits for VMware Tools to be available.
    
    .DESCRIPTION
    This function gracefully stops a VM, starts it again, and then waits for VMware Tools
    to be running before returning. This ensures the VM is fully ready for operations.
    
    .PARAMETER FusionVM
    A FusionVM object or VM name to restart
    
    .PARAMETER MaxWaitMinutes
    Maximum time to wait for the VM to be ready after restart (default: 5 minutes)
    
    .EXAMPLE
    Restart-FusionVM -FusionVM "DEMOVM"
    
    .EXAMPLE
    Get-FusionVm -Name "TestVM" | Restart-FusionVM
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$FusionVM,
        
        [Parameter()]
        [int]$MaxWaitMinutes = 5
    )
    
    process {
        # Resolve VM object if name was provided
        if ($FusionVM -is [string]) {
            $vmObject = Get-FusionVm -Name $FusionVM
            if (-not $vmObject) {
                throw "VM '$FusionVM' not found"
            }
        } else {
            $vmObject = $FusionVM
        }
        
        Write-Verbose "Restarting VM '$($vmObject.Name)'"
        
        # Stop the VM using existing function
        try {
            if ($vmObject.Status -eq "Running") {
                Write-Verbose "Stopping VM '$($vmObject.Name)'..."
                Stop-FusionVm -FusionVM $vmObject
                
                # Wait a moment for the VM to fully stop
                Start-Sleep -Seconds 3
            } else {
                Write-Verbose "VM '$($vmObject.Name)' is already stopped"
            }
        } catch {
            throw "Failed to stop VM '$($vmObject.Name)': $($_.Exception.Message)"
        }
        
        # Start the VM using existing function (which includes Wait-FusionVmReady)
        try {
            Write-Verbose "Starting VM '$($vmObject.Name)'..."
            Start-FusionVm -FusionVM $vmObject
            Write-Verbose "VM '$($vmObject.Name)' has been restarted and is ready"
        } catch {
            throw "Failed to start VM '$($vmObject.Name)': $($_.Exception.Message)"
        }
        
        # Return the updated VM object
        Get-FusionVm -Name $vmObject.Name
    }
}

