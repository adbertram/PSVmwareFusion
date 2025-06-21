# PSVmwareFusion

A PowerShell module for managing VMware Fusion virtual machines on macOS.

## Description

PSVmwareFusion provides a comprehensive set of PowerShell functions to manage VMware Fusion VMs directly from the command line. The module wraps VMware's `vmrun` command-line utility with PowerShell-friendly functions that support pipeline operations and rich object output.

## Prerequisites

- macOS with VMware Fusion installed
- PowerShell 5.1 or later
- VMware Fusion's `vmrun` utility (included with VMware Fusion)

## Installation

### From Source
```powershell
git clone https://github.com/adbertram/PSVmwareFusion.git
Import-Module ./PSVmwareFusion/PSVmwareFusion.psd1
```

## Functions

### VM Management
- **Get-FusionVm** - List and filter virtual machines
- **Start-FusionVm** - Start virtual machines 
- **Stop-FusionVm** - Stop virtual machines
- **Wait-FusionVmReady** - Wait for VM to be fully ready with VMware Tools

### Snapshot Management
- **Get-FusionVmSnapshot** - List VM snapshots with size and file information
- **New-FusionVmSnapshot** - Create new VM snapshots
- **Restore-FusionVmSnapshot** - Restore VMs to specific snapshots
- **Remove-FusionVmSnapshot** - Delete VM snapshots

## Usage Examples

### Basic VM Operations
```powershell
# List all VMs
Get-FusionVm

# Get specific VM
Get-FusionVm -VMName "MyVM"

# Start a VM
Get-FusionVm -VMName "MyVM" | Start-FusionVm

# Stop a VM  
Get-FusionVm -VMName "MyVM" | Stop-FusionVm
```

### Snapshot Operations
```powershell
# List all snapshots for a VM
Get-FusionVm -VMName "MyVM" | Get-FusionVmSnapshot

# Create a snapshot
Get-FusionVm -VMName "MyVM" | New-FusionVmSnapshot -Name "BeforeUpdate" -Description "Pre-update state"

# Create a snapshot after stopping the VM (faster)
Get-FusionVm -VMName "MyVM" | New-FusionVmSnapshot -Name "CleanState" -Shutdown

# Restore to a snapshot
Get-FusionVm -VMName "MyVM" | Get-FusionVmSnapshot -Name "BeforeUpdate" | Restore-FusionVmSnapshot

# Remove a snapshot
Get-FusionVm -VMName "MyVM" | Get-FusionVmSnapshot -Name "OldSnapshot" | Remove-FusionVmSnapshot
```

### Advanced Pipeline Operations
```powershell
# Start multiple VMs
Get-FusionVm | Where-Object Status -eq "Stopped" | Start-FusionVm

# Get snapshot information with sizes
Get-FusionVm | Get-FusionVmSnapshot | Format-Table Name, VMName, Size, SizeBytes

# Remove old snapshots
Get-FusionVm | Get-FusionVmSnapshot | Where-Object Name -like "*old*" | Remove-FusionVmSnapshot
```

## Object Properties

### VM Objects
- **Name** - VM display name
- **Path** - Full path to .vmx file
- **Status** - Current VM state (Running/Stopped)
- **CurrentSnapshot** - Name of current snapshot
- **IPAddress** - VM's IP address (if running)

### Snapshot Objects  
- **Name** - Snapshot name
- **VMName** - Parent VM name
- **VMPath** - Full path to parent VM
- **Size** - Total size in GB
- **SizeBytes** - Total size in bytes
- **Files** - Array of snapshot files with paths, sizes, and types

## Features

- **Pipeline Support** - All functions support PowerShell pipeline operations
- **Rich Objects** - Functions return structured objects instead of plain text
- **Error Handling** - Comprehensive error handling with meaningful messages
- **Verbose Output** - Detailed verbose logging for troubleshooting
- **File System Integration** - Snapshot functions include actual file sizes and paths
- **State Management** - Automatic VM state restoration after operations

## Requirements

This module requires VMware Fusion to be installed on macOS. The module automatically detects the VMware Fusion installation and uses the appropriate `vmrun` executable.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

**Adam Bertram**
- GitHub: [@adbertram](https://github.com/adbertram)