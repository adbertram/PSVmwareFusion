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
- **Get-DemoVm** - List and filter virtual machines
- **Start-DemoVm** - Start virtual machines 
- **Stop-DemoVm** - Stop virtual machines
- **Wait-DemoVmReady** - Wait for VM to be fully ready with VMware Tools

### Snapshot Management
- **Get-DemoVmSnapshot** - List VM snapshots with size and file information
- **New-DemoVmSnapshot** - Create new VM snapshots
- **Restore-DemoVmSnapshot** - Restore VMs to specific snapshots
- **Remove-DemoVmSnapshot** - Delete VM snapshots

## Usage Examples

### Basic VM Operations
```powershell
# List all VMs
Get-DemoVm

# Get specific VM
Get-DemoVm -VMName "MyVM"

# Start a VM
Get-DemoVm -VMName "MyVM" | Start-DemoVm

# Stop a VM  
Get-DemoVm -VMName "MyVM" | Stop-DemoVm
```

### Snapshot Operations
```powershell
# List all snapshots for a VM
Get-DemoVm -VMName "MyVM" | Get-DemoVmSnapshot

# Create a snapshot
Get-DemoVm -VMName "MyVM" | New-DemoVmSnapshot -Name "BeforeUpdate" -Description "Pre-update state"

# Create a snapshot after stopping the VM (faster)
Get-DemoVm -VMName "MyVM" | New-DemoVmSnapshot -Name "CleanState" -Shutdown

# Restore to a snapshot
Get-DemoVm -VMName "MyVM" | Get-DemoVmSnapshot -Name "BeforeUpdate" | Restore-DemoVmSnapshot

# Remove a snapshot
Get-DemoVm -VMName "MyVM" | Get-DemoVmSnapshot -Name "OldSnapshot" | Remove-DemoVmSnapshot
```

### Advanced Pipeline Operations
```powershell
# Start multiple VMs
Get-DemoVm | Where-Object Status -eq "Stopped" | Start-DemoVm

# Get snapshot information with sizes
Get-DemoVm | Get-DemoVmSnapshot | Format-Table Name, VMName, Size, SizeBytes

# Remove old snapshots
Get-DemoVm | Get-DemoVmSnapshot | Where-Object Name -like "*old*" | Remove-DemoVmSnapshot
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