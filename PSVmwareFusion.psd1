@{
    RootModule = 'PSVmwareFusion.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'f8b9c3d2-1a4e-5f6b-8c7d-9e0f1a2b3c4d'
    Author = 'Adam Bertram'
    CompanyName = 'Adam Bertram'
    Copyright = '(c) 2025 Adam Bertram. All rights reserved.'
    Description = 'PowerShell module for managing VMware Fusion virtual machines on macOS'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-DemoVm',
        'Start-DemoVm', 
        'Stop-DemoVm',
        'Wait-DemoVmReady',
        'Get-DemoVmSnapshot',
        'New-DemoVmSnapshot',
        'Restore-DemoVmSnapshot',
        'Remove-DemoVmSnapshot'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    RequiredModules = @()
    RequiredAssemblies = @()
    ScriptsToProcess = @()
    TypesToProcess = @()
    FormatsToProcess = @()
    NestedModules = @()
    DscResourcesToExport = @()
    ModuleList = @()
    FileList = @(
        'PSVmwareFusion.psm1',
        'PSVmwareFusion.psd1'
    )
    PrivateData = @{
        PSData = @{
            Tags = @('VMware', 'Fusion', 'VirtualMachine', 'macOS', 'Snapshot', 'VM')
            LicenseUri = 'https://github.com/adbertram/PSVmwareFusion/blob/main/LICENSE'
            ProjectUri = 'https://github.com/adbertram/PSVmwareFusion'
            ReleaseNotes = 'Initial release of PSVmwareFusion module'
        }
    }
    HelpInfoURI = 'https://github.com/adbertram/PSVmwareFusion'
    DefaultCommandPrefix = ''
}