#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }

BeforeAll {
    # Run the code under test in strict mode so an unguarded missing property fails here, not in an
    # operator's session that happens to enable it.
    Set-StrictMode -Version Latest

    . "$PSScriptRoot/../../source/Private/Get-ExportCommandList.ps1"
}

Describe 'Get-ExportCommandList' {
    BeforeAll {
        $script:commands = @(Get-ExportCommandList)
    }

    It 'returns a non-empty list of cmdlet names' {
        $script:commands.Count | Should -BeGreaterThan 50
        $script:commands | ForEach-Object { $_ | Should -BeOfType [string] }
    }

    It 'contains no duplicate names (case-insensitive)' {
        $script:commands.Count | Should -Be @($script:commands | Select-Object -Unique).Count
    }

    It 'names only Get- cmdlets, since the export is read-only' {
        @($script:commands | Where-Object { $_ -notmatch '^Get-' }).Count | Should -Be 0
    }

    It 'leaves out the two cmdlets the caller handles separately' {
        $script:commands | Should -Not -Contain 'Get-Label'
        $script:commands | Should -Not -Contain 'Get-ComplianceSecurityFilter'
    }

    It 'includes the cmdlets that need paging' {
        $script:commands | Should -Contain 'Get-QuarantineMessage'
        $script:commands | Should -Contain 'Get-DlpDetectionsReport'
    }
}
