#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }

# Regression test for the HIGH finding: Export-ComplianceDataFile only ever writes a new .xml
# file on success; nothing ever deletes stale files from a prior run. Re-running against a
# different tenant's -OutputPath (the function's own .EXAMPLE blocks use fixed, reusable paths)
# previously left the prior tenant's exported data readable by New-PurviewConfigurationReport
# with no warning - the same class of cross-tenant leak the original CRITICAL fixed, just moved
# from a script-scope variable to disk.
#
# Deliberately does NOT mock Export-Clixml/Import-Clixml - this test writes real files to
# Pester's own $TestDrive sandbox so the actual on-disk behaviour is what's under test.

BeforeAll {
    function Connect-IPPSSession
    {
        [CmdletBinding()]
        param()
    }

    function Disconnect-ExchangeOnline
    {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub signature only, mocked in tests below')]
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [Parameter()]
            [string[]]$ConnectionId
        )
    }

    function Get-ConnectionInformation
    {
        [CmdletBinding()]
        param()
    }

    function Get-InsiderRiskPolicy
    {
        [CmdletBinding()]
        param()
    }

    . "$PSScriptRoot/../../source/Public/Export-PurviewConfiguration.ps1"

    Mock Disconnect-ExchangeOnline -MockWith {}

    function Set-MockConnection
    {
        # Export-PurviewConfiguration.ps1 diffs Get-ConnectionInformation's result before and
        # after Connect-IPPSSession to find the ConnectionId/TenantID of the session it just
        # opened. A mock that returns the same static object on every call would be filtered out
        # as "already present" on the second (after-connect) call - this returns empty on the
        # first call of each pair, then the given connection on the next, mirroring a real
        # connect actually adding a new session.
        # Named Set- (not New-) because it reconfigures the existing Get-ConnectionInformation
        # mock in place; it only changes test-double state, not anything ShouldProcess applies
        # to, and its ConnectionId/TenantId parameters are used inside the mock's scriptblock via
        # .GetNewClosure(), which ScriptAnalyzer's static analysis does not trace into.
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
        param(
            [Parameter(Mandatory)]
            [string]$ConnectionId,
            [Parameter(Mandatory)]
            [string]$TenantId
        )
        $script:mockConnectionCallCount = 0
        Mock Get-ConnectionInformation -MockWith {
            $script:mockConnectionCallCount++
            if ($script:mockConnectionCallCount % 2 -eq 1)
            {
                @()
            }
            else
            {
                @([pscustomobject]@{ ConnectionId = $ConnectionId; TenantID = $TenantId })
            }
        }.GetNewClosure()
    }
}

Describe 'Export-PurviewConfiguration file-level cross-tenant leak' {
    It 'refuses to reuse a different tenant''s OutputPath without -Force, and the stale file survives' {
        $sharedPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $sharedPath -Force | Out-Null

        # Tenant A run: writes a real Get-InsiderRiskPolicy.xml to $sharedPath.
        Mock Connect-IPPSSession -MockWith {}
        Set-MockConnection -ConnectionId 'conn-a' -TenantId 'tenant-a'
        Mock Get-InsiderRiskPolicy -MockWith { @([pscustomobject]@{ Name = 'TENANT-A-POLICY' }) }

        Export-PurviewConfiguration -OutputPath $sharedPath -Command 'Get-InsiderRiskPolicy' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false

        Test-Path -Path (Join-Path -Path $sharedPath -ChildPath 'Get-InsiderRiskPolicy.xml') | Should -BeTrue

        # Tenant B run against the SAME OutputPath: a different tenant, and its account lacks
        # Insider Risk Management (CommandNotFoundException) - the realistic trigger scenario.
        Set-MockConnection -ConnectionId 'conn-b' -TenantId 'tenant-b'
        Mock Get-InsiderRiskPolicy -MockWith { throw [System.Management.Automation.CommandNotFoundException]::new('Get-InsiderRiskPolicy not found') }

        { Export-PurviewConfiguration -OutputPath $sharedPath -Command 'Get-InsiderRiskPolicy' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false -ErrorAction Stop } |
            Should -Throw

        # The safety check must have refused BEFORE anything touched the stale file - tenant A's
        # data is still sitting there, readable by a report render against this same folder.
        $staleContent = Import-Clixml -Path (Join-Path -Path $sharedPath -ChildPath 'Get-InsiderRiskPolicy.xml')
        $staleContent.Name | Should -Be 'TENANT-A-POLICY'
    }

    It 'allows reuse with -Force, purging the stale tenant''s file first' {
        $sharedPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $sharedPath -Force | Out-Null

        Mock Connect-IPPSSession -MockWith {}
        Set-MockConnection -ConnectionId 'conn-a' -TenantId 'tenant-a'
        Mock Get-InsiderRiskPolicy -MockWith { @([pscustomobject]@{ Name = 'TENANT-A-POLICY' }) }
        Export-PurviewConfiguration -OutputPath $sharedPath -Command 'Get-InsiderRiskPolicy' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false

        Set-MockConnection -ConnectionId 'conn-b' -TenantId 'tenant-b'
        Mock Get-InsiderRiskPolicy -MockWith { @([pscustomobject]@{ Name = 'TENANT-B-POLICY' }) }

        Export-PurviewConfiguration -OutputPath $sharedPath -Command 'Get-InsiderRiskPolicy' -SkipModuleCheck -SkipComplianceSecurityFilter -Force -Confirm:$false

        $content = Import-Clixml -Path (Join-Path -Path $sharedPath -ChildPath 'Get-InsiderRiskPolicy.xml')
        $content.Name | Should -Be 'TENANT-B-POLICY'
    }

    It 'leaves an unrelated file in OutputPath alone even under -Force' {
        $sharedPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $sharedPath -Force | Out-Null
        'not export data' | Set-Content -Path (Join-Path -Path $sharedPath -ChildPath 'notes.xml')

        Mock Connect-IPPSSession -MockWith {}
        Set-MockConnection -ConnectionId 'conn-a' -TenantId 'tenant-a'
        Mock Get-InsiderRiskPolicy -MockWith { @([pscustomobject]@{ Name = 'TENANT-A-POLICY' }) }

        Export-PurviewConfiguration -OutputPath $sharedPath -Command 'Get-InsiderRiskPolicy' -SkipModuleCheck -SkipComplianceSecurityFilter -Force -Confirm:$false

        Test-Path -Path (Join-Path -Path $sharedPath -ChildPath 'notes.xml') | Should -BeTrue
    }

    It 'fails closed on a folder with known export files but no manifest (pre-fix folder)' {
        $sharedPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $sharedPath -Force | Out-Null
        [pscustomobject]@{ Name = 'LEGACY-POLICY' } | Export-Clixml -Path (Join-Path -Path $sharedPath -ChildPath 'Get-InsiderRiskPolicy.xml')

        Mock Connect-IPPSSession -MockWith {}
        Set-MockConnection -ConnectionId 'conn-a' -TenantId 'tenant-a'
        Mock Get-InsiderRiskPolicy -MockWith { @([pscustomobject]@{ Name = 'TENANT-A-POLICY' }) }

        { Export-PurviewConfiguration -OutputPath $sharedPath -Command 'Get-InsiderRiskPolicy' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false -ErrorAction Stop } |
            Should -Throw
    }

    It 'proceeds normally against a brand-new, empty OutputPath with no -Force needed' {
        $freshPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid())

        Mock Connect-IPPSSession -MockWith {}
        Set-MockConnection -ConnectionId 'conn-a' -TenantId 'tenant-a'
        Mock Get-InsiderRiskPolicy -MockWith { @([pscustomobject]@{ Name = 'TENANT-A-POLICY' }) }

        $result = Export-PurviewConfiguration -OutputPath $freshPath -Command 'Get-InsiderRiskPolicy' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false

        $result.Exported | Should -BeTrue
    }

    It 'allows re-running a -Command subset for the SAME tenant without -Force' {
        $sharedPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $sharedPath -Force | Out-Null

        Mock Connect-IPPSSession -MockWith {}
        Set-MockConnection -ConnectionId 'conn-a' -TenantId 'tenant-a'
        Mock Get-InsiderRiskPolicy -MockWith { @([pscustomobject]@{ Name = 'TENANT-A-POLICY' }) }

        Export-PurviewConfiguration -OutputPath $sharedPath -Command 'Get-InsiderRiskPolicy' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false

        # Re-run the SAME subset for the SAME tenant (e.g. retry after a transient failure) -
        # must succeed without -Force, since the tenant stamp matches. Reset the connection mock
        # for this second invocation too (same tenant, but it's a fresh Get-ConnectionInformation
        # before/after pair).
        Set-MockConnection -ConnectionId 'conn-a' -TenantId 'tenant-a'
        { Export-PurviewConfiguration -OutputPath $sharedPath -Command 'Get-InsiderRiskPolicy' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false -ErrorAction Stop } |
            Should -Not -Throw
    }
}
