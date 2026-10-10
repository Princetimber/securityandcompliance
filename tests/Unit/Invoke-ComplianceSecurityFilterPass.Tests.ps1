#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }

BeforeAll {
    # Run the code under test in strict mode so an unguarded missing property fails here, not in an
    # operator's session that happens to enable it.
    Set-StrictMode -Version Latest

    # Stubs for Security & Compliance PowerShell cmdlets (ExchangeOnlineManagement module) that are
    # not installed in this environment, so Mock has a real command to attach to.
    function Connect-IPPSSession
    {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub signature only, mocked in tests below')]
        [CmdletBinding()]
        param(
            [Parameter()]
            [string]$UserPrincipalName,
            [Parameter()]
            [switch]$EnableSearchOnlySession
        )
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
    function Get-ComplianceSecurityFilter
    {
        [CmdletBinding()]
        param()
    }

    . "$PSScriptRoot/../../source/Private/Get-NewConnectionInformation.ps1"
    . "$PSScriptRoot/../../source/Private/Export-ComplianceDataFile.ps1"
    . "$PSScriptRoot/../../source/Private/Invoke-ComplianceSecurityFilterPass.ps1"
}

Describe 'Invoke-ComplianceSecurityFilterPass' {
    BeforeEach {
        Mock Connect-IPPSSession {}
        Mock Disconnect-ExchangeOnline {}
        Mock Get-ConnectionInformation { @() }
        Mock Get-NewConnectionInformation { [pscustomobject]@{ ConnectionId = 'search-1'; TenantID = 'tenant-a' } }
        Mock Export-ComplianceDataFile { $true }
        Mock Get-Module { [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.9.0' } }
        $script:standardId = 'standard-1'
    }

    It 'is skipped under -DeviceCode and never reconnects' {
        $result = Invoke-ComplianceSecurityFilterPass -ConnectParameter @{} -OutputPath $TestDrive -ParameterSetName 'DeviceCode' -StandardConnectionId ([ref]$script:standardId) -WarningVariable w -WarningAction SilentlyContinue
        $result.Command | Should -Be 'Get-ComplianceSecurityFilter'
        $result.Exported | Should -BeFalse
        ($w -join ' ') | Should -Match 'DeviceCode'
        Should -Invoke Connect-IPPSSession -Times 0
        $script:standardId | Should -Be 'standard-1'
    }

    It 'is skipped when the loaded module is older than 3.9.0' {
        Mock Get-Module { [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.5.0' } }
        $result = Invoke-ComplianceSecurityFilterPass -ConnectParameter @{} -OutputPath $TestDrive -ParameterSetName 'Default' -StandardConnectionId ([ref]$script:standardId) -WarningVariable w -WarningAction SilentlyContinue
        $result.Exported | Should -BeFalse
        ($w -join ' ') | Should -Match '3\.9\.0'
        Should -Invoke Connect-IPPSSession -Times 0
        Should -Invoke Disconnect-ExchangeOnline -Times 0
    }

    Context 'Successful pass' {
        BeforeEach {
            Mock Get-ComplianceSecurityFilter { @([pscustomobject]@{ Name = 'Filter1' }, [pscustomobject]@{ Name = 'Filter2' }) }
        }

        It 'exports the data and reports the record count' {
            $result = Invoke-ComplianceSecurityFilterPass -ConnectParameter @{ UserPrincipalName = 'a@contoso.com' } -OutputPath $TestDrive -ParameterSetName 'Default' -StandardConnectionId ([ref]$script:standardId)
            $result.RecordCount | Should -Be 2
            $result.Exported | Should -BeTrue
            Should -Invoke Export-ComplianceDataFile -Times 1 -ParameterFilter { $CmdletName -eq 'Get-ComplianceSecurityFilter' }
        }

        It 'reuses the caller authentication parameters for the search-only reconnect' {
            $null = Invoke-ComplianceSecurityFilterPass -ConnectParameter @{ UserPrincipalName = 'a@contoso.com' } -OutputPath $TestDrive -ParameterSetName 'Default' -StandardConnectionId ([ref]$script:standardId)
            Should -Invoke Connect-IPPSSession -Times 1 -ParameterFilter { $EnableSearchOnlySession -and $UserPrincipalName -eq 'a@contoso.com' }
        }

        It 'disconnects the standard session, clears the caller variable, then disconnects the search session' {
            $null = Invoke-ComplianceSecurityFilterPass -ConnectParameter @{} -OutputPath $TestDrive -ParameterSetName 'Default' -StandardConnectionId ([ref]$script:standardId)
            $script:standardId | Should -BeNullOrEmpty
            Should -Invoke Disconnect-ExchangeOnline -Times 1 -ParameterFilter { $ConnectionId -eq 'standard-1' }
            Should -Invoke Disconnect-ExchangeOnline -Times 1 -ParameterFilter { $ConnectionId -eq 'search-1' }
        }

        It 'does not try to disconnect a standard session the caller no longer has' {
            $script:standardId = $null
            $null = Invoke-ComplianceSecurityFilterPass -ConnectParameter @{} -OutputPath $TestDrive -ParameterSetName 'Default' -StandardConnectionId ([ref]$script:standardId)
            Should -Invoke Disconnect-ExchangeOnline -Times 0 -ParameterFilter { $ConnectionId -eq 'standard-1' }
            Should -Invoke Disconnect-ExchangeOnline -Times 1 -ParameterFilter { $ConnectionId -eq 'search-1' }
        }
    }

    It 'reports zero records and warns when the cmdlet returns nothing' {
        Mock Get-ComplianceSecurityFilter { $null }
        $result = Invoke-ComplianceSecurityFilterPass -ConnectParameter @{} -OutputPath $TestDrive -ParameterSetName 'Default' -StandardConnectionId ([ref]$script:standardId) -WarningVariable w -WarningAction SilentlyContinue
        $result.RecordCount | Should -Be 0
        $result.Exported | Should -BeFalse
        ($w -join ' ') | Should -Match 'No data generated'
        Should -Invoke Export-ComplianceDataFile -Times 0
    }

    It 'turns a failure into an error plus a zero-record result and still disconnects the search session' {
        Mock Get-ComplianceSecurityFilter { throw 'Access denied' }
        $result = Invoke-ComplianceSecurityFilterPass -ConnectParameter @{} -OutputPath $TestDrive -ParameterSetName 'Default' -StandardConnectionId ([ref]$script:standardId) -ErrorVariable e -ErrorAction SilentlyContinue
        $result.Exported | Should -BeFalse
        ($e | Out-String) | Should -Match 'eDiscovery Administrator'
        Should -Invoke Disconnect-ExchangeOnline -Times 1 -ParameterFilter { $ConnectionId -eq 'search-1' }
    }
}
