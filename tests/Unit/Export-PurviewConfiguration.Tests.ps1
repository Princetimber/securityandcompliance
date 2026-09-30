#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }

BeforeAll {
    # Stubs for Security & Compliance PowerShell cmdlets (ExchangeOnlineManagement module) that
    # are not installed in this environment. Declared before dot-sourcing so Mock has a real
    # command to attach to, with a signature matching every parameter the code under test binds.
    function Connect-IPPSSession
    {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub signature only, mocked in tests below')]
        [CmdletBinding()]
        param(
            [Parameter()]
            [switch]$EnableSearchOnlySession
        )
    }

    function Disconnect-ExchangeOnline
    {
        # SupportsShouldProcess automatically supplies the -Confirm common parameter; no
        # manual [switch]$Confirm is declared here.
        [CmdletBinding(SupportsShouldProcess)]
        param()
    }

    function Get-Label
    {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub signature only, mocked in tests below')]
        [CmdletBinding()]
        param(
            [Parameter()]
            [switch]$IncludeDetailedLabelActions
        )
    }

    . "$PSScriptRoot/../../Export-PurviewConfiguration.ps1"

    Mock Connect-IPPSSession -MockWith {}
    Mock Disconnect-ExchangeOnline -MockWith {}
    Mock Export-Clixml -MockWith {}
}

Describe 'Export-PurviewConfiguration' {
    Context 'Parameter validation' {
        It 'requires the OutputPath parameter' {
            { Export-PurviewConfiguration } | Should -Throw
        }

        It 'throws on an unrecognised -Command value (regression for command-injection finding)' {
            { Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-TotallyMadeUpCmdlet' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false } |
                Should -Throw
        }
    }

    Context 'Successful export' {
        BeforeAll {
            Mock Get-Label -MockWith { @([pscustomobject]@{ Name = 'Confidential' }) }
        }

        It 'exports data and reports Exported = $true' {
            $result = Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-Label' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false

            $result.Command | Should -Be 'Get-Label'
            $result.RecordCount | Should -Be 1
            $result.Exported | Should -BeTrue
            Should -Invoke Export-Clixml -Times 1
        }
    }

    Context 'ShouldProcess / -WhatIf honesty (regression for HIGH finding)' {
        BeforeAll {
            Mock Get-Label -MockWith { @([pscustomobject]@{ Name = 'Confidential' }) }
        }

        It 'reports Exported = $false and never calls Export-Clixml under -WhatIf' {
            $result = Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-Label' -SkipModuleCheck -SkipComplianceSecurityFilter -WhatIf

            $result.Exported | Should -BeFalse
            Should -Invoke Export-Clixml -Times 0
        }
    }

    Context 'Cmdlet not available to the connected account' {
        It 'treats a CommandNotFoundException as a benign per-tenant condition' {
            # 'Get-DlpCompliancePolicy' is a valid -Command value but is not stubbed anywhere in
            # this test file, so it genuinely does not exist in this session - exercising the
            # real CommandNotFoundException catch branch rather than a simulated one.
            $result = Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-DlpCompliancePolicy' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false -WarningVariable capturedWarning -WarningAction SilentlyContinue

            $result.Exported | Should -BeFalse
            $result.RecordCount | Should -Be 0
            $capturedWarning | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Module bootstrap (Install-Module hardening)' {
        BeforeAll {
            Mock Get-Label -MockWith { @([pscustomobject]@{ Name = 'Confidential' }) }
            Mock Install-Module -MockWith {}
            Mock Get-Module -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' -and $ListAvailable } -MockWith { $null }
            Mock Get-Module -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' -and -not $ListAvailable } -MockWith {
                [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.5.0' }
            }
        }

        It 'installs from PSGallery, pinned, when the module is missing or below minimum version' {
            $null = Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-Label' -SkipComplianceSecurityFilter -Confirm:$false

            Should -Invoke Install-Module -Times 1 -ParameterFilter {
                $Name -eq 'ExchangeOnlineManagement' -and $Repository -eq 'PSGallery'
            }
        }

        It 'does not install the module under -WhatIf' {
            $null = Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-Label' -SkipComplianceSecurityFilter -WhatIf

            Should -Invoke Install-Module -Times 0
        }
    }

    Context 'Get-ComplianceSecurityFilter version gate' {
        BeforeAll {
            Mock Get-Module -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' -and -not $ListAvailable } -MockWith {
                [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.5.0' }
            }
        }

        It 'skips with a warning when the loaded module is below the required version' {
            $result = Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-ComplianceSecurityFilter' -SkipModuleCheck -Confirm:$false -WarningVariable capturedWarning -WarningAction SilentlyContinue

            $result.Command | Should -Be 'Get-ComplianceSecurityFilter'
            $result.Exported | Should -BeFalse
            $capturedWarning | Should -Not -BeNullOrEmpty
        }
    }
}
