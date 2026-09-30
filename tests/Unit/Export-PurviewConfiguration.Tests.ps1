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
            [switch]$EnableSearchOnlySession,
            [Parameter()]
            [string]$UserPrincipalName,
            [Parameter()]
            [string]$CertificateThumbprint,
            [Parameter()]
            [string]$CertificateFilePath,
            [Parameter()]
            [securestring]$CertificatePassword,
            [Parameter()]
            [string]$AppId,
            [Parameter()]
            [string]$Organization,
            [Parameter()]
            [string]$AccessToken
        )
    }

    function Disconnect-ExchangeOnline
    {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub signature only, mocked in tests below')]
        # SupportsShouldProcess automatically supplies the -Confirm common parameter; no
        # manual [switch]$Confirm is declared here.
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [Parameter()]
            [string[]]$ConnectionId
        )
    }

    $script:defaultConnectionInformationCallCount = 0
    function Get-ConnectionInformation
    {
        # Default (unmocked) return: empty on the first call (the "before connect" snapshot the
        # real code takes to diff against), a connection with a non-null TenantID on every call
        # after that - mimicking a genuine connect actually adding a new session, which the
        # before/after ConnectionId diff in Export-PurviewConfiguration.ps1 depends on. A static
        # return here would make every call "already present" and filtered out of the diff.
        # Tests that care about specific ConnectionId/TenantID values override this with their
        # own Mock.
        [CmdletBinding()]
        param()
        $script:defaultConnectionInformationCallCount++
        if ($script:defaultConnectionInformationCallCount -eq 1)
        {
            @()
        }
        else
        {
            @([pscustomobject]@{ ConnectionId = 'default-connection'; TenantID = 'default-tenant' })
        }
    }

    function Get-ComplianceSecurityFilter
    {
        [CmdletBinding()]
        param()
    }

    function Get-QuarantineMessage
    {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub signature only, mocked in tests below')]
        [CmdletBinding()]
        param(
            [Parameter()]
            [int]$Page,
            [Parameter()]
            [int]$PageSize,
            [Parameter()]
            [datetime]$StartReceivedDate,
            [Parameter()]
            [datetime]$EndReceivedDate
        )
    }

    function Get-DlpDetectionsReport
    {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub signature only, mocked in tests below')]
        [CmdletBinding()]
        param(
            [Parameter()]
            [int]$Page,
            [Parameter()]
            [int]$PageSize
        )
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

    . "$PSScriptRoot/../../source/Public/Export-PurviewConfiguration.ps1"

    Mock Connect-IPPSSession -MockWith {}
    Mock Disconnect-ExchangeOnline -MockWith {}
    Mock Export-Clixml -MockWith {}
}

Describe 'Export-PurviewConfiguration' {
    BeforeEach {
        # Reset the default Get-ConnectionInformation stub's call counter before every test, so
        # each test's own "before connect" snapshot starts fresh rather than continuing a count
        # left over from whichever test ran previously in this file.
        $script:defaultConnectionInformationCallCount = 0
    }

    Context 'Parameter validation' {
        It 'requires the OutputPath parameter' {
            # Actually invoking the function without -OutputPath would prompt on the missing
            # mandatory parameter and hang on stdin outside this sandboxed session - assert on
            # the parameter metadata instead.
            $attribute = (Get-Command Export-PurviewConfiguration).Parameters['OutputPath'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            $attribute.Mandatory | Should -BeTrue
        }

        It 'throws on an unrecognised -Command value (regression for command-injection finding)' {
            { Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-TotallyMadeUpCmdlet' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false } |
                Should -Throw
        }

        It 'validates -Command before connecting or installing anything (regression for MEDIUM finding: validated too late)' {
            Mock Install-Module -MockWith {}
            { Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-TotallyMadeUpCmdlet' -Confirm:$false -ErrorAction Stop } |
                Should -Throw

            Should -Invoke Connect-IPPSSession -Times 0
            Should -Invoke Install-Module -Times 0
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

    Context 'Authentication parameter sets' {
        BeforeAll {
            Mock Get-Label -MockWith { @([pscustomobject]@{ Name = 'Confidential' }) }
        }

        It 'connects interactively with no auth parameters (default set)' {
            $null = Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-Label' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false

            Should -Invoke Connect-IPPSSession -Times 1 -ParameterFilter {
                -not $CertificateThumbprint -and -not $CertificateFilePath -and -not $AccessToken
            }
        }

        It 'passes -UserPrincipalName through on the default set' {
            $null = Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-Label' -UserPrincipalName 'admin@contoso.onmicrosoft.com' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false

            Should -Invoke Connect-IPPSSession -Times 1 -ParameterFilter {
                $UserPrincipalName -eq 'admin@contoso.onmicrosoft.com'
            }
        }

        It 'passes -CertificateThumbprint, -AppId, and -Organization through together (Windows only)' -Skip:(-not $IsWindows) {
            $null = Export-PurviewConfiguration -OutputPath $TestDrive -CertificateThumbprint 'ABCDEF0123456789' -AppId $([guid]::NewGuid()) -Organization 'contoso.onmicrosoft.com' -Command 'Get-Label' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false

            Should -Invoke Connect-IPPSSession -Times 1 -ParameterFilter {
                $CertificateThumbprint -eq 'ABCDEF0123456789' -and $Organization -eq 'contoso.onmicrosoft.com'
            }
        }

        It 'rejects the -CertificateThumbprint set on a non-Windows platform' -Skip:$IsWindows {
            { Export-PurviewConfiguration -OutputPath $TestDrive -CertificateThumbprint 'ABCDEF0123456789' -AppId $([guid]::NewGuid()) -Organization 'contoso.onmicrosoft.com' -Command 'Get-Label' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false } |
                Should -Throw '*Windows certificate store*'
        }

        It 'passes -AccessToken and -Organization through together' {
            $null = Export-PurviewConfiguration -OutputPath $TestDrive -AccessToken 'fake.jwt.token' -Organization 'contoso.onmicrosoft.com' -Command 'Get-Label' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false

            Should -Invoke Connect-IPPSSession -Times 1 -ParameterFilter {
                $AccessToken -eq 'fake.jwt.token' -and $Organization -eq 'contoso.onmicrosoft.com'
            }
        }
    }

    Context 'Reconnect and disconnect target only this function''s own sessions' {
        BeforeAll {
            Mock Get-Module -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' -and -not $ListAvailable } -MockWith {
                [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.9.0' }
            }
            Mock Get-ComplianceSecurityFilter -MockWith { @([pscustomobject]@{ Name = 'Filter1' }) }
        }

        BeforeEach {
            # Reset per-It, not just per-Context: each It below calls Export-PurviewConfiguration
            # once and expects the call-count-driven Get-ConnectionInformation sequence to start
            # fresh, not continue from wherever the previous It left off.
            $script:connectionInformationCallCount = 0
            Mock Get-ConnectionInformation -MockWith {
                $script:connectionInformationCallCount++
                switch ($script:connectionInformationCallCount)
                {
                    1 { @() }
                    2 { @([pscustomobject]@{ ConnectionId = 'standard-1'; TenantID = 'tenant-1' }) }
                    3 { @([pscustomobject]@{ ConnectionId = 'standard-1'; TenantID = 'tenant-1' }) }
                    default { @([pscustomobject]@{ ConnectionId = 'standard-1'; TenantID = 'tenant-1' }, [pscustomobject]@{ ConnectionId = 'search-1'; TenantID = 'tenant-1' }) }
                }
            }
        }

        It 'reuses the same authentication parameters for the -EnableSearchOnlySession reconnect' {
            $null = Export-PurviewConfiguration -OutputPath $TestDrive -AccessToken 'fake.jwt.token' -Organization 'contoso.onmicrosoft.com' -Command 'Get-ComplianceSecurityFilter' -SkipModuleCheck -Confirm:$false

            Should -Invoke Connect-IPPSSession -Times 1 -ParameterFilter {
                -not $EnableSearchOnlySession -and $AccessToken -eq 'fake.jwt.token'
            }
            Should -Invoke Connect-IPPSSession -Times 1 -ParameterFilter {
                $EnableSearchOnlySession -and $AccessToken -eq 'fake.jwt.token'
            }
        }

        It 'disconnects only the standard-session ConnectionId this function opened, never a blind disconnect' {
            $null = Export-PurviewConfiguration -OutputPath $TestDrive -AccessToken 'fake.jwt.token' -Organization 'contoso.onmicrosoft.com' -Command 'Get-ComplianceSecurityFilter' -SkipModuleCheck -Confirm:$false

            # -Exactly: Pester's -Times N means "at least N" without it, which would not catch a
            # double-disconnect of the same session (the CSF pass's own disconnect plus a second
            # one from the outer finally, if $standardConnectionId were not cleared in between).
            Should -Invoke Disconnect-ExchangeOnline -Times 1 -Exactly -ParameterFilter { $ConnectionId -eq 'standard-1' }
            Should -Invoke Disconnect-ExchangeOnline -Times 1 -Exactly -ParameterFilter { $ConnectionId -eq 'search-1' }
        }

        It 'disconnects the standard session even when -SkipComplianceSecurityFilter skips the CSF pass entirely (regression for MEDIUM finding: session left connected)' {
            $null = Export-PurviewConfiguration -OutputPath $TestDrive -AccessToken 'fake.jwt.token' -Organization 'contoso.onmicrosoft.com' -Command 'Get-Label' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false

            Should -Invoke Disconnect-ExchangeOnline -Times 1 -Exactly -ParameterFilter { $ConnectionId -eq 'standard-1' }
        }

        It 'disconnects the standard session even when a terminating error occurs after connecting' {
            Mock New-Item -MockWith { throw 'disk full' }

            { Export-PurviewConfiguration -OutputPath (Join-Path $TestDrive ([guid]::NewGuid())) -AccessToken 'fake.jwt.token' -Organization 'contoso.onmicrosoft.com' -Command 'Get-Label' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false -ErrorAction Stop } |
                Should -Throw

            Should -Invoke Disconnect-ExchangeOnline -Times 1 -Exactly -ParameterFilter { $ConnectionId -eq 'standard-1' }
        }
    }

    Context 'Paged reporting cmdlets (regression for MEDIUM finding: silent under-reporting)' {
        It 'pages through Get-QuarantineMessage until a short page ends the loop' {
            Mock Get-QuarantineMessage -ParameterFilter { $Page -eq 1 } -MockWith {
                1..1000 | ForEach-Object { [pscustomobject]@{ Identity = "msg-$_" } }
            }
            Mock Get-QuarantineMessage -ParameterFilter { $Page -eq 2 } -MockWith {
                @([pscustomobject]@{ Identity = 'msg-1001' })
            }

            $result = Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-QuarantineMessage' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false

            $result.RecordCount | Should -Be 1001
            Should -Invoke Get-QuarantineMessage -Times 2
            Should -Invoke Get-QuarantineMessage -Times 1 -ParameterFilter { $PageSize -eq 1000 -and $StartReceivedDate -and $EndReceivedDate }
        }

        It 'stops after a single short page when there is only one page of data' {
            Mock Get-DlpDetectionsReport -MockWith {
                @([pscustomobject]@{ Identity = 'event-1' }, [pscustomobject]@{ Identity = 'event-2' })
            }

            $result = Export-PurviewConfiguration -OutputPath $TestDrive -Command 'Get-DlpDetectionsReport' -SkipModuleCheck -SkipComplianceSecurityFilter -Confirm:$false

            $result.RecordCount | Should -Be 2
            Should -Invoke Get-DlpDetectionsReport -Times 1 -ParameterFilter { $PageSize -eq 5000 }
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
