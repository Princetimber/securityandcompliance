#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }

BeforeAll {
    # Invoke-PurviewConfigurationAudit.ps1 dot-sources both real function files itself;
    # mock the two stage functions afterwards rather than stubbing their dependencies.
    . "$PSScriptRoot/../../Invoke-PurviewConfigurationAudit.ps1"

    Mock Export-PurviewConfiguration -MockWith {
        [pscustomobject]@{ Command = 'Get-Label'; RecordCount = 1; Exported = $true }
    }
    Mock New-PurviewConfigurationReport -MockWith {}
}

Describe 'Invoke-PurviewConfigurationAudit' {
    Context 'Parameter validation' {
        It 'requires the OutputPath parameter' {
            # Actually invoking the function without -OutputPath would prompt on the missing
            # mandatory parameter and hang on stdin outside this sandboxed session - assert on
            # the parameter metadata instead.
            $attribute = (Get-Command Invoke-PurviewConfigurationAudit).Parameters['OutputPath'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            $attribute.Mandatory | Should -BeTrue
        }
    }

    Context 'Pass-through to both stages' {
        It 'passes -Command and -SkipModuleCheck through to Export-PurviewConfiguration' {
            Invoke-PurviewConfigurationAudit -OutputPath $TestDrive -Command 'Get-Label' -SkipModuleCheck -Confirm:$false

            Should -Invoke Export-PurviewConfiguration -Times 1 -ParameterFilter {
                $OutputPath -eq $TestDrive -and $Command -contains 'Get-Label' -and $SkipModuleCheck -eq $true
            }
        }

        It 'passes -SourcePath and -HTMLReport through to New-PurviewConfigurationReport' {
            Invoke-PurviewConfigurationAudit -OutputPath $TestDrive -HTMLReport 'Custom.html' -Confirm:$false

            Should -Invoke New-PurviewConfigurationReport -Times 1 -ParameterFilter {
                $SourcePath -eq $TestDrive -and $HTMLReport -eq 'Custom.html'
            }
        }

        It 'passes -AccessToken and -Organization through to Export-PurviewConfiguration' {
            Invoke-PurviewConfigurationAudit -OutputPath $TestDrive -AccessToken 'fake.jwt.token' -Organization 'contoso.onmicrosoft.com' -Confirm:$false

            Should -Invoke Export-PurviewConfiguration -Times 1 -ParameterFilter {
                $AccessToken -eq 'fake.jwt.token' -and $Organization -eq 'contoso.onmicrosoft.com'
            }
        }
    }

    Context 'ShouldProcess / -WhatIf' {
        It 'runs neither stage under -WhatIf' {
            Invoke-PurviewConfigurationAudit -OutputPath $TestDrive -WhatIf

            Should -Invoke Export-PurviewConfiguration -Times 0
            Should -Invoke New-PurviewConfigurationReport -Times 0
        }
    }
}
