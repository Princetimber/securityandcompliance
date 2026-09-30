#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }

BeforeAll {
    . "$PSScriptRoot/../../New-PurviewConfigurationReport.ps1"

    function Get-TestSourcePath
    {
        # Pester's $TestDrive is an ephemeral, per-run sandbox that Pester deletes itself -
        # writing the report there (rather than mocking Out-File) exercises the real
        # begin/process/end pipeline while still never touching a real location on disk.
        (New-Item -ItemType Directory -Path (Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid())) -Force).FullName
    }

    function Get-ReportHtml
    {
        param(
            [Parameter(Mandatory)]
            [string]$SourcePath
        )

        New-PurviewConfigurationReport -SourcePath $SourcePath -Confirm:$false
        Get-Content -Path (Join-Path -Path $SourcePath -ChildPath 'Report.html') -Raw
    }
}

Describe 'New-PurviewConfigurationReport' {
    Context 'Parameter validation' {
        It 'requires the SourcePath parameter' {
            # Actually invoking the function without -SourcePath would prompt on the missing
            # mandatory parameter and hang on stdin outside this sandboxed session - assert on
            # the parameter metadata instead.
            $attribute = (Get-Command New-PurviewConfigurationReport).Parameters['SourcePath'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            $attribute.Mandatory | Should -BeTrue
        }

        It 'rejects a SourcePath that does not exist' {
            { New-PurviewConfigurationReport -SourcePath (Join-Path -Path $TestDrive -ChildPath 'does-not-exist') } | Should -Throw
        }

        It 'exposes SourcePath as a parameter' {
            Get-Command New-PurviewConfigurationReport | Should-HaveParameter -Parameter SourcePath
        }
    }

    Context 'Cross-run data isolation (regression for CRITICAL data-leak finding)' {
        It 'does not leak a prior run''s data into a run against a source with no matching export' {
            $tenantA = Get-TestSourcePath
            $tenantB = Get-TestSourcePath

            [pscustomobject]@{ Name = 'TENANT-A-POLICY'; Settings = @() } |
                Export-Clixml -Path (Join-Path -Path $tenantA -ChildPath 'Get-InsiderRiskPolicy.xml')

            $null = Get-ReportHtml -SourcePath $tenantA
            $htmlFromB = Get-ReportHtml -SourcePath $tenantB

            $htmlFromB | Should -Not -Match 'TENANT-A-POLICY'
        }
    }

    Context 'Report content rendering' {
        BeforeAll {
            $script:tenantPath = Get-TestSourcePath

            $labelActions = @(
                @{
                    Type     = 'encrypt'
                    Settings = @(
                        @{ Key = 'color'; Value = '#FF0000' }
                        @{ Key = 'rightsdefinitions'; Value = '{"Identity":"user@contoso.com","Rights":"View"}' }
                    )
                }
            ) | ConvertTo-Json -Depth 5

            $localeSettings = @(
                @{ LocaleKey = 'en-us'; Settings = @(@{ Key = 'tooltip'; Value = 'Test tooltip' }) }
            ) | ConvertTo-Json -Depth 5

            [pscustomobject]@{
                displayname             = 'Confidential'
                name                    = 'Confidential'
                ImmutableId             = [guid]::NewGuid().ToString()
                Priority                = 1
                ParentLabelDisplayName  = $null
                ParentId                = $null
                Disabled                = $false
                Comment                 = 'Test label'
                tooltip                 = 'Test tooltip'
                ContentType             = 'File, Email'
                Workload                = 'All'
                # Sentinel value that appears ONLY in Settings, not in LabelActions/anywhere else
                # in this fixture, so the assertion below can't pass vacuously via a different
                # code path rendering the same string.
                Settings                = @('[settingsonlykey, sentinel-7f3a]')
                LabelActions            = $labelActions
                LocaleSettings          = $localeSettings
                Policy                  = 'Policy1'
                ReadOnly                = $false
                ExternalIdentity        = $null
                Mode                    = 'Enabled'
                CreatedBy               = 'admin@contoso.com'
                LastModifiedBy          = 'admin@contoso.com'
                WhenChangedUTC          = (Get-Date)
                WhenCreatedUTC          = (Get-Date)
                Identity                = 'Confidential'
            } | Export-Clixml -Path (Join-Path -Path $tenantPath -ChildPath 'Get-Label.xml')

            [pscustomobject]@{
                name                = 'Confidential-Policy'
                Priority            = 0
                Comment             = 'Test label policy'
                Labels              = @('Confidential')
                Settings            = @('[PostponeRestrict, false]')
                ExchangeLocation    = @([pscustomobject]@{ Name = 'All' })
                ModernGroupLocation = @([pscustomobject]@{ Name = 'All' })
                Enabled             = $true
            } | Export-Clixml -Path (Join-Path -Path $tenantPath -ChildPath 'Get-Labelpolicy.xml')

            [pscustomobject]@{
                name     = 'DLP-Policy'
                Priority = 0
                Comment  = 'Test DLP policy'
                Enabled  = $true
                Workload = 'Exchange'
            } | Export-Clixml -Path (Join-Path -Path $tenantPath -ChildPath 'Get-DlpCompliancePolicy.xml')

            [pscustomobject]@{
                name             = 'DLP-Rule'
                Priority         = 0
                ParentPolicyName = 'DLP-Policy'
                Comment          = 'Test DLP rule'
                Workload         = 'Exchange'
            } | Export-Clixml -Path (Join-Path -Path $tenantPath -ChildPath 'Get-DlpComplianceRule.xml')

            [pscustomobject]@{
                Name = 'Retention-Policy'
            } | Export-Clixml -Path (Join-Path -Path $tenantPath -ChildPath 'Get-RetentionCompliancePolicy.xml')

            $script:html = Get-ReportHtml -SourcePath $tenantPath
        }

        It 'renders the label display name' {
            $html | Should -Match 'Confidential'
        }

        It 'renders an advanced label setting that is not one of the excluded parameter keys (regression for inverted filter finding)' {
            # 'sentinel-7f3a' exists only in this label's Settings array, nowhere else in the
            # fixture, so this can't pass because some other rendering path happens to emit it.
            $html | Should -Match 'settingsonlykey'
            $html | Should -Match 'sentinel-7f3a'
        }

        It 'wraps the document in a proper html element' {
            $html | Should -Match '<html'
            $html | Should -Match '</html>'
        }

        It 'renders the sensitivity label policy, DLP policy, DLP rule, and a generic detail section' {
            $html | Should -Match 'Confidential-Policy'
            $html | Should -Match 'DLP-Policy'
            $html | Should -Match 'DLP-Rule'
            $html | Should -Match 'Retention-Policy'
        }
    }

    Context 'ShouldProcess / -WhatIf' {
        It 'does not write the report when -WhatIf is specified' {
            $tenantPath = Get-TestSourcePath
            New-PurviewConfigurationReport -SourcePath $tenantPath -WhatIf

            Test-Path -Path (Join-Path -Path $tenantPath -ChildPath 'Report.html') | Should -BeFalse
        }
    }
}
