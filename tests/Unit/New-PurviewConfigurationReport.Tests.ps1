#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }

BeforeAll {
    # Run the code under test in strict mode so an unguarded missing property fails here, not in an
    # operator's session that happens to enable it.
    Set-StrictMode -Version Latest
    . "$PSScriptRoot/../../source/Public/New-PurviewConfigurationReport.ps1"

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
                @{
                    Type     = 'applycontentmarking'
                    Settings = @(
                        @{ Key = 'markingtext'; Value = 'CONFIDENTIAL' }
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

            @(
                [pscustomobject]@{ Name = 'Built-in-SIT'; Publisher = 'Microsoft Corporation' }
                [pscustomobject]@{ Name = 'Custom-SIT'; Publisher = 'Contoso' }
            ) | Export-Clixml -Path (Join-Path -Path $tenantPath -ChildPath 'Get-DlpSensitiveInformationType.xml')

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

        It 'never emits a `<th> outside a `<tr>, and never the invalid `</BR> tag (regression for LOW HTML findings)' {
            $thCount = ([regex]::Matches($html, '<th\b')).Count
            $trThCount = ([regex]::Matches($html, '<tr><th\b')).Count
            $trThCount | Should -Be $thCount
            $html | Should -Not -Match '</BR>'
        }

        It 'never nests a `<tr> inside another `<tr> for a multi-setting label action (regression for LOW HTML finding)' {
            # The label fixture's encrypt action has two settings (color, rightsdefinitions),
            # which is exactly the rowspan case the original nested-<tr> bug produced.
            $html | Should -Not -Match '<tr>\s*<td[^>]*>[^<]*</td>\s*<tr>'
        }

        It 'renders the applycontentmarking label action' {
            $html | Should -Match 'markingtext'
            $html | Should -Match 'CONFIDENTIAL'
        }

        It 'renders only the custom SIT, excluding the built-in Microsoft one' {
            $html | Should -Match 'Custom-SIT'
            $html | Should -Not -Match 'Built-in-SIT'
        }

        It 'renders the sensitivity label policy, DLP policy, DLP rule, and a generic detail section' {
            $html | Should -Match 'Confidential-Policy'
            $html | Should -Match 'DLP-Policy'
            $html | Should -Match 'DLP-Rule'
            $html | Should -Match 'Retention-Policy'
        }
    }

    Context 'DSPM for AI policy section' {
        BeforeAll {
            $dspmSource = Get-TestSourcePath
            @(
                [pscustomobject]@{ Name = 'DSPM for AI: Detect sensitive info added to AI sites'; Priority = 0; Comment = ''; Enabled = $true; Workload = 'Endpoint' }
                [pscustomobject]@{ Name = 'Ordinary-DLP-Policy'; Priority = 1; Comment = ''; Enabled = $true; Workload = 'Exchange' }
            ) | Export-Clixml -Path (Join-Path -Path $dspmSource -ChildPath 'Get-DlpCompliancePolicy.xml')
            @(
                [pscustomobject]@{ Name = 'DSPM for AI - Detect risky AI usage'; Enabled = $true }
                [pscustomobject]@{ Name = 'Microsoft AI Hub - Legacy IRM'; Enabled = $true }
                [pscustomobject]@{ Name = 'Ordinary-IRM-Policy'; Enabled = $true }
            ) | Export-Clixml -Path (Join-Path -Path $dspmSource -ChildPath 'Get-InsiderRiskPolicy.xml')
            @(
                [pscustomobject]@{ Name = 'DSPM for AI - Unethical behavior in AI apps'; Enabled = $true }
                [pscustomobject]@{ Name = 'Ordinary-CC-Policy'; Enabled = $true }
            ) | Export-Clixml -Path (Join-Path -Path $dspmSource -ChildPath 'Get-SupervisoryReviewPolicyV2.xml')
            $dspmHtml = Get-ReportHtml -SourcePath $dspmSource
            $script:dspmSection = [regex]::Match($dspmHtml, '(?s)<h2[^>]*>DSPM for AI Policies</h2>(.*?)(?=<h2|</body>)').Groups[1].Value
        }

        It 'renders a DSPM for AI Policies heading' {
            $dspmHtml | Should -Match 'DSPM for AI Policies</h2>'
        }

        It 'includes DLP, IRM and Communication Compliance policies with a DSPM for AI or Microsoft AI Hub name prefix' {
            $script:dspmSection | Should -Match 'Detect sensitive info added to AI sites'
            $script:dspmSection | Should -Match 'Detect risky AI usage'
            $script:dspmSection | Should -Match 'Microsoft AI Hub - Legacy IRM'
            $script:dspmSection | Should -Match 'Unethical behavior in AI apps'
        }

        It 'labels each policy with the workload it was exported from' {
            $script:dspmSection | Should -Match 'DLP'
            $script:dspmSection | Should -Match 'Insider Risk'
            $script:dspmSection | Should -Match 'Communication Compliance'
        }

        It 'excludes policies without a DSPM for AI or Microsoft AI Hub prefix' {
            $script:dspmSection | Should -Not -Match 'Ordinary-'
        }

        It 'renders the no-data message when no DSPM for AI policy was exported' {
            $emptySource = Get-TestSourcePath
            [pscustomobject]@{ Name = 'Ordinary-DLP-Policy'; Priority = 1; Comment = ''; Enabled = $true; Workload = 'Exchange' } | Export-Clixml -Path (Join-Path -Path $emptySource -ChildPath 'Get-DlpCompliancePolicy.xml')
            $emptyHtml = Get-ReportHtml -SourcePath $emptySource
            $emptySection = [regex]::Match($emptyHtml, '(?s)<h2[^>]*>DSPM for AI Policies</h2>(.*?)(?=<h2|</body>)').Groups[1].Value
            $emptySection | Should -Match 'No data exported for this workload'
        }
    }

    Context 'Insider Risk cases section' {
        It 'renders cases from Get-InsiderRiskCase.xml under an Insider Risk Cases heading' {
            $irmSource = Get-TestSourcePath
            [pscustomobject]@{ Name = 'IRM-Case-1'; CaseType = 'InsiderRisk' } |
                Export-Clixml -Path (Join-Path -Path $irmSource -ChildPath 'Get-InsiderRiskCase.xml')

            $irmHtml = Get-ReportHtml -SourcePath $irmSource

            $irmHtml | Should -Match 'Insider Risk Cases</h2>'
            $irmHtml | Should -Match 'IRM-Case-1'
        }

        It 'does not render eDiscovery cases from Get-ComplianceCase.xml in the Insider Risk Cases section' {
            $irmSource = Get-TestSourcePath
            [pscustomobject]@{ Name = 'eDiscovery-Case-1'; CaseType = 'eDiscovery' } |
                Export-Clixml -Path (Join-Path -Path $irmSource -ChildPath 'Get-ComplianceCase.xml')

            $irmHtml = Get-ReportHtml -SourcePath $irmSource
            $irmSection = [regex]::Match($irmHtml, '(?s)<h2[^>]*>Insider Risk Cases</h2>(.*?)(?=<h2|</body>)').Groups[1].Value

            $irmSection | Should -Not -Match 'eDiscovery-Case-1'
            $irmSection | Should -Match 'No data exported for this workload'
        }
    }

    Context 'Retention label, file plan, retention event and hold sections' {
        BeforeAll {
            function Get-SectionHtml
            {
                param(
                    [Parameter(Mandatory)]
                    [string]$Html,
                    [Parameter(Mandatory)]
                    [string]$Heading
                )
                [regex]::Match($Html, "(?s)<h2[^>]*>$([regex]::Escape($Heading))</h2>(.*?)(?=<h2|</body>)").Groups[1].Value
            }
            $retentionSource = Get-TestSourcePath
            $exports = @{
                'Get-ComplianceTag'               = [pscustomobject]@{ Name = 'Label-Keep-7y'; IsRecordLabel = $true }
                'Get-FilePlanPropertyAuthority'   = [pscustomobject]@{ Name = 'Authority-A' }
                'Get-FilePlanPropertyDepartment'  = [pscustomobject]@{ Name = 'Department-B' }
                'Get-ComplianceRetentionEvent'    = [pscustomobject]@{ Name = 'Event-Leaver' }
                'Get-ComplianceRetentionEventType' = [pscustomobject]@{ Name = 'EventType-Leaver' }
                'Get-HoldCompliancePolicy'        = [pscustomobject]@{ Name = 'Hold-Policy-1' }
                'Get-HoldComplianceRule'          = [pscustomobject]@{ Name = 'Hold-Rule-1' }
                'Get-CaseHoldRule'                = [pscustomobject]@{ Name = 'Case-Hold-Rule-1' }
            }
            foreach ($cmdlet in $exports.Keys)
            {
                $exports[$cmdlet] | Export-Clixml -Path (Join-Path -Path $retentionSource -ChildPath "$cmdlet.xml")
            }
            $script:retentionHtml = Get-ReportHtml -SourcePath $retentionSource
        }

        It 'renders retention labels under a Retention Labels heading' {
            $section = Get-SectionHtml -Html $script:retentionHtml -Heading 'Retention Labels'
            $section | Should -Match 'Label-Keep-7y'
        }

        It 'renders file plan properties from every file plan cmdlet, labelled with the property type' {
            $section = Get-SectionHtml -Html $script:retentionHtml -Heading 'File Plan Properties'
            $section | Should -Match 'Authority-A'
            $section | Should -Match 'Department-B'
            $section | Should -Match 'Authority'
            $section | Should -Match 'Department'
        }

        It 'renders retention events and retention event types in separate sections' {
            (Get-SectionHtml -Html $script:retentionHtml -Heading 'Retention Events') | Should -Match 'Event-Leaver'
            (Get-SectionHtml -Html $script:retentionHtml -Heading 'Retention Event Types') | Should -Match 'EventType-Leaver'
            (Get-SectionHtml -Html $script:retentionHtml -Heading 'Retention Events') | Should -Not -Match 'EventType-Leaver'
        }

        It 'renders hold policies, hold rules and case hold rules in separate sections' {
            (Get-SectionHtml -Html $script:retentionHtml -Heading 'Hold Policies') | Should -Match 'Hold-Policy-1'
            (Get-SectionHtml -Html $script:retentionHtml -Heading 'Hold Rules') | Should -Match 'Hold-Rule-1'
            (Get-SectionHtml -Html $script:retentionHtml -Heading 'Case Hold Rules') | Should -Match 'Case-Hold-Rule-1'
        }

        It 'renders the no-data message for each new section when nothing was exported' {
            $emptyHtml = Get-ReportHtml -SourcePath (Get-TestSourcePath)
            foreach ($heading in 'Retention Labels', 'File Plan Properties', 'Retention Events', 'Retention Event Types', 'Hold Policies', 'Hold Rules', 'Case Hold Rules')
            {
                (Get-SectionHtml -Html $emptyHtml -Heading $heading) | Should -Match 'No data exported for this workload'
            }
        }
    }

    Context 'Audit log retention policy section' {
        It 'renders policies from Get-UnifiedAuditLogRetentionPolicy.xml under an Audit Log Retention Policies heading' {
            $auditSource = Get-TestSourcePath
            [pscustomobject]@{ Name = 'Audit-Retention-1y'; RetentionDuration = 'TwelveMonths' } |
                Export-Clixml -Path (Join-Path -Path $auditSource -ChildPath 'Get-UnifiedAuditLogRetentionPolicy.xml')

            $auditHtml = Get-ReportHtml -SourcePath $auditSource
            $auditSection = [regex]::Match($auditHtml, '(?s)<h2[^>]*>Audit Log Retention Policies</h2>(.*?)(?=<h2|</body>)').Groups[1].Value

            $auditSection | Should -Match 'Audit-Retention-1y'
            $auditSection | Should -Match 'TwelveMonths'
        }

        It 'renders the no-data message when no audit log retention policy was exported' {
            $emptyHtml = Get-ReportHtml -SourcePath (Get-TestSourcePath)
            $emptySection = [regex]::Match($emptyHtml, '(?s)<h2[^>]*>Audit Log Retention Policies</h2>(.*?)(?=<h2|</body>)').Groups[1].Value

            $emptySection | Should -Match 'No data exported for this workload'
        }
    }

    Context 'Endpoint DLP policy section' {
        BeforeAll {
            $script:endpointSource = Get-TestSourcePath
            @(
                [pscustomobject]@{ Name = 'Endpoint-DLP-Policy'; Priority = 0; Comment = ''; Enabled = $true; Workload = 'Endpoint'; EndpointDlpLocation = @('All') }
                [pscustomobject]@{ Name = 'Exchange-Only-Policy'; Priority = 1; Comment = ''; Enabled = $true; Workload = 'Exchange'; EndpointDlpLocation = @() }
                [pscustomobject]@{ Name = 'No-Endpoint-Property-Policy'; Priority = 2; Comment = ''; Enabled = $true; Workload = 'Exchange' }
            ) | Export-Clixml -Path (Join-Path -Path $script:endpointSource -ChildPath 'Get-DlpCompliancePolicy.xml')
            $endpointHtml = Get-ReportHtml -SourcePath $script:endpointSource
            $script:endpointSection = [regex]::Match($endpointHtml, '(?s)<h2[^>]*>Endpoint DLP Policies</h2>(.*?)(?=<h2|</body>)').Groups[1].Value
        }

        It 'lists a DLP policy that has an endpoint location' {
            $script:endpointSection | Should -Match 'Endpoint-DLP-Policy'
        }

        It 'excludes DLP policies with an empty or missing endpoint location' {
            $script:endpointSection | Should -Not -Match 'Exchange-Only-Policy'
            $script:endpointSection | Should -Not -Match 'No-Endpoint-Property-Policy'
        }

        It 'renders the no-data message when no DLP policy is scoped to endpoints' {
            $noEndpointSource = Get-TestSourcePath
            [pscustomobject]@{ Name = 'Exchange-Only-Policy'; Priority = 1; Comment = ''; Enabled = $true; Workload = 'Exchange'; EndpointDlpLocation = @() } |
                Export-Clixml -Path (Join-Path -Path $noEndpointSource -ChildPath 'Get-DlpCompliancePolicy.xml')
            $noEndpointHtml = Get-ReportHtml -SourcePath $noEndpointSource
            $noEndpointSection = [regex]::Match($noEndpointHtml, '(?s)<h2[^>]*>Endpoint DLP Policies</h2>(.*?)(?=<h2|</body>)').Groups[1].Value

            $noEndpointSection | Should -Match 'No data exported for this workload'
        }
    }

    Context 'ShouldProcess / -WhatIf' {
        It 'does not write the report when -WhatIf is specified' {
            $tenantPath = Get-TestSourcePath
            New-PurviewConfigurationReport -SourcePath $tenantPath -WhatIf

            Test-Path -Path (Join-Path -Path $tenantPath -ChildPath 'Report.html') | Should -BeFalse
        }
    }

    Context 'Transcript cleanup on failure (regression for MEDIUM finding: transcript left running on error)' {
        It 'stops the transcript even when report generation throws' {
            $tenantPath = Get-TestSourcePath
            Mock Start-Transcript -MockWith {}
            Mock Stop-Transcript -MockWith {}
            Mock Out-File -MockWith { throw 'boom' }

            { New-PurviewConfigurationReport -SourcePath $tenantPath -Transcript -Confirm:$false } | Should -Throw

            Should -Invoke Stop-Transcript -Times 1
        }

        It 'does not call Start-Transcript or Stop-Transcript when -Transcript -WhatIf is specified' {
            $tenantPath = Get-TestSourcePath
            Mock Start-Transcript -MockWith {}
            Mock Stop-Transcript -MockWith {}

            New-PurviewConfigurationReport -SourcePath $tenantPath -Transcript -WhatIf

            Should -Invoke Start-Transcript -Times 0
            Should -Invoke Stop-Transcript -Times 0
        }

        It 'warns and never calls Stop-Transcript when Start-Transcript itself fails' {
            $tenantPath = Get-TestSourcePath
            Mock Start-Transcript -MockWith { throw 'Access to the path is denied' }
            Mock Stop-Transcript -MockWith {}

            New-PurviewConfigurationReport -SourcePath $tenantPath -Transcript -Confirm:$false -WarningVariable capturedWarning -WarningAction SilentlyContinue

            Should -Invoke Stop-Transcript -Times 0
            $capturedWarning | Should -Not -BeNullOrEmpty
        }
    }
}
