#Requires -Version 7.0
function Export-PurviewConfiguration
{
    <#
    .SYNOPSIS
        Export the Microsoft Purview (Security & Compliance) configuration from a tenant.

    .DESCRIPTION
        Connects to Security & Compliance PowerShell (Connect-IPPSSession, part of the
        ExchangeOnlineManagement module) and exports the tenant's Information Protection,
        DLP, Retention, Audit, Device Compliance, eDiscovery, Communication Compliance,
        Insider Risk Management, Information Barriers, and related configuration to Clixml
        files, one file per cmdlet, under -OutputPath. Cmdlets not available to the
        connected account's role (see .NOTES) are skipped with a warning, not an error.

        The caller must already be signed in to Security & Compliance PowerShell
        (Connect-IPPSSession) before calling this function, or must be able to interactively
        authenticate — Connect-IPPSSession is invoked from inside this function.

        Requires membership of the Compliance Administrator or Security Administrator role
        (or an equivalent custom role) in the target tenant.

    .PARAMETER OutputPath
        Folder to write the exported .xml files to. Created if it does not already exist.

    .PARAMETER Command
        Optional list of cmdlet names (matching the keys of the internal command table) to
        run, instead of the full default set. Use this to re-run/target a subset, e.g. after
        a transient failure.

    .PARAMETER SkipModuleCheck
        Skip the ExchangeOnlineManagement module version check/install. Use when the caller
        has already verified/loaded the module.

    .PARAMETER SkipComplianceSecurityFilter
        Skip the dedicated -EnableSearchOnlySession pass for Get-ComplianceSecurityFilter (see
        .NOTES). Use this if the connected account doesn't have eDiscovery Administrator and
        you'd rather skip the extra reconnect than see it fail.

    .EXAMPLE
        Export-PurviewConfiguration -OutputPath C:\output\MIP\

        Connects to Security & Compliance PowerShell and exports the full default set of
        configuration to C:\output\MIP\.

    .EXAMPLE
        Export-PurviewConfiguration -OutputPath ./out -Command 'Get-DlpCompliancePolicy','Get-DlpComplianceRule' -Verbose

        Re-exports only the DLP policy and rule data.

    .OUTPUTS
        PSCustomObject
        One object per cmdlet run, with properties: Command, RecordCount, Exported.

    .NOTES
        Known Limitations - excluded from the default export set:

        Require a mandatory per-object -Identity (or date-range/-Case/-Policy) parameter and
        cannot be enumerated blind. Call them directly, per identity, as a targeted follow-up:
            Get-InformationBarrierRecipientStatus
            Get-InformationBarrierReportDetails
            Get-InformationBarrierReportSummary
            Get-RoleGroupMember
            Get-ComplianceCaseMember
            Get-SupervisoryReviewActivity
            Get-QuarantineMessageHeader
            Get-LongTermAuditItems
            Get-LongTermAuditStats
            Get-CaseHoldPolicy (requires -Case or -Policy)

        Out of scope - these are Exchange Online PowerShell cmdlets (Connect-ExchangeOnline),
        not Security & Compliance PowerShell (Connect-IPPSSession), and will never resolve in
        an IPPSSession regardless of role/license:
            Get-TransportRule
            Get-DataEncryptionPolicy
            Get-IRMConfiguration

        RBAC/feature-gated cmdlets: Security & Compliance PowerShell only exposes a cmdlet in
        the session if the connected account's role assignment grants it (e.g. Information
        Barriers, some Insider Risk Management, and audit-configuration cmdlets require a
        specific admin role beyond Compliance/Security Administrator, or the underlying
        feature to be licensed/enabled). If a cmdlet isn't available to the connected
        account, calling it raises a CommandNotFoundException, which this function treats as
        a benign per-tenant condition (Write-Warning) rather than a failure (Write-Error) —
        see the -Command parameter to target specific cmdlets once the right role is granted.

        Get-ComplianceSecurityFilter requires a session opened with Connect-IPPSSession
        -EnableSearchOnlySession and ExchangeOnlineManagement v3.9.0+ (August 2025) — it
        cannot run alongside the rest of the export in the standard session. This function
        runs it as a separate pass at the end: disconnects the standard session, reconnects
        with -EnableSearchOnlySession, exports, and returns. Use -SkipComplianceSecurityFilter
        to omit this pass entirely.

        Required permissions and management roles:
        The connected account needs role assignments (Microsoft Purview role groups, or the
        equivalent Microsoft Entra ID admin roles) covering each functional area this
        function reads. Source: "Roles and role groups in Microsoft Defender for Office 365
        and Microsoft Purview" (https://learn.microsoft.com/microsoft-365/security/office-365-security/scc-permissions)
        and the workload-specific permissions pages linked below.

            Baseline (most Information Protection/DLP/Retention/RBAC-read cmdlets):
                Compliance Administrator, or Compliance Data Administrator, or Security
                Administrator (Microsoft Entra ID role, or the matching Purview role group).

            Role/organization reads (Get-RoleGroup, Get-ManagementRole,
            Get-SecurityPrincipal, Get-OrganizationSegment):
                Organization Management role group (Role Management role — the most
                restrictive of the set; not included in Compliance Administrator alone).

            eDiscovery / Compliance Search (Get-ComplianceCase*, Get-ComplianceSearch*,
            Get-ComplianceSecurityFilter, Get-eDiscoveryCaseAdmin, Get-HoldCompliancePolicy,
            Get-HoldComplianceRule):
                eDiscovery Manager role group — the eDiscovery Administrator sub-role is
                required for org-wide (not just own-case) visibility, and specifically for
                Get-ComplianceSecurityFilter.
                https://learn.microsoft.com/purview/edisc-permissions

            Insider Risk Management (Get-InsiderRiskPolicy):
                Insider Risk Management or Insider Risk Management Admins role group, or
                Organization Management / Compliance Administrator.
                https://learn.microsoft.com/purview/insider-risk-management-permissions

            Information Barriers (Get-InformationBarrierPolicy,
            Get-InformationBarrierPoliciesApplicationStatus):
                IB Compliance Management role — default in Compliance Administrator,
                Compliance Data Administrator, Organization Management, Security
                Administrator.
                https://learn.microsoft.com/purview/information-barriers-policies#required-subscriptions-and-permissions

            Audit (Get-AuditConfig, Get-AuditConfigurationPolicy, Get-AuditConfigurationRule,
            Get-UnifiedAuditLogRetentionPolicy, Get-AdminAuditLogConfig):
                View-Only Audit Logs (or Audit Logs) role — default in Compliance
                Administrator, Compliance Data Administrator, Organization Management,
                Security Administrator, Security Reader.
                https://learn.microsoft.com/purview/audit-get-started#step-2-assign-permissions-to-search-the-audit-log

            Communication Compliance (Get-SupervisoryReview*):
                A Communication Compliance role group (Admins/Analysts/Investigators/
                Viewers), or Organization Management/Compliance Administrator for initial
                setup only.
                https://learn.microsoft.com/purview/communication-compliance-permissions

            Records Management / Retention (Get-RetentionCompliancePolicy,
            Get-RetentionComplianceRule, Get-FilePlanProperty*, Get-ComplianceTag*,
            Get-AdaptiveScope):
                Records Management role group, or Compliance Administrator / Compliance
                Data Administrator.

            Device Compliance / Conditional Access reporting (Get-Device*):
                These surface Intune/Endpoint Manager data synced into the compliance
                portal — typically also requires Global Reader or an Intune admin role, not
                purely a Purview role group.

            Mail flow / Quarantine (Get-QuarantineMessage, Get-MailFilterListReport):
                A Quarantine role (e.g. Quarantine Administrator) or Security
                Administrator/Security Reader, and/or the relevant Exchange Online role.

        In practice, an assessment/reporting account that needs full coverage from this
        function should be a member of: Compliance Administrator (or Compliance Data
        Administrator), Organization Management, and eDiscovery Manager (with the eDiscovery
        Administrator role for Get-ComplianceSecurityFilter). Add Insider Risk Management /
        Insider Risk Management Admins if Get-InsiderRiskPolicy coverage is required. Follow
        least-privilege: grant only the role groups covering the sections you actually need —
        every cmdlet this function can't reach degrades to a Write-Warning, not a failure.

        Author/Copyright:
            Architecture & Security - Advania

    .LINK
        https://www.advania.co.uk
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'Folder to write exported .xml files to'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [string[]]$Command,

        [Parameter()]
        [switch]$SkipModuleCheck,

        [Parameter()]
        [switch]$SkipComplianceSecurityFilter
    )

    begin
    {
        function Export-ComplianceDataFile
        {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)]
                [string]$CmdletName,

                [Parameter()]
                [AllowNull()]
                $Data,

                [Parameter(Mandatory)]
                [string]$Destination
            )

            $filePath = Join-Path -Path $Destination -ChildPath "$($CmdletName).xml"
            if ($PSCmdlet.ShouldProcess($filePath, 'Export-Clixml'))
            {
                $Data | Export-Clixml -Path $filePath
            }
        }

        if (-not $SkipModuleCheck)
        {
            Write-Verbose 'Checking for ExchangeOnlineManagement module (minimum version 3.0)'
            $exchModule = Get-Module -Name ExchangeOnlineManagement -ListAvailable |
                Sort-Object -Property Version -Descending |
                Select-Object -First 1

            if (-not $exchModule -or $exchModule.Version -lt [version]'3.0')
            {
                Write-Verbose 'ExchangeOnlineManagement 3.0+ not found. Installing for current user.'
                Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -AllowClobber -Force -MinimumVersion 3.0
            }

            if (-not (Get-Module -Name ExchangeOnlineManagement))
            {
                Import-Module -Name ExchangeOnlineManagement -MinimumVersion 3.0 -ErrorAction Stop
            }
        }

        try
        {
            Write-Verbose 'Connecting to Security & Compliance PowerShell'
            Connect-IPPSSession -ErrorAction Stop
        }
        catch
        {
            Write-Error -Message "Failed to connect to Security & Compliance PowerShell: $($_.Exception.Message)" -Category ConnectionError -ErrorAction Stop
        }

        if (-not (Test-Path -Path $OutputPath))
        {
            if ($PSCmdlet.ShouldProcess($OutputPath, 'Create output directory'))
            {
                $null = New-Item -Path $OutputPath -ItemType Directory -Force
            }
        }

        # Cmdlets that take no mandatory parameters and can be enumerated blind.
        # See .NOTES for cmdlets intentionally excluded because they require a per-object Identity.
        $defaultCommands = @(
            'Get-Labelpolicy'
            'Get-LabelpolicyRule'
            'Get-DlpCompliancePolicy'
            'Get-DlpComplianceRule'
            'Get-DlpDetectionsReport'
            'Get-DlpEdmSchema'
            'Get-DlpKeywordDictionary'
            'Get-DlpSensitiveInformationType'
            'Get-DlpSensitiveInformationTypeConfig'
            'Get-DlpSensitiveInformationTypeRulePackage'
            'Get-DlpSiDetectionsReport'
            'Get-RetentionCompliancePolicy'
            'Get-RetentionComplianceRule'
            'Get-AdaptiveScope'
            'Get-AuditConfig'
            'Get-AuditConfigurationPolicy'
            'Get-AuditConfigurationRule'
            'Get-DeviceComplianceDetailsReport'
            'Get-DeviceComplianceDetailsReportFilter'
            'Get-DeviceCompliancePolicyInventory'
            'Get-DeviceComplianceReportDate'
            'Get-DeviceComplianceSummaryReport'
            'Get-DeviceComplianceUserInventory'
            'Get-DeviceConditionalAccessPolicy'
            'Get-DeviceConditionalAccessRule'
            'Get-DeviceConfigurationPolicy'
            'Get-DeviceConfigurationRule'
            'Get-DevicePolicy'
            'Get-DeviceTenantPolicy'
            'Get-DeviceTenantRule'
            'Get-FilePlanPropertyAuthority'
            'Get-FilePlanPropertyCategory'
            'Get-FilePlanPropertyCitation'
            'Get-FilePlanPropertyDepartment'
            'Get-FilePlanPropertyReferenceId'
            'Get-FilePlanPropertyStructure'
            'Get-FilePlanPropertySubCategory'
            'Get-ComplianceCase'
            'Get-ComplianceCaseStatistics'
            'Get-ComplianceRetentionEvent'
            'Get-ComplianceRetentionEventType'
            'Get-ComplianceSearch'
            'Get-ComplianceSearchAction'
            'Get-ComplianceTag'
            'Get-ComplianceTagStorage'
            'Get-HoldCompliancePolicy'
            'Get-HoldComplianceRule'
            'Get-CaseHoldRule'
            'Get-eDiscoveryCaseAdmin'
            'Get-SupervisoryReviewOverallProgressReport'
            'Get-SupervisoryReviewPolicyReport'
            'Get-SupervisoryReviewPolicyV2'
            'Get-SupervisoryReviewReport'
            'Get-SupervisoryReviewRule'
            'Get-SupervisoryReviewTopCasesReport'
            'Get-InsiderRiskPolicy'
            'Get-InformationBarrierPolicy'
            'Get-InformationBarrierPoliciesApplicationStatus'
            'Get-QuarantineMessage'
            'Get-ActivityAlert'
            'Get-AdminAuditLogConfig'
            'Get-AutoSensitivityLabelPolicy'
            'Get-AutoSensitivityLabelRule'
            'Get-DataRetentionReport'
            'Get-MailFilterListReport'
            'Get-ManagementRole'
            'Get-OrganizationSegment'
            'Get-PolicyConfig'
            'Get-ProtectionAlert'
            'Get-RegulatoryComplianceUI'
            'Get-RoleGroup'
            'Get-SCInsights'
            'Get-SecurityPrincipal'
            'Get-UnifiedAuditLogRetentionPolicy'
        )

        $commandsToRun = if ($Command) { $Command } else { $defaultCommands }
    }

    process
    {
        # Get-Label needs -IncludeDetailedLabelActions to capture full label configuration,
        # so it is always run separately from the generic loop below.
        if (-not $Command -or $Command -contains 'Get-Label')
        {
            try
            {
                Write-Verbose 'Running Get-Label -IncludeDetailedLabelActions'
                $labelData = Get-Label -IncludeDetailedLabelActions -ErrorAction Stop
                Export-ComplianceDataFile -CmdletName 'Get-Label' -Data $labelData -Destination $OutputPath
                [pscustomobject]@{
                    Command      = 'Get-Label'
                    RecordCount  = @($labelData).Count
                    Exported     = $true
                }
            }
            catch
            {
                Write-Error -Message "Get-Label failed: $($_.Exception.Message)"
                [pscustomobject]@{
                    Command      = 'Get-Label'
                    RecordCount  = 0
                    Exported     = $false
                }
            }
        }

        # Get-Label already ran above (with -IncludeDetailedLabelActions); Get-ComplianceSecurityFilter
        # runs in its own dedicated pass below (separate session). Skip both here to avoid a
        # redundant/weaker duplicate run when -Command explicitly includes either name.
        foreach ($cmdletName in $commandsToRun | Where-Object { $_ -notin @('Get-Label', 'Get-ComplianceSecurityFilter') })
        {
            Write-Verbose "Running $cmdletName"
            try
            {
                $data = & $cmdletName -ErrorAction Stop
                if ($data)
                {
                    Write-Verbose "Exporting data generated by $cmdletName"
                    Export-ComplianceDataFile -CmdletName $cmdletName -Data $data -Destination $OutputPath
                    [pscustomobject]@{
                        Command      = $cmdletName
                        RecordCount  = @($data).Count
                        Exported     = $true
                    }
                }
                else
                {
                    Write-Warning "No data generated by $cmdletName"
                    [pscustomobject]@{
                        Command      = $cmdletName
                        RecordCount  = 0
                        Exported     = $false
                    }
                }
            }
            catch [System.Management.Automation.CommandNotFoundException]
            {
                # Security & Compliance PowerShell only exposes a cmdlet in the session if the
                # connected account's role assignment grants it. A missing cmdlet is a normal,
                # per-tenant/per-role condition here, not a script failure.
                Write-Warning "$cmdletName is not available to the connected account (likely requires an additional admin role, or the underlying feature isn't licensed/enabled). Skipping."
                [pscustomobject]@{
                    Command      = $cmdletName
                    RecordCount  = 0
                    Exported     = $false
                }
            }
            catch
            {
                Write-Error -Message "$cmdletName failed: $($_.Exception.Message)"
                [pscustomobject]@{
                    Command      = $cmdletName
                    RecordCount  = 0
                    Exported     = $false
                }
            }
        }

        # Get-ComplianceSecurityFilter (and the *-ComplianceSearch cmdlet family more broadly)
        # requires a dedicated session opened with -EnableSearchOnlySession and cannot run
        # alongside the rest of this export in the standard session. Run it last, in its own
        # reconnect, so the bulk of the export still completes even if this step is skipped or
        # fails (e.g. account lacks eDiscovery Administrator).
        if ((-not $Command -or $Command -contains 'Get-ComplianceSecurityFilter') -and -not $SkipComplianceSecurityFilter)
        {
            $searchSessionModule = Get-Module -Name ExchangeOnlineManagement | Sort-Object -Property Version -Descending | Select-Object -First 1
            if ($searchSessionModule -and $searchSessionModule.Version -lt [version]'3.9.0')
            {
                Write-Warning "Get-ComplianceSecurityFilter requires ExchangeOnlineManagement v3.9.0 or later (loaded: $($searchSessionModule.Version)). Skipping. Update the module, then re-run with -Command 'Get-ComplianceSecurityFilter' to retry just this cmdlet."
                [pscustomobject]@{
                    Command      = 'Get-ComplianceSecurityFilter'
                    RecordCount  = 0
                    Exported     = $false
                }
            }
            else
            {
                try
                {
                    Write-Verbose 'Reconnecting with -EnableSearchOnlySession for Get-ComplianceSecurityFilter'
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                    Connect-IPPSSession -EnableSearchOnlySession -ErrorAction Stop

                    $data = Get-ComplianceSecurityFilter -ErrorAction Stop
                    if ($data)
                    {
                        Write-Verbose 'Exporting data generated by Get-ComplianceSecurityFilter'
                        Export-ComplianceDataFile -CmdletName 'Get-ComplianceSecurityFilter' -Data $data -Destination $OutputPath
                        [pscustomobject]@{
                            Command      = 'Get-ComplianceSecurityFilter'
                            RecordCount  = @($data).Count
                            Exported     = $true
                        }
                    }
                    else
                    {
                        Write-Warning 'No data generated by Get-ComplianceSecurityFilter'
                        [pscustomobject]@{
                            Command      = 'Get-ComplianceSecurityFilter'
                            RecordCount  = 0
                            Exported     = $false
                        }
                    }
                }
                catch
                {
                    Write-Error -Message "Get-ComplianceSecurityFilter failed: $($_.Exception.Message). Requires the eDiscovery Administrator role (see .NOTES) in addition to Compliance/Security Administrator."
                    [pscustomobject]@{
                        Command      = 'Get-ComplianceSecurityFilter'
                        RecordCount  = 0
                        Exported     = $false
                    }
                }
            }
        }
    }
}
