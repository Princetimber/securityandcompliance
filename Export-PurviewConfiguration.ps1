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

        Four mutually exclusive authentication methods are available, strongest/most
        unattended-friendly first - see .NOTES for the exact permissions each needs:
            -CertificateThumbprint : app-only, certificate already in the local certificate
                store. Windows only (the Cert: provider does not exist elsewhere).
            -CertificateFilePath   : app-only, a PFX certificate file loaded at runtime. The
                cross-platform default for unattended automation.
            -AccessToken           : app-only or delegated, relays an OAuth JWT the caller
                already acquired by any means (workload identity federation, a managed
                identity token exchanged via Az, or any other MSAL flow). This function never
                acquires or refreshes the token itself.
            (default, no auth parameters) : fully interactive, delegated sign-in via
                Connect-IPPSSession's own browser-based modern authentication. Optionally
                pass -UserPrincipalName to skip the username prompt.
        Connect-IPPSSession has no managed-identity or device-code parameter of its own (unlike
        Connect-MgGraph) - a managed identity is only reachable by acquiring its token
        separately and passing it via -AccessToken.

        The same authentication method and parameters are reused for the dedicated
        -EnableSearchOnlySession reconnect required by Get-ComplianceSecurityFilter (see
        .NOTES), so an app-only run does not drop into an interactive prompt partway through.

        Requires membership of the Compliance Administrator or Compliance Data Administrator
        role (or an equivalent custom role) in the target tenant for the baseline cmdlet set —
        see LEAST-PRIVILEGE.md and .NOTES below for the full per-section breakdown.

    .PARAMETER OutputPath
        Folder to write the exported .xml files to. Created if it does not already exist.

    .PARAMETER UserPrincipalName
        Optional, default (interactive) authentication only. Account to sign in as - skips the
        username prompt in the modern authentication dialog.

    .PARAMETER CertificateThumbprint
        App-only authentication using a certificate already in the caller's certificate store
        (Cert:\CurrentUser\My or Cert:\LocalMachine\My). Windows only. Requires -AppId and
        -Organization.

    .PARAMETER CertificateFilePath
        App-only authentication using a PFX certificate file loaded at runtime. Cross-platform.
        Requires -CertificatePassword, -AppId, and -Organization.

    .PARAMETER CertificatePassword
        Password for the PFX file specified by -CertificateFilePath.

    .PARAMETER AppId
        Application (client) ID of the Entra app registration used for certificate-based
        authentication. Required with -CertificateThumbprint or -CertificateFilePath.

    .PARAMETER Organization
        Primary .onmicrosoft.com domain of the target tenant. Required with
        -CertificateThumbprint, -CertificateFilePath, or -AccessToken.

    .PARAMETER AccessToken
        A JWT access token the caller already acquired for Security & Compliance PowerShell,
        by any method (workload identity federation, a managed identity token exchange, or any
        other MSAL flow). Requires -Organization. This function never acquires, caches, or
        refreshes this token itself.

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

        Connects interactively to Security & Compliance PowerShell and exports the full
        default set of configuration to C:\output\MIP\.

    .EXAMPLE
        Export-PurviewConfiguration -OutputPath ./out -CertificateFilePath ./app.pfx -CertificatePassword (Get-Credential -UserName cert).Password -AppId $appId -Organization contoso.onmicrosoft.com

        Unattended app-only export using a PFX certificate.

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
        runs it as a separate pass at the end: disconnects only its own standard-session
        connection (by ConnectionId, not a blind Disconnect-ExchangeOnline that would tear down
        any other session the caller has open), reconnects with -EnableSearchOnlySession using
        the same authentication parameters, exports, and disconnects that search-only
        connection too before returning. Use -SkipComplianceSecurityFilter to omit this pass
        entirely.

        Authentication methods (see .PARAMETER above for the exact parameters of each) and the
        Entra/Purview permissions each needs:

            -CertificateThumbprint / -CertificateFilePath (app-only, certificate-based auth):
                The app registration (identified by -AppId) needs the Office 365 Exchange
                Online API application permission "Exchange.ManageAsApp", and the connecting
                service principal needs the same Microsoft Purview role assignments listed
                below as a human account would (e.g. Compliance Administrator). Whether
                -EnableSearchOnlySession is reachable under app-only auth has not been
                verified against a live tenant by this function's author - if it is not,
                Get-ComplianceSecurityFilter's dedicated pass will fail and should be skipped
                with -SkipComplianceSecurityFilter for app-only runs until confirmed.

            -AccessToken (bring-your-own-token, app-only or delegated depending on how the
            caller acquired it): this function performs no permission check of its own - the
            token's scopes/role assignments are whatever the caller's acquisition flow
            (workload identity federation, a managed identity's exchanged token, etc.) granted.

            Default (interactive delegated sign-in): governed entirely by the signed-in
            account's own Entra ID / Purview role assignments, not by any parameter here.

        None of the above has been verified against a live tenant by this function's author -
        confirm behaviour, especially the -EnableSearchOnlySession + app-only combination,
        before relying on it for unattended production automation.

        Required permissions and management roles (interactive/delegated baseline):
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
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Default')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'Folder to write exported .xml files to'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter(ParameterSetName = 'Default')]
        [string]$UserPrincipalName,

        [Parameter(ParameterSetName = 'CertificateThumbprint', Mandatory = $true)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'CertificateFilePath', Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$CertificateFilePath,

        [Parameter(ParameterSetName = 'CertificateFilePath', Mandatory = $true)]
        [securestring]$CertificatePassword,

        [Parameter(ParameterSetName = 'CertificateThumbprint', Mandatory = $true)]
        [Parameter(ParameterSetName = 'CertificateFilePath', Mandatory = $true)]
        [string]$AppId,

        [Parameter(ParameterSetName = 'CertificateThumbprint', Mandatory = $true)]
        [Parameter(ParameterSetName = 'CertificateFilePath', Mandatory = $true)]
        [Parameter(ParameterSetName = 'AccessToken', Mandatory = $true)]
        [string]$Organization,

        [Parameter(ParameterSetName = 'AccessToken', Mandatory = $true)]
        [string]$AccessToken,

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
            # Returns $true only when the write actually happened, so callers can report an
            # accurate Exported value instead of assuming success whenever this is reached.
            [CmdletBinding(SupportsShouldProcess)]
            [OutputType([bool])]
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
                return $true
            }
            return $false
        }

        if (-not $SkipModuleCheck)
        {
            Write-Verbose 'Checking for ExchangeOnlineManagement module (minimum version 3.0)'
            $exchModule = Get-Module -Name ExchangeOnlineManagement -ListAvailable |
                Sort-Object -Property Version -Descending |
                Select-Object -First 1

            if (-not $exchModule -or $exchModule.Version -lt [version]'3.0')
            {
                if ($PSCmdlet.ShouldProcess('ExchangeOnlineManagement (CurrentUser scope)', 'Install-Module'))
                {
                    Write-Verbose 'ExchangeOnlineManagement 3.0+ not found. Installing for current user.'
                    try
                    {
                        Install-Module -Name ExchangeOnlineManagement -Repository PSGallery -Scope CurrentUser -AllowClobber -Force -MinimumVersion 3.0 -ErrorAction Stop
                    }
                    catch
                    {
                        Write-Error -Message "Failed to install ExchangeOnlineManagement: $($_.Exception.Message)" -Category NotInstalled -ErrorAction Stop
                    }
                }
            }

            if (-not (Get-Module -Name ExchangeOnlineManagement))
            {
                Import-Module -Name ExchangeOnlineManagement -MinimumVersion 3.0 -ErrorAction Stop
            }
        }

        # Build once, reused unmodified for both the standard session below and the
        # -EnableSearchOnlySession reconnect later, so an app-only run never drops into an
        # interactive prompt partway through for the Get-ComplianceSecurityFilter pass.
        $connectParams = switch ($PSCmdlet.ParameterSetName)
        {
            'CertificateThumbprint'
            {
                if (-not $IsWindows)
                {
                    Write-Error -Message 'The -CertificateThumbprint parameter set requires the Windows certificate store (the Cert: provider) and is not supported on this platform. Use -CertificateFilePath instead.' -Category InvalidOperation -ErrorAction Stop
                }
                @{ CertificateThumbprint = $CertificateThumbprint; AppId = $AppId; Organization = $Organization }
            }
            'CertificateFilePath'
            {
                try
                {
                    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificateFilePath, $CertificatePassword)
                }
                catch
                {
                    Write-Error -Message "Failed to load certificate from '$CertificateFilePath': $($_.Exception.Message)" -Category SecurityError -ErrorAction Stop
                }
                if ($certificate.NotAfter -lt (Get-Date))
                {
                    Write-Error -Message "Certificate '$CertificateFilePath' expired on $($certificate.NotAfter)." -Category SecurityError -ErrorAction Stop
                }
                elseif ($certificate.NotAfter -lt (Get-Date).AddDays(30))
                {
                    Write-Warning "Certificate '$CertificateFilePath' expires on $($certificate.NotAfter) - within 30 days."
                }
                @{ CertificateFilePath = $CertificateFilePath; CertificatePassword = $CertificatePassword; AppId = $AppId; Organization = $Organization }
            }
            'AccessToken'
            {
                @{ AccessToken = $AccessToken; Organization = $Organization }
            }
            default
            {
                if ($UserPrincipalName) { @{ UserPrincipalName = $UserPrincipalName } } else { @{} }
            }
        }

        try
        {
            Write-Verbose "Connecting to Security & Compliance PowerShell (method: $($PSCmdlet.ParameterSetName))"
            $priorConnectionIds = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ConnectionId)
            Connect-IPPSSession @connectParams -ErrorAction Stop
            $standardConnectionId = Get-ConnectionInformation |
                Where-Object { $_.ConnectionId -notin $priorConnectionIds } |
                Select-Object -First 1 -ExpandProperty ConnectionId
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

        # Get-Label and Get-ComplianceSecurityFilter are handled in dedicated passes below and
        # are not part of $defaultCommands, but are valid values for -Command.
        $validCommands = $defaultCommands + @('Get-Label', 'Get-ComplianceSecurityFilter')
        if ($Command)
        {
            $unknownCommands = @($Command | Where-Object { $_ -notin $validCommands })
            if ($unknownCommands.Count -gt 0)
            {
                Write-Error -Message "Unknown -Command value(s): $($unknownCommands -join ', '). Valid values are: $($validCommands -join ', ')" -Category InvalidArgument -ErrorAction Stop
            }
        }

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
                $wasExported = Export-ComplianceDataFile -CmdletName 'Get-Label' -Data $labelData -Destination $OutputPath
                [pscustomobject]@{
                    Command      = 'Get-Label'
                    RecordCount  = @($labelData).Count
                    Exported     = $wasExported
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
                    $wasExported = Export-ComplianceDataFile -CmdletName $cmdletName -Data $data -Destination $OutputPath
                    [pscustomobject]@{
                        Command      = $cmdletName
                        RecordCount  = @($data).Count
                        Exported     = $wasExported
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
                $searchConnectionId = $null
                try
                {
                    Write-Verbose 'Reconnecting with -EnableSearchOnlySession for Get-ComplianceSecurityFilter, reusing the same authentication method'
                    if ($standardConnectionId)
                    {
                        # Disconnect only the standard session this function itself opened -
                        # never a blind Disconnect-ExchangeOnline, which would also tear down
                        # any other Exchange Online/IPPS session the caller has open.
                        Disconnect-ExchangeOnline -ConnectionId $standardConnectionId -Confirm:$false -ErrorAction SilentlyContinue
                    }

                    $priorConnectionIds = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ConnectionId)
                    Connect-IPPSSession @connectParams -EnableSearchOnlySession -ErrorAction Stop
                    $searchConnectionId = Get-ConnectionInformation |
                        Where-Object { $_.ConnectionId -notin $priorConnectionIds } |
                        Select-Object -First 1 -ExpandProperty ConnectionId

                    $data = Get-ComplianceSecurityFilter -ErrorAction Stop
                    if ($data)
                    {
                        Write-Verbose 'Exporting data generated by Get-ComplianceSecurityFilter'
                        $wasExported = Export-ComplianceDataFile -CmdletName 'Get-ComplianceSecurityFilter' -Data $data -Destination $OutputPath
                        [pscustomobject]@{
                            Command      = 'Get-ComplianceSecurityFilter'
                            RecordCount  = @($data).Count
                            Exported     = $wasExported
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
                finally
                {
                    # Leave no search-only session connected behind on return, success or not.
                    if ($searchConnectionId)
                    {
                        Disconnect-ExchangeOnline -ConnectionId $searchConnectionId -Confirm:$false -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }
}
