#Requires -Version 7.0
# Dot-sources its own Private dependencies so this file stays directly dot-sourceable on its
# own (`. ./source/Public/Export-PurviewConfiguration.ps1`), not only via the root loader.
. "$PSScriptRoot/../Private/Export-ComplianceDataFile.ps1"
. "$PSScriptRoot/../Private/Get-PagedReportData.ps1"
. "$PSScriptRoot/../Private/Confirm-ExportOutputPath.ps1"
. "$PSScriptRoot/../Private/Invoke-ExportCommand.ps1"
. "$PSScriptRoot/../Private/Get-NewConnectionInformation.ps1"

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

        Six mutually exclusive authentication methods are available, strongest/most
        unattended-friendly first - see .NOTES for the exact permissions each needs:
            -CertificateThumbprint : app-only, certificate already in the local certificate
                store. Windows only (the Cert: provider does not exist elsewhere).
            -CertificateFilePath   : app-only, a PFX certificate file loaded at runtime. The
                cross-platform default for unattended automation.
            -AccessToken           : app-only or delegated, relays an OAuth JWT the caller
                already acquired by any means (workload identity federation, a managed
                identity token exchanged via Az, or any other MSAL flow). This function never
                acquires or refreshes the token itself.
            -DeviceCode            : delegated, OAuth device code flow for hosts with no local
                browser (SSH sessions, containers). Works standalone - just -DeviceCode, nothing
                else required: prints a URL and a short code, and sign-in (credential entry,
                MFA) happens entirely in a browser on any device. Connect-IPPSSession is itself
                a thin wrapper around Connect-ExchangeOnline -ConnectionUri
                'https://ps.compliance.protection.outlook.com/PowerShell-LiveId' that only
                exposes Connect-ExchangeOnline's native -Device switch inside Azure Cloud
                Shell - this function calls Connect-ExchangeOnline directly, with the same
                Security & Compliance -ConnectionUri, to reach that same native device-code
                path everywhere else: Microsoft's own pre-consented first-party client and
                token handling, not a custom app registration or a third-party MSAL library.
                Optionally pass -Organization (your tenant's .onmicrosoft.com domain) to sign in
                against that specific tenant instead of the multi-tenant 'organizations'
                endpoint. KNOWN LIMITATION: Get-ComplianceSecurityFilter's dedicated
                -EnableSearchOnlySession reconnect (see below) is wired internally by
                Connect-IPPSSession itself, via a variable this function cannot set from
                outside that cmdlet - so under -DeviceCode that pass is always skipped with a
                warning, equivalent to -SkipComplianceSecurityFilter, regardless of -Command.
            -Credential             : delegated, username/password sign-in with no interactive
                prompt. Requires an account not enforced for MFA/Conditional Access-blocked
                legacy auth, or this fails. Optionally pass -Organization.
            (default, no auth parameters) : fully interactive, delegated sign-in via
                Connect-IPPSSession's own browser-based modern authentication. Optionally
                pass -UserPrincipalName to skip the username prompt.

        The same authentication method and parameters are reused for the dedicated
        -EnableSearchOnlySession reconnect required by Get-ComplianceSecurityFilter (see
        .NOTES), so an app-only run does not drop into an interactive prompt partway through.

        -OutputPath is tenant-stamped: the first successful export writes an ExportManifest.xml
        recording the connected tenant ID. A later run against the same -OutputPath for a
        DIFFERENT tenant refuses to proceed (preventing one tenant's exported .xml files from
        silently surviving into another tenant's folder and being picked up by
        New-PurviewConfigurationReport) unless -Force is specified, which purges the known
        export files first. Re-running for the SAME tenant - including a -Command subset retry
        - needs no -Force.

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
        Primary .onmicrosoft.com domain of the target tenant (Connect-IPPSSession requires this
        exact form - not a tenant ID GUID). Required with -CertificateThumbprint,
        -CertificateFilePath, or -AccessToken. Optional with -DeviceCode (signs in against that
        specific tenant instead of the multi-tenant endpoint) or -Credential.
    .PARAMETER AccessToken
        A JWT access token the caller already acquired for Security & Compliance PowerShell,
        by any method (workload identity federation, a managed identity token exchange, or any
        other MSAL flow). Requires -Organization. This function never acquires, caches, or
        refreshes this token itself.
    .PARAMETER DeviceCode
        Switch to use delegated OAuth device code sign-in - prints a code and verification URL
        to complete sign-in on any device with a browser (credential entry and MFA happen
        there, not on this host). Works alone, with no other parameters required - calls
        Connect-ExchangeOnline's native -Device switch directly (Microsoft's own pre-consented
        client), not a custom app registration or third-party library. Skips the
        Get-ComplianceSecurityFilter pass automatically - see .NOTES.
    .PARAMETER Credential
        PSCredential for delegated username/password sign-in with no interactive prompt. Fails
        for accounts enforced for MFA or blocked by Conditional Access for legacy/basic auth.
        Optionally combine with -Organization.
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
    .PARAMETER Force
        Required to reuse an -OutputPath that was last exported for a different tenant, or that
        already contains exported .xml files with no tenant manifest (a folder from before this
        safety check existed). Purges the known per-cmdlet export files and any stale manifest
        first. Never removes a file that isn't one of this function's own known export names.

    .EXAMPLE
        Export-PurviewConfiguration -OutputPath C:\output\MIP\

        Connects interactively to Security & Compliance PowerShell and exports the full
        default set of configuration to C:\output\MIP\.

    .EXAMPLE
        Export-PurviewConfiguration -OutputPath ./out -CertificateFilePath ./app.pfx -CertificatePassword (Get-Credential -UserName cert).Password -AppId $appId -Organization contoso.onmicrosoft.com

        Unattended app-only export using a PFX certificate.

    .EXAMPLE
        Export-PurviewConfiguration -OutputPath ./out -DeviceCode

        Delegated sign-in via OAuth device code flow - prints a code and URL to complete
        sign-in (credentials and MFA) in a browser on any device. Useful on hosts with no
        local browser (SSH sessions, containers). No -AppId or -Organization needed.

    .EXAMPLE
        Export-PurviewConfiguration -OutputPath ./out -Credential (Get-Credential)

        Delegated sign-in with a username/password credential, no interactive prompt. Fails
        for accounts enforced for MFA or blocked by Conditional Access for legacy auth.

    .EXAMPLE
        Export-PurviewConfiguration -OutputPath ./out -Command 'Get-DlpCompliancePolicy','Get-DlpComplianceRule' -Verbose
        Re-exports only the DLP policy and rule data for the same tenant already stamped in
        ./out - no -Force needed for a same-tenant re-run.
    .OUTPUTS
        PSCustomObject
        One object per cmdlet run, with properties: Command, RecordCount, Exported.
    .NOTES
        Tenant safety: see .DESCRIPTION and -Force above. The manifest is ExportManifest.xml in
        -OutputPath, written via Export-Clixml, containing TenantId (from the connected
        session's Get-ConnectionInformation.TenantID) and ExportedUtc.
        Paging: Get-QuarantineMessage and Get-DlpDetectionsReport both default to a bounded
        PageSize (100 and 1000 respectively) and, for Get-QuarantineMessage, a bounded date
        window (last 16 days by default, 30 days maximum) - confirmed against Microsoft Learn.
        Called with no parameters at all, either would silently return only the first page/
        default window with no indication data was truncated. Both are paged internally at
        their maximum PageSize (1000 and 5000), and Get-QuarantineMessage is also given an
        explicit -StartReceivedDate/-EndReceivedDate spanning its full 30-day maximum. No
        other cmdlet in the default set was found to page/window in the same way as of this
        writing - re-verify against Microsoft Learn if Microsoft changes these defaults.

        Known Limitations - excluded from the default export set (per-object -Identity-only
        cmdlets, and Exchange Online PowerShell cmdlets out of scope for an IPPS session): see
        LEAST-PRIVILEGE.md's "Excluded from the default set entirely" section for the full list.
        RBAC/feature-gated cmdlets: Security & Compliance PowerShell only exposes a cmdlet in
        the session if the connected account's role assignment grants it (e.g. Information
        Barriers, some Insider Risk Management, and audit-configuration cmdlets require a
        specific admin role beyond Compliance/Security Administrator, or the underlying
        feature to be licensed/enabled). If a cmdlet isn't available to the connected
        account, calling it raises a CommandNotFoundException, which this function treats as
        a benign per-tenant condition (Write-Warning) rather than a failure (Write-Error) —
        see the -Command parameter to target specific cmdlets once the right role is granted.
        This now also applies to Get-Label (previously a bare Write-Error) - unified into the
        same per-cmdlet dispatch as every other cmdlet.
        Get-ComplianceSecurityFilter requires a session opened with Connect-IPPSSession
        -EnableSearchOnlySession and ExchangeOnlineManagement v3.9.0+ (August 2025) — it
        cannot run alongside the rest of the export in the standard session. This function
        runs it as a separate pass at the end: disconnects only its own standard-session
        connection (by ConnectionId, not a blind Disconnect-ExchangeOnline that would tear down
        any other session the caller has open), reconnects with -EnableSearchOnlySession using
        the same authentication parameters, exports, and disconnects that search-only
        connection too before returning. Use -SkipComplianceSecurityFilter to omit this pass
        entirely. The standard session is also disconnected in an outer finally block covering
        every other path (skipped CSF pass, too-old module, or an error anywhere in between),
        so it is never left connected regardless of how the function exits.
        Authentication methods (see .PARAMETER above for the exact parameters of each), the
        Entra/Purview permissions each needs, and the interactive/delegated baseline role
        matrix are all in LEAST-PRIVILEGE.md's "Authentication methods" and "Baseline role"
        sections - including the confirmed "Exchange.ManageAsApp" application permission for
        the two certificate-based methods, and the explicit note that none of the six
        authentication methods (least of all -EnableSearchOnlySession under app-only auth)
        have been verified against a live tenant by this function's author.
        Compliance Administrator (or Compliance Data Administrator) alone is sufficient to
        execute this function end-to-end without a terminating error. Role groups it doesn't
        cover - Organization Management (Get-RoleGroup/Get-ManagementRole/
        Get-SecurityPrincipal/Get-OrganizationSegment), eDiscovery Manager/Administrator
        (Get-ComplianceSecurityFilter and the other eDiscovery cmdlets), Global Reader/Intune
        (Get-Device*) - just degrade those specific cmdlets to a Write-Warning via the
        CommandNotFoundException handling in Invoke-ExportCommand; they do not fail the run.
        Security Administrator is NOT an adequate substitute for the Compliance Administrator
        baseline: it only happens to cover a few individual sections (Information Barriers,
        Audit config, Quarantine/mail filter reporting) and would leave most of the default
        cmdlet set (DLP, Retention, Information Protection, Insider Risk) skipped with
        warnings. See LEAST-PRIVILEGE.md's "True minimum for a narrow run" section.
        Source: "Roles and role groups in Microsoft Defender for Office 365 and Microsoft
        Purview" (https://learn.microsoft.com/microsoft-365/security/office-365-security/scc-permissions).
        -DeviceCode and the Windows broker (WAM): on Windows, Connect-ExchangeOnline
        authenticates through the WAM broker by default. A device-code sign-in never registers
        an account with WAM, but Disconnect-ExchangeOnline's cleanup still asks the broker to
        remove that (non-existent) account. The native MSALRuntime broker surfaces this as an
        unmanaged AccountNotFound exception on a background thread, which is NOT a catchable
        PowerShell error - it crashes the entire pwsh process (seen as "Unhandled exception
        Microsoft.Identity.Client.NativeInterop.MsalRuntimeException: Status: AccountNotFound").
        To avoid this, the -DeviceCode connect parameters include -DisableWAM when the installed
        ExchangeOnlineManagement version exposes that parameter (present since the module added
        WAM support; confirmed on 3.10.1). No try/catch can work around this crash because it
        does not go through normal PowerShell error handling.

        Author/Copyright:
            Architecture & Security - Advania
    .LINK
        https://www.advania.co.uk
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DeviceCode', Justification = 'Parameter-set discriminator only - selection happens via $PSCmdlet.ParameterSetName, not the switch value itself')]
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
        [Parameter(ParameterSetName = 'DeviceCode')]
        [Parameter(ParameterSetName = 'Credential')]
        [string]$Organization,
        [Parameter(ParameterSetName = 'AccessToken', Mandatory = $true)]
        [string]$AccessToken,
        [Parameter(ParameterSetName = 'DeviceCode', Mandatory = $true)]
        [switch]$DeviceCode,
        [Parameter(ParameterSetName = 'Credential', Mandatory = $true)]
        [pscredential]$Credential,
        [Parameter()]
        [string[]]$Command,
        [Parameter()]
        [switch]$SkipModuleCheck,
        [Parameter()]
        [switch]$SkipComplianceSecurityFilter,
        [Parameter()]
        [switch]$Force
    )
    # Validated before anything connects or installs: a typo'd -Command value should never cost
    # a real sign-in (interactive or app-only) before failing.
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
    # Get-Label and Get-ComplianceSecurityFilter are not part of $defaultCommands (Get-Label
    # needs -IncludeDetailedLabelActions, handled via $commandSpecs below; Get-ComplianceSecurityFilter
    # needs its own session, handled in the dedicated pass at the end), but are valid -Command values.
    $validCommands = $defaultCommands + @('Get-Label', 'Get-ComplianceSecurityFilter')
    if ($Command)
    {
        $unknownCommands = @($Command | Where-Object { $_ -notin $validCommands })
        if ($unknownCommands.Count -gt 0)
        {
            Write-Error -Message "Unknown -Command value(s): $($unknownCommands -join ', '). Valid values are: $($validCommands -join ', ')" -Category InvalidArgument -ErrorAction Stop
        }
    }
    $commandsToRun = if ($Command) { $Command } else { $defaultCommands + @('Get-Label') }
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
    # Built once, reused unmodified for both the standard session below and the
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
        'DeviceCode'
        {
            # Connect-IPPSSession is itself a thin wrapper around Connect-ExchangeOnline with
            # this exact -ConnectionUri, but only exposes -Device (native device-code sign-in)
            # inside Azure Cloud Shell. Calling Connect-ExchangeOnline directly, with the same
            # -ConnectionUri, reaches that same native path everywhere else - Microsoft's own
            # pre-consented first-party client, not a custom app registration or MSAL library.
            $deviceConnectParams = @{ ConnectionUri = 'https://ps.compliance.protection.outlook.com/PowerShell-LiveId'; Device = $true; ShowBanner = $false }
            if ($Organization) { $deviceConnectParams.AzureADAuthorizationEndpointUri = "https://login.microsoftonline.com/$Organization" }
            # A device-code sign-in never registers an account with the Windows broker (WAM). On
            # Windows, Disconnect-ExchangeOnline's cleanup still asks WAM to remove that
            # non-existent account, and the native MSALRuntime broker surfaces this as an
            # unmanaged AccountNotFound exception that crashes the whole pwsh process (not a
            # catchable PowerShell error - see .NOTES). -DisableWAM keeps this connection off the
            # broker entirely, avoiding the crash on disconnect. Only set it when the installed
            # module exposes the parameter (added in ExchangeOnlineManagement 3.x).
            if ((Get-Command -Name Connect-ExchangeOnline).Parameters.ContainsKey('DisableWAM'))
            {
                $deviceConnectParams.DisableWAM = $true
            }
            $deviceConnectParams
        }
        'Credential'
        {
            if ($Organization) { @{ Credential = $Credential; Organization = $Organization } } else { @{ Credential = $Credential } }
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
        if ($PSCmdlet.ParameterSetName -eq 'DeviceCode')
        {
            Connect-ExchangeOnline @connectParams -ErrorAction Stop
        }
        else
        {
            Connect-IPPSSession @connectParams -ErrorAction Stop
        }
        $standardConnection = Get-NewConnectionInformation -PriorConnectionIds $priorConnectionIds
        $standardConnectionId = $standardConnection.ConnectionId
        $tenantId = $standardConnection.TenantID
    }
    catch
    {
        Write-Error -Message "Failed to connect to Security & Compliance PowerShell: $($_.Exception.Message)" -Category ConnectionError -ErrorAction Stop
    }
    try
    {
        if (-not (Test-Path -Path $OutputPath))
        {
            if ($PSCmdlet.ShouldProcess($OutputPath, 'Create output directory'))
            {
                $null = New-Item -Path $OutputPath -ItemType Directory -Force
            }
        }
        Confirm-ExportOutputPath -Path $OutputPath -TenantId $tenantId -KnownCommands $validCommands -Force:$Force
        # Get-Label needs -IncludeDetailedLabelActions to capture full label configuration;
        # Get-QuarantineMessage/Get-DlpDetectionsReport need paging (see Get-PagedReportData's
        # comment). Every other cmdlet runs with no additional parameters.
        $commandSpecs = @{
            'Get-Label'               = @{ AdditionalParameters = @{ IncludeDetailedLabelActions = $true } }
            'Get-QuarantineMessage'   = @{ Paged = $true; PageSize = 1000; AdditionalParameters = @{ StartReceivedDate = (Get-Date).AddDays(-30); EndReceivedDate = (Get-Date) } }
            'Get-DlpDetectionsReport' = @{ Paged = $true; PageSize = 5000; AdditionalParameters = @{} }
        }
        foreach ($cmdletName in $commandsToRun | Where-Object { $_ -ne 'Get-ComplianceSecurityFilter' })
        {
            $spec = if ($commandSpecs.ContainsKey($cmdletName)) { $commandSpecs[$cmdletName] } else { @{ AdditionalParameters = @{} } }
            Write-Verbose "Running $cmdletName"
            Invoke-ExportCommand -CmdletName $cmdletName -Spec $spec -OutputPath $OutputPath
        }
        # Get-ComplianceSecurityFilter (and the *-ComplianceSearch cmdlet family more broadly)
        # requires a dedicated session opened with -EnableSearchOnlySession and cannot run
        # alongside the rest of the export in the standard session. Run it last, in its own
        # reconnect, so the bulk of the export still completes even if this step is skipped or
        # fails (e.g. account lacks eDiscovery Administrator).
        if ((-not $Command -or $Command -contains 'Get-ComplianceSecurityFilter') -and -not $SkipComplianceSecurityFilter)
        {
            if ($PSCmdlet.ParameterSetName -eq 'DeviceCode')
            {
                # -EnableSearchOnlySession is wired by Connect-IPPSSession into a module-private
                # script-scoped variable that only Connect-IPPSSession itself (running inside
                # ExchangeOnlineManagement) can set - calling Connect-ExchangeOnline directly, as
                # -DeviceCode does, cannot reach it. No known way to run this pass under
                # -DeviceCode; always skipped, same as -SkipComplianceSecurityFilter.
                Write-Warning 'Get-ComplianceSecurityFilter requires a dedicated -EnableSearchOnlySession reconnect, which is not reachable through -DeviceCode (see .NOTES). Skipping. Use a different authentication method to include this cmdlet, or pass -SkipComplianceSecurityFilter to silence this warning.'
                [pscustomobject]@{
                    Command     = 'Get-ComplianceSecurityFilter'
                    RecordCount = 0
                    Exported    = $false
                }
            }
            else
            {
                $searchSessionModule = Get-Module -Name ExchangeOnlineManagement | Sort-Object -Property Version -Descending | Select-Object -First 1
                if ($searchSessionModule -and $searchSessionModule.Version -lt [version]'3.9.0')
                {
                    Write-Warning "Get-ComplianceSecurityFilter requires ExchangeOnlineManagement v3.9.0 or later (loaded: $($searchSessionModule.Version)). Skipping. Update the module, then re-run with -Command 'Get-ComplianceSecurityFilter' to retry just this cmdlet."
                    [pscustomobject]@{
                        Command     = 'Get-ComplianceSecurityFilter'
                        RecordCount = 0
                        Exported    = $false
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
                            # Cleared so the outer finally below doesn't attempt a second disconnect
                            # of a session already gone.
                            $standardConnectionId = $null
                        }
                        $priorConnectionIds = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ConnectionId)
                        Connect-IPPSSession @connectParams -EnableSearchOnlySession -ErrorAction Stop
                        $searchConnectionId = (Get-NewConnectionInformation -PriorConnectionIds $priorConnectionIds).ConnectionId
                        $data = Get-ComplianceSecurityFilter -ErrorAction Stop
                        if ($data)
                        {
                            Write-Verbose 'Exporting data generated by Get-ComplianceSecurityFilter'
                            $wasExported = Export-ComplianceDataFile -CmdletName 'Get-ComplianceSecurityFilter' -Data $data -Destination $OutputPath
                            [pscustomobject]@{
                                Command     = 'Get-ComplianceSecurityFilter'
                                RecordCount = @($data).Count
                                Exported    = $wasExported
                            }
                        }
                        else
                        {
                            Write-Warning 'No data generated by Get-ComplianceSecurityFilter'
                            [pscustomobject]@{
                                Command     = 'Get-ComplianceSecurityFilter'
                                RecordCount = 0
                                Exported    = $false
                            }
                        }
                    }
                    catch
                    {
                        Write-Error -Message "Get-ComplianceSecurityFilter failed: $($_.Exception.Message). Requires the eDiscovery Administrator role (see .NOTES) in addition to Compliance/Security Administrator."
                        [pscustomobject]@{
                            Command     = 'Get-ComplianceSecurityFilter'
                            RecordCount = 0
                            Exported    = $false
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
    finally
    {
        # Covers every path that does NOT already disconnect the standard session itself:
        # -SkipComplianceSecurityFilter, an -ExchangeOnlineManagement version too old for the
        # CSF pass, -Command not including Get-ComplianceSecurityFilter, or a terminating error
        # anywhere above (including Confirm-ExportOutputPath's tenant-mismatch refusal).
        if ($standardConnectionId)
        {
            Disconnect-ExchangeOnline -ConnectionId $standardConnectionId -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}
