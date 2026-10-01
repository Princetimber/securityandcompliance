#Requires -Version 7.0

. "$PSScriptRoot/Export-PurviewConfiguration.ps1"
. "$PSScriptRoot/New-PurviewConfigurationReport.ps1"

function Invoke-PurviewConfigurationAudit
{
    <#
    .SYNOPSIS
        Export a tenant's Microsoft Purview configuration and render it as an HTML report
        in one call.

    .DESCRIPTION
        Convenience wrapper that runs Export-PurviewConfiguration followed by
        New-PurviewConfigurationReport against the same -OutputPath. Dot-sourcing this file
        also loads both underlying functions individually, so they can still be called on
        their own — e.g. to re-export a subset of cmdlets, or to re-render the report from an
        existing export without reconnecting to the tenant.

        Requires membership of the Compliance Administrator or Compliance Data Administrator
        role (or an equivalent custom role) in the target tenant for the baseline cmdlet set —
        see LEAST-PRIVILEGE.md for the full per-section breakdown.

    .PARAMETER OutputPath
        Folder to write the exported .xml files and the HTML report to. Created if it does
        not already exist. Passed through to both Export-PurviewConfiguration -OutputPath
        and New-PurviewConfigurationReport -SourcePath.

    .PARAMETER HTMLReport
        Filename to write the HTML report to, relative to -OutputPath. Defaults to
        'Report.html'.

    .PARAMETER UserPrincipalName
        Passed through to Export-PurviewConfiguration -UserPrincipalName (default/interactive
        authentication only).

    .PARAMETER CertificateThumbprint
        Passed through to Export-PurviewConfiguration -CertificateThumbprint (app-only,
        Windows certificate store). Requires -AppId and -Organization.

    .PARAMETER CertificateFilePath
        Passed through to Export-PurviewConfiguration -CertificateFilePath (app-only, PFX
        file, cross-platform). Requires -CertificatePassword, -AppId, and -Organization.

    .PARAMETER CertificatePassword
        Passed through to Export-PurviewConfiguration -CertificatePassword.

    .PARAMETER AppId
        Passed through to Export-PurviewConfiguration -AppId.

    .PARAMETER Organization
        Passed through to Export-PurviewConfiguration -Organization.

    .PARAMETER AccessToken
        Passed through to Export-PurviewConfiguration -AccessToken (bring-your-own-token,
        app-only or delegated). Requires -Organization.

    .PARAMETER DeviceCode
        Passed through to Export-PurviewConfiguration -DeviceCode (delegated OAuth device code
        sign-in via Connect-ExchangeOnline's native -Device switch). Works standalone - no
        other parameters required. Optionally combine with -Organization to target a specific
        tenant instead of the multi-tenant endpoint. Always skips the
        Get-ComplianceSecurityFilter pass - see Export-PurviewConfiguration's .NOTES.

    .PARAMETER Credential
        Passed through to Export-PurviewConfiguration -Credential (delegated username/password
        sign-in, no interactive prompt). Optionally combine with -Organization.

    .PARAMETER Command
        Optional list of cmdlet names to export, instead of the full default set. Passed
        through to Export-PurviewConfiguration -Command.

    .PARAMETER SkipModuleCheck
        Skip the ExchangeOnlineManagement module version check/install. Passed through to
        Export-PurviewConfiguration -SkipModuleCheck.

    .PARAMETER SkipComplianceSecurityFilter
        Skip the dedicated -EnableSearchOnlySession pass for Get-ComplianceSecurityFilter.
        Passed through to Export-PurviewConfiguration -SkipComplianceSecurityFilter. Use this
        if the connected account doesn't have eDiscovery Administrator and you'd rather avoid
        the extra reconnect/disconnect than see it fail.

    .PARAMETER Force
        Passed through to Export-PurviewConfiguration -Force. Required to reuse an -OutputPath
        that was last exported for a different tenant, or that already contains exported .xml
        files with no tenant manifest.

    .PARAMETER Transcript
        Start a PowerShell transcript alongside report generation. Passed through to
        New-PurviewConfigurationReport -Transcript.

    .PARAMETER TranscriptFileName
        Format string (year, month, day) for the transcript filename when -Transcript is
        used. Passed through to New-PurviewConfigurationReport -TranscriptFileName.

    .EXAMPLE
        Invoke-PurviewConfigurationAudit -OutputPath C:\output\MIP\ -Verbose

        Connects to Security & Compliance PowerShell, exports the full default set of
        configuration to C:\output\MIP\, then renders C:\output\MIP\Report.html.

    .EXAMPLE
        Export-PurviewConfiguration -OutputPath ./out
        New-PurviewConfigurationReport -SourcePath ./out -HTMLReport Report.html

        Equivalent to the wrapper, run as two separate steps — useful when you want to
        inspect/re-run the export before rendering, or hand the export folder to someone
        else to render offline.

    .OUTPUTS
        PSCustomObject
        The per-command export summary objects returned by Export-PurviewConfiguration.

    .NOTES
        See Export-PurviewConfiguration and New-PurviewConfigurationReport for the full
        comment-based help on each stage, including the Known Limitations note on
        identity-scoped cmdlets that are not included in the default export set.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DeviceCode', Justification = 'Parameter-set discriminator only - selection happens via $PSCmdlet.ParameterSetName, not the switch value itself')]
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Default')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'Folder to write exported .xml files and the HTML report to'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter(Position = 1)]
        [string]$HTMLReport = 'Report.html',

        [Parameter(ParameterSetName = 'Default')]
        [string]$UserPrincipalName,

        [Parameter(ParameterSetName = 'CertificateThumbprint', Mandatory = $true)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'CertificateFilePath', Mandatory = $true)]
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
        [switch]$Force,

        [Parameter()]
        [switch]$Transcript,

        [Parameter()]
        [string]$TranscriptFileName = 'AAD-{0},{1},{2}-MIPConfigurationReportGenerator.txt'
    )

    process
    {
        if (-not $PSCmdlet.ShouldProcess($OutputPath, 'Export Purview configuration and generate HTML report'))
        {
            return
        }

        $exportParams = @{
            OutputPath = $OutputPath
        }
        switch ($PSCmdlet.ParameterSetName)
        {
            'CertificateThumbprint'
            {
                $exportParams.CertificateThumbprint = $CertificateThumbprint
                $exportParams.AppId = $AppId
                $exportParams.Organization = $Organization
            }
            'CertificateFilePath'
            {
                $exportParams.CertificateFilePath = $CertificateFilePath
                $exportParams.CertificatePassword = $CertificatePassword
                $exportParams.AppId = $AppId
                $exportParams.Organization = $Organization
            }
            'AccessToken'
            {
                $exportParams.AccessToken = $AccessToken
                $exportParams.Organization = $Organization
            }
            'DeviceCode'
            {
                $exportParams.DeviceCode = $true
                if ($Organization) { $exportParams.Organization = $Organization }
            }
            'Credential'
            {
                $exportParams.Credential = $Credential
                if ($Organization) { $exportParams.Organization = $Organization }
            }
            default
            {
                if ($UserPrincipalName) { $exportParams.UserPrincipalName = $UserPrincipalName }
            }
        }
        if ($Command) { $exportParams.Command = $Command }
        if ($SkipModuleCheck) { $exportParams.SkipModuleCheck = $true }
        if ($SkipComplianceSecurityFilter) { $exportParams.SkipComplianceSecurityFilter = $true }
        if ($Force) { $exportParams.Force = $true }

        Write-Verbose "Stage 1/2: Export-PurviewConfiguration -OutputPath $OutputPath"
        Export-PurviewConfiguration @exportParams

        $reportParams = @{
            SourcePath = $OutputPath
            HTMLReport = $HTMLReport
        }
        if ($Transcript)
        {
            $reportParams.Transcript = $true
            $reportParams.TranscriptFileName = $TranscriptFileName
        }

        Write-Verbose "Stage 2/2: New-PurviewConfigurationReport -SourcePath $OutputPath -HTMLReport $HTMLReport"
        New-PurviewConfigurationReport @reportParams
    }
}
