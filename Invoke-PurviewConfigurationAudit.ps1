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
    [CmdletBinding(SupportsShouldProcess)]
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

        [Parameter()]
        [string[]]$Command,

        [Parameter()]
        [switch]$SkipModuleCheck,

        [Parameter()]
        [switch]$SkipComplianceSecurityFilter,

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
        if ($Command) { $exportParams.Command = $Command }
        if ($SkipModuleCheck) { $exportParams.SkipModuleCheck = $true }
        if ($SkipComplianceSecurityFilter) { $exportParams.SkipComplianceSecurityFilter = $true }

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
