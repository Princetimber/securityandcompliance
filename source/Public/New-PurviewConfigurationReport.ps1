#Requires -Version 7.0
function New-PurviewConfigurationReport
{
    <#
    .SYNOPSIS
        Generate an HTML report from a Microsoft Purview configuration export.

    .DESCRIPTION
        Reads the .xml files produced by Export-PurviewConfiguration from -SourcePath and
        renders an HTML report covering Information Protection labels/policies, Auto-Labeling,
        DLP, Retention, Communication Compliance, Data Classification/Sensitive Information
        Types, Information Barriers, and Insider Risk Management configuration. Sections with
        no exported data (e.g. cmdlets not available to the connected account's role) render
        as "No data exported for this workload" rather than being silently omitted. Useful for
        reviewing a tenant's configuration against a proposed design where direct portal
        access is not available.

    .PARAMETER SourcePath
        Folder containing the .xml files produced by Export-PurviewConfiguration.
    .PARAMETER HTMLReport
        Filename to write the HTML report to, relative to -SourcePath. Defaults to
        'Report.html'.
    .PARAMETER Transcript
        Start a PowerShell transcript alongside report generation.
    .PARAMETER TranscriptFileName
        Format string (year, month, day) for the transcript filename when -Transcript is used.

    .EXAMPLE
        New-PurviewConfigurationReport -SourcePath C:\output\MIP\ -HTMLReport Report.html
        Reads C:\output\MIP\*.xml and writes C:\output\MIP\Report.html.

    .OUTPUTS
        None. Writes an HTML file to disk.

    .NOTES
        Author/Copyright:
            Technology Architecture - Content+Cloud
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([void])]
    param(
        [Parameter(
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'Folder containing exported .xml data'
        )]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [string]$SourcePath,

        [Parameter(Position = 1)]
        [string]$HTMLReport = 'Report.html',

        [Parameter()]
        [switch]$Transcript,

        [Parameter()]
        [string]$TranscriptFileName = 'AAD-{0},{1},{2}-MIPConfigurationReportGenerator.txt'
    )

    function Get-SourceData
    {
        # Reads a single Command.xml export on demand. Deliberately stateless (no script-scope
        # caching) - a prior CRITICAL finding was a cross-tenant data leak caused by script-scope
        # variables surviving between calls in the same session.
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path,
            [Parameter(Mandatory)]
            [string]$Cmdlet
        )
        $sourceDataPath = Join-Path -Path $Path -ChildPath "$Cmdlet.xml"
        if (Test-Path -Path $sourceDataPath)
        {
            Import-Clixml -Path $sourceDataPath
        }
        else
        {
            Write-Verbose "Source data file not found, skipping: $sourceDataPath"
        }
    }
    function ConvertTo-MIPHashtable
    {
        # Converts an array of "[Setting1, Value1]" strings into a Setting->Value hashtable.
        [CmdletBinding()]
        param(
            [Parameter()]
            [AllowNull()]
            [string[]]$SourceArray
        )
        $data = @{}
        foreach ($entry in $SourceArray)
        {
            $entryParts = ($entry.TrimStart('[').TrimEnd(']')).Split(',', 2).TrimStart(' ')
            $data[$entryParts[0]] = $entryParts[1]
        }
        return $data
    }
    function ConvertTo-SafeHtml
    {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [AllowNull()]
            $InputObject
        )
        process
        {
            if ($null -eq $InputObject)
            {
                return ''
            }
            [System.Net.WebUtility]::HtmlEncode([string]$InputObject)
        }
    }
    function ConvertTo-PropertyRowsHtml
    {
        # Renders "<tr><td>PropertyName</td><td>value</td></tr>" for each named property, in
        # the order given - replaces long runs of near-identical $output += lines where the
        # visible label is always the property name itself.
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            $Item,
            [Parameter(Mandatory)]
            [string[]]$Property
        )
        $rows = [System.Collections.Generic.List[string]]::new()
        foreach ($name in $Property)
        {
            $rows.Add("<tr><td>$(ConvertTo-SafeHtml $name)</td><td>$(ConvertTo-SafeHtml $Item.$name)</td></tr>")
        }
        return ($rows -join '')
    }
    function ConvertTo-DetailSectionHtml
    {
        # Renders a simple "one table per object, one row per property" section for
        # workloads that don't need a hand-crafted layout.
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Heading,
            [Parameter()]
            [AllowNull()]
            [object[]]$Items,
            [Parameter()]
            [string]$TitleProperty = 'Name',
            [Parameter()]
            [string[]]$ExcludeProperty = @('PSComputerName', 'RunspaceId', 'PSShowComputerName')
        )
        $section = [System.Collections.Generic.List[string]]::new()
        $section.Add("<h2 align='left'>$(ConvertTo-SafeHtml $Heading)</h2>")
        if (-not $Items -or @($Items).Count -eq 0)
        {
            $section.Add('<p><i>No data exported for this workload.</i></p>')
            return ($section -join '')
        }

        foreach ($item in $Items)
        {
            $title = if ($item.PSObject.Properties.Name -contains $TitleProperty) { $item.$TitleProperty } else { '(unnamed)' }
            $section.Add("<table align='center' style='width: 65%;'><tr><th colspan=2>$(ConvertTo-SafeHtml $title)</th></tr>")
            foreach ($property in $item.PSObject.Properties)
            {
                if ($ExcludeProperty -contains $property.Name)
                {
                    continue
                }
                $section.Add("<tr><td style='width: 30%;'>$(ConvertTo-SafeHtml $property.Name)</td><td>$(ConvertTo-SafeHtml $property.Value)</td></tr>")
            }
            $section.Add('</table><br/>')
        }
        return ($section -join '')
    }

    function ConvertTo-LabelActionRowsHtml
    {
        # Renders one <tr> per setting for an encrypt/applycontentmarking label action, with
        # the action-type cell rowspan'd across the first row only - never a <tr> nested inside
        # another <tr>, which the original inline rendering produced and no browser accepts as
        # valid HTML5.
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ActionLabel,
            [Parameter(Mandatory)]
            [AllowNull()]
            $Settings
        )
        $settingsList = @($Settings.GetEnumerator())
        if ($settingsList.Count -eq 0)
        {
            return ''
        }
        $rows = [System.Collections.Generic.List[string]]::new()
        $rowspan = $settingsList.Count
        $isFirstRow = $true
        foreach ($marking in $settingsList)
        {
            $actionLabelCell = if ($isFirstRow) { "<td rowspan='$rowspan'>$(ConvertTo-SafeHtml $ActionLabel)</td>" } else { '' }
            if ($marking.Key -eq 'rightsdefinitions')
            {
                $definedRights = $marking.Value | ConvertFrom-Json
                $rightsCells = if ($definedRights -is [array])
                {
                    ($definedRights | ForEach-Object { "$(ConvertTo-SafeHtml $_.Identity): $(ConvertTo-SafeHtml $_.Rights)<br/>" }) -join ''
                }
                else
                {
                    "$(ConvertTo-SafeHtml $definedRights.Identity): $(ConvertTo-SafeHtml $definedRights.Rights)<br/>"
                }
                $rows.Add("<tr>$actionLabelCell<td>Rights Definitions:</td><td>$rightsCells</td></tr>")
            }
            else
            {
                $rows.Add("<tr>$actionLabelCell<td>$(ConvertTo-SafeHtml $marking.Key):</td><td>$(ConvertTo-SafeHtml $marking.Value)</td></tr>")
            }
            $isFirstRow = $false
        }
        return ($rows -join '')
    }

    function ConvertTo-LabelSectionHtml
    {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object[]]$Labels
        )
        $output = [System.Collections.Generic.List[string]]::new()
        $output.Add("<h2 align='left'>Sensitivity Labels</h2>")
        foreach ($label in $Labels)
        {
            $labelSettings = ConvertTo-MIPHashtable -SourceArray $label.Settings
            $labelActions = $label.LabelActions | ConvertFrom-Json
            $labelLocaleSettings = $label.LocaleSettings | ConvertFrom-Json
            $output.Add("<table align='center' style='width: 65%;'>
            <tr><th colspan=4>$(ConvertTo-SafeHtml $label.displayname)</th></tr>
            <tr><td style='width: 20%;'>Immutable Label Name</td><td style='width: 30%;'>$(ConvertTo-SafeHtml $label.name)</td><td style='width: 20%;'>Immutable Id</td><td style='width: 30%;'>$(ConvertTo-SafeHtml $label.ImmutableId)</td></tr>
            <tr><td>Display name</td><td>$(ConvertTo-SafeHtml $label.displayname)</td><td>Priority</td><td>$(ConvertTo-SafeHtml $label.Priority)</td></tr>
            <tr><td>Parent label display name</td><td>$(ConvertTo-SafeHtml $label.ParentLabelDisplayName)</td><td>Parent label ID</td><td>$(ConvertTo-SafeHtml $label.ParentId)</td></tr>
            <tr><td>Enabled</td><td>$(if (-not $label.Disabled) { 'True' } else { 'False' })</td></tr>
            <tr><td>Administration Comment</td><td colspan='3'>$(ConvertTo-SafeHtml $label.Comment)</td></tr>
            ")
            $output.Add("<tr><th class='subheading' colspan=4>Label Settings</th></tr>
            <tr><td>Tool tip</td><td colspan='3'>$(ConvertTo-SafeHtml $label.tooltip)</td></tr>
            <tr><td>Content Type</td><td>$(ConvertTo-SafeHtml $label.ContentType)</td></tr>
            <tr><td>Workload</td><td>$(ConvertTo-SafeHtml $label.Workload)</td></tr>
            ")
            foreach ($labelSetting in $labelSettings.GetEnumerator())
            {
                # Exclude advanced settings which are also parameters
                if ('tooltip', 'contenttype', 'displayname' -notcontains $labelSetting.Key)
                {
                    $output.Add("<tr><td>$(ConvertTo-SafeHtml $labelSetting.Key)</td><td>$(ConvertTo-SafeHtml $labelSetting.Value)</td></tr>")
                }
            }
            $output.Add("<tr><th class='subheading' colspan=4>Label Actions</th></tr>
            <tr><td colspan=1><b>Action Type</b></td><td colspan=1><b>Setting</b></td><td colspan=2><b>Value</b></td></tr>
            ")
            foreach ($action in $labelActions)
            {
                switch ($action.type)
                {
                    'encrypt'
                    {
                        $output.Add((ConvertTo-LabelActionRowsHtml -ActionLabel 'Content Encryption' -Settings $action.Settings))
                    }
                    'applycontentmarking'
                    {
                        $output.Add((ConvertTo-LabelActionRowsHtml -ActionLabel 'Apply Content Marking' -Settings $action.Settings))
                    }
                }
            }
            $output.Add("<tr><th class='subheading' colspan=4>Locale Settings</th></tr>
            ")
            foreach ($localeSetting in $labelLocaleSettings)
            {
                $output.Add("<tr><td>Locale Settings</td><td><table style='width: 100%;'><tr class='noborder'><td>$(ConvertTo-SafeHtml $localeSetting.LocaleKey)</td><td style='width: 75%;'>$(
                    foreach ($localeSettingItem in $localeSetting.Settings.GetEnumerator()) {
                        "$(ConvertTo-SafeHtml $localeSettingItem.Key): $(ConvertTo-SafeHtml $localeSettingItem.Value)<br/>"
                    }
                )</td></tr></table></td></tr>")
            }
            $output.Add("<tr><th class='subheading' colspan=4>System Parameters</th></tr>
            ")
            $output.Add((ConvertTo-PropertyRowsHtml -Item $label -Property @('Policy', 'ReadOnly', 'ExternalIdentity', 'Mode', 'CreatedBy', 'LastModifiedBy', 'WhenChangedUTC', 'WhenCreatedUTC')))
            $output.Add("<tr><td>Identity</td><td colspan='3'>$(ConvertTo-SafeHtml $label.Identity)</td></tr>
            </table><br/>
            ")
        }
        return ($output -join '')
    }

    function ConvertTo-LabelPolicySectionHtml
    {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object[]]$LabelPolicies
        )
        $output = [System.Collections.Generic.List[string]]::new()
        $output.Add("<h2 align='left'>Sensitivity Label Policies</h2>")
        foreach ($labelPolicy in $LabelPolicies)
        {
            $labelPolicySettings = ConvertTo-MIPHashtable -SourceArray $labelPolicy.Settings
            $output.Add("<table align='center' style='width: 65%;'>
            <tr><th colspan=3>$(ConvertTo-SafeHtml $labelPolicy.name)</th></tr>
            <tr><td style='width: 25%;'>Policy Name</td><td>$(ConvertTo-SafeHtml $labelPolicy.name)</td></tr>
            <tr><td>Priority</td><td>$(ConvertTo-SafeHtml $labelPolicy.Priority)</td></tr>
            <tr><td>Administration Comment</td><td>$(ConvertTo-SafeHtml $labelPolicy.Comment)</td></tr>
            <tr><td>Published Labels</td><td>$($labelPolicy.Labels | ForEach-Object { "$(ConvertTo-SafeHtml $_)<br/>" })</td></tr>
            ")
            $output.Add("<tr><th class='subheading' colspan=3>Advanced Settings</th></tr>
            ")
            foreach ($labelPolicySetting in $labelPolicySettings.GetEnumerator())
            {
                $output.Add("<tr><td>$(ConvertTo-SafeHtml $labelPolicySetting.Key)</td><td>$(ConvertTo-SafeHtml $labelPolicySetting.Value)</td></tr>")
            }
            $output.Add("<tr><th class='subheading' colspan=3>Additional Settings</th></tr>
            ")
            $output.Add((ConvertTo-PropertyRowsHtml -Item $labelPolicy -Property @('SharePointLocation', 'SharePointLocationException')))
            $output.Add("<tr><td>ExchangeLocation</td><td>$(ConvertTo-SafeHtml (($labelPolicy.ExchangeLocation | Select-Object -ExpandProperty Name) -join ', '))</td></tr>")
            $output.Add((ConvertTo-PropertyRowsHtml -Item $labelPolicy -Property @('ExchangeLocationException', 'PublicFolderLocation', 'SkypeLocation', 'SkypeLocationException')))
            $output.Add("<tr><td>ModernGroupLocation</td><td>$(ConvertTo-SafeHtml (($labelPolicy.ModernGroupLocation | Select-Object -ExpandProperty Name) -join ', '))</td></tr>")
            $output.Add((ConvertTo-PropertyRowsHtml -Item $labelPolicy -Property @('ModernGroupLocationException', 'OneDriveLocation', 'OneDriveLocationException', 'DistributionStatus', 'DistributionResults', 'ReadOnly', 'ExternalIdentity', 'Workload', 'Enabled', 'Mode', 'CreatedBy', 'LastModifiedBy', 'WhenChangedUTC', 'WhenCreatedUTC', 'Identity')))
            $output.Add('</table><br/>')
        }
        return ($output -join '')
    }

    function ConvertTo-DlpPolicySectionHtml
    {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object[]]$DlpPolicies
        )
        $output = [System.Collections.Generic.List[string]]::new()
        $output.Add("<h2 align='left'>DLP Policies</h2>")
        foreach ($dlpPolicy in $DlpPolicies)
        {
            $output.Add("<table align='center' style='width: 65%;'>
            <tr><th colspan=3>$(ConvertTo-SafeHtml $dlpPolicy.name)</th></tr>
            <tr><td style='width: 25%;'>Policy Name</td><td>$(ConvertTo-SafeHtml $dlpPolicy.name)</td></tr>
            <tr><td>Priority</td><td>$(ConvertTo-SafeHtml $dlpPolicy.Priority)</td></tr>
            <tr><td>Administration Comment</td><td>$(ConvertTo-SafeHtml $dlpPolicy.Comment)</td></tr>
            <tr><td>Enabled</td><td>$(ConvertTo-SafeHtml $dlpPolicy.Enabled)</td></tr>
            <tr><td>Workload</td><td>$(ConvertTo-SafeHtml $dlpPolicy.Workload)</td></tr>
            ")
            $output.Add("<tr><th class='subheading' colspan=3>Policy Locations and Exceptions</th></tr>
            ")
            $dlpPolicyLocationProperties = @(
                'SharePointLocation', 'SharePointLocationException', 'ExchangeLocation', 'ExchangeOnPremisesLocation',
                'SharePointOnPremisesLocation', 'SharePointOnPremisesLocationException', 'TeamsLocation',
                'TeamsLocationException', 'EndpointDlpLocation', 'EndpointDlpLocationException', 'ThirdPartyAppDlpLocation',
                'ThirdPartyAppDlpLocationException', 'OnPremisesScannerDlpLocation', 'OnPremisesScannerDlpLocationException',
                'ExchangeSender', 'ExchangeSenderMemberOf', 'ExchangeSenderException', 'ExchangeSenderMemberOfException',
                'OneDriveSharedBy', 'OneDriveSharedByMemberOf', 'ExceptIfOneDriveSharedByMemberOf', 'ExtendedProperties',
                'OneDriveLocation', 'OneDriveLocationException'
            )
            $output.Add((ConvertTo-PropertyRowsHtml -Item $dlpPolicy -Property $dlpPolicyLocationProperties))
            $output.Add("<tr><th class='subheading' colspan=3>Additional Settings</th></tr>")
            $output.Add((ConvertTo-PropertyRowsHtml -Item $dlpPolicy -Property @('DistributionStatus', 'DistributionResults', 'ReadOnly', 'ExternalIdentity', 'Mode', 'Type', 'CreatedBy', 'LastModifiedBy', 'WhenChangedUTC', 'WhenCreatedUTC', 'Identity')))
            $output.Add('</table><br/>')
        }
        return ($output -join '')
    }

    function ConvertTo-DlpRuleSectionHtml
    {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object[]]$DlpRules
        )
        $output = [System.Collections.Generic.List[string]]::new()
        $output.Add("<h2 align='left'>DLP Rules</h2>")
        foreach ($dlpRule in $DlpRules)
        {
            $output.Add("<table align='center' style='width: 65%;'>
            <tr><th colspan=3>$(ConvertTo-SafeHtml $dlpRule.name)</th></tr>
            <tr><td style='width: 25%;'>Policy Name</td><td>$(ConvertTo-SafeHtml $dlpRule.name)</td></tr>
            <tr><td>Priority</td><td>$(ConvertTo-SafeHtml $dlpRule.Priority)</td></tr>
            <tr><td>ParentPolicyName</td><td>$(ConvertTo-SafeHtml $dlpRule.ParentPolicyName)</td></tr>
            <tr><td>Administration Comment</td><td>$(ConvertTo-SafeHtml $dlpRule.Comment)</td></tr>
            ")
            $output.Add("<tr><th class='subheading' colspan=3>Additional Settings</th></tr>")
            $output.Add((ConvertTo-PropertyRowsHtml -Item $dlpRule -Property @('DistributionStatus', 'DistributionResults', 'ReadOnly', 'ExternalIdentity', 'Workload', 'Disabled', 'Mode', 'Type', 'CreatedBy', 'LastModifiedBy', 'WhenChangedUTC', 'WhenCreatedUTC', 'Identity')))
            $output.Add('</table><br/>')
        }
        return ($output -join '')
    }

    if ($Transcript)
    {
        $startTime = [datetime]::Now
        $transcriptPath = Join-Path -Path $SourcePath -ChildPath ($TranscriptFileName -f $startTime.Year, $startTime.Month, $startTime.Day)
    }
    $transcriptStarted = $false
    try
    {
        if ($Transcript -and $PSCmdlet.ShouldProcess($transcriptPath, 'Start transcript'))
        {
            # Own the ShouldProcess decision here rather than inferring it from $WhatIfPreference
            # afterwards - that inference could not distinguish -WhatIf from a -Confirm decline,
            # or from Start-Transcript failing outright (e.g. a path/permission error), any of
            # which would still have left $transcriptStarted incorrectly $true and made the
            # finally block below call Stop-Transcript on a transcript that never started.
            try
            {
                Start-Transcript -Path $transcriptPath -WhatIf:$false -Confirm:$false -ErrorAction Stop
                $transcriptStarted = $true
            }
            catch
            {
                Write-Warning "Transcript not started: $($_.Exception.Message)"
            }
        }

        $output = [System.Collections.Generic.List[string]]::new()
        $output.Add('
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Information Protection Report</title>
<style>
    body {
        font-family: Segoe UI,Arial,sans-serif;
        font-size: 10pt;
    }
    table{
        border-collapse: collapse;
    }
    tr{
        border-bottom:1px solid lightblue;
    }
    tr.noborder{
        border:0px;
    }
    th{
        background-color:lightblue;
        font-size: 14pt;
    }
    th.subheading{
        text-align: left;
        background-color: antiquewhite;
        border-top:1px solid antiquewhite;
        border-bottom:1px solid antiquewhite;
        font-size: 11pt;
    }
</style>
</head>')
        $output.Add("
<body>
<h1 align='center'>Information Protection Configuration Report</h1>
<h4 align='center' style='border-bottom: 1px lightblue solid; padding-bottom: 10px;'>Generated $(ConvertTo-SafeHtml (Get-Date -Format 'dd/MM/yyyy HH:mm'))</h4>
")
        $output.Add((ConvertTo-LabelSectionHtml -Labels (Get-SourceData -Path $SourcePath -Cmdlet 'Get-Label')))
        $output.Add((ConvertTo-LabelPolicySectionHtml -LabelPolicies (Get-SourceData -Path $SourcePath -Cmdlet 'Get-Labelpolicy')))
        $output.Add((ConvertTo-DetailSectionHtml -Heading 'Auto-Labeling Policies' -Items (Get-SourceData -Path $SourcePath -Cmdlet 'Get-AutoSensitivityLabelPolicy') -TitleProperty 'Name'))
        $output.Add((ConvertTo-DetailSectionHtml -Heading 'Auto-Labeling Rules' -Items (Get-SourceData -Path $SourcePath -Cmdlet 'Get-AutoSensitivityLabelRule') -TitleProperty 'Name'))
        $output.Add((ConvertTo-DlpPolicySectionHtml -DlpPolicies (Get-SourceData -Path $SourcePath -Cmdlet 'Get-DlpCompliancePolicy')))
        $output.Add((ConvertTo-DlpRuleSectionHtml -DlpRules (Get-SourceData -Path $SourcePath -Cmdlet 'Get-DlpComplianceRule')))
        $output.Add((ConvertTo-DetailSectionHtml -Heading 'Retention Policies' -Items (Get-SourceData -Path $SourcePath -Cmdlet 'Get-RetentionCompliancePolicy') -TitleProperty 'Name'))
        $output.Add((ConvertTo-DetailSectionHtml -Heading 'Retention Rules' -Items (Get-SourceData -Path $SourcePath -Cmdlet 'Get-RetentionComplianceRule') -TitleProperty 'Name'))
        $output.Add((ConvertTo-DetailSectionHtml -Heading 'Adaptive Scopes' -Items (Get-SourceData -Path $SourcePath -Cmdlet 'Get-AdaptiveScope') -TitleProperty 'Name'))
        $output.Add((ConvertTo-DetailSectionHtml -Heading 'Communication Compliance Policies' -Items (Get-SourceData -Path $SourcePath -Cmdlet 'Get-SupervisoryReviewPolicyV2') -TitleProperty 'Name'))
        $output.Add((ConvertTo-DetailSectionHtml -Heading 'Communication Compliance Rules' -Items (Get-SourceData -Path $SourcePath -Cmdlet 'Get-SupervisoryReviewRule') -TitleProperty 'Name'))
        # Built-in SITs report Publisher 'Microsoft Corporation'; only admin-created custom
        # SITs (any other Publisher value) belong in this report.
        $sensitiveInformationTypes = Get-SourceData -Path $SourcePath -Cmdlet 'Get-DlpSensitiveInformationType'
        $customSensitiveInformationTypes = @($sensitiveInformationTypes | Where-Object { $_.Publisher -ne 'Microsoft Corporation' })
        $output.Add((ConvertTo-DetailSectionHtml -Heading 'Custom Sensitive Information Types' -Items $customSensitiveInformationTypes -TitleProperty 'Name'))
        $output.Add((ConvertTo-DetailSectionHtml -Heading 'DLP Keyword Dictionaries' -Items (Get-SourceData -Path $SourcePath -Cmdlet 'Get-DlpKeywordDictionary') -TitleProperty 'Name'))
        $output.Add((ConvertTo-DetailSectionHtml -Heading 'DLP EDM Schemas' -Items (Get-SourceData -Path $SourcePath -Cmdlet 'Get-DlpEdmSchema') -TitleProperty 'Name'))
        $output.Add((ConvertTo-DetailSectionHtml -Heading 'Information Barrier Policies' -Items (Get-SourceData -Path $SourcePath -Cmdlet 'Get-InformationBarrierPolicy') -TitleProperty 'Name'))
        $output.Add((ConvertTo-DetailSectionHtml -Heading 'Insider Risk Policies' -Items (Get-SourceData -Path $SourcePath -Cmdlet 'Get-InsiderRiskPolicy') -TitleProperty 'Name'))
        $output.Add('</body></html>')
        $htmlReportPath = Join-Path -Path $SourcePath -ChildPath $HTMLReport
        if ($PSCmdlet.ShouldProcess($htmlReportPath, 'Write HTML report'))
        {
            ($output -join '') | Out-File -FilePath $htmlReportPath
            Write-Verbose "Report written to $htmlReportPath"
        }
    }
    finally
    {
        if ($transcriptStarted)
        {
            Stop-Transcript
        }
    }
}
