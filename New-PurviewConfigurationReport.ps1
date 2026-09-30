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

    begin
    {
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

        function Import-SourceData
        {
            # Loads Command.xml exports from $SourcePath into script-scoped variables named
            # after the mapped variable name, e.g. x_Labels, x_DLPCompliancePolicies.
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [string]$Path,

                [Parameter(Mandatory)]
                [hashtable]$CommandMap
            )

            foreach ($mapEntry in $CommandMap.GetEnumerator())
            {
                $sourceDataPath = Join-Path -Path $Path -ChildPath "$($mapEntry.Key).xml"
                if (Test-Path -Path $sourceDataPath)
                {
                    New-Variable -Name $mapEntry.Value -Value (Import-Clixml -Path $sourceDataPath) -Force -Scope Script
                }
                else
                {
                    Write-Verbose "Source data file not found, skipping: $sourceDataPath"
                }
            }
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

            $sectionHtml = "<h2 align='left'>$(ConvertTo-SafeHtml $Heading)</h4>"
            if (-not $Items -or @($Items).Count -eq 0)
            {
                $sectionHtml += "<p><i>No data exported for this workload.</i></p>"
                return $sectionHtml
            }

            foreach ($item in $Items)
            {
                $title = if ($item.PSObject.Properties.Name -contains $TitleProperty) { $item.$TitleProperty } else { '(unnamed)' }
                $sectionHtml += "<table align='center' style='width: 65%;'><th colspan=2>$(ConvertTo-SafeHtml $title)</th>"
                foreach ($property in $item.PSObject.Properties)
                {
                    if ($ExcludeProperty -contains $property.Name)
                    {
                        continue
                    }
                    $sectionHtml += "<tr><td style='width: 30%;'>$(ConvertTo-SafeHtml $property.Name)</td><td>$(ConvertTo-SafeHtml $property.Value)</td></tr>"
                }
                $sectionHtml += "</table><br/>"
            }
            return $sectionHtml
        }

        if ($Transcript)
        {
            $startTime = [datetime]::Now
            $transcriptPath = Join-Path -Path $SourcePath -ChildPath ($TranscriptFileName -f $startTime.Year, $startTime.Month, $startTime.Day)
            Start-Transcript -Path $transcriptPath
        }

        # Maps the exported cmdlet name to the script-scoped variable name it is loaded into.
        $commandMap = @{
            'Get-Label'                                  = 'x_Labels'
            'Get-Labelpolicy'                             = 'x_Labelpolicies'
            'Get-LabelpolicyRule'                         = 'x_LabelpolicyRules'
            'Get-AadProtectionLevel'                      = 'x_AadProtectionLevels'
            'Get-AutoSensitivityLabelPolicy'              = 'x_AutoSensitivityLabelPolicy'
            'Get-AutoSensitivityLabelRule'                = 'x_AutoSensitivityLabelRule'
            'Get-DlpCompliancePolicy'                     = 'x_DLPCompliancePolicies'
            'Get-DlpComplianceRule'                       = 'x_DLPComplianceRules'
            'Get-DlpDetectionsReport'                     = 'x_DLPDetectionsReports'
            'Get-DlpEdmSchema'                            = 'x_DLPEdmSchemas'
            'Get-DlpKeywordDictionary'                    = 'x_DLPKeywordDictionarys'
            'Get-DlpSensitiveInformationType'             = 'x_DLPSensitiveInformationTypes'
            'Get-DlpSensitiveInformationTypeConfig'       = 'x_DLPSensitiveInformationTypeConfig'
            'Get-DlpSensitiveInformationTypeRulePackage'  = 'x_DLPSensitiveInformationTypeRulePackage'
            'Get-DlpSiDetectionsReport'                   = 'x_DLPSiDetectionsReport'
            'Get-RetentionCompliancePolicy'               = 'x_RetentionCompliancePolicy'
            'Get-RetentionComplianceRule'                 = 'x_RetentionComplianceRule'
            'Get-AdaptiveScope'                           = 'x_AdaptiveScope'
            'Get-AuditConfig'                             = 'x_AuditConfig'
            'Get-AuditConfigurationPolicy'                = 'x_AuditConfigurationPolicy'
            'Get-AuditConfigurationRule'                  = 'x_AuditConfigurationRule'
            'Get-DeviceComplianceDetailsReport'           = 'x_DeviceComplianceDetailsReport'
            'Get-DeviceComplianceDetailsReportFilter'     = 'x_DeviceComplianceDetailsReportFilter'
            'Get-DeviceCompliancePolicyInventory'         = 'x_DeviceCompliancePolicyInventory'
            'Get-DeviceComplianceReportDate'              = 'x_DeviceComplianceReportDate'
            'Get-DeviceComplianceSummaryReport'           = 'x_DeviceComplianceSummaryReport'
            'Get-DeviceComplianceUserInventory'           = 'x_DeviceComplianceUserInventory'
            'Get-DeviceConditionalAccessPolicy'           = 'x_DeviceConditionalAccessPolicy'
            'Get-DeviceConditionalAccessRule'             = 'x_DeviceConditionalAccessRule'
            'Get-DeviceConfigurationPolicy'               = 'x_DeviceConfigurationPolicy'
            'Get-DeviceConfigurationRule'                 = 'x_DeviceConfigurationRule'
            'Get-DevicePolicy'                            = 'x_DevicePolicy'
            'Get-DeviceTenantPolicy'                      = 'x_DeviceTenantPolicy'
            'Get-DeviceTenantRule'                        = 'x_DeviceTenantRule'
            'Get-FilePlanPropertyAuthority'               = 'x_FilePlanPropertyAuthority'
            'Get-FilePlanPropertyCategory'                = 'x_FilePlanPropertyCategory'
            'Get-FilePlanPropertyCitation'                = 'x_FilePlanPropertyCitation'
            'Get-FilePlanPropertyDepartment'               = 'x_FilePlanPropertyDepartment'
            'Get-FilePlanPropertyReferenceId'             = 'x_FilePlanPropertyReferenceId'
            'Get-FilePlanPropertyStructure'               = 'x_FilePlanPropertyStructure'
            'Get-FilePlanPropertySubCategory'             = 'x_FilePlanPropertySubCategory'
            'Get-ComplianceCase'                          = 'x_ComplianceCase'
            'Get-ComplianceCaseStatistics'                = 'x_ComplianceCaseStatistics'
            'Get-ComplianceRetentionEvent'                = 'x_ComplianceRetentionEvent'
            'Get-ComplianceRetentionEventType'            = 'x_ComplianceRetentionEventType'
            'Get-ComplianceSearch'                        = 'x_ComplianceSearch'
            'Get-ComplianceSearchAction'                  = 'x_ComplianceSearchAction'
            'Get-ComplianceSecurityFilter'                = 'x_ComplianceSecurityFilter'
            'Get-ComplianceTag'                           = 'x_ComplianceTag'
            'Get-ComplianceTagStorage'                    = 'x_ComplianceTagStorage'
            'Get-HoldCompliancePolicy'                    = 'x_HoldCompliancePolicy'
            'Get-HoldComplianceRule'                      = 'x_HoldComplianceRule'
            'Get-CaseHoldPolicy'                          = 'x_CaseHoldPolicy'
            'Get-CaseHoldRule'                            = 'x_CaseHoldRule'
            'Get-eDiscoveryCaseAdmin'                     = 'x_eDiscoveryCaseAdmin'
            'Get-SupervisoryReviewOverallProgressReport'  = 'x_SupervisoryReviewOverallProgressReport'
            'Get-SupervisoryReviewPolicyReport'           = 'x_SupervisoryReviewPolicyReport'
            'Get-SupervisoryReviewPolicyV2'               = 'x_SupervisoryReviewPolicyV2'
            'Get-SupervisoryReviewReport'                 = 'x_SupervisoryReviewReport'
            'Get-SupervisoryReviewRule'                   = 'x_SupervisoryReviewRule'
            'Get-SupervisoryReviewTopCasesReport'         = 'x_SupervisoryReviewTopCasesReport'
            'Get-InsiderRiskPolicy'                       = 'x_InsiderRiskPolicy'
            'Get-InformationBarrierPolicy'                = 'x_InformationBarrierPolicy'
            'Get-InformationBarrierPoliciesApplicationStatus' = 'x_InformationBarrierPoliciesApplicationStatus'
            'Get-QuarantineMessage'                       = 'x_QuarantineMessage'
            'Get-ActivityAlert'                           = 'x_ActivityAlert'
            'Get-AdminAuditLogConfig'                     = 'x_AdminAuditLogConfig'
            'Get-DataRetentionReport'                     = 'x_DataRetentionReport'
            'Get-MailFilterListReport'                    = 'x_MailFilterListReport'
            'Get-ManagementRole'                          = 'x_ManagementRole'
            'Get-OrganizationSegment'                     = 'x_OrganizationSegment'
            'Get-PolicyConfig'                            = 'x_PolicyConfig'
            'Get-ProtectionAlert'                         = 'x_ProtectionAlert'
            'Get-RegulatoryComplianceUI'                  = 'x_RegulatoryComplianceUI'
            'Get-RoleGroup'                               = 'x_RoleGroup'
            'Get-SCInsights'                              = 'x_SCInsights'
            'Get-SecurityPrincipal'                       = 'x_SecurityPrincipal'
            'Get-UnifiedAuditLogRetentionPolicy'          = 'x_UnifiedAuditLogRetentionPolicy'
        }

        Import-SourceData -Path $SourcePath -CommandMap $commandMap
    }

    process
    {
        $output = '
<!DOCTYPE html>
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
</head>'

        $output += "
<body>
<h1 align='center'>Information Protection Configuration Report</h1>
<h4 align='center' style='border-bottom: 1px lightblue solid; padding-bottom: 10px;'>Generated $(ConvertTo-SafeHtml (Get-Date -Format 'dd/MM/yyyy HH:mm'))</h4>
"
        #region Sensitivity Labels
        $output += "<h2 align='left'>Sensitivity Labels</h4>"
        foreach ($label in $x_Labels)
        {
            $labelSettings = ConvertTo-MIPHashtable -SourceArray $label.Settings
            $labelActions = $label.LabelActions | ConvertFrom-Json
            $labelLocaleSettings = $label.LocaleSettings | ConvertFrom-Json

            $output += "<table align='center' style='width: 65%;'>
            <th colspan=4>$(ConvertTo-SafeHtml $label.displayname)</th>
            <tr><td style='width: 20%;'>Immutable Label Name</td><td style='width: 30%;'>$(ConvertTo-SafeHtml $label.name)</td><td style='width: 20%;'>Immutable Id</td><td style='width: 30%;'>$(ConvertTo-SafeHtml $label.ImmutableId)</td></tr>
            <tr><td>Display name</td><td>$(ConvertTo-SafeHtml $label.displayname)</td><td>Priority</td><td>$(ConvertTo-SafeHtml $label.Priority)</td></tr>
            <tr><td>Parent label display name</td><td>$(ConvertTo-SafeHtml $label.ParentLabelDisplayName)</td><td>Parent label ID</td><td>$(ConvertTo-SafeHtml $label.ParentId)</td></tr>
            <tr><td>Enabled</td><td>$(if (-not $label.Disabled) { 'True' } else { 'False' })</td></tr>
            <tr><td>Administration Comment</td><td colspan='3'>$(ConvertTo-SafeHtml $label.Comment)</td></tr>
            "
            $output += "<th class='subheading' colspan=4>Label Settings</th>
            <tr><td>Tool tip</td><td colspan='3'>$(ConvertTo-SafeHtml $label.tooltip)</td></tr>
            <tr><td>Content Type</td><td>$(ConvertTo-SafeHtml $label.ContentType)</td></tr>
            <tr><td>Workload</td><td>$(ConvertTo-SafeHtml $label.Workload)</td></tr>
            "
            foreach ($labelSetting in $labelSettings.GetEnumerator())
            {
                # Exclude advanced settings which are also parameters
                if ('tooltip', 'contenttype', 'displayname' -contains $labelSetting.Key)
                {
                    $output += "<tr><td>$(ConvertTo-SafeHtml $labelSetting.Key)</td><td>$(ConvertTo-SafeHtml $labelSetting.Value)</td></tr>"
                }
            }

            $output += "<th class='subheading' colspan=4>Label Actions</th>
            <tr><td colspan=1><b>Action Type</b></td><td colspan=1><b>Setting</b></td><td colspan=2><b>Value</b></td></tr>
            "
            foreach ($action in $labelActions)
            {
                switch ($action.type)
                {
                    'encrypt'
                    {
                        $output += "
                        <tr>
                            <td rowspan='$($action.Settings.Count + 1)'>Content Encryption</td>
                            $(
                                foreach ($marking in $action.Settings.GetEnumerator()) {
                                    if ($marking.Key -eq 'rightsdefinitions') {
                                        "<tr>
                                            <td>Rights Definitions:</td>
                                            <td>"
                                                $definedRights = $marking.Value | ConvertFrom-Json
                                                if ($definedRights -is [array]) {
                                                    foreach ($definedRight in $definedRights.GetEnumerator()) {
                                                        "$(ConvertTo-SafeHtml $definedRight.Identity): $(ConvertTo-SafeHtml $definedRight.Rights)<br/>"
                                                    }
                                                } else {
                                                    "$(ConvertTo-SafeHtml $definedRights.Identity): $(ConvertTo-SafeHtml $definedRights.Rights)<br/>"
                                                }
                                            "</td>
                                        </tr>"
                                    } else {
                                        "<tr>
                                            <td>$(ConvertTo-SafeHtml $marking.Key):</td><td>$(ConvertTo-SafeHtml $marking.Value)</td>
                                        </tr>"
                                    }
                                }
                            )
                        </tr>"
                    }
                    'applycontentmarking'
                    {
                        $output += "
                        <tr>
                            <td rowspan='$($action.Settings.Count + 1)'>Apply Content Marking</td>
                            $(
                                foreach ($marking in $action.Settings.GetEnumerator()) {
                                    "<tr>
                                        <td>$(ConvertTo-SafeHtml $marking.Key):</td><td>$(ConvertTo-SafeHtml $marking.Value)</td>
                                    </tr>"
                                }
                            )
                        </tr>
                        "
                    }
                }
            }

            $output += "<th class='subheading' colspan=4>Locale Settings</th>
            "
            foreach ($localeSetting in $labelLocaleSettings)
            {
                $output += "<tr><td>Locale Settings</td><td><table style='width: 100%;'><tr class='noborder'><td>$(ConvertTo-SafeHtml $localeSetting.LocaleKey)</td><td style='width: 75%;'>$(
                    foreach ($localeSettingItem in $localeSetting.Settings.GetEnumerator()) {
                        "$(ConvertTo-SafeHtml $localeSettingItem.Key): $(ConvertTo-SafeHtml $localeSettingItem.Value)<br/>"
                    }
                )</td></tr></table></td></tr>"
            }

            $output += "<th class='subheading' colspan=4>System Parameters</th>
            "
            $output += "<tr><td>Policy</td><td>$(ConvertTo-SafeHtml $label.Policy)</td></tr>
            <tr><td>ReadOnly</td><td>$(ConvertTo-SafeHtml $label.ReadOnly)</td></tr>
            <tr><td>ExternalIdentity</td><td>$(ConvertTo-SafeHtml $label.ExternalIdentity)</td></tr>
            <tr><td>Mode</td><td>$(ConvertTo-SafeHtml $label.Mode)</td></tr>
            <tr><td>CreatedBy</td><td>$(ConvertTo-SafeHtml $label.CreatedBy)</td></tr>
            <tr><td>LastModifiedBy</td><td>$(ConvertTo-SafeHtml $label.LastModifiedBy)</td></tr>
            <tr><td>WhenChangedUTC</td><td>$(ConvertTo-SafeHtml $label.WhenChangedUTC)</td></tr>
            <tr><td>WhenCreatedUTC</td><td>$(ConvertTo-SafeHtml $label.WhenCreatedUTC)</td></tr>
            <tr><td>Identity</td><td colspan='3'>$(ConvertTo-SafeHtml $label.Identity)</td></tr>
            </table><br/>
            "
        }
        #endregion Sensitivity Labels

        #region Sensitivity Label Policies
        $output += "<h2 align='left'>Sensitivity Label Policies</h4>"
        foreach ($labelPolicy in $x_Labelpolicies)
        {
            $labelPolicySettings = ConvertTo-MIPHashtable -SourceArray $labelPolicy.Settings

            $output += "<table align='center' style='width: 65%;'>
            <th colspan=3>$(ConvertTo-SafeHtml $labelPolicy.name)</th>
            <tr><td style='width: 25%;'>Policy Name</td><td>$(ConvertTo-SafeHtml $labelPolicy.name)</td></tr>
            <tr><td>Priority</td><td>$(ConvertTo-SafeHtml $labelPolicy.Priority)</td></tr>
            <tr><td>Administration Comment</td><td>$(ConvertTo-SafeHtml $labelPolicy.Comment)</td></tr>
            <tr><td>Published Labels</td><td>$($labelPolicy.Labels | ForEach-Object { "$(ConvertTo-SafeHtml $_)</BR>" })</td></tr>
            "
            $output += "<th class='subheading' colspan=3>Advanced Settings</th>
            "
            foreach ($labelPolicySetting in $labelPolicySettings.GetEnumerator())
            {
                $output += "<tr><td>$(ConvertTo-SafeHtml $labelPolicySetting.Key)</td><td>$(ConvertTo-SafeHtml $labelPolicySetting.Value)</td></tr>"
            }
            $output += "<th class='subheading' colspan=3>Additional Settings</th>
            "
            $output += "
            <tr><td>SharePointLocation</td><td>$(ConvertTo-SafeHtml $labelPolicy.SharePointLocation)</td></tr>
            <tr><td>SharePointLocationException</td><td>$(ConvertTo-SafeHtml $labelPolicy.SharePointLocationException)</td></tr>
            <tr><td>ExchangeLocation</td><td>$(ConvertTo-SafeHtml (($labelPolicy.ExchangeLocation | Select-Object -ExpandProperty Name) -join ', '))</td></tr>
            <tr><td>ExchangeLocationException</td><td>$(ConvertTo-SafeHtml $labelPolicy.ExchangeLocationException)</td></tr>
            <tr><td>PublicFolderLocation</td><td>$(ConvertTo-SafeHtml $labelPolicy.PublicFolderLocation)</td></tr>
            <tr><td>SkypeLocation</td><td>$(ConvertTo-SafeHtml $labelPolicy.SkypeLocation)</td></tr>
            <tr><td>SkypeLocationException</td><td>$(ConvertTo-SafeHtml $labelPolicy.SkypeLocationException)</td></tr>
            <tr><td>ModernGroupLocation</td><td>$(ConvertTo-SafeHtml (($labelPolicy.ModernGroupLocation | Select-Object -ExpandProperty Name) -join ', '))</td></tr>
            <tr><td>ModernGroupLocationException</td><td>$(ConvertTo-SafeHtml $labelPolicy.ModernGroupLocationException)</td></tr>
            <tr><td>OneDriveLocation</td><td>$(ConvertTo-SafeHtml $labelPolicy.OneDriveLocation)</td></tr>
            <tr><td>OneDriveLocationException</td><td>$(ConvertTo-SafeHtml $labelPolicy.OneDriveLocationException)</td></tr>
            <tr><td>DistributionStatus</td><td>$(ConvertTo-SafeHtml $labelPolicy.DistributionStatus)</td></tr>
            <tr><td>DistributionResults</td><td>$(ConvertTo-SafeHtml $labelPolicy.DistributionResults)</td></tr>
            <tr><td>ReadOnly</td><td>$(ConvertTo-SafeHtml $labelPolicy.ReadOnly)</td></tr>
            <tr><td>ExternalIdentity</td><td>$(ConvertTo-SafeHtml $labelPolicy.ExternalIdentity)</td></tr>
            <tr><td>Workload</td><td>$(ConvertTo-SafeHtml $labelPolicy.Workload)</td></tr>
            <tr><td>Enabled</td><td>$(ConvertTo-SafeHtml $labelPolicy.Enabled)</td></tr>
            <tr><td>Mode</td><td>$(ConvertTo-SafeHtml $labelPolicy.Mode)</td></tr>
            <tr><td>CreatedBy</td><td>$(ConvertTo-SafeHtml $labelPolicy.CreatedBy)</td></tr>
            <tr><td>LastModifiedBy</td><td>$(ConvertTo-SafeHtml $labelPolicy.LastModifiedBy)</td></tr>
            <tr><td>WhenChangedUTC</td><td>$(ConvertTo-SafeHtml $labelPolicy.WhenChangedUTC)</td></tr>
            <tr><td>WhenCreatedUTC</td><td>$(ConvertTo-SafeHtml $labelPolicy.WhenCreatedUTC)</td></tr>
            <tr><td>Identity</td><td>$(ConvertTo-SafeHtml $labelPolicy.Identity)</td></tr>
            </table><br/>
            "
        }
        #endregion Sensitivity Label Policies

        #region Auto-Labeling
        $output += ConvertTo-DetailSectionHtml -Heading 'Auto-Labeling Policies' -Items $x_AutoSensitivityLabelPolicy -TitleProperty 'Name'
        $output += ConvertTo-DetailSectionHtml -Heading 'Auto-Labeling Rules' -Items $x_AutoSensitivityLabelRule -TitleProperty 'Name'
        #endregion Auto-Labeling

        #region DLP Policies
        $output += "<h2 align='left'>DLP Policies</h4>"
        foreach ($dlpPolicy in $x_DLPCompliancePolicies)
        {
            $output += "<table align='center' style='width: 65%;'>
            <th colspan=3>$(ConvertTo-SafeHtml $dlpPolicy.name)</th>
            <tr><td style='width: 25%;'>Policy Name</td><td>$(ConvertTo-SafeHtml $dlpPolicy.name)</td></tr>
            <tr><td>Priority</td><td>$(ConvertTo-SafeHtml $dlpPolicy.Priority)</td></tr>
            <tr><td>Administration Comment</td><td>$(ConvertTo-SafeHtml $dlpPolicy.Comment)</td></tr>
            <tr><td>Enabled</td><td>$(ConvertTo-SafeHtml $dlpPolicy.Enabled)</td></tr>
            <tr><td>Workload</td><td>$(ConvertTo-SafeHtml $dlpPolicy.Workload)</td></tr>
            "
            $output += "<th class='subheading' colspan=3>Policy Locations and Exceptions</th>
            "
            $output += "
            <tr><td>SharePointLocation</td><td>$(ConvertTo-SafeHtml $dlpPolicy.SharePointLocation)</td></tr>
            <tr><td>SharePointLocationException</td><td>$(ConvertTo-SafeHtml $dlpPolicy.SharePointLocationException)</td></tr>
            <tr><td>ExchangeLocation</td><td>$(ConvertTo-SafeHtml $dlpPolicy.ExchangeLocation)</td></tr>
            <tr><td>ExchangeOnPremisesLocation</td><td>$(ConvertTo-SafeHtml $dlpPolicy.ExchangeOnPremisesLocation)</td></tr>
            <tr><td>SharePointOnPremisesLocation</td><td>$(ConvertTo-SafeHtml $dlpPolicy.SharePointOnPremisesLocation)</td></tr>
            <tr><td>SharePointOnPremisesLocationException</td><td>$(ConvertTo-SafeHtml $dlpPolicy.SharePointOnPremisesLocationException)</td></tr>
            <tr><td>TeamsLocation</td><td>$(ConvertTo-SafeHtml $dlpPolicy.TeamsLocation)</td></tr>
            <tr><td>TeamsLocationException</td><td>$(ConvertTo-SafeHtml $dlpPolicy.TeamsLocationException)</td></tr>
            <tr><td>EndpointDlpLocation</td><td>$(ConvertTo-SafeHtml $dlpPolicy.EndpointDlpLocation)</td></tr>
            <tr><td>EndpointDlpLocationException</td><td>$(ConvertTo-SafeHtml $dlpPolicy.EndpointDlpLocationException)</td></tr>
            <tr><td>ThirdPartyAppDlpLocation</td><td>$(ConvertTo-SafeHtml $dlpPolicy.ThirdPartyAppDlpLocation)</td></tr>
            <tr><td>ThirdPartyAppDlpLocationException</td><td>$(ConvertTo-SafeHtml $dlpPolicy.ThirdPartyAppDlpLocationException)</td></tr>
            <tr><td>OnPremisesScannerDlpLocation</td><td>$(ConvertTo-SafeHtml $dlpPolicy.OnPremisesScannerDlpLocation)</td></tr>
            <tr><td>OnPremisesScannerDlpLocationException</td><td>$(ConvertTo-SafeHtml $dlpPolicy.OnPremisesScannerDlpLocationException)</td></tr>
            <tr><td>ExchangeSender</td><td>$(ConvertTo-SafeHtml $dlpPolicy.ExchangeSender)</td></tr>
            <tr><td>ExchangeSenderMemberOf</td><td>$(ConvertTo-SafeHtml $dlpPolicy.ExchangeSenderMemberOf)</td></tr>
            <tr><td>ExchangeSenderException</td><td>$(ConvertTo-SafeHtml $dlpPolicy.ExchangeSenderException)</td></tr>
            <tr><td>ExchangeSenderMemberOfException</td><td>$(ConvertTo-SafeHtml $dlpPolicy.ExchangeSenderMemberOfException)</td></tr>
            <tr><td>OneDriveSharedBy</td><td>$(ConvertTo-SafeHtml $dlpPolicy.OneDriveSharedBy)</td></tr>
            <tr><td>OneDriveSharedByMemberOf</td><td>$(ConvertTo-SafeHtml $dlpPolicy.OneDriveSharedByMemberOf)</td></tr>
            <tr><td>ExceptIfOneDriveSharedByMemberOf</td><td>$(ConvertTo-SafeHtml $dlpPolicy.ExceptIfOneDriveSharedByMemberOf)</td></tr>
            <tr><td>ExtendedProperties</td><td>$(ConvertTo-SafeHtml $dlpPolicy.ExtendedProperties)</td></tr>
            <tr><td>OneDriveLocation</td><td>$(ConvertTo-SafeHtml $dlpPolicy.OneDriveLocation)</td></tr>
            <tr><td>OneDriveLocationException</td><td>$(ConvertTo-SafeHtml $dlpPolicy.OneDriveLocationException)</td></tr>
            "

            $output += "<th class='subheading' colspan=3>Additional Settings</th>
            <tr><td>DistributionStatus</td><td>$(ConvertTo-SafeHtml $dlpPolicy.DistributionStatus)</td></tr>
            <tr><td>DistributionResults</td><td>$(ConvertTo-SafeHtml $dlpPolicy.DistributionResults)</td></tr>
            <tr><td>ReadOnly</td><td>$(ConvertTo-SafeHtml $dlpPolicy.ReadOnly)</td></tr>
            <tr><td>ExternalIdentity</td><td>$(ConvertTo-SafeHtml $dlpPolicy.ExternalIdentity)</td></tr>
            <tr><td>Mode</td><td>$(ConvertTo-SafeHtml $dlpPolicy.Mode)</td></tr>
            <tr><td>Type</td><td>$(ConvertTo-SafeHtml $dlpPolicy.Type)</td></tr>
            <tr><td>CreatedBy</td><td>$(ConvertTo-SafeHtml $dlpPolicy.CreatedBy)</td></tr>
            <tr><td>LastModifiedBy</td><td>$(ConvertTo-SafeHtml $dlpPolicy.LastModifiedBy)</td></tr>
            <tr><td>WhenChangedUTC</td><td>$(ConvertTo-SafeHtml $dlpPolicy.WhenChangedUTC)</td></tr>
            <tr><td>WhenCreatedUTC</td><td>$(ConvertTo-SafeHtml $dlpPolicy.WhenCreatedUTC)</td></tr>
            <tr><td>Identity</td><td>$(ConvertTo-SafeHtml $dlpPolicy.Identity)</td></tr>
            </table><br/>
            "
        }
        #endregion DLP Policies

        #region DLP Rules
        $output += "<h2 align='left'>DLP Rules</h4>"
        foreach ($dlpRule in $x_DLPComplianceRules)
        {
            $output += "<table align='center' style='width: 65%;'>
            <th colspan=3>$(ConvertTo-SafeHtml $dlpRule.name)</th>
            <tr><td style='width: 25%;'>Policy Name</td><td>$(ConvertTo-SafeHtml $dlpRule.name)</td></tr>
            <tr><td>Priority</td><td>$(ConvertTo-SafeHtml $dlpRule.Priority)</td></tr>
            <tr><td>ParentPolicyName</td><td>$(ConvertTo-SafeHtml $dlpRule.ParentPolicyName)</td></tr>
            <tr><td>Administration Comment</td><td>$(ConvertTo-SafeHtml $dlpRule.Comment)</td></tr>
            "

            $output += "<th class='subheading' colspan=3>Additional Settings</th>
            <tr><td>DistributionStatus</td><td>$(ConvertTo-SafeHtml $dlpRule.DistributionStatus)</td></tr>
            <tr><td>DistributionResults</td><td>$(ConvertTo-SafeHtml $dlpRule.DistributionResults)</td></tr>
            <tr><td>ReadOnly</td><td>$(ConvertTo-SafeHtml $dlpRule.ReadOnly)</td></tr>
            <tr><td>ExternalIdentity</td><td>$(ConvertTo-SafeHtml $dlpRule.ExternalIdentity)</td></tr>
            <tr><td>Workload</td><td>$(ConvertTo-SafeHtml $dlpRule.Workload)</td></tr>
            <tr><td>Disabled</td><td>$(ConvertTo-SafeHtml $dlpRule.Disabled)</td></tr>
            <tr><td>Mode</td><td>$(ConvertTo-SafeHtml $dlpRule.Mode)</td></tr>
            <tr><td>Type</td><td>$(ConvertTo-SafeHtml $dlpRule.Type)</td></tr>
            <tr><td>CreatedBy</td><td>$(ConvertTo-SafeHtml $dlpRule.CreatedBy)</td></tr>
            <tr><td>LastModifiedBy</td><td>$(ConvertTo-SafeHtml $dlpRule.LastModifiedBy)</td></tr>
            <tr><td>WhenChangedUTC</td><td>$(ConvertTo-SafeHtml $dlpRule.WhenChangedUTC)</td></tr>
            <tr><td>WhenCreatedUTC</td><td>$(ConvertTo-SafeHtml $dlpRule.WhenCreatedUTC)</td></tr>
            <tr><td>Identity</td><td>$(ConvertTo-SafeHtml $dlpRule.Identity)</td></tr>
            </table><br/>
            "
        }
        #endregion DLP Rules

        #region Retention
        $output += ConvertTo-DetailSectionHtml -Heading 'Retention Policies' -Items $x_RetentionCompliancePolicy -TitleProperty 'Name'
        $output += ConvertTo-DetailSectionHtml -Heading 'Retention Rules' -Items $x_RetentionComplianceRule -TitleProperty 'Name'
        $output += ConvertTo-DetailSectionHtml -Heading 'Adaptive Scopes' -Items $x_AdaptiveScope -TitleProperty 'Name'
        #endregion Retention

        #region Communication Compliance
        $output += ConvertTo-DetailSectionHtml -Heading 'Communication Compliance Policies' -Items $x_SupervisoryReviewPolicyV2 -TitleProperty 'Name'
        $output += ConvertTo-DetailSectionHtml -Heading 'Communication Compliance Rules' -Items $x_SupervisoryReviewRule -TitleProperty 'Name'
        #endregion Communication Compliance

        #region Data Classification
        # Built-in SITs report Publisher 'Microsoft Corporation'; only admin-created custom
        # SITs (any other Publisher value) belong in this report.
        $customSensitiveInformationTypes = @($x_DLPSensitiveInformationTypes | Where-Object { $_.Publisher -ne 'Microsoft Corporation' })
        $output += ConvertTo-DetailSectionHtml -Heading 'Custom Sensitive Information Types' -Items $customSensitiveInformationTypes -TitleProperty 'Name'
        $output += ConvertTo-DetailSectionHtml -Heading 'DLP Keyword Dictionaries' -Items $x_DLPKeywordDictionarys -TitleProperty 'Name'
        $output += ConvertTo-DetailSectionHtml -Heading 'DLP EDM Schemas' -Items $x_DLPEdmSchemas -TitleProperty 'Name'
        #endregion Data Classification

        #region Information Barriers
        $output += ConvertTo-DetailSectionHtml -Heading 'Information Barrier Policies' -Items $x_InformationBarrierPolicy -TitleProperty 'Name'
        #endregion Information Barriers

        #region Insider Risk Management
        $output += ConvertTo-DetailSectionHtml -Heading 'Insider Risk Policies' -Items $x_InsiderRiskPolicy -TitleProperty 'Name'
        #endregion Insider Risk Management

        $output += '</body></html>'

        $htmlReportPath = Join-Path -Path $SourcePath -ChildPath $HTMLReport

        if ($PSCmdlet.ShouldProcess($htmlReportPath, 'Write HTML report'))
        {
            $output | Out-File -FilePath $htmlReportPath
            Write-Verbose "Report written to $htmlReportPath"
        }
    }

    end
    {
        if ($Transcript)
        {
            Stop-Transcript
        }
    }
}
