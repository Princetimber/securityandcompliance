#Requires -Version 7.0
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
