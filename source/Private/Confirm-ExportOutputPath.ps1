#Requires -Version 7.0
function Confirm-ExportOutputPath
{
    # Refuses to silently reuse a different tenant's -OutputPath (the same class of
    # cross-tenant leak the original CRITICAL script-scope-variable finding addressed, just
    # moved to disk) by stamping every successful export run with the connected tenant ID.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$TenantId,
        [Parameter(Mandatory)]
        [string[]]$KnownCommands,
        [Parameter()]
        [switch]$Force
    )

    $manifestPath = Join-Path -Path $Path -ChildPath 'ExportManifest.xml'
    $existingManifest = if (Test-Path -Path $manifestPath) { Import-Clixml -Path $manifestPath } else { $null }
    $knownFilesPresent = @($KnownCommands | Where-Object { Test-Path -Path (Join-Path -Path $Path -ChildPath "$_.xml") })

    if ($existingManifest -and $existingManifest.TenantId -ne $TenantId -and -not $Force)
    {
        Write-Error -Message "OutputPath '$Path' was last exported for a different tenant ($($existingManifest.TenantId)), not the connected tenant ($TenantId). Re-run with -Force to purge it, or use a different -OutputPath." -Category ResourceExists -ErrorAction Stop
    }

    if (-not $existingManifest -and $knownFilesPresent.Count -gt 0 -and -not $Force)
    {
        Write-Error -Message "OutputPath '$Path' already contains exported .xml files with no tenant manifest (likely from a run before this safety check existed). Re-run with -Force to confirm intentional reuse, or use a different -OutputPath." -Category ResourceExists -ErrorAction Stop
    }

    if ($Force)
    {
        # Purge only this function's own known export file names - never a wildcard delete
        # of the caller-supplied -OutputPath, so an unrelated file always survives.
        foreach ($cmdletName in $KnownCommands)
        {
            $filePath = Join-Path -Path $Path -ChildPath "$cmdletName.xml"
            if ((Test-Path -Path $filePath) -and $PSCmdlet.ShouldProcess($filePath, 'Remove stale export file'))
            {
                Remove-Item -Path $filePath -Force
            }
        }
        if ((Test-Path -Path $manifestPath) -and $PSCmdlet.ShouldProcess($manifestPath, 'Remove stale manifest'))
        {
            Remove-Item -Path $manifestPath -Force
        }
    }

    if ($PSCmdlet.ShouldProcess($manifestPath, 'Write export manifest'))
    {
        [pscustomobject]@{ TenantId = $TenantId; ExportedUtc = (Get-Date).ToUniversalTime() } | Export-Clixml -Path $manifestPath
    }
}
