#Requires -Version 7.0
function Get-NewConnectionInformation
{
    # Diffs Get-ConnectionInformation against a before-connect snapshot to find the session a
    # Connect-IPPSSession call just opened. If the diff finds nothing - Get-ConnectionInformation
    # lagging the new session, or any other timing/filtering mismatch - falls back to the single
    # connection now present only when that is unambiguous (exactly one). With more than one,
    # guessing which ConnectionId is ours risks disconnecting the wrong session (or never
    # disconnecting the real one) later, so this fails loudly instead of returning $null and
    # silently leaving a live, untracked session connected.
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$PriorConnectionIds
    )

    $connections = @(Get-ConnectionInformation)
    $newConnection = $connections | Where-Object { $_.ConnectionId -notin $PriorConnectionIds } | Select-Object -First 1
    if ($newConnection)
    {
        return $newConnection
    }

    if ($connections.Count -eq 1)
    {
        return $connections[0]
    }

    Write-Error -Message "Connected, but could not identify the new session's ConnectionId - Get-ConnectionInformation showed no new connection and $($connections.Count) connections are present, so which one is this function's own session cannot be determined safely." -Category ConnectionError -ErrorAction Stop
}
