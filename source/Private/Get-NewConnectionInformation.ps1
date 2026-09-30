#Requires -Version 7.0
function Get-NewConnectionInformation
{
    # Diffs Get-ConnectionInformation against a before-connect snapshot to find the session a
    # Connect-IPPSSession call just opened. Returns only a connection whose ConnectionId was NOT
    # already present before connecting - never falls back to "the only connection present" or
    # any other guess, because a Connect-IPPSSession call that silently reused or failed to
    # replace an existing session would otherwise hand back that stale (possibly wrong-tenant)
    # connection as if it were the one just opened, defeating the tenant-stamp safety check
    # downstream by binding it to the wrong tenant's ConnectionId/TenantID. If no genuinely new
    # ConnectionId is found - lag, a reused session, or any other mismatch - fails loudly instead
    # of silently leaving a live, untracked (or misidentified) session connected.
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

    Write-Error -Message "Connected, but could not identify the new session's ConnectionId - Get-ConnectionInformation shows no connection that wasn't already present before connecting ($($connections.Count) total connections). Refusing to guess, since incorrectly reusing a prior session's identity could bind subsequent operations to the wrong tenant." -Category ConnectionError -ErrorAction Stop
}
