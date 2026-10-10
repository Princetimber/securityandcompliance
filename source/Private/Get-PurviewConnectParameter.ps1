#Requires -Version 7.0
function Get-PurviewConnectParameter
{
    # Builds the Connect-IPPSSession / Connect-ExchangeOnline parameter hashtable for the
    # authentication method the caller selected. Built once and reused unmodified for both the
    # standard session and the later -EnableSearchOnlySession reconnect, so an app-only run
    # never drops into an interactive prompt partway through.
    # $BoundParameter is the caller's $PSBoundParameters; values are read with the indexer
    # because dot access to a missing key throws under Set-StrictMode.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$ParameterSetName,
        [Parameter(Mandatory)]
        [hashtable]$BoundParameter
    )

    switch ($ParameterSetName)
    {
        'CertificateThumbprint'
        {
            if (-not $IsWindows)
            {
                Write-Error -Message 'The -CertificateThumbprint parameter set requires the Windows certificate store (the Cert: provider) and is not supported on this platform. Use -CertificateFilePath instead.' -Category InvalidOperation -ErrorAction Stop
            }
            @{ CertificateThumbprint = $BoundParameter['CertificateThumbprint']; AppId = $BoundParameter['AppId']; Organization = $BoundParameter['Organization'] }
        }
        'CertificateFilePath'
        {
            $certificatePath = $BoundParameter['CertificateFilePath']
            $certificatePassword = $BoundParameter['CertificatePassword']
            try
            {
                $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath, $certificatePassword)
            }
            catch
            {
                Write-Error -Message "Failed to load certificate from '$certificatePath': $($_.Exception.Message)" -Category SecurityError -ErrorAction Stop
            }
            if ($certificate.NotAfter -lt (Get-Date))
            {
                Write-Error -Message "Certificate '$certificatePath' expired on $($certificate.NotAfter)." -Category SecurityError -ErrorAction Stop
            }
            elseif ($certificate.NotAfter -lt (Get-Date).AddDays(30))
            {
                Write-Warning "Certificate '$certificatePath' expires on $($certificate.NotAfter) - within 30 days."
            }
            @{ CertificateFilePath = $certificatePath; CertificatePassword = $certificatePassword; AppId = $BoundParameter['AppId']; Organization = $BoundParameter['Organization'] }
        }
        'AccessToken'
        {
            @{ AccessToken = $BoundParameter['AccessToken']; Organization = $BoundParameter['Organization'] }
        }
        'DeviceCode'
        {
            # Connect-IPPSSession is itself a thin wrapper around Connect-ExchangeOnline with
            # this exact -ConnectionUri, but only exposes -Device (native device-code sign-in)
            # inside Azure Cloud Shell. Calling Connect-ExchangeOnline directly, with the same
            # -ConnectionUri, reaches that same native path everywhere else - Microsoft's own
            # pre-consented first-party client, not a custom app registration or MSAL library.
            $deviceConnectParams = @{ ConnectionUri = 'https://ps.compliance.protection.outlook.com/PowerShell-LiveId'; Device = $true; ShowBanner = $false }
            if ($BoundParameter['Organization']) { $deviceConnectParams.AzureADAuthorizationEndpointUri = "https://login.microsoftonline.com/$($BoundParameter['Organization'])" }
            # A device-code sign-in never registers an account with the Windows broker (WAM). On
            # Windows, Disconnect-ExchangeOnline's cleanup still asks WAM to remove that
            # non-existent account, and the native MSALRuntime broker surfaces this as an
            # unmanaged AccountNotFound exception that crashes the whole pwsh process (not a
            # catchable PowerShell error - see the .NOTES of Export-PurviewConfiguration).
            # -DisableWAM keeps this connection off the broker entirely, avoiding the crash on
            # disconnect. Only set it when the installed module exposes the parameter (added in
            # ExchangeOnlineManagement 3.x).
            if ((Get-Command -Name Connect-ExchangeOnline).Parameters.ContainsKey('DisableWAM'))
            {
                $deviceConnectParams.DisableWAM = $true
            }
            $deviceConnectParams
        }
        'Credential'
        {
            $credentialConnectParams = if ($BoundParameter['Organization']) { @{ Credential = $BoundParameter['Credential']; Organization = $BoundParameter['Organization'] } } else { @{ Credential = $BoundParameter['Credential'] } }
            # Same WAM broker exposure as -DeviceCode (see that branch's comment): -Credential
            # authenticates via ROPC, a non-interactive flow that never registers an account with
            # the broker either, and WAM is on by default here too (DisableWAM defaults to $false
            # in Connect-IPPSSession/Connect-ExchangeOnline regardless of parameter set).
            # Unverified against a live tenant, since this bug was only observed and confirmed
            # fixed under -DeviceCode - applied defensively on the same reasoning.
            if ((Get-Command -Name Connect-IPPSSession).Parameters.ContainsKey('DisableWAM'))
            {
                $credentialConnectParams.DisableWAM = $true
            }
            $credentialConnectParams
        }
        default
        {
            if ($BoundParameter['UserPrincipalName']) { @{ UserPrincipalName = $BoundParameter['UserPrincipalName'] } } else { @{} }
        }
    }
}
