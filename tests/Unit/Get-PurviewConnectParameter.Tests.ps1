#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }

BeforeAll {
    # Run the code under test in strict mode so an unguarded missing property fails here, not in an
    # operator's session that happens to enable it.
    Set-StrictMode -Version Latest

    . "$PSScriptRoot/../../source/Private/Get-PurviewConnectParameter.ps1"

    function Get-TestCredential
    {
        # Placeholder fixture credential built without a plaintext-to-SecureString conversion.
        $secret = [System.Security.SecureString]::new()
        foreach ($character in 'P@ssw0rd!'.ToCharArray())
        {
            $secret.AppendChar($character)
        }
        [pscredential]::new('admin@contoso.onmicrosoft.com', $secret)
    }

    function Export-TestCertificate
    {
        # Writes a self-signed PFX valid between the given dates and returns its path.
        param(
            [Parameter(Mandatory)]
            [datetime]$NotBefore,
            [Parameter(Mandatory)]
            [datetime]$NotAfter,
            [Parameter(Mandatory)]
            [securestring]$Password
        )
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=PurviewConfigurationTest',
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $certificate = $request.CreateSelfSigned($NotBefore, $NotAfter)
        $path = Join-Path -Path $TestDrive -ChildPath "$([guid]::NewGuid()).pfx"
        $passwordText = [System.Net.NetworkCredential]::new('', $Password).Password
        [System.IO.File]::WriteAllBytes($path, $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $passwordText))
        $path
    }
}

Describe 'Get-PurviewConnectParameter' {
    Context 'Default (interactive) set' {
        It 'returns an empty table when no user principal name is bound' {
            $result = Get-PurviewConnectParameter -ParameterSetName 'Default' -BoundParameter @{ OutputPath = 'x' }
            $result | Should -BeOfType [hashtable]
            $result.Count | Should -Be 0
        }

        It 'passes the user principal name through when bound' {
            $result = Get-PurviewConnectParameter -ParameterSetName 'Default' -BoundParameter @{ UserPrincipalName = 'a@contoso.com' }
            $result.UserPrincipalName | Should -Be 'a@contoso.com'
            $result.Count | Should -Be 1
        }
    }

    Context 'AccessToken set' {
        It 'passes the token and organization through' {
            $result = Get-PurviewConnectParameter -ParameterSetName 'AccessToken' -BoundParameter @{ AccessToken = 'jwt'; Organization = 'contoso.onmicrosoft.com' }
            $result.AccessToken | Should -Be 'jwt'
            $result.Organization | Should -Be 'contoso.onmicrosoft.com'
            $result.Count | Should -Be 2
        }
    }

    Context 'CertificateThumbprint set' {
        It 'passes thumbprint, app id and organization through (Windows only)' -Skip:(-not $IsWindows) {
            $result = Get-PurviewConnectParameter -ParameterSetName 'CertificateThumbprint' -BoundParameter @{ CertificateThumbprint = 'ABC'; AppId = 'app'; Organization = 'contoso.onmicrosoft.com' }
            $result.CertificateThumbprint | Should -Be 'ABC'
            $result.AppId | Should -Be 'app'
        }

        It 'refuses on a platform without the Cert: provider' -Skip:$IsWindows {
            { Get-PurviewConnectParameter -ParameterSetName 'CertificateThumbprint' -BoundParameter @{ CertificateThumbprint = 'ABC'; AppId = 'app'; Organization = 'o' } } |
                Should -Throw -ExpectedMessage '*requires the Windows certificate store*'
        }
    }

    Context 'CertificateFilePath set' {
        BeforeAll {
            $script:pfxPassword = Get-TestCredential | Select-Object -ExpandProperty Password
        }

        It 'passes path, password, app id and organization through for a valid certificate' {
            $path = Export-TestCertificate -NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddDays(365) -Password $script:pfxPassword
            $result = Get-PurviewConnectParameter -ParameterSetName 'CertificateFilePath' -BoundParameter @{
                CertificateFilePath = $path; CertificatePassword = $script:pfxPassword; AppId = 'app'; Organization = 'contoso.onmicrosoft.com'
            } -WarningVariable warnings -WarningAction SilentlyContinue
            $result.CertificateFilePath | Should -Be $path
            $result.AppId | Should -Be 'app'
            @($warnings).Count | Should -Be 0
        }

        It 'warns when the certificate expires within 30 days' {
            $path = Export-TestCertificate -NotBefore (Get-Date).AddDays(-300) -NotAfter (Get-Date).AddDays(10) -Password $script:pfxPassword
            $null = Get-PurviewConnectParameter -ParameterSetName 'CertificateFilePath' -BoundParameter @{
                CertificateFilePath = $path; CertificatePassword = $script:pfxPassword; AppId = 'app'; Organization = 'o'
            } -WarningVariable warnings -WarningAction SilentlyContinue
            ($warnings -join ' ') | Should -Match 'within 30 days'
        }

        It 'refuses an expired certificate' {
            $path = Export-TestCertificate -NotBefore (Get-Date).AddDays(-400) -NotAfter (Get-Date).AddDays(-5) -Password $script:pfxPassword
            { Get-PurviewConnectParameter -ParameterSetName 'CertificateFilePath' -BoundParameter @{
                    CertificateFilePath = $path; CertificatePassword = $script:pfxPassword; AppId = 'app'; Organization = 'o'
                } } | Should -Throw -ExpectedMessage '*expired on*'
        }

        It 'refuses a file that is not a loadable certificate' {
            $bad = Join-Path -Path $TestDrive -ChildPath 'not-a-cert.pfx'
            Set-Content -Path $bad -Value 'not a certificate' -Encoding utf8NoBOM
            { Get-PurviewConnectParameter -ParameterSetName 'CertificateFilePath' -BoundParameter @{
                    CertificateFilePath = $bad; CertificatePassword = $script:pfxPassword; AppId = 'app'; Organization = 'o'
                } } | Should -Throw -ExpectedMessage '*Failed to load certificate*'
        }
    }

    Context 'DeviceCode set' {
        It 'targets the Security & Compliance endpoint with the native device flow' {
            Mock Get-Command -ParameterFilter { $Name -eq 'Connect-ExchangeOnline' } -MockWith {
                [pscustomobject]@{ Parameters = @{} }
            }
            $result = Get-PurviewConnectParameter -ParameterSetName 'DeviceCode' -BoundParameter @{ DeviceCode = $true }
            $result.ConnectionUri | Should -Be 'https://ps.compliance.protection.outlook.com/PowerShell-LiveId'
            $result.Device | Should -BeTrue
            $result.ContainsKey('AzureADAuthorizationEndpointUri') | Should -BeFalse
            $result.ContainsKey('DisableWAM') | Should -BeFalse
        }

        It 'signs in against the named tenant when an organization is bound' {
            Mock Get-Command -ParameterFilter { $Name -eq 'Connect-ExchangeOnline' } -MockWith { [pscustomobject]@{ Parameters = @{} } }
            $result = Get-PurviewConnectParameter -ParameterSetName 'DeviceCode' -BoundParameter @{ Organization = 'contoso.onmicrosoft.com' }
            $result.AzureADAuthorizationEndpointUri | Should -Be 'https://login.microsoftonline.com/contoso.onmicrosoft.com'
        }

        It 'adds -DisableWAM only when the installed module exposes it' {
            Mock Get-Command -ParameterFilter { $Name -eq 'Connect-ExchangeOnline' } -MockWith {
                [pscustomobject]@{ Parameters = @{ DisableWAM = $true } }
            }
            (Get-PurviewConnectParameter -ParameterSetName 'DeviceCode' -BoundParameter @{}).DisableWAM | Should -BeTrue
        }
    }

    Context 'Credential set' {
        It 'passes the credential alone when no organization is bound' {
            Mock Get-Command -ParameterFilter { $Name -eq 'Connect-IPPSSession' } -MockWith { [pscustomobject]@{ Parameters = @{} } }
            $cred = Get-TestCredential
            $result = Get-PurviewConnectParameter -ParameterSetName 'Credential' -BoundParameter @{ Credential = $cred }
            $result.Credential | Should -Be $cred
            $result.ContainsKey('Organization') | Should -BeFalse
            $result.ContainsKey('DisableWAM') | Should -BeFalse
        }

        It 'adds the organization and -DisableWAM when available' {
            Mock Get-Command -ParameterFilter { $Name -eq 'Connect-IPPSSession' } -MockWith {
                [pscustomobject]@{ Parameters = @{ DisableWAM = $true } }
            }
            $result = Get-PurviewConnectParameter -ParameterSetName 'Credential' -BoundParameter @{ Credential = (Get-TestCredential); Organization = 'contoso.onmicrosoft.com' }
            $result.Organization | Should -Be 'contoso.onmicrosoft.com'
            $result.DisableWAM | Should -BeTrue
        }
    }
}
