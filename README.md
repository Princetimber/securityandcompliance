# securityandcompliance

PowerShell tooling to export a Microsoft Purview (Security & Compliance) tenant's
configuration to Clixml and render it as a static HTML report — useful for reviewing a
tenant's configuration against a proposed design when direct portal access isn't
available.

## Functions

| Function | Purpose |
|---|---|
| `Export-PurviewConfiguration` | Connects to Security & Compliance PowerShell and exports Information Protection, DLP, Retention, Audit, Device Compliance, eDiscovery, Communication Compliance, Insider Risk, and Information Barriers configuration to one `.xml` file per cmdlet. |
| `New-PurviewConfigurationReport` | Renders the exported `.xml` files into a single static `Report.html`. Local only — reads files already on disk, makes no connection of its own. |
| `Invoke-PurviewConfigurationAudit` | Convenience wrapper that runs both of the above against the same `-OutputPath` in one call. |

Each is independently usable — export now, render later, re-render without reconnecting,
or re-export just a subset with `-Command`.

## Quick start

```powershell
# One call: connect, export, render
Invoke-PurviewConfigurationAudit -OutputPath C:\output\MIP\ -Verbose

# Equivalent, as two separate steps
Export-PurviewConfiguration -OutputPath ./out
New-PurviewConfigurationReport -SourcePath ./out -HTMLReport Report.html

# Unattended, app-only via a PFX certificate
Export-PurviewConfiguration -OutputPath ./out `
    -CertificateFilePath ./app.pfx -CertificatePassword $certPassword `
    -AppId $appId -Organization contoso.onmicrosoft.com

# Re-export just a subset after a transient failure or role change
Export-PurviewConfiguration -OutputPath ./out -Command 'Get-DlpCompliancePolicy','Get-DlpComplianceRule'
```

## Authentication

Four mutually exclusive methods, strongest/most unattended-friendly first:

| Method | Parameters | Notes |
|---|---|---|
| Certificate, local store | `-CertificateThumbprint -AppId -Organization` | App-only. Windows only (`Cert:` provider). |
| Certificate, PFX file | `-CertificateFilePath -CertificatePassword -AppId -Organization` | App-only. Cross-platform default for unattended runs. |
| Bring-your-own token | `-AccessToken -Organization` | App-only or delegated, depending on how the caller acquired the JWT (workload identity federation, a managed identity token exchange, or any other MSAL flow). Never acquired or refreshed by this function. |
| Default | none, or `-UserPrincipalName` | Fully interactive delegated sign-in. |

`Connect-IPPSSession` has no managed-identity or device-code parameter of its own — a
managed identity is only reachable by acquiring its token separately and passing it via
`-AccessToken`.

See [LEAST-PRIVILEGE.md](./LEAST-PRIVILEGE.md) for the exact Entra/Purview permissions
each method and each cmdlet section needs.

**Not verified against a live tenant** — none of the four authentication methods have
been run against a real tenant by this function's author. Confirm behaviour, especially
`-EnableSearchOnlySession` under app-only auth, before relying on this for unattended
production automation.

## Tenant safety

`-OutputPath` is tenant-stamped: the first successful export writes an
`ExportManifest.xml` recording the connected tenant's ID. A later run against the same
`-OutputPath` for a **different** tenant refuses to proceed — preventing one tenant's
exported `.xml` files from silently surviving into another tenant's folder and being
picked up by `New-PurviewConfigurationReport` — unless `-Force` is given, which purges
only the known per-cmdlet export file names (never an arbitrary file in `-OutputPath`).
Re-running for the **same** tenant, including a `-Command` subset retry, needs no
`-Force`.

## Repository layout

Organized in the Sampler `source/Private` + `source/Public` convention (one function per
file), without being a buildable module — no manifest, no `build.ps1`, no GitVersion.

```
PurviewConfiguration.ps1        # dot-source loader: loads every function in one call
source/
├── Public/                     # exported functions, one file per function
│   ├── Export-PurviewConfiguration.ps1
│   ├── New-PurviewConfigurationReport.ps1
│   └── Invoke-PurviewConfigurationAudit.ps1
└── Private/                    # internal helpers, one file per function
    ├── Export-ComplianceDataFile.ps1
    ├── Get-PagedReportData.ps1
    ├── Confirm-ExportOutputPath.ps1
    ├── Invoke-ExportCommand.ps1
    └── Get-NewConnectionInformation.ps1
tests/Unit/                     # Pester v6 unit tests, mirroring source/
LEAST-PRIVILEGE.md              # full auth-method and per-cmdlet-section permissions
PSScriptAnalyzerSettings.psd1
```

Load everything in one call:

```powershell
. ./PurviewConfiguration.ps1
```

Or dot-source a single public function directly — each one loads its own private
dependencies:

```powershell
. ./source/Public/Export-PurviewConfiguration.ps1
```

This is a flat dot-source layout, not a module, so every function (public and private)
becomes a plain global function in the caller's session once loaded. Prefer a fresh
PowerShell session per run, or check `Get-Command <name> -All` first if this is ever
loaded alongside other modules that might define a same-named function.

## Requirements

- PowerShell 7.0+
- [ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement)
  module v3.0+ (installed automatically on first run unless `-SkipModuleCheck` is
  specified); v3.9.0+ is required for the `Get-ComplianceSecurityFilter` pass
  (`-EnableSearchOnlySession`).

## Testing

Pester v6, mocking every external call — no test contacts a live tenant.

```powershell
Import-Module Pester -MinimumVersion 6.0.0 -Force
Invoke-Pester -Path ./tests/Unit
```

`PSScriptAnalyzer -Settings ./PSScriptAnalyzerSettings.psd1` is clean across the repo.

## Known limitations

- Cmdlets requiring a mandatory per-object `-Identity` (or date-range/`-Case`/`-Policy`)
  parameter can't be enumerated blind and are excluded from the default export set — see
  LEAST-PRIVILEGE.md for the full list and how to call them directly as a targeted
  follow-up.
- `Get-ComplianceSecurityFilter` requires a separate `-EnableSearchOnlySession` reconnect
  and ExchangeOnlineManagement v3.9.0+; skip it with `-SkipComplianceSecurityFilter` if
  the connected account lacks eDiscovery Administrator.
- Nothing in the code enforces or checks role membership at runtime — a cmdlet the
  connected account can't reach degrades to a warning, not a failure.
