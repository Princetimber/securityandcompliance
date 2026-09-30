# Least-Privilege Permissions

Applies to `Invoke-PurviewConfigurationAudit`, and the two functions it wraps:
`Export-PurviewConfiguration` (connects and reads) and `New-PurviewConfigurationReport`
(local rendering only, no connection).

## Summary

`New-PurviewConfigurationReport` only reads the local `.xml` files that
`Export-PurviewConfiguration` wrote — it needs no permissions of its own. All access
requirements live in `Export-PurviewConfiguration`, via `Connect-IPPSSession`
(Security & Compliance PowerShell).

## Authentication methods

`Export-PurviewConfiguration` (and `Invoke-PurviewConfigurationAudit`, which passes these
through) supports four mutually exclusive authentication methods via `Connect-IPPSSession`:

| Method | Parameters | Notes |
|---|---|---|
| Certificate, local store | `-CertificateThumbprint -AppId -Organization` | App-only. Windows only (`Cert:` provider). |
| Certificate, PFX file | `-CertificateFilePath -CertificatePassword -AppId -Organization` | App-only. Cross-platform default for unattended runs. |
| Bring-your-own token | `-AccessToken -Organization` | App-only or delegated depending on how the caller acquired the JWT (workload identity federation, a managed identity token exchange, or any other MSAL flow). This function never acquires or refreshes it. |
| Default | none, or `-UserPrincipalName` | Fully interactive delegated sign-in. |

`Connect-IPPSSession` has no managed-identity or device-code parameter of its own - a managed
identity is only reachable by acquiring its token separately and passing it via `-AccessToken`.

**Not verified against a live tenant**: whether `-EnableSearchOnlySession` (required for
`Get-ComplianceSecurityFilter`) works under app-only (certificate/token) authentication, as
opposed to only interactive/delegated. If it does not, skip that pass for app-only runs with
`-SkipComplianceSecurityFilter`.

## Baseline role

Required for most of the ~90 default cmdlets:

- **Compliance Administrator** or **Compliance Data Administrator** (Microsoft Entra ID
  role, or the equivalent Purview role group) — covers Information Protection, DLP,
  Retention, Insider Risk, Information Barriers, and Audit reads.

## Add only if you need these specific sections

Least-privilege: each missing role just degrades a cmdlet to a `Write-Warning`, not a
failure.

| Section | Extra role needed |
|---|---|
| `Get-RoleGroup`, `Get-ManagementRole`, `Get-SecurityPrincipal`, `Get-OrganizationSegment` | **Organization Management** (Role Management role) |
| eDiscovery/Compliance Search cmdlets, and specifically `Get-ComplianceSecurityFilter` | **eDiscovery Manager**, with the **eDiscovery Administrator** sub-role for org-wide visibility |
| `Get-InsiderRiskPolicy` | **Insider Risk Management** (or **Insider Risk Management Admins**) |
| Device Compliance / Conditional Access reporting (`Get-Device*`) | **Global Reader** or an Intune admin role (this data is Intune-synced, not pure Purview) |
| Quarantine / mail filter reporting | **Security Administrator**/**Security Reader** or a **Quarantine** role |

## True minimum for a narrow run

If you only need the core Information Protection/DLP/Retention picture — skip
`-Command` targeting `Get-ComplianceSecurityFilter`, `Get-RoleGroup`,
`Get-InsiderRiskPolicy`, `Get-Device*` — **Compliance Administrator alone is
sufficient**. Everything else in the default set will either succeed or degrade
gracefully to a warning rather than break the run.

## Known gap

Nothing in the code enforces or checks role membership at runtime — it relies
entirely on Exchange Online PowerShell's server-side `CommandNotFoundException`
behavior (`Export-PurviewConfiguration.ps1` line 392) to skip cmdlets the account
can't reach. This is a reasonable and intentional design (documented in `.NOTES`,
lines 78-85), but there is no client-side pre-flight permission check.

## Source

`Export-PurviewConfiguration.ps1` `.NOTES` section (lines 94-164) contains the full,
per-cmdlet-group permissions breakdown this document summarizes, with links to the
relevant Microsoft Learn pages.
