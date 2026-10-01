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
through) supports six mutually exclusive authentication methods, five via
`Connect-IPPSSession` directly and one (`-DeviceCode`) via `Connect-ExchangeOnline` with the
same Security & Compliance `-ConnectionUri` (see below):

| Method | Parameters | Notes |
|---|---|---|
| Certificate, local store | `-CertificateThumbprint -AppId -Organization` | App-only. Windows only (`Cert:` provider). |
| Certificate, PFX file | `-CertificateFilePath -CertificatePassword -AppId -Organization` | App-only. Cross-platform default for unattended runs. |
| Bring-your-own token | `-AccessToken -Organization` | App-only or delegated depending on how the caller acquired the JWT (workload identity federation, a managed identity token exchange, or any other MSAL flow). This function never acquires or refreshes it. |
| Device code | `-DeviceCode` (standalone; `-Organization` optional override) | Delegated. Connects via `Connect-ExchangeOnline`'s native `-Device` switch directly (same `-ConnectionUri` Connect-IPPSSession itself hardcodes for Security & Compliance PowerShell), using Microsoft's own pre-consented first-party client - no custom app registration or third-party auth library. For hosts with no local browser; sign-in happens in a browser on any device. Skips the `Get-ComplianceSecurityFilter` pass automatically (see below). |
| Credential | `-Credential`, optionally `-Organization` | Delegated username/password, no interactive prompt. Fails for MFA-enforced or Conditional-Access-blocked-legacy-auth accounts. |
| Default | none, or `-UserPrincipalName` | Fully interactive delegated sign-in. |

`Connect-IPPSSession` has no managed-identity parameter of its own - a managed identity is
only reachable by acquiring its token separately and passing it via `-AccessToken`.
`Connect-IPPSSession` is itself a thin wrapper around `Connect-ExchangeOnline -ConnectionUri
'https://ps.compliance.protection.outlook.com/PowerShell-LiveId'`, and does have a native
device-code path (`Connect-ExchangeOnline -Device`) - but only exposes that switch to its own
caller inside Azure Cloud Shell. `-DeviceCode` calls `Connect-ExchangeOnline` directly with the
same `-ConnectionUri` to reach that native path everywhere else (confirmed by reading
`(Get-Command Connect-IPPSSession).Definition` against the installed
ExchangeOnlineManagement 3.10.1 module).

**Not verified against a live tenant**: whether `-EnableSearchOnlySession` (required for
`Get-ComplianceSecurityFilter`) works under app-only (certificate/token) authentication, as
opposed to only interactive/delegated. If it does not, skip that pass for app-only runs with
`-SkipComplianceSecurityFilter`. Nothing in this document has been verified against a live
tenant - confirm behaviour before relying on it for unattended production automation.

### App-only permissions (certificate-based methods)

Confirmed against Microsoft Learn's app-only authentication guide
(https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2): the app
registration (identified by `-AppId`) needs the **"Microsoft Exchange Online Protection"**
API's application permission **"Exchange.ManageAsApp"** - this is the Security & Compliance
PowerShell API; **"Office 365 Exchange Online"** is the separate API for
`Connect-ExchangeOnline` and is the wrong one for this function. The connecting service
principal also needs the same Microsoft Purview role assignments listed below as a human
account would (e.g. Compliance Administrator).

### Bring-your-own-token method

`-AccessToken`: this function performs no permission check of its own - the token's
scopes/role assignments are whatever the caller's acquisition flow (workload identity
federation, a managed identity's exchanged token, etc.) granted.

### Device code method

`-DeviceCode`: delegated sign-in, so governed by the signing-in account's own Entra ID /
Purview role assignments, same as the default interactive method. Works standalone - no
`-AppId` involved at all, since this calls `Connect-ExchangeOnline -Device` directly rather
than acquiring a token itself: Microsoft's own pre-consented first-party client handles
authentication the same way the default interactive method does, just via a device code
instead of a local browser popup. Pass `-Organization` (your tenant's `.onmicrosoft.com`
domain) to sign in against that specific tenant instead of the multi-tenant `organizations`
endpoint.

**Known limitation - `Get-ComplianceSecurityFilter` is always skipped under `-DeviceCode`**:
the dedicated `-EnableSearchOnlySession` reconnect pass (see below) is wired by
`Connect-IPPSSession` into a module-private script-scoped variable that only
`Connect-IPPSSession` itself, running inside the ExchangeOnlineManagement module, can set -
confirmed by reading `(Get-Command Connect-ExchangeOnline).Definition`, which reads that
variable via `Test-Path Variable:Script:EnableSearchOnlySession` rather than accepting it as a
parameter. Calling `Connect-ExchangeOnline` directly, as `-DeviceCode` does, cannot reach it.
This pass is always skipped under `-DeviceCode`, equivalent to `-SkipComplianceSecurityFilter`,
regardless of `-Command`. Use a different authentication method to include this cmdlet.

**Superseded design note**: an earlier version of `-DeviceCode` acquired its own token via the
third-party MSAL.PS module against a well-known public client ID, then passed it to
`Connect-IPPSSession -AccessToken`. That failed against a live tenant with `UnAuthorized` -
most likely because that client ID was never consented for the Security & Compliance
PowerShell resource in that tenant. The current design avoids the whole class of problem by
never acquiring a token itself.

### Credential method

`-Credential`: delegated sign-in, governed by the signed-in account's own role assignments.
Requires the account to be exempt from MFA enforcement and from any Conditional Access policy
blocking legacy/basic authentication, or the sign-in fails.

### Default (interactive) method

Governed entirely by the signed-in account's own Entra ID / Purview role assignments listed
below, not by any parameter.

## Baseline role

Required for most of the default cmdlet set (`$validCommands` in
`Export-PurviewConfiguration.ps1` — 75 entries as of this writing; that variable is the
authoritative, current count, not this document):

- **Compliance Administrator** or **Compliance Data Administrator** (Microsoft Entra ID
  role, or the equivalent Purview role group) — covers Information Protection, DLP,
  Retention, Insider Risk, Information Barriers, and Audit reads.

## Add only if you need these specific sections

Least-privilege: each missing role just degrades a cmdlet to a `Write-Warning`, not a
failure (`CommandNotFoundException`, handled in the cmdlet dispatch helper).

| Section | Extra role needed | Learn reference |
|---|---|---|
| `Get-RoleGroup`, `Get-ManagementRole`, `Get-SecurityPrincipal`, `Get-OrganizationSegment` | **Organization Management** (Role Management role — the most restrictive of the set; not included in Compliance Administrator alone) | — |
| eDiscovery/Compliance Search cmdlets (`Get-ComplianceCase*`, `Get-ComplianceSearch*`, `Get-eDiscoveryCaseAdmin`, `Get-HoldCompliancePolicy`, `Get-HoldComplianceRule`), and specifically `Get-ComplianceSecurityFilter` | **eDiscovery Manager**, with the **eDiscovery Administrator** sub-role for org-wide (not just own-case) visibility, and specifically for `Get-ComplianceSecurityFilter` | https://learn.microsoft.com/purview/edisc-permissions |
| `Get-InsiderRiskPolicy` | **Insider Risk Management** (or **Insider Risk Management Admins**) role group, or Organization Management / Compliance Administrator | https://learn.microsoft.com/purview/insider-risk-management-permissions |
| Information Barriers (`Get-InformationBarrierPolicy`, `Get-InformationBarrierPoliciesApplicationStatus`) | **IB Compliance Management** role — default in Compliance Administrator, Compliance Data Administrator, Organization Management, Security Administrator | https://learn.microsoft.com/purview/information-barriers-policies#required-subscriptions-and-permissions |
| Audit (`Get-AuditConfig`, `Get-AuditConfigurationPolicy`, `Get-AuditConfigurationRule`, `Get-UnifiedAuditLogRetentionPolicy`, `Get-AdminAuditLogConfig`) | **View-Only Audit Logs** (or Audit Logs) role — default in Compliance Administrator, Compliance Data Administrator, Organization Management, Security Administrator, Security Reader | https://learn.microsoft.com/purview/audit-get-started#step-2-assign-permissions-to-search-the-audit-log |
| Communication Compliance (`Get-SupervisoryReview*`) | A Communication Compliance role group (Admins/Analysts/Investigators/Viewers), or Organization Management/Compliance Administrator for initial setup only | https://learn.microsoft.com/purview/communication-compliance-permissions |
| Records Management / Retention (`Get-RetentionCompliancePolicy`, `Get-RetentionComplianceRule`, `Get-FilePlanProperty*`, `Get-ComplianceTag*`, `Get-AdaptiveScope`) | **Records Management** role group, or Compliance Administrator / Compliance Data Administrator | — |
| Device Compliance / Conditional Access reporting (`Get-Device*`) | **Global Reader** or an Intune admin role (this data is Intune-synced, not pure Purview) | — |
| Quarantine / mail filter reporting (`Get-QuarantineMessage`, `Get-MailFilterListReport`) | **Security Administrator**/**Security Reader** or a **Quarantine** role (e.g. Quarantine Administrator), and/or the relevant Exchange Online role | — |

Source for the table above: "Roles and role groups in Microsoft Defender for Office 365
and Microsoft Purview"
(https://learn.microsoft.com/microsoft-365/security/office-365-security/scc-permissions).

In practice, an assessment/reporting account that needs full coverage should be a member
of: Compliance Administrator (or Compliance Data Administrator), Organization Management,
and eDiscovery Manager (with the eDiscovery Administrator role for
`Get-ComplianceSecurityFilter`). Add Insider Risk Management / Insider Risk Management
Admins if `Get-InsiderRiskPolicy` coverage is required.

## Excluded from the default set entirely

- **Require a per-object `-Identity`** (or date-range/`-Case`/`-Policy`) and can't be
  enumerated blind: `Get-InformationBarrierRecipientStatus`,
  `Get-InformationBarrierReportDetails`, `Get-InformationBarrierReportSummary`,
  `Get-RoleGroupMember`, `Get-ComplianceCaseMember`, `Get-SupervisoryReviewActivity`,
  `Get-QuarantineMessageHeader`, `Get-LongTermAuditItems`, `Get-LongTermAuditStats`,
  `Get-CaseHoldPolicy` (requires `-Case` or `-Policy`).
- **Out of scope** - Exchange Online PowerShell cmdlets (`Connect-ExchangeOnline`), not
  Security & Compliance PowerShell (`Connect-IPPSSession`), and will never resolve in an
  IPPS session: `Get-TransportRule`, `Get-DataEncryptionPolicy`, `Get-IRMConfiguration`.

## True minimum for a narrow run

If you only need the core Information Protection/DLP/Retention picture — skip
`-Command` targeting `Get-ComplianceSecurityFilter`, `Get-RoleGroup`,
`Get-InsiderRiskPolicy`, `Get-Device*` — **Compliance Administrator alone is
sufficient**. Everything else in the default set will either succeed or degrade
gracefully to a warning rather than break the run.

## Known gap

Nothing in the code enforces or checks role membership at runtime — it relies
entirely on Exchange Online PowerShell's server-side `CommandNotFoundException`
behavior (handled in `Export-PurviewConfiguration.ps1`'s `Invoke-ExportCommand` private
function) to skip cmdlets the account can't reach. This is a reasonable and intentional
design (documented in that function's `.NOTES` section), but there is no client-side
pre-flight permission check.

## Source

This document is the canonical, full per-cmdlet-group permissions breakdown - referenced
by name (not line number, which drifts) from `Export-PurviewConfiguration.ps1`'s `.NOTES`
section.
