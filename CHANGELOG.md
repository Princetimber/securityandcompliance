# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `Export-PurviewConfiguration` exports Insider Risk Management cases (`Get-ComplianceCase
  -CaseType InsiderRisk`) to `Get-InsiderRiskCase.xml`, selectable with `-Command
  Get-InsiderRiskCase`. `Get-InsiderRiskCase` is a name for that run, not a real cmdlet. It has
  its own file so it does not overwrite the eDiscovery `Get-ComplianceCase.xml`.
  `Invoke-ExportCommand` accepts a `Cmdlet` key in a command spec for this. The role the call
  needs has not been verified against Microsoft Learn.
- `New-PurviewConfigurationReport` renders an "Insider Risk Cases" section from that file.
- `New-PurviewConfigurationReport` renders a "DSPM for AI Policies" section. No cmdlet or API
  reads DSPM for AI itself, so the section lists the exported DLP, Insider Risk and
  Communication Compliance policies whose name starts with "DSPM for AI" or "Microsoft AI Hub"
  (the prefix used by policies created during the preview), tagged with their source workload.
  Portal-only DSPM for AI state (recommendations, policy status, AI app and data discovery
  settings) and its collection policies are not covered.

### Fixed

- `Export-PurviewConfiguration -DeviceCode` crashed the entire `pwsh` process on disconnect,
  on Windows. WAM (the Windows broker), on by default since ExchangeOnlineManagement 3.7,
  never registers an account during a device-code sign-in, and `Disconnect-ExchangeOnline`'s
  cleanup asking the broker to remove that non-existent account threw an unmanaged
  `MsalRuntimeException: AccountNotFound` that bypassed PowerShell's error handling entirely.
  Fixed by passing `-DisableWAM` on the `-DeviceCode` connect path when the installed module
  exposes the parameter. Confirmed fixed live on Windows.
- Applied the same `-DisableWAM` fix defensively to the `-Credential` (ROPC) authentication
  path, which shares the same precondition (WAM on by default, no account registered by this
  non-interactive flow). Not yet reproduced or confirmed live.

See `Export-PurviewConfiguration.ps1`'s `.NOTES` and `LEAST-PRIVILEGE.md`'s "Device code
method" / "Credential method" sections for the full write-up.
