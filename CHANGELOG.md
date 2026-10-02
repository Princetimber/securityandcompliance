# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
