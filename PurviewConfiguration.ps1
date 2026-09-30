#Requires -Version 7.0
<#
    Dot-source loader. Defines no functions itself - loads every private helper from
    source/Private/, then every public function from source/Public/, in sorted order within
    each folder. Load order within a folder does not matter: PowerShell resolves calls between
    these functions at invocation time, not at definition time.

    Each source/Public/*.ps1 file also dot-sources its own source/Private/ dependencies (if
    any) directly, so it stays independently dot-sourceable
    (e.g. `. ./source/Public/Export-PurviewConfiguration.ps1`) without going through this
    loader - this loader is a convenience for loading everything in one call, e.g. for a
    one-shot audit run or for Pester tests that need the full set.

    No module boundary: this is a flat dot-source layout, not a buildable module, so every
    source/Private/*.ps1 function becomes a plain global function in the caller's session once
    loaded - exactly like the public ones, with no enforced "private" scoping. In a long-lived
    session that also loads other tooling, a generically-named private helper here (e.g.
    Get-PagedReportData, Invoke-ExportCommand) could collide with and silently shadow a
    same-named function from another loaded module, or vice versa. Prefer a fresh PowerShell
    session per run, or check `Get-Command <name> -All` first if this is ever loaded alongside
    other modules in the same session.
#>

$privatePath = Join-Path -Path $PSScriptRoot -ChildPath 'source/Private'
$publicPath = Join-Path -Path $PSScriptRoot -ChildPath 'source/Public'

foreach ($path in @($privatePath, $publicPath))
{
    $files = @(Get-ChildItem -Path $path -Filter '*.ps1' -ErrorAction SilentlyContinue | Sort-Object -Property Name)
    if ($files.Count -eq 0)
    {
        throw "No .ps1 files found in '$path'. Expected one file per function."
    }
    foreach ($file in $files)
    {
        . $file.FullName
    }
}
