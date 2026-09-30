#Requires -Version 7.0
function Get-PagedReportData
{
    # Get-QuarantineMessage and Get-DlpDetectionsReport default to a bounded PageSize
    # (100 and 1000 respectively - confirmed on Microsoft Learn) and silently return
    # only the first page if called with no paging parameters at all, understating the
    # true record count with no indication a page limit was hit. Loops -Page until a
    # short page confirms there is nothing left.
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string]$CmdletName,
        [Parameter(Mandatory)]
        [int]$PageSize,
        [Parameter()]
        [hashtable]$AdditionalParameters = @{}
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $page = 1
    do
    {
        $pageParameters = $AdditionalParameters.Clone()
        $pageParameters.Page = $page
        $pageParameters.PageSize = $PageSize
        $batch = @(& $CmdletName @pageParameters -ErrorAction Stop)
        foreach ($item in $batch)
        {
            $results.Add($item)
        }
        $page++
    } while ($batch.Count -eq $PageSize)

    return $results.ToArray()
}
