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

    # Hard ceiling in case the underlying cmdlet ever ignores -Page/-PageSize and keeps
    # returning a full page forever - 10,000 pages at the smallest PageSize this function is
    # called with (1000) is 10 million records, far beyond any real tenant's data for these
    # cmdlets; this exists only to fail loudly instead of looping forever if that assumption
    # is ever wrong.
    $maximumPages = 10000

    $results = [System.Collections.Generic.List[object]]::new()
    $page = 1
    do
    {
        if ($page -gt $maximumPages)
        {
            Write-Error -Message "$CmdletName did not finish paging after $maximumPages pages - it may not be honouring -Page/-PageSize. Stopping to avoid an unbounded loop." -Category LimitsExceeded -ErrorAction Stop
        }
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
