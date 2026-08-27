<#
.SYNOPSIS
    Aggregates and displays account compliance telemetry from report directories.
.DESCRIPTION
    Parses timestamped compliance reports chronologically, builds dynamic state timelines,
    calculates historical deltas, and streams human-readable console metrics.
.PARAMETER ReportDirectory
    Validated file-system path to the folder containing compliance CSV reports.
.PARAMETER TargetPlatform
    Platform ID filter constraint.
.PARAMETER PassThru
    Returns raw PSCustomObject telemetry to the pipeline instead of visual formatting.
.OUTPUTS
    Console formatted table OR [PSCustomObject] telemetry output.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$ReportDirectory,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9\-_]+$')]
    [string]$TargetPlatform = 'AD005-WIN-EPM-CA-21',

    [Switch]$PassThru
)

function Get-AccountComplianceMap {
    [CmdletBinding()]
    param([string]$Path, [string]$Platform)

    $resolvedPath = (Get-Item -LiteralPath $Path).FullName
    $accountMap = [System.Collections.Generic.Dictionary[string, hashtable]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $allReportDates = [System.Collections.Generic.List[datetime]]::new()

    $reportFiles = Get-ChildItem -LiteralPath $resolvedPath -Filter "InventoryReports.ComplianceReportUI_*.csv" |
        Where-Object { $_.Name -match '^InventoryReports\.ComplianceReportUI_(\d{4}-\d{2}-\d{2})' } |
        Select-Object FullName, @{ Name = 'ReportDate'; Expression = { [datetime]::Parse($Matches[1]) } } |
        Sort-Object ReportDate

    foreach ($file in $reportFiles) {
        $currentDate = $file.ReportDate
        $allReportDates.Add($currentDate)

        Import-Csv -LiteralPath $file.FullName | ForEach-Object {
            if ($Platform -and $_.'Platform ID' -ne $Platform) { return }

            $key = "$($_.'Target system user name')|$($_.'Target system address')|$($_.'Safe')|$($_.'Platform ID')"
            $isCompliant = $_.'Compliance status' -eq 'Compliant'

            $expDays = $null
            $rawExp  = $_.'Expiration period (days)'

            # Matches signed integers, zeroes, and floating-point values (e.g., -865, 0, 0.5)
            if (-not [string]::IsNullOrWhiteSpace($rawExp) -and $rawExp -match '(-?\d+(?:\.\d+)?)') {
                $expDays = [double]$Matches[1]
            }

            if (-not $accountMap.ContainsKey($key)) {
                $accountMap[$key] = @{
                    UserName       = $_.'Target system user name'
                    Address        = $_.'Target system address'
                    Safe           = $_.'Safe'
                    PlatformId     = $_.'Platform ID'
                    ExpirationDays = $expDays
                    FirstSeen      = $currentDate
                    History        = [System.Collections.Generic.Dictionary[datetime, hashtable]]::new()
                }
            } else {
                $accountMap[$key].ExpirationDays = $expDays
            }

            $accountMap[$key].History[$currentDate] = @{
                IsPresent   = $true
                IsCompliant = $isCompliant
            }
        }
    }

    foreach ($account in $accountMap.Values) {
        foreach ($date in $allReportDates) {
            if (-not $account.History.ContainsKey($date)) {
                $account.History[$date] = @{ IsPresent = $false; IsCompliant = $false }
            }
        }
    }

    return $accountMap
}

<#
.SYNOPSIS
    Processes historical account compliance maps to extract per-report telemetry.
.DESCRIPTION
    Iterates chronologically through report dates to compute total active accounts,
    compliance breakdowns, added/removed deltas, and compliance state transitions
    (Resolved and Regressed accounts).
.PARAMETER Map
    The populated generic dictionary containing account metadata and timeline histories.
.OUTPUTS
    [PSCustomObject] Aggregate telemetry containing total unique accounts and report metrics.
#>
function Measure-AccountTelemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.Dictionary[string, hashtable]]$Map
    )

    $totalAccounts = $Map.Count
    $reportDates = [System.Collections.Generic.List[datetime]]::new()

    if ($totalAccounts -gt 0) {
        foreach ($account in $Map.Values) {
            $reportDates.AddRange($account.History.Keys)
            break
        }
        $reportDates.Sort()
    }

    $reportSummaries = [System.Collections.Generic.List[PSCustomObject]]::new()

    for ($i = 0; $i -lt $reportDates.Count; $i++) {
        $currentDate  = $reportDates[$i]
        $previousDate = if ($i -gt 0) { $reportDates[$i - 1] } else { $null }

        # Metric accumulators for current report snapshot
        $present      = 0
        $compliant    = 0
        $nonCompliant = 0
        $added        = 0
        $removed      = 0
        $resolved     = 0
        $regressed    = 0

        foreach ($account in $Map.Values) {
            $history      = $account.History
            $currSnapshot = $history[$currentDate]

            if ($currSnapshot.IsPresent) {
                $present++
                
                if ($currSnapshot.IsCompliant) {
                    $compliant++
                } else {
                    $nonCompliant++
                }

                # Evaluate state transitions relative to the prior report
                if ($previousDate) {
                    $prevSnapshot = $history[$previousDate]

                    if (-not $prevSnapshot.IsPresent) {
                        # Account did not exist in prior report
                        $added++
                    } else {
                        # Account existed in prior report: check compliance status changes
                        if (-not $prevSnapshot.IsCompliant -and $currSnapshot.IsCompliant) {
                            # Transition: Non-Compliant -> Compliant
                            $resolved++
                        } elseif ($prevSnapshot.IsCompliant -and -not $currSnapshot.IsCompliant) {
                            # Transition: Compliant -> Non-Compliant
                            $regressed++
                        }
                    }
                }
            } else {
                # Account is absent in current report but was present in prior report
                if ($previousDate -and $history[$previousDate].IsPresent) {
                    $removed++
                }
            }
        }

        # Record aggregated snapshot telemetry
        $reportSummaries.Add([PSCustomObject]@{
            ReportDate           = $currentDate.ToString('yyyy-MM-dd')
            TotalActiveAccounts  = $present
            CompliantAccounts    = $compliant
            NonCompliantAccounts = $nonCompliant
            AccountsAdded        = $added
            AccountsRemoved      = $removed
            AccountsResolved     = $resolved
            AccountsRegressed    = $regressed
        })
    }

    return [PSCustomObject]@{
        TotalUniqueAccounts = $totalAccounts
        ReportSummaries     = $reportSummaries
    }
}

function Out-ComplianceConsole {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)][PSCustomObject]$Telemetry)

    process {
        $hdrColor = $PSStyle.Foreground.Cyan + $PSStyle.Bold
        $valColor = $PSStyle.Foreground.Yellow + $PSStyle.Bold
        $reset    = $PSStyle.Reset

        [Console]::WriteLine("${hdrColor}=======================================================${reset}")
        [Console]::WriteLine("${hdrColor} COMPLIANCE TRACKING TELEMETRY OVERVIEW${reset}")
        [Console]::WriteLine(" Total Unique Accounts Engine Tracked: ${valColor}$($Telemetry.TotalUniqueAccounts)${reset}")
        [Console]::WriteLine("${hdrColor}=======================================================${reset}`n")

        $Telemetry.ReportSummaries | Format-Table -Property `
            @{ Label = 'Report Date';   Expression = { $_.ReportDate };           Width = 13 },
            @{ Label = 'Active';        Expression = { $_.TotalActiveAccounts };  Width = 10 },
            @{ Label = 'Compliant';     Expression = { $_.CompliantAccounts };    Width = 11 },
            @{ Label = 'Non-Compliant'; Expression = { $_.NonCompliantAccounts }; Width = 15 },
            @{ Label = 'Added';         Expression = { $_.AccountsAdded };        Width = 11 },
            @{ Label = 'Removed';       Expression = { $_.AccountsRemoved };      Width = 11 },
            @{ Label = 'Resolved';      Expression = { $_.AccountsResolved };     Width = 11 },
            @{ Label = 'Regressed';     Expression = { $_.AccountsRegressed };    Width = 11 }

    }
}

# Execution Controller Sequence
$mapData = Get-AccountComplianceMap -Path $ReportDirectory -Platform $TargetPlatform
$telemetryData = Measure-AccountTelemetry -Map $mapData

if ($PassThru) {
    return $telemetryData
} else {
    $telemetryData | Out-ComplianceConsole
}