param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[a-zA-Z0-9-]+$')]
    [string]$subDomain
)

function Write-Log {
    <#
    .SYNOPSIS
        Outputs a formatted log message to the console and a file.
    #>
    param (
        [Parameter(Mandatory = $true)] [string]$message,
        [Parameter(Mandatory = $true)] [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")] [string]$severity,
        [ConsoleColor]$ForegroundColor
    )

    if ($severity -eq "DEBUG" -and -not $Debug) { return }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$($severity.PadRight(5))] $message"

    if (-not $PSBoundParameters.ContainsKey('ForegroundColor')) {
        $ForegroundColor = switch ($Severity) {
            "INFO"  { "Green" }
            "WARN"  { "Yellow" }
            "ERROR" { "Red" }
            "DEBUG" { "Gray" }
        }
    }

    Write-Host $logMessage -ForegroundColor $ForegroundColor

    if ($LogPath) {
        Add-Content -Path $LogPath -Value $logMessage
    }
}

function Protect-CsvField {
    param([object]$Value)

    if ($null -eq $Value) { return $null }
    $str = [string]$Value
    if ($str -match '^[=+\-@\t\r]') {
        return "'$str" # Prepend single quote to neutralize executable formulas in Excel
    }
    return $Value
}

function Connect-Identity {
    <#
    .SYNOPSIS
        Authenticates to CyberArk Identity using Client Credentials to obtain an OAuth2 token.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[a-zA-Z0-9-]+$')]
        [string]$subDomain,    
        
        [Parameter(Mandatory=$true)]
        [string]$userName,
        
        [Parameter(Mandatory=$true)]
        [securestring]$password
    )

    $currentEndpoint = [System.Uri]::new("https://$subDomain.cyberark.cloud/shell/api/endpoint/$subDomain")
    Write-Verbose "Status: Connect-Identity | currentEndpoint: $currentEndpoint"
    $identityAddress = (Invoke-RestMethod -URI $currentEndpoint -Method GET).fqdn
    Write-Verbose "Status: Connect-Identity | identityAddress: $identityAddress"

    try {
        $URI = [System.Uri]::new("https://$identityAddress/oauth2/platformtoken")
        Write-Verbose "Status: Connect-Identity | URI: $URI"
        $Body = "grant_type=client_credentials&client_id=$username&client_secret=$([System.Net.NetworkCredential]::new('', $password).Password)"

        Invoke-RestMethod -URI $URI -Method Post -Body $Body

    }
    catch {
        throw "Unexpected error from $($URI): $($_.Exception.Message) - $($_.ErrorDetails.Message)"
    }
}

function Get-Accounts {
<#
.SYNOPSIS
    Defines validated parameters for REST API query operations.
.DESCRIPTION
    Accepts endpoint URIs, request headers, pagination offsets, and CyberArk filter parameters.
    Ensures strict type binding, input validation, and scheme enforcement before execution.
.PARAMETER RootUri
    Target HTTPS endpoint URI for the API call.
.PARAMETER Headers
    Hashtable containing HTTP request headers.
.PARAMETER Search
    Optional search term to filter results.
.PARAMETER SearchType
    Search matching mode ('contains' or 'startswith'). Defaults to 'contains'.
.PARAMETER Sort
    Sort direction ('asc' or 'desc'). Defaults to 'asc'.
.PARAMETER Offset
    Zero-based index offset for pagination. Must be non-negative.
.PARAMETER Limit
    Maximum records to fetch per request (1 to 1000). Defaults to 1000.
.PARAMETER Filter
    Custom search filter string.
.PARAMETER SavedFilter
    Predefined filter state category.
.PARAMETER SkipCertificateCheck
    Disables SSL/TLS certificate validation. USE ONLY IN ISOLATED LAB/TESTING ENVIRONMENTS.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ $_.Scheme -eq 'https' })]
        [System.Uri]$RootUri,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [hashtable]$Headers,

        [string]$Search,
        
        [ValidateSet('contains','startswith')]
        [string]$SearchType = 'contains',
        
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Offset = 0,

        [ValidateRange(1, 1000)]
        [int]$limit = 1000, 

        [string]$filter,

        [ValidateSet('Regular','Recently','New','Link','Deleted','PolicyFailures','AccessedByUsers','ModifiedByUsers','ModifiedByCPM','DisabledPasswordByUser','DisabledPasswordByCPM','ScheduledForChange','ScheduledForVerify','ScheduledForReconcile','SuccessfullyReconciled','FailedChange','FailedVerify','FailedReconcile','LockedOrNew','Locked','Favorites','DeleteInsightStatus')]
        [string]$SavedFilter,

        [switch]$SkipCertificateCheck
    )

    # Preparing the URL 

    $searchList = [System.Collections.Generic.List[string]]::new()

    if (-not [string]::IsNullOrWhiteSpace($Search)) {
        $searchList.Add("search=$([System.Uri]::EscapeDataString($Search))")
    }

    if (-not [string]::IsNullOrWhiteSpace($Filter)) {
        $searchList.Add("filter=$([System.Uri]::EscapeDataString($Filter))")
    }

    if (-not [string]::IsNullOrWhiteSpace($SearchType)) {
        $searchList.Add("searchType=$SearchType")
    }

    if (-not [string]::IsNullOrWhiteSpace($SavedFilter)) {
        $searchList.Add("savedfilter=$SavedFilter")
    }

    $searchQuery = if ($searchList.Count -gt 0) { 
        [string]::Join('&', $searchList) 
    } else { 
        [string]::Empty 
    }

<#
    $paginationList = [System.Collections.Generic.List[string]]::new()
    $paginationList.Add("offset=$Offset")
    $paginationList.Add("limit=$Limit")
    $paginationQuery = [string]::Join('&', $paginationList)


    $fullQuery = if (-not [string]::IsNullOrWhiteSpace($searchQuery)) {
        "$paginationQuery&$searchQuery"
    } else {
        $paginationQuery
    }
#>
<#
    $baseEndpoint = [System.Uri]::new($RootUri, 'API/Accounts')
    $uriBuilder   = [System.UriBuilder]::new($baseEndpoint)
    $uriBuilder.Query = $fullQuery    
    
    $URI = $uriBuilder.Uri
#>
    $allAccounts = [System.Collections.Generic.List[object]]::new()
    #$totalCount = 0

    $hasMorePages = $true
    $nextUri = $null

#    try {
        
        do {
            # Determine request URI based on pagination state
            if ($null -eq $nextUri) {
                # Construct initial or manual offset request
                $pageQuery = "offset=$offset&limit=$Limit"
                $fullQuery = if ($searchQuery) { 
                        "$pageQuery&$searchQuery"
                    } else { 
                        $pageQuery 
                    }

                $baseEndpoint = [System.Uri]::new($RootUri, 'API/Accounts')
                $uriBuilder = [System.UriBuilder]::new($baseEndpoint)
                $uriBuilder.Query = $fullQuery
                $targetUri = $uriBuilder.Uri
            }
            else {
                $targetUri = $nextUri
            }

            try {
                if ($SkipCertificateCheck.IsPresent) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
                Write-Verbose "Status: Get-Accounts | URI: $targetUri"
                $response = Invoke-RestMethod -Uri $targetUri -Headers $Headers -Method Get
            }
            catch {
                $errorMsg = if ($_.ErrorDetails) {
                        $_.ErrorDetails.Message
                    } else {
                        $_.Exception.Message
                    }
                throw "Unexpected error communicating with $($targetUri): $errorMsg"
            }
            finally {
                if ($SkipCertificateCheck.IsPresent) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null }
            }
            

            $items = $response.value
            $itemCount = if ($null -ne $items) { $items.Count } else { 0 }

            if ($itemCount -gt 0) {
                $allAccounts.AddRange([object[]]$items)
                #$items | ForEach-Object { $_ }
                #$totalStreamed += $itemCount
            }

            # 3. Dynamic API Bug Recovery Logic
            if (-not [string]::IsNullOrWhiteSpace($response.nextLink)) {
                # CASE 1 & 2: API provided nextLink. Check if search query was stripped.
                $cleanNext  = $response.nextLink.TrimStart('/')
                $parsedNext = [System.Uri]::new($RootUri, $cleanNext)
                $builder    = [System.UriBuilder]::new($parsedNext)
                $existingQ  = $builder.Query.TrimStart('?')

                # If search criteria exist but are missing from nextLink, re-inject them
                if ($searchQuery -and ($existingQ -notmatch '(search|filter|savedfilter)=')) {
                    $builder.Query = if ($existingQ) { "$existingQ&$searchQuery" } else { $searchQuery }
                }

                $nextUri = $builder.Uri
                $offset += $itemCount
            }
            elseif ($itemCount -eq $Limit) {
                # CASE 3: API bug omitted nextLink entirely, but record count matches page limit.
                # Force manual offset iteration.
                $offset += $Limit
                $nextUri = $null # Triggers manual URI construction on next iteration
            }
            else {
                # Reached end of dataset (itemCount < Limit and no nextLink)
                $hasMorePages = $false
            }

            # Break loop if 0 records returned on a manual page check
            if ($itemCount -eq 0) {
                $hasMorePages = $false
            }

        } while ($hasMorePages)


<#
        do {
            Write-Verbose "Status: Get-Accounts | URI: $URI"
            $response = Invoke-RestMethod -Uri $URI -Method GET -Headers $headers
                        
            if ($totalCount -eq 0 -and $null -ne $response.count) {
                $totalCount = $response.count
                Write-Verbose "Status: Get-Accounts | Retrieving $totalCount accounts"
            }

            if ($null -ne $response.value) {
                $allAccounts.AddRange($response.value)
            }

            if (-not [string]::IsNullOrWhiteSpace($response.nextLink)) {
                
                $nextBaseUri = [System.Uri]::new($RootUri, $response.nextLink)
                $builder = [System.UriBuilder]::new($nextBaseUri)

                $existingQuery = $builder.Query.TrimStart('?')

                if ([string]::IsNullOrWhiteSpace($existingQuery)) {
                    $builder.Query = $SearchQuery
                } else {
                    $builder.Query = "$existingQuery&$SearchQuery"
                }

                $URI = $builder.Uri
            #    Write-Verbose "Fetching next page: $URI"
            }

        } while ($null -ne $URI)
#>
        [PSCustomObject]@{
            value = $allAccounts.ToArray()
            count = $allAccounts.Count
        }
    }
#    catch {
#        $errorMsg = if ($_.ErrorDetails) {
#            $_.ErrorDetails.Message
#        } else {
#            $_.Exception.Message
#        }
#        throw "Unexpected error communicating with $($URI): $errorMsg"
#    }
#    finally {
#        if ($SkipCertificateCheck.IsPresent) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null }
#    }
#}

$pCloudBase = [System.Uri]::new("https://$subDomain.privilegecloud.cyberark.cloud")

Write-Host "Authenticating to $($pCloudBase.AbsoluteUri)..." -ForegroundColor Green

$Password = Read-Host "Enter Password for $Username" -AsSecureString

$auth = Connect-Identity -subDomain $subDomain -userName $Username -password $Password

$Password.Dispose()
$Password = $null

$rootURI = [System.Uri]::new($pCloudBase, "PasswordVault/")

$headers = @{
    "Authorization" = "$($auth.token_type) $($auth.access_token)"
    "Content-Type"  = "application/json"
}

$auth = $null

#$retAccounts = Get-Accounts -rootURI $rootURI -headers $headers -SavedFilter DeleteInsightStatus
$retAccounts = Get-Accounts -rootURI $rootURI -headers $headers -SavedFilter DisabledPasswordByUser

# Ensure payload structure matches expected contract
if (-not $retAccounts.PSObject.Properties.Match('value').Count) {
    throw "Input payload does not contain a top-level 'value' array property."
}

# Stream processing pipeline: Constant O(1) memory overhead
$retAccounts.value | ForEach-Object {
    $item = $_
    $sec  = $item.secretManagement

    [PSCustomObject]@{
        categoryModificationTime   = Protect-CsvField $item.categoryModificationTime
        platformId                 = Protect-CsvField $item.platformId
        safeName                   = Protect-CsvField $item.safeName
        deleteInsightStatus        = Protect-CsvField $item.deleteInsightStatus
        lastModifiedBy             = Protect-CsvField $item.lastModifiedBy
        id                         = Protect-CsvField $item.id
        name                       = Protect-CsvField $item.name
        address                    = Protect-CsvField $item.address
        userName                   = Protect-CsvField $item.userName
        secretType                 = Protect-CsvField $item.secretType
        automaticManagementEnabled = Protect-CsvField $sec.automaticManagementEnabled
        manualManagementReason     = Protect-CsvField $sec.manualManagementReason
        lastModifiedTime           = Protect-CsvField $sec.lastModifiedTime
        createdTime                = Protect-CsvField $item.createdTime
    }
} | Export-Csv -LiteralPath "temp\disabled-accounts.csv" -NoTypeInformation -Encoding utf8