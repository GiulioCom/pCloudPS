<#
.SYNOPSIS
    Parses CyberArk CPM log files for postponed account tasks and re-enables automatic management via the Privilege Cloud REST API.

.DESCRIPTION
    Scans a CyberArk Central Policy Manager (CPM) error log (such as pm_error.log) line-by-line
    for CACPM725I failure events indicating an account has been postponed. 
    
    The script streams the log from disk, deduplicates Safe and Object pairs using an internal case-insensitive hash set,
    authenticates to the Idira Identity/Privilege Cloud REST API, and toggles 'automaticManagementEnabled' 
    back to $true.

.PARAMETER Username
    The API username used with the related privilige to enable accounts on the destination Safeto acquire a bearer session token from the 

.PARAMETER SubDomain
    The unique tenant subdomain prefix for CyberArk Privilege Cloud 
    (e.g., 'mycompany' in https://mycompany.privilegecloud.cyberark.cloud). 
    Validated strictly against alphanumeric characters and hyphens.

.PARAMETER CpmLogPath
    The fully qualified or relative file system path to the target CPM log file. 
    Validated with -LiteralPath to prevent character injection or wildcard expansion issues 
    with paths containing parentheses or square brackets.

.PARAMETER Log
    Switch parameter. When present, enables structured audit output to an external log file.

.PARAMETER LogFolder
    The directory where audit logs will be written when -Log is specified. 
    Defaults to the current working directory. Validated for directory path existence.

.EXAMPLE
    PS C:\> .\Resume-CpmPostponedAccount.ps1 -Username 'abcss@corp' -SubDomain 'acme-corp' -CpmLogPath 'C:\CPM\Logs\pm_error.log' -Log
#>
param (
    [Parameter(Mandatory=$true, HelpMessage = "Privilege Cloud API username.")]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter(Mandatory=$true, HelpMessage = "Privilege Cloud tenant subdomain prefix (alphanumeric and hyphens only).")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9-]+$')]
    [string]$SubDomain,
    
    [Parameter(Mandatory = $true, HelpMessage = "Path to the CyberArk CPM error log file (e.g., pm_error.log).")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
            throw "The specified CPM log file does not exist or is not a readable file: '$_'"
        }
        $true
    })]
    [string]$CpmLogPath,

    [Parameter(HelpMessage = "Enable logging to file")]
    [switch]$Log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$LogFolder    
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

    if ($severity -eq "DEBUG" -and -not $ShowDebug) { return }

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

    if ($script:EnableLogging) {
        [System.IO.File]::AppendAllText($script:LogFilePath, "$logMessage`r`n")
    }
}
function Write-Box {
    <#
    .SYNOPSIS
        Displays a centered title within a fixed 42-character decorative box.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({$_.Length -le 38})]
        [string]$title
    )

    $totalWidth = 42
    $contentWidth = $totalWidth - 2
    
    # Calculate padding for centering
    $leftPadding  = [Math]::Floor(($contentWidth - $title.Length) / 2)
    $rightPadding = $contentWidth - $title.Length - $leftPadding
    
    # Construct lines
    $horizontalLine = "+" + ("-" * ($totalWidth - 2)) + "+"
    $centeredText   = "|" + (" " * $leftPadding) + $title + (" " * $rightPadding) + "|"

    $textProp = @{
        "Severity"        = "INFO"
        "ForegroundColor" = "Cyan"
    }
    
    $textProp = @{
        "Severity" = "INFO"
        "ForegroundColor" = "Cyan"
    }

    Write-Log $horizontalLine @textProp
    Write-Log $centeredText   @textProp
    Write-Log $horizontalLine @textProp
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

        [string]$Filter,

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

    $allAccounts = [System.Collections.Generic.List[object]]::new()

    $hasMorePages = $true
    $nextUri = $null

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

    [PSCustomObject]@{
        value = $allAccounts.ToArray()
        count = $allAccounts.Count
    }
}

function Resume-IdiraAccount {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ $_.Scheme -eq 'https' })]
        [System.Uri]$Uri,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [hashtable]$Headers,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Safe,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Object

    )
    
    $SearchAccountPattern = "(?:^.*$Safe-|^[^-]+-)(?<Target>.+)-SHSAdmin$"

    $enAccountBody = ConvertTo-Json -InputObject (,@{
        op    = "replace"
        path  = "/secretManagement/automaticManagementEnabled"
        value = $true
    }) -Compress
    
    $EndpointAddress = $null

    if ($Object -match $SearchAccountPattern) {
        $EndpointAddress = $Matches['Target']
    } else {
        Write-Log "Objcat name '$Object' can't extract address using regex '$SearchAccountPattern'."
        return
    }
    
    $accounts = Get-Accounts -rootURI $Uri -headers $Headers -filter "safeName eq $Safe" -Search "$EndpointAddress"

    if ($accounts.value.count -ne 1) {
        Write-Log "Found $($accounts.value.count) accounts, can't proceed with 0 or multiple account" WARN
        return
    }

    foreach ($account in $accounts.value) {
        if ($account.secretManagement.automaticManagementEnabled -eq $false){
        # Resume the account
            try {
                $ResumeUri = [System.Uri]::new($Uri, "API/Accounts/$($account.id)")
                $result = Invoke-RestMethod -Uri $ResumeUri -Method Patch -Headers $Headers -Body $enAccountBody
                Write-Log "Account '$($result.name)' successfully modified by '$($result.lastModifiedBy)'." INFO
            }
            catch {
                Write-Log "Failed to resume the account '$($account.name)' - '$($account.Id)'. Details: $($_.Exception.Message)" ERROR
            }
        } else {
            Write-Log "Account '$($account.name)' is Active, Resume not needed." WARN
        }

    }
}

$ResolvedPath = (Resolve-Path -LiteralPath $CpmLogPath).ProviderPath

### Begin Script ###

## Prepare log folder and file
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)

$script:EnableLogging = $Log.IsPresent
$script:LogFilePath   = $null

if ($script:EnableLogging) {
    if (-not $PSBoundParameters.ContainsKey('logFolder')) {
        # Default to a 'log' folder in the same directory as the script
        $LogFolder = Join-Path -Path $PSScriptRoot -ChildPath "log"
    }

    # Ensure the log folder exists
if (-not (Test-Path -Path $LogFolder -PathType Container)) {
        [void](New-Item -Path $LogFolder -ItemType Directory -Force)
    }

    # Create log file name based on timestamp and script name
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFileName = "${timestamp}_${scriptName}.log"
    
    $script:LogFilePath = Join-Path -Path $LogFolder -ChildPath $logFileName

    Write-Log "Logging enabled. Log file: $($script:LogFilePath)" INFO
}
## Log file done

Write-Box "$scriptName"	

$pCloudBase = [System.Uri]::new("https://$subDomain.privilegecloud.cyberark.cloud")

Write-Host "Authenticating to $($pCloudBase.AbsoluteUri)..." -ForegroundColor Green

$Password = Read-Host "Enter Password for $Username" -AsSecureString

$auth = Connect-Identity -subDomain $subDomain -userName $Username -password $Password

$Password.Dispose()
$Password = $null

$PvwaUri = [System.Uri]::new($pCloudBase, "PasswordVault/")

$Headers = @{
    "Authorization" = "$($auth.token_type) $($auth.access_token)"
    "Content-Type"  = "application/json"
}

$auth = $null

# End of Auth and clean sensitive data

$Pattern = 'CACPM725I[^(]*\(Safe:\s*(?<Safe>[^,]+),\s*Folder:\s*[^,]+,\s*Object:\s*(?<Object>[^)]+)\)\s+failed\b'

$SeenPairs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

switch -Regex -File $ResolvedPath {
    $Pattern {
        $Safe   = $Matches['Safe'].Trim()
        $Object = $Matches['Object'].Trim()
        $DeduplicationKey = "$Safe`t$Object"

        # HashSet.Add returns $false if the key already exists
        if ($SeenPairs.Add($DeduplicationKey)) {
            Write-Log "Resuming '$Object' from Safe '$Safe'" INFO
            Resume-IdiraAccount -Uri $PvwaUri -Headers $Headers -Safe $Safe -Object $Object
        }
    }
}