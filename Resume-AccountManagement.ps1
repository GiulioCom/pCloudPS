<#
.SYNOPSIS
    Automates the detection and remediation of disabled Idira Privilege Cloud accounts.

.DESCRIPTION
    Resume-AccountManagement authenticates to a Idira tenant, retrieves 
    all accounts assigned to a specified Safe via paginated REST API calls, and inspects 
    their secret management state. 
    
    If an account's automatic secret management is disabled ($false) and its last modified 
    timestamp exceeds 90 days (calculated in Unix epoch seconds), the function issues a 
    PATCH request to re-enable automatic management.

.PARAMETER SubDomain
    The CyberArk tenant subdomain (e.g., 'tenant' for tenant.privilegecloud.cyberark.cloud).
    Must not be empty.

.PARAMETER Username
    The identity account executing the API requests. Requires administrative privileges 
    to query and update vault accounts.

.PARAMETER Safe
    The target Safe name to inspect. Automatically URL-encoded to prevent OData injection.

.EXAMPLE
    Resume-AccountManagement -SubDomain "company" -Username "api_admin" -SafeName "Linux-Servers-Safe" -Verbose

#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[a-zA-Z0-9-]+$')]
    [string]$subDomain,
    
    [Parameter(Mandatory=$true)]
    [string]$safe
)

function Connect-Identity {
    <#
    .SYNOPSIS
        Authenticates to CyberArk Identity using Client Credentials to obtain an OAuth2 token.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [string]$subDomain,    
        [Parameter(Mandatory=$true)] [string]$userName,
        [Parameter(Mandatory=$true)] [securestring]$password
    )

    $currentEndpoint = "https://$subDomain.cyberark.cloud/shell/api/endpoint/$subDomain"
    $identityAddress = (Invoke-RestMethod -URI $currentEndpoint -Method GET).fqdn

    try {
        $URI = "https://$identityAddress/oauth2/platformtoken"
        $Body = "grant_type=client_credentials&client_id=$username&client_secret=$([System.Net.NetworkCredential]::new('', $password).Password)"

        return Invoke-RestMethod -URI $URI -Method Post -Body $Body
    }
    catch {
        throw "Unexpected error from $($URI): $($_.Exception.Message) - $($_.ErrorDetails.Message)"
    }
}

function Get-Accounts {
    <#
    .SYNOPSIS
        Searches for accounts in the vault based on a query string and safe filter.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^https://')]
        [string]$rootURI,

        [Parameter(Mandatory=$true)]
        [hashtable]$headers,

        [string]$search,
        
        [string]$filter,

        [ValidateRange(1, 1000)]
        [int]$limit = 1000, 

        [bool]$SkipCertificateCheck = $false
    )

    $queryParameters = [System.Collections.Generic.List[string]]::new()
    
    if (-not [string]::IsNullOrWhiteSpace($search)) {
        $safeSearch = [uri]::EscapeDataString($search)
        $queryParameters.Add("search=$safeSearch")
    }
    
    if (-not [string]::IsNullOrWhiteSpace($filter)) {
        $safeFilter = [uri]::EscapeDataString($filter)
        $queryParameters.Add("filter=$safeFilter")
    }

    $queryParameters.Add("limit=$limit")

    $queryString = [string]::Join('&', $queryParameters)
    
    $URI = "$rootURI/Accounts?$queryString"

    Write-Verbose "Status: Get-Accounts | Initial URI: $URI"
    
    $allAccounts = [System.Collections.Generic.List[object]]::new()
    $totalCount = 0

    try {
        if ($SkipCertificateCheck) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }

        do {
            $response = Invoke-RestMethod -Uri $URI -Method GET -Headers $headers
                        
            if ($totalCount -eq 0 -and $null -ne $response.count) {
                $totalCount = $response.count
            }

            if ($null -ne $response.value) {
                $allAccounts.AddRange($response.value)
            }

            if (![string]::IsNullOrWhiteSpace($response.nextLink)) {
                $URI = "$rootURI/$($response.nextLink)"
                Write-Verbose "Fetching next page: $URI"
            } else {
                $URI = $null
            }

            } while ($URI)

            return [PSCustomObject]@{
                value = $allAccounts.ToArray()
                count = $totalCount
            }
        }
    catch {
        $errorMsg = if ($_.ErrorDetails) {
            $_.ErrorDetails.Message
        } else {
            $_.Exception.Message
        }
        throw "Unexpected error communicating with $($URI): $errorMsg"
    }
    finally {
        if ($SkipCertificateCheck) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null }
    }
}

# Prompt for password securely
$Password = Read-Host "Enter Password for $Username" -AsSecureString

Write-Host "Authenticating to Identity Tenant..." -ForegroundColor Green

$auth = Connect-Identity -subDomain $subDomain -userName $Username -password $Password

Write-Host "Authenticated to Identity Tenant..." -ForegroundColor Green

$Password.Dispose()
$Password = $null

$rootURI = "https://$subDomain.privilegecloud.cyberark.cloud/PasswordVault/API"

$headers = @{
    "Authorization" = "$($auth.token_type) $($auth.access_token)"
    "Content-Type"  = "application/json"
}

$auth = $null

# Get the current threshold for compliant account: current time -90 days
[long]$thresholdEpoch = [DateTimeOffset]::UtcNow.AddDays(-90).ToUnixTimeSeconds()

$accounts = Get-Accounts -rootURI $rootURI -headers $headers -filter "safeName eq $safe"

$enAccountBody = ConvertTo-Json -InputObject (,@{
    op    = "replace"
    path  = "/secretManagement/automaticManagementEnabled"
    value = $true
}) -Compress

$enAccountParms = @{
    Method  = 'Patch'
    Headers = $headers
    Body    = $enAccountBody    
}

foreach ($account in $accounts.value) {
    if ($account.secretManagement.automaticManagementEnabled -eq $false -and
        $account.secretManagement.lastModifiedTime -lt $thresholdEpoch){
        # Resume the account
        try {
            $enAccountParms.Uri = "$rootURI/Accounts/$($account.id)"
            $result = Invoke-RestMethod @enAccountParms
            Write-Verbose "Account $($result.name) successfully modified by $($result.lastModifiedBy)."
        }
        catch {
            Write-Error "Failed to modify account ID $($account.id). Reason: $_"
        }

    }
}