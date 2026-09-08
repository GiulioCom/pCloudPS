param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[a-zA-Z0-9-]+$')]
    [string]$subDomain,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("Change", "Verify", "Reconcile", "Resume", "Unlock", "Delete")]
    [string]$action,

    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$InventoryReport
)

function Connect-IdentitySecure {
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
        [ValidateNotNullOrEmpty()]
        [string]$userName,

        [Parameter(Mandatory=$true)]
        [securestring]$password
    )

    try {
        
        $currentEndpoint = "https://$subDomain.cyberark.cloud/shell/api/endpoint/$subDomain"
        $identityAddress = (Invoke-RestMethod -URI $currentEndpoint -Method GET).fqdn
        $identityTenantID = $identityAddress.split('.')[0]
        
        
        $currentEndpoint = "https://$identityAddress/Security/StartAuthentication"
        $startAuthBody = ConvertTo-Json -InputObject @{
            TenantId = $identityTenantID
            Version = "1.0"
            User = $userName
        } -Compress

        $startAuthHeaders = @{ "X-IDAP-NATIVE-CLIENT" = $true }
        
        $startAuthResponse = Invoke-RestMethod -URI $currentEndpoint -Method Post -Headers $startAuthHeaders -Body $startAuthBody

        $mechanismId = $null
        foreach ($challenge in $startAuthResponse.Result.Challenges) {
            foreach ($mechanism in $challenge.Mechanisms) {
                if ($mechanism.PromptSelectMech -eq "Password") {
                    $mechanismId = $mechanism.MechanismId
                    break
                }
            }
            if ($mechanismId) { break }
        }
        
        if (-not $mechanismId) {
            throw "Password mechanism not found."
        }

        $currentEndpoint = "https://$identityAddress/Security/AdvanceAuthentication"
        $plainTextPassword = [System.Net.NetworkCredential]::new('', $password).Password
        
        $advAuthBody = ConvertTo-Json -InputObject @{
            TenantId = $identityTenantID
            SessionId = $startAuth.Result.SessionId
            MechanismId = $mechanismId
            Action = "Answer"
            Answer = $plainTextPassword
        } -Compress

        $advAuthResponse = Invoke-RestMethod -URI $currentEndpoint -Method Post -Body $advAuthBody
        return $advAuthResponse.Result.Token

    }
    catch {
        $errorMsg = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw "Authentication failed at $currentEndpoint : $errorMsg"
    }
    finally {
        if ($null -ne $plainTextPassword) {
            $plainTextPassword = $null
            $advAuthBody = $null
            [System.GC]::Collect()
        }
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

        [Parameter(Mandatory=$true)]
        [string]$search,

        [ValidateRange(1, 1000)]
        [int]$limit = 1000, 

        [bool]$SkipCertificateCheck = $false
    )

    Write-Verbose "Status: Get-Accounts | Initial URI: $currentURI"

    $safeSearch = [uri]::EscapeDataString($search)
    $URI = "$rootURI/Accounts?search=$safeSearch&limit=$limit"
    
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
                Write-Verbose "Fetching next page: $currentURI"
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
        $errorMsg = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        throw "Unexpected error communicating with $($currentURI): $errorMsg"
    }
    finally {
        if ($SkipCertificateCheck) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null }
    }
}

function Send-BulkActions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^https://')]
        [string]$rootURI,

        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Change", "Verify", "Reconcile", "Resume", "Unlock", "Delete")]
        [string]$action,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.Collections.Generic.List[string]]$IdList
    )

    $targetEndpoint = "$rootURI/accounts/$action/bulk"
    
    $body = ConvertTo-Json -InputObject @{
        accountIds              = $IdList.ToArray()
        deleteOnlyPrivateSshKey = $false
    } -Compress
    
    try {
        $response = Invoke-RestMethod -Uri $targetEndpoint -Method 'POST' -Headers $Headers -Body $body -ErrorAction Stop
        Write-Verbose "Batch successful."
    }
    catch {
        throw "Failed to process batch at $targetEndpoint. Error: $_"
    }
}

# Prompt for password securely
$Password = Read-Host "Enter Password for $Username" -AsSecureString

Write-Output "Authenticating to Identity Tenant..."

$auth = Connect-IdentitySecure -subDomain $subDomain -userName $Username -password $Password

Write-Output "Authenticated to Identity Tenant..."

$Password.Dispose()
$Password = $null

$rootURI = "https://$subDomain.privilegecloud.cyberark.cloud/api"

$headers = @{
    "Authorization" = "Bearer $auth"
    "Content-Type"  = "application/json"
}

$auth = $null

$batchLimit = 10000
$batchList = [System.Collections.Generic.List[string]]::new($batchLimit)
$validIdPattern = '^[a-zA-Z0-9_-]+$'

Write-Output "Processing inventory report: $InventoryReport"
Import-Csv -Path $InventoryReport | ForEach-Object {
    $accountId = $_.'Account ID'

    if ($accountId -match $validIdPattern) {
        $batchList.Add($accountId)
    }
    else {
        Write-Warning "Invalid Account ID skipped: $accountId"
    }

    if ($batchList.Count -eq $batchLimit) {
        Send-BulkActions -rootURI $rootURI -Headers $headers -action $action -IdList $batchList
        $batchList.Clear()
    }
}

if ($batchList.Count -gt 0) {
    Send-BulkActions -rootURI $rootURI -Headers $headers -action $action -IdList $batchList
    $batchList.Clear()
}

Write-Output "Bulk operations completed successfully."
