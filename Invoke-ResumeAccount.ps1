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
    #$identityTenantID = $identityAddress.split('.')[0]

    try {
        $URI = "https://$identityAddress/oauth2/platformtoken"
        $Body = "grant_type=client_credentials&client_id=$username&client_secret=$([System.Net.NetworkCredential]::new('', $password).Password)"

        return Invoke-RestMethod -URI $URI -Method Post -Body $Body
    }
    catch {
        throw "Unexpected error from $($URI): $($_.Exception.Message) - $($_.ErrorDetails.Message)"
    }
}

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