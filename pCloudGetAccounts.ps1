param(
    [Parameter(Mandatory=$true)]
    [string]$Username
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

function Connect-Identity {
    <#
    .SYNOPSIS
        Authenticates to CyberArk Identity using Client Credentials to obtain an OAuth2 token.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [string]$identityAddress,    
        [Parameter(Mandatory=$true)] [string]$userName,
        [Parameter(Mandatory=$true)] [securestring]$password
    )

    $connectionParam = @{
        Uri = $identityAddress
        Method = "POST" 
        Body = "grant_type=client_credentials&client_id=$username&client_secret=$(ConvertTo-PlainText $password)"
    }

    try {
        return Invoke-RestMethod @connectionParam
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
        [Parameter(Mandatory=$true)] [string]$pCloudAddress,    
        [Parameter(Mandatory=$true)] [string]$userName,
        [Parameter(Mandatory=$true)] [securestring]$password
    )

    try {
        
        $subDomain = ($pCloudAddress).Split('.')[0]
        $identityAddress = (Invoke-RestMethod -URI "https://$pCloudAddress/shell/api/endpoint/$subDomain" -Method GET).fqdn
        $identityTenantID = $identityAddress.split('.')[0]
        
        $startAuthenicationBody = @{
            TenantId = $identityTenantID
            Version = "1.0"
            User = $userName
        } | ConvertTo-Json

        $startAuthenicationHeaders = @{ "X-IDAP-NATIVE-CLIENT" = $true }
        
        $startAuthenication = Invoke-RestMethod -URI "https://$identityAddress/Security/StartAuthentication" -Method Post -Headers $startAuthenicationHeaders -Body $startAuthenicationBody

        foreach ($challenge in $startAuthenication.Result.Challenges) {
            foreach ($mechanism in $challenge.Mechanisms) {
                if ($mechanism.PromptSelectMech -eq "Password") {
                    $mechanismId = $mechanism.MechanismId
                    break
                }
            }
        }
        
        $advancedAuthenticationBody = @{
            TenantId = $identityTenantID
            SessionId = $startAuthenication.Result.SessionId
            MechanismId = $mechanismId
            Action = "Answer"
            Answer = ConvertTo-PlainText $password
        } | ConvertTo-Json

        $advancedAuthenication = Invoke-RestMethod -URI "https://$identityAddress/Security/AdvanceAuthentication" -Method Post -Body $advancedAuthenticationBody
        return [PSCustomObject]@{
            SubDomain = $subDomain
            Token     = $advancedAuthenication.Result.Token
        }
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
        [Parameter(Mandatory=$true)] [string]$PVWAAddress,
        [Parameter(Mandatory=$true)] [string]$search,
        [Parameter(Mandatory=$true)] [string]$accessToken,
        [bool]$SkipCertificateCheck = $false
    )

    $URI = "$PVWAAddress/API/Accounts$search&limit=1000"
    
    Write-Log "Status: Get-Account | $URI" DEBUG

    $headers = @{ "Authorization" = $accessToken }

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
                $URI = "$PVWAAddress/$($response.nextLink)"
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
        throw "Unexpected error from $($URI): $($_.Exception.Message) - $($_.ErrorDetails.Message)"
    }
    finally {
        if ($SkipCertificateCheck) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null }
    }
}

$ISPSSUrl = "https://aaq4162.id.cyberark.cloud" # Change me
$pCloudUrl = "https://cyberarch.privilegecloud.cyberark.cloud/PasswordVault" # Change me

# Prompt for password securely
$Password = Read-Host "Enter Password" -AsSecureString
$PlainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
)
 
# Log file
# $LogFile = "C:\Temp\CyberArk_Delete_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"


# Authenticate and get token
Write-Host "Authenticating to CyberArk..."
$AuthBody = @{
    grant_type = "client_credentials"
    client_id = $Username
    client_secret = $PlainPassword
}

$headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
}

try {
    $AuthResponse = Invoke-RestMethod -Uri "$ISPSSUrl/oauth2/platformtoken" -Method POST -Body $AuthBody
    $accessToken = "Bearer $($AuthResponse.access_token)"
    $headers["Authorization"] = "Bearer $($AuthResponse.access_token)"
    $headers["Content-Type"] = "application/json"
    Write-Host "Authentication successful."

} catch {
    Write-Error "Authentication failed: $_"
    exit
}

# Get Account
#Invoke-RestMethod -Uri "$pCloudUrl/API/Accounts" -Method "Get" -Headers $Headers

#Invoke-RestMethod -Uri "$pCloudUrl/api/Accounts/223_4" -Method Delete -Headers $Headers

$pCloudCommonParams = @{
    PVWAAddress = $pCloudUrl
    accessToken = $accessToken
}

$SafeName = "Giulio-Sync"
$LastRunTime = 0

$pCloudSearch = '?filter=safeName eq {0} AND secretModificationTime gte {1}' -f $SafeName, $LastRunTime
$pCloudAccounts = Get-Accounts @pCloudCommonParams -search $pCloudSearch

#foreach ($account in $pCloudAccounts.value){
#    Write-Host $account.name
#}
Write-Host "Accounts: $($pCloudAccounts.value.count)"
if ($null -ne $pCloudAccounts.nextLink) {
    Write-Host "NextLink: $($pCloudAccounts.nextLink)"
}
 
# Logoff
# Invoke-RestMethod -Uri "$pCloudUrl/api/Auth/Logoff" -Method POST -Headers $Headers
#Write-Host "Session closed. Log file: $LogFile"