param(
    [Parameter(Mandatory=$true)]
    [string]$CSVPath,
 
    [Parameter(Mandatory=$true)]
    [string]$Username,
 
    [switch]$DryRun
)

# Tenants details
$ISPSSUrl = "https://aaq4162.id.cyberark.cloud" # Change me
$pCloudUrl = "https://cyberarch.privilegecloud.cyberark.cloud/PasswordVault" # Change me

# Prompt for password securely
$Password = Read-Host "Enter Password" -AsSecureString
$PlainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
)
 
# Log file
$LogFile = "C:\Temp\CyberArk_Delete_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
 
# Authenticate and get token
Write-Host "Authenticating to CyberArk..."
$AuthBody = @{
    grant_type = "client_credentials"
    client_id = $Username
    client_secret = $PlainPassword
}

$Headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
}

try {
    $AuthResponse = Invoke-RestMethod -Uri "$ISPSSUrl/oauth2/platformtoken" -Method POST -Body $AuthBody
    $Headers["Authorization"] = "Bearer $($AuthResponse.access_token)"
    $Headers["Content-Type"] = "application/json"
    Write-Host "Authentication successful."
} catch {
    Write-Error "Authentication failed: $_"
    exit
}
 
# Import CSV
if (-Not (Test-Path $CSVPath)) {
    Write-Error "CSV file not found: $CSVPath"
    exit
}

$Accounts = Import-Csv $CSVPath
 
# Process accounts
foreach ($Account in $Accounts) {
    $SafeName = $Account.SafeName
    $AccountID = $Account.AccountID.trim()
    $DeleteURL = "$pCloudUrl/Accounts/$AccountID"
 
    if ($DryRun) {
        Write-Host "[DRY-RUN] Would delete Account: $AccountID from Safe: $SafeName"
        Add-Content -Path $LogFile -Value "[DRY-RUN] $SafeName,$AccountID"
    } else {
        try {
            Invoke-RestMethod -Uri $DeleteURL -Method Delete -Headers $Headers
            Write-Host "Deleted Account: $AccountID from Safe: $SafeName"
            Add-Content -Path $LogFile -Value "Deleted: $SafeName,$AccountID"
        } catch {
            Write-Warning "Failed to delete Account: $AccountID from Safe: $SafeName - $_"
            Add-Content -Path $LogFile -Value "Failed: $SafeName,$AccountID"
        }
    }
}
 
# Logoff
#Invoke-RestMethod -Uri "$PVWAURL/api/Auth/Logoff" -Method POST -Headers $Headers
Write-Host "Session closed. Log file: $LogFile"