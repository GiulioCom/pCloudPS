[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Username
)

$ISPSSUrl = "https://aaq4162.id.cyberark.cloud" # Change me
$pCloudUrl = "https://cyberarch.privilegecloud.cyberark.cloud" # Change me
$outputPath = "SafeMembers.csv"

# Prompt for password securely
$Password = Read-Host "Enter Password" -AsSecureString
$PlainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
)
 
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
    $headers["Authorization"] = "Bearer $($AuthResponse.access_token)"
    $headers["Content-Type"] = "application/json"
    Write-Host "Authentication successful."

} catch {
    Write-Error "Authentication failed: $_"
    exit
}

$reportList = [System.Collections.Generic.List[psobject]]::new()

$AllSafes = Invoke-RestMethod -Uri "$pCloudUrl/PasswordVault/API/Safes/?limit=1000" -Method "Get" -Headers $Headers

foreach ($safe in $AllSafes.value) {
    Write-Host "Processing Safe: $($safe.safeName) - $($safe.safeUrlId)"
    $safeMemberDetails = $null
    
    $URIAllSafeMembers = "{0}/PasswordVault/API/Safes/{1}/Members/?limit=1000" -f $pCloudUrl, $safe.safeUrlId
    
    try {
        $safeMemberDetails = Invoke-RestMethod -Uri $URIAllSafeMembers -Method "Get" -Headers $Headers
    }
    catch {
        Write-Error "$_"
    }
    
    if ($null -ne $safeMemberDetails){
        foreach ($memberDetails in $safeMemberDetails.value) {
            Write-Host "- $($memberDetails.memberName) - $($memberDetails.memberType)"
        }
        
        $safeMemberDetails.value | ForEach-Object {
            $row = [ordered]@{
                SafeName         = $_.safeName
                SafeNumber       = $_.safeNumber
                UserId           = $_.memberId
                UserName         = $_.memberName
                UserType         = $_.memberType
                IsPredefinedUser = $_.isPredefinedUser
            }

            if ($member.permissions) {
                foreach ($prop in $member.permissions.PSObject.Properties) {
                    $row["$($prop.Name)"] = $prop.Value
                }
            }

            $reportList.Add([PSCustomObject]$row)
        } 
    }
}


$reportList | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
