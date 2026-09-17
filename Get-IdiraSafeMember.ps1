[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[a-zA-Z0-9-]+$')]
    [string]$subDomain,
    
    [Parameter(Mandatory=$true)]
    [string]$CSVPath,

    [switch]$DryRun,

    [Parameter(HelpMessage = "Enable logging to file")]
    [switch]$log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$logFolder
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

$rootURI = [System.Uri]::new($pCloudBase, "PasswordVault/")

$headers = @{
    "Authorization" = "$($auth.token_type) $($auth.access_token)"
    "Content-Type"  = "application/json"
}

$auth = $null

$reportList = [System.Collections.Generic.List[psobject]]::new()

$URI = [System.Uri]::new($rootURI, "API/Safes/?limit=1000")
$AllSafes = Invoke-RestMethod -Uri $URI -Method "Get" -Headers $Headers

foreach ($safe in $AllSafes.value) {
    Write-Log "Processing Safe: $($safe.safeName) - $($safe.safeUrlId)" INFO
    $safeMemberDetails = $null
    
    $URIAllSafeMembers = [System.Uri]::new($rootURI,"API/Safes/$($safe.safeUrlId)/Members/?limit=1000")
    
    try {
        $safeMemberDetails = Invoke-RestMethod -Uri $URIAllSafeMembers -Method "Get" -Headers $Headers
    }
    catch {
        Write-Log "$_" ERROR
    }
    
    if ($null -ne $safeMemberDetails){
        foreach ($memberDetails in $safeMemberDetails.value) {
            Write-Log "- $($memberDetails.memberName) - $($memberDetails.memberType)" INFO
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