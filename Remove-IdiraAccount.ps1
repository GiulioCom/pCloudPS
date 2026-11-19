<#
.SYNOPSIS
    Streams account records from a CSV file and removes them from Palo Alto Networks Idira Privilege Cloud.

.DESCRIPTION
    Reads a target account CSV inventory line-by-line through the PowerShell pipeline to maintain 
    a constant, low memory footprint across large datasets. Resolves the tenant CyberArk Identity 
    endpoint via Platform Discovery, authenticates to retrieve a Bearer token, and reuses a 
    single WebRequestSession to execute REST API DELETE operations against Privilege Cloud.

    Implements SupportsShouldProcess with ConfirmImpact = 'High'. By default, the script prompts 
    for interactive confirmation before deleting accounts, supports non-destructive simulation 
    via -WhatIf, and allows unattended automation via -Confirm:$false. Optional file logging 
    captures audit evidence and execution events.

.PARAMETER Username
    Specifies the administrative account or operator identity used to authenticate 
    against the CyberArk Identity endpoint to obtain a Bearer token.

.PARAMETER subDomain
    Specifies the customer tenant subdomain (e.g., "corp-prod" for 
    https://corp-prod.privilegecloud.cyberark.cloud). Validated strictly against 
    RFC DNS label syntax (1-63 alphanumeric characters and internal hyphens only).

.PARAMETER CsvFilePath
    Specifies the literal file system path to the source CSV file containing the target 
    account records ('id', 'name', 'SafeName'). A ValidateScript block verifies that the 
    path exists and points to a readable leaf file.

.PARAMETER log
    Switch parameter. Enables output logging to a timestamped file on disk for compliance 
    and operational tracking.

.PARAMETER logFolder
    Specifies the target directory where execution logs will be written when -log is 
    active. If omitted while -log is specified, the script defaults to the current working directory.

.INPUTS
    None. You cannot pipe objects directly to this script.

.OUTPUTS
    None. Execution status and audit events are written to the console and optional log file.

.EXAMPLE
    # Example 1: Dry-Run Simulation (-WhatIf)
    # Previews every account deletion target without sending any DELETE requests to Privilege Cloud.
    .\Remove-IdiraAccount.ps1 -Username "svc-pam-admin" -subDomain "corp-prod" -CsvFilePath "C:\Reports\20261119_Accounts.csv" -WhatIf

.EXAMPLE
    # Example 2: Interactive Execution (Default High-Impact Confirmation)
    # Automatically prompts [Y] Yes / [A] Yes to All / [N] No before deleting accounts because ConfirmImpact is set to High.
    .\Remove-IdiraAccount.ps1 -Username "svc-pam-admin" -subDomain "corp-prod" -CsvFilePath "C:\Reports\20261119_Accounts.csv"

.EXAMPLE
    # Example 3: Unattended Automation (-Confirm:$false)
    # Suppresses interactive confirmation prompts for scheduled tasks or CI/CD pipelines.
    .\Remove-IdiraAccount.ps1 -Username "svc-pam-admin" -subDomain "corp-prod" -CsvFilePath "C:\Reports\20261119_Accounts.csv" -Confirm:$false

.NOTES
    Author:       Giulio Compagnone
    Email:        gcompagnone@paloaltonetworks.com
    Company:      Palo Alto Networks
    Version:      1.0.0
    Created:      2026-11-19

    DISCLAIMER:
    This script is provided solely for demonstration and educational purposes ("AS-IS").
    Any application in a staging or production environment must be thoroughly tested and 
    validated prior to deployment. Neither the author nor the company assumes any liability 
    or responsibility for service disruption, data loss, unrecoverable account deletion, 
    or unintended operational consequences resulting from the execution of this code.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [ValidatePattern('\A[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z')]
    [string]$subDomain,
    
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
            throw "CSV file not found at literal path: '$_'."
        }
        $true
    })]    
    [string]$CsvFilePath,

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
    param (
        [Parameter(Mandatory=$true)]
        [ValidatePattern('\A[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z')]
        [string]$subDomain,    
        
        [Parameter(Mandatory=$true)]
        [string]$userName,
        
        [Parameter(Mandatory=$true)]
        [securestring]$password
    )

    try {
        $IdentityUri = (Invoke-RestMethod -URI "https://platform-discovery.cyberark.cloud/api/identity-endpoint/$subDomain" -Method GET).endpoint
    }
    catch {
        throw "Identity Discovery error: $($_.Exception.Message) - $($_.ErrorDetails.Message)"
    }

    try {
        $Body = "grant_type=client_credentials&client_id=$username&client_secret=$([System.Net.NetworkCredential]::new('', $password).Password)"
        Invoke-RestMethod -URI "$IdentityUri/oauth2/platformtoken" -Method Post -Body $Body 
    }
    catch {
        throw "Authentication error: $($_.Exception.Message) - $($_.ErrorDetails.Message)"
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

$AuthResponse = Connect-Identity -subDomain $subDomain -userName $Username -password $Password

$Password.Dispose()
$Password = $null

$PvwaUri = [System.Uri]::new($pCloudBase, "PasswordVault/")

$pCloudSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$pCloudSession.MaximumRedirection = 0
$pCloudSession.Headers['Authorization'] = "$($authResponse.token_type) $($authResponse.access_token)"
$pCloudSession.Headers['Accept']        = 'application/json'

$authResponse = $null

Write-Log "Processing file '$CsvFilePath'..." INFO

Import-Csv -LiteralPath $CsvFilePath | ForEach-Object {
    $AccountName = $_.name
    $AccountId = $_.id.trim()
    $SafeName = $_.SafeName

    $DeleteUri = [System.Uri]::new($PvwaUri, "API/Accounts/$AccountID")
 
    if ($PSCmdlet.ShouldProcess("Account '$AccountName' ('$AccountId') in Safe '$SafeName'", 'DELETE')) {
        try {
            Invoke-RestMethod -Uri $DeleteUri -Method Delete -WebSession $pCloudSession
            Write-Log "Deleted Account: $AccountId from Safe: $SafeName" INFO
        } catch {
            Write-Log "Failed to delete Account: $AccountId from Safe: $SafeName - $_" WARN
        }
    }
}