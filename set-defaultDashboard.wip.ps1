<#
.SYNOPSIS
    Create/Maintain a dashboard from a template dashboard. Schedule this for an easily updated 'default' environment dashboard

.DESCRIPTION
    Intended to empower a 'default' dashboard shared between many Dynatrace Monitoring environments.
    Uses an existing dashboard or dashboard json export (from file) as a template to create the new dashboards.
    To provide support for links specific to the 

.NOTES
    Version: alpha - 20200701
    Author: michael.ball8
    Requirements: Powershell 5+
    Changelog:        
        alpha
#>

<###########################
# Start of scaffold block #
###########################>

PARAM (
    # The cluster or tenant the Dasboard will be placed in
    [Parameter()][ValidateNotNullOrEmpty()] $dtenv = $env:dtenv,
    # Token for the target tenant w/ DataExport and WriteConfig perms
    [Alias('dttoken')][ValidateNotNullOrEmpty()][string] $token = $env:dttoken,

    <##################################
    # Start of Script-specific params #
    ##################################>

    # A shortcut for specifying a new name for the created report
    [ValidateNotNullOrEmpty()][string]$destinationReportName,
    # A default dashboard will by default not have a normal user attached
    [ValidateNotNullOrEmpty()][string]$destinationReportOwner = 'admin',

    # The json file that represents the source dashboard
    [ValidateScript( { if (Test-Path -Path $_ -PathType Leaf) { $true } else { throw "Unable to validate file '$_' exists" } })][String]$sourceFile,
    # The URL of the source Environment
    [ValidateNotNullOrEmpty()][String]$sourceEnvironment,
    # The ID of the source Dashboard - just like if you wanted to open it in browser
    [ValidateNotNullOrEmpty()][String]$sourceDashboardID,
    # A Token with DataExport and ReadConfig access to the source Environment
    [ValidateNotNullOrEmpty()][String]$sourceToken,

    <#################################
    # Stop of Script-specific params #
    #################################>

    # Prints Help output
    [Alias('h')][switch] $help,
    # use this switch to tell this script to not check token or cluster viability
    [switch] $noCheckCompatibility,
    # use this switch to tell powershell to ignore ssl concerns
    [switch] $noCheckCertificate,

    # DO NOT USE - This is set by Script Author
    [String[]]$script:tokenPermissionRequirements = @('DataExport', 'WriteConfig')
)

# Help flag checks
if ($h -or $help) {
    Get-Help $script:MyInvocation.MyCommand.Path -Detailed
    exit 0
}

# Ensure that dtenv and token are both populated
if (!$script:dtenv) {
    return Write-Error "dtenv was not populated - unable to continue"
}
elseif (!$script:token) {
    return Write-Error "token/dttoken was not populated - unable to continue"
}

# Try to 'fix' a missing https:// in the env
if ($script:dtenv -notlike "https://*" -and $script:dtenv -notlike "http://*") {
    Write-Host -ForegroundColor DarkYellow -Object "WARN: Environment URI was missing 'httpx://' prefix"
    $script:dtenv = "https://$script:dtenv"
    Write-host -ForegroundColor Cyan "New environment URL: $script:dtenv"
}

# Try to 'fix' a trailing '/'
if ($script:dtenv[$script:dtenv.Length - 1] -eq '/') { 
    $script:dtenv = $script:dtenv.Substring(0, $script:dtenv.Length - 1) 
    write-host -ForegroundColor DarkYellow -Object "WARNING: Removed trailing '/' from dtenv input"
}

$baseURL = "$script:dtenv/api/v1"

# Setup Network settings to work from less new setups
if ($nocheckcertificate) {
    # SSL and other compatability settings
    function Disable-SslVerification {
        if (-not ([System.Management.Automation.PSTypeName]"TrustEverything").Type) {
            Add-Type -TypeDefinition  @"
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class TrustEverything
{
    private static bool ValidationCallback(object sender, X509Certificate certificate, X509Chain chain,
    SslPolicyErrors sslPolicyErrors) { return true; }
    public static void SetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = ValidationCallback; }
    public static void UnsetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = null; } } 
"@
        }
        [TrustEverything]::SetCallback()
    }
    function Enable-SslVerification {
        if (([System.Management.Automation.PSTypeName]"TrustEverything").Type) {
            [TrustEverything]::UnsetCallback()
        }
    }
    Disable-SslVerification   
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocoltype]::Tls12 

# Construct the headers for this API request 
$headers = @{
    Authorization  = "Api-Token $script:token";
    Accept         = "application/json; charset=utf-8";
    "Content-Type" = "application/json; charset=utf-8"
}

function confirm-supportedClusterVersion ($minimumVersion = 176) {
    # Environment version check - cancel out if too old 
    $uri = "$baseURL/config/clusterversion"
    Write-Host -ForegroundColor cyan -Object "Cluster Version Check: GET $uri"
    $res = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri 
    $envVersion = $res.version -split '\.'
    if ($envVersion -and ([int]$envVersion[0]) -ne 1 -and ([int]$envVersion[1]) -lt $minimumVersion) {
        write-host "Failed Environment version check - Expected: > 1.176 - Got: $($res.version)"
        exit
    }
}

function confirm-requireTokenPerms ($token, $requirePerms) {
    # Token has required Perms Check - cancel out if it doesn't have what's required
    $uri = "$baseURL/tokens/lookup"
    Write-Host -ForegroundColor cyan -Object "Token Permissions Check: POST $uri"
    $res = Invoke-RestMethod -Method POST -Headers $headers -Uri $uri -body "{ `"token`": `"$script:token`"}"
    if (($requirePerms | Where-Object { $_ -notin $res.scopes }).count) {
        write-host "Failed Token Permission check. Token requires: $($requirePerms -join ',')"
        write-host "Token provided only had: $($res.scopes -join ',')"
        exit
    }
}

if (!$noCheckCompatibility) {
    <#
        Determine what type environment we have? This script will only work on tenants 
        
        SaaS tenant = https://*.live.dynatrace.com
        Managed tenant = https://*/e/UUID
        Managed Cluster = https://*
    #>
    $envType = 'cluster'
    if ($script:dtenv -like "*.live.dynatrace.com") {
        $envType = 'env'
    }
    elseif ($script:dtenv -like "http*://*/e/*") {
        $envType = 'env'
    }

    # Script won't work on a cluster
    if ($envType -eq 'cluster') {
        write-error "'$script:dtenv' looks like an invalid URL (and Clusters are not supported by this script)"
        return
    }
    
    confirm-supportedClusterVersion 182
    confirm-requireTokenPerms $script:token $script:tokenPermissionRequirements
}

<#########################
# Stop of scaffold block #
#########################>

# If no source Environment and no sourceFile then this is an intra Environment move/copy
if (!$script:sourceEnvironment -and !$script:sourceFile) {
    $script:sourceEnvironment = $script:dtenv
    $script:sourceToken = $script:token
}

# If we're connecting to another dt tenant, confirm we've got the required creds
if (!$script:sourceFile) {
    <#
        Determine what type environment we have? This script will only work on tenants 
        
        SaaS tenant = https://*.live.dynatrace.com
        Managed tenant = https://*/e/UUID
        Managed Cluster = https://*
    #>
    $envType = 'cluster'
    if ($script:dtenv -like "*.live.dynatrace.com") {
        $envType = 'env'
    }
    elseif ($script:dtenv -like "http*://*/e/*") {
        $envType = 'env'
    }

    # Script won't work on a cluster
    if ($envType -eq 'cluster') {
        write-error "'$script:dtenv' looks like an invalid URL (and Clusters are not supported by this script)"
        return
    }
    
    confirm-supportedClusterVersion 182
    confirm-requireTokenPerms $script:sourceToken "DataExport", "ReadConfig"
}

function import-DashboardJSON ($environment, $token, [String]$dashboardJSON) {
    $headers = @{
        Authorization  = "Api-Token $Token"
        "Content-Type" = "application/json"
    }
    $url = "$environment/api/config/v1/dashboards"
    $dashboardJSON = $dashboardJSON -replace '%%ENV%%', $environment
    $res = @()
    try {
        $response = Invoke-WebRequest -Method POST -Headers $headers -Uri $url -Body $dashboardJSON -UseBasicParsing -ErrorAction Stop
        $res = $response.content | ConvertFrom-Json
        Write-host "Dashboard created successfully. Name: " -nonewline 
        write-host $res.name -NoNewline -ForegroundColor Gray
        write-host " - ID: " -NoNewline
        write-host $res.id -ForegroundColor Gray
        Write-host "Access URL: " -NoNewline -ForegroundColor Gray
        write-host "$environment/#dashboard;id=$($res.id)" -ForegroundColor cyan
        return $res.id
    }
    catch [System.Net.WebException] {
        $respStream = $_.Exception.Response.getResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $reader.baseStream.Position = 0
        $res = $reader.ReadToEnd() | ConvertFrom-Json

        write-host "Error attempting to import: $($res.error.code)"
        write-host "Message: $($res.error.message)" -ForegroundColor Red

        Write-error "Import failed - No changes made"
    }
}

function export-Dashboard ($environment, $token, $dashboardID) {
    $headers = @{
        Authorization  = "Api-Token $Token"
        "Content-Type" = "application/json"
    }
    $url = "$environment/api/config/v1/dashboards/$dashboardID"

    write-host -ForegroundColor cyan "Fetch Dashboard JSON: GET $url"
    $response = Invoke-RestMethod -Method GET -Headers $headers -Uri $url

    return $response
}

# collect the 'template' dashboard's structure
$export = if ($script:sourceFile) {
    Get-Content -Path $script:sourceFile -Raw | ConvertFrom-Json -Depth 20
} else {
    export-Dashboard $sourceEnvironment $sourceToken $sourceDashboardID
}

# update the output for importing
$export.PSObject.properties.remove('id')
$export.dashboardMetadata.owner = ''
$export.dashboardMetadata.shared = $true
$export.dashboardMetadata.sharingDetails.published = $true
if ($script:destinationReportName) {
    $export.dashboardMetadata.name = $script:destinationReportName
}

# Convert the exported PSObject back to JSON
$json = $export | ConvertTo-Json -Depth 20 -Compress
write-host "Dashboard Export is $($json | Measure-Object -Character | Select-Object -ExpandProperty characters) bytes"

# upload the new dashboard
$newDashID = import-DashboardJSON $script:dtenv $script:token $json

# fetch dashboard data (now that it's been made)
$dashData = export-Dashboard $script:dtenv $script:token $newDashID
$dashData.dashboardMetadata.owner = $script:destinationReportOwner

$headers = @{
    Authorization  = "Api-Token $script:token"
    "Content-Type" = "application/json"
}
$url = "$script:dtenv/api/config/v1/dashboards/$newDashID"
write-host -ForegroundColor cyan "Set owner of new dashboard: PUT $url"
Invoke-RestMethod -Method PUT -Headers $headers -Uri $url -Body ($dashData | ConvertTo-Json -Depth 20 -Compress)
