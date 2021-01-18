<#
.SYNOPSIS
    Create/Maintain a dashboard from a template dashboard. Schedule this for an easily updated 'default' environment dashboard

.DESCRIPTION
    Intended to empower a 'default' dashboard shared between many Dynatrace Monitoring environments.
    Uses an existing dashboard or dashboard json export (from file) as a template to create the new dashboards.
    To provide support for links specific to the environment, the string %%ENV%% is replaced with the environment URL.

     Changelog:
        1.2.1 - 20210118
            Fixed bug where confirm-requiredTokenPerms is run to check a secondary token
        1.2.0 - 20201112
            Merged the different 1.x versions into 1.2.0.
            Fixed bugs with checking the 'goodness' of the source environment's token
        1.1.0 - 20201007
            Added the destinationEnvironmentName param for resolving the %%ENVNAME%% template string
        1.0.1 - 20201001
            Fixed a bug that caused a pre-existing dashboard to not be updated
        1.0.0
            MVP

.NOTES
    Author: Michael Ball
    Version: 1.2.1 - 20210118
    Requirements: Powershell 5+   
#>

<###########################
# Start of scaffold block #
###########################>

PARAM (
    # The cluster or tenant the Dasboard will be placed in
    [Parameter()][ValidateNotNullOrEmpty()] $dtenv = $env:dtenv,
    # Token for the destination tenant w/ DataExport and WriteConfig perms
    [Alias('dttoken')][ValidateNotNullOrEmpty()][string] $token = $env:dttoken,

    <##################################
    # Start of Script-specific params #
    ##################################>

    # A shortcut for specifying a new name for the created report
    [ValidateNotNullOrEmpty()][string]$destinationReportName,
    # A default dashboard will by default not have a normal user attached
    [ValidateNotNullOrEmpty()][string]$destinationReportOwner = 'admin',
    # Required if the %%ENVNAME%% template string is present in the template. Should represent the environment name
    [ValidateNotNullOrEmpty()][string]$destinationEnvironmentName,

    # The json file that represents the source dashboard
    [ValidateScript( { if (Test-Path -Path $_ -PathType Leaf) { $true } else { throw "Unable to validate file '$_' exists" } })][String]$sourceFile,
    # The URL of the source Environment
    [ValidateNotNullOrEmpty()][String]$sourceEnvironment,
    # The ID of the source Dashboard - just like if you wanted to open it in browser
    [ValidateNotNullOrEmpty()][String]$sourceDashboardID,
    # A Token with DataExport and ReadConfig access to the source Environment
    [ValidateNotNullOrEmpty()][String]$sourceToken,

    # Force the creation of a new dashboard
    [Switch]$force = $false,

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

function confirm-supportedClusterVersion ($minimumVersion = 176, $logmsg = '') {
    # Environment version check - cancel out if too old 
    $uri = "$baseURL/config/clusterversion"
    Write-Host -ForegroundColor cyan -Object "Cluster Version Check$logmsg`: GET $uri"
    $res = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri 
    $envVersion = $res.version -split '\.'
    if ($envVersion -and ([int]$envVersion[0]) -ne 1 -and ([int]$envVersion[1]) -lt $minimumVersion) {
        write-Error "Failed Environment version check - Expected: > 1.176 - Got: $($res.version)"
        exit
    }
}

function confirm-requiredTokenPerms ($token, $requirePerms, $envUrl = $script:dtenv, $logmsg = '') {
    # Token has required Perms Check - cancel out if it doesn't have what's required
    $uri = "$envUrl/api/v1/tokens/lookup"
    $headers = @{
        Authorization  = "Api-Token $token";
        Accept         = "application/json; charset=utf-8";
        "Content-Type" = "application/json; charset=utf-8"
    }
    Write-Host -ForegroundColor cyan -Object "Token Permissions Check$logmsg`: POST $uri"
    $res = Invoke-RestMethod -Method POST -Headers $headers -Uri $uri -body "{ `"token`": `"$token`"}"
    if (($requirePerms | Where-Object { $_ -notin $res.scopes }).count) {
        write-error "Failed Token Permission check. Token requires: $($requirePerms -join ',')"
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
    
    confirm-supportedClusterVersion 182 -logmsg ' (Destination Cluster)'
    confirm-requiredTokenPerms $script:token $script:tokenPermissionRequirements -logmsg ' (Token for Destination Cluster)'
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
    if ($script:sourceEnvironment -like "*.live.dynatrace.com") {
        $envType = 'env'
    }
    elseif ($script:sourceEnvironment -like "http*://*/e/*") {
        $envType = 'env'
    }

    # Script won't work on a cluster
    if ($envType -eq 'cluster') {
        write-error "'$script:sourceEnvironment' looks like an invalid URL (and Clusters are not supported by this script)"
        return
    }
    
    confirm-supportedClusterVersion 182 -logmsg ' (Source Cluster)'
    confirm-requiredTokenPerms $script:sourceToken "DataExport", "ReadConfig" -envUrl $script:sourceEnvironment -logmsg ' (Token for Source Cluster)'
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
$import = if ($script:sourceFile) {
    Get-Content -Path $script:sourceFile -Raw | ConvertFrom-Json -Depth 20
}
else {
    export-Dashboard $sourceEnvironment $sourceToken $sourceDashboardID
}

# destinationReportName isn't required - populate it from the source dashboard if it's missing
if (!$script:destinationReportName) {
    $script:destinationReportName = $import.dashboardMetadata.name
}

# If we're not forced - check that a report doesn't already exist to overwrite
if (!$script:force) {
    # Attempt to find a dashboard that this should be overwriting
    $headers = @{Authorization = "Api-Token $script:token"; "Content-Type" = "application/json" }
    $url = "$script:dtenv/api/config/v1/dashboards"
    write-host -ForegroundColor cyan "Fetch all dashboards in destination tenant: GET $url"
    $dashboards = Invoke-RestMethod -Method GET -Headers $headers -Uri $url
    
    # filter based on the owner and name we're about to set
    $filtered = $dashboards.dashboards | Where-Object -Property owner -eq -Value $script:destinationReportOwner
    $filtered = $filtered | Where-Object -Property name -eq -Value $script:destinationReportName

    # If there's more than one left complain #todo check content for the $script:destinationReportMarker
    if (@($filtered).Length -gt 1) {
        Write-Error "Unable to determine which dashboard is intended for replacement."
        Write-Host "Please review the intended owner and name of the default dashboard and the dashboards that would conflict:"
        Write-Host "Current values: `r`n`t-destinationReportOwner = $script:destinationReportOwner`r`n`t-destinationReportName = $script:destinationReportName"
        Write-Host "Dashboards that match owner/name combo - preference is that there should only be one:"
        $filtered | % { "'$($_.name)' by $($_.owner): $script:dtenv/#dashboard;id=$($_.id)" }
        exit
    }
    elseif (@($filtered).Length -lt 1 ) {
        Write-host "We couldn't find a dashboard"
        $noExistingDashboard = $true
    }
    else {
        Write-host "We found exactly one dashboard"
        $existingDashboard = $filtered[0]
    }
}

# If we're forcing the new creation or couldn't find a recognisable pre-existing reports
if ($script:force -or $noExistingDashboard) {
    Write-Verbose "f:$force and nED: $noExistingDashboard"

    # update the output for importing
    $import.PSObject.properties.remove('id')
    $import.dashboardMetadata.owner = ''
    $import.dashboardMetadata.shared = $true
    $import.dashboardMetadata.sharingDetails.published = $true
    $import.dashboardMetadata.name = $script:destinationReportName

    # Convert the exported PSObject back to JSON
    $json = $import | ConvertTo-Json -Depth 20 -Compress
    $json = $json -replace "%%ENV%%", "$script:dtenv"

    write-host "Dashboard Import is $($json | Measure-Object -Character | Select-Object -ExpandProperty characters) bytes"

    # upload the new dashboard
    $newDashID = import-DashboardJSON $script:dtenv $script:token $json

    # fetch dashboard data (now that it's been made)
    $dashData = export-Dashboard $script:dtenv $script:token $newDashID
    $dashData.dashboardMetadata.owner = $script:destinationReportOwner

    # re-upload the re-authored dashboard
    $headers = @{Authorization = "Api-Token $script:token"; "Content-Type" = "application/json" }
    $url = "$script:dtenv/api/config/v1/dashboards/$newDashID"
    write-host -ForegroundColor cyan "Setting owner of new dashboard: PUT $url"
    Invoke-RestMethod -Method PUT -Headers $headers -Uri $url -Body ($dashData | ConvertTo-Json -Depth 20 -Compress)

}
# If we found a pre-existing report then just update the tiles and send the update
else {
    # Pull the structure of the current dashboard
    $existingDashboardData = export-Dashboard $script:dtenv $script:token $existingDashboard.id
    $existingDashboardData.tiles = $import.tiles

    $headers = @{Authorization = "Api-Token $script:token"; "Content-Type" = "application/json" }
    $url = "$script:dtenv/api/config/v1/dashboards/$($existingDashboard.id)"
    $json = $existingDashboardData | ConvertTo-Json -Depth 20 -Compress
    $json = $json -replace "%%ENV%%", "$script:dtenv"
    if ($script:destinationEnvironmentName) { $json = $json -replace "%%ENVNAME%%", "$script:destinationEnvironmentName" }

    write-host -ForegroundColor cyan "Update the existing default dashboard: PUT $url"
    Invoke-RestMethod -Method PUT -Headers $headers -Uri $url -Body $json
}

Write-Host -ForegroundColor Green "Complete"

