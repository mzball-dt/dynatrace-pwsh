<#
    .Synopsis
        Basis for creating API scripts
    .Description
        This script forms the basis (scaffold) for scripts to perform API calls
    .Notes
        Author: <Author Name>
        Version: 1.0.0 - <date>
        ChangeLog
            1.0.0 
                MVP - Things work
            
    .Example
        <PLACEHOLDER> - insert sample usage here
#>

<#
###########################
# Start of scaffold block #
###########################
#>
PARAM (
    # The cluster or tenant the HU report should be fetched from
    [Parameter()][ValidateNotNullOrEmpty()] $dtenv = $env:dtenv,
    # Token must have Smartscape Read access for a tenant
    [Alias('dttoken')][ValidateNotNullOrEmpty()][string] $token = $env:dttoken,

    <##################################
    # Start of Script-specific params #
    ##################################>

    # Entity Selection options
    [ValidateNotNullOrEmpty()][String] $type,
    [ValidateNotNullOrEmpty()][String[]] $id,
    [ValidateNotNullOrEmpty()][String[]] $name,
    [ValidateNotNullOrEmpty()][String[]] $tag,
    [ValidateNotNullOrEmpty()][String] $mzId,
    [ValidateNotNullOrEmpty()][String] $mzName,
    [ValidateSet('HEALTHY', 'UNHEALTHY')][String] $healthState,


    [int]$pageSize = 500,


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
    [String[]]$script:tokenPermissionRequirements = @('DataExport', 'ReadSyntheticData'),
    [String]$script:tokenPermissionRequirementsAggregator = 'or'
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

## Sets TLS to 1.2
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
    if ($envVersion -and (([int]$envVersion[0]) -ne 1 -or ([int]$envVersion[1]) -lt $minimumVersion)) {
        Write-Error "Failed Environment version check - Expected: > 1.$minimumVersion - Got: $($res.version)"
        exit
    }
}

function confirm-requiredTokenPerms ($token, $requirePerms, $logmsg = '') {
    # Token has required Perms Check - cancel out if it doesn't have what's required
    $uri = "$baseURL/tokens/lookup"
    $headers = @{
        Authorization  = "Api-Token $token";
        Accept         = "application/json; charset=utf-8";
        "Content-Type" = "application/json; charset=utf-8"
    }
    Write-Host -ForegroundColor cyan -Object "Token Permissions Check$logmsg`: POST $uri"
    $res = Invoke-RestMethod -Method POST -Headers $headers -Uri $uri -body "{ `"token`": `"$token`"}"
    if (($requirePerms | Where-Object { $_ -notin $res.scopes }).count) {
        Write-Error "Failed Token Permission check. Token requires: $($requirePerms -join ', ')"
        write-host "Token provided only had: $($res.scopes -join ', ')"
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
        exit
    }
    
    # check that other requirements are met
    confirm-supportedClusterVersion 192
    confirm-requiredTokenPerms $script:token $script:tokenPermissionRequirements
}

function convertTo-jsDate($date) {
    return [Math]::Floor(1000 * (Get-Date ($date) -UFormat %s))
}

$baseURL = "$script:dtenv/api/v1"

<#
###########################
# End of scaffold block #
###########################
#>

$uri = "$script:dtenv/api/v1/synthetic/monitors"

# Add the timestamps if they exist
# $uri += if ($script:from) { "&from=" + [System.Web.HttpUtility]::UrlEncode($script:from) }
# $uri += if ($script:to) { "&to=" + [System.Web.HttpUtility]::UrlEncode($script:to) }
$uri += "&pageSize=$script:pageSize"

# Did user use explicit Selector?
if ($script:selector) {
    $uri += ( "&entitySelector=" + [System.Web.HttpUtility]::UrlEncode($script:selector, [System.Text.Encoding]::UTF8) )
}
else {
    $selectorPrefix = "&entitySelector="
    $selectors = @()
    $selectors += if ($script:type) { 'type("' + $script:type + '")' }
    $selectors += if ($script:id) { 'entityId("' + ($script:id -join '","') + '")' }
    $selectors += if ($script:name) { 'entityName("' + ($script:name -join '","') + '")' }
    $selectors += if ($script:tag) { 'tag("' + ($script:tag -join '","') + '")' }
    $selectors += if ($script:mzId) { 'mzId("' + $script:mzId + '")' }
    $selectors += if ($script:mzName) { 'mzName("' + $script:mzName -join '","' + '")' }
    $selectors += if ($script:healthState) { 'healthState("' + $script:healthState + '")' }
    $uri += ($selectorPrefix + ($selectors -join ','))
}

# Output the uri used as information event
write-host $uri -ForegroundColor Cyan

try {
    Write-host -ForegroundColor cyan "Get list of synthetic Monitors: $uri"
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction stop
    }
    else {
        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -skipcertificatecheck -ErrorAction stop
    }
}
catch {
    Write-Error $_
    exit 1
}

if (!$response.entities) {
    return Write-Warning "No Monitoring Entities Found"
}



# iterate through the returned data to construct a PWSH Object, output and possibly save it
$data = @()
Foreach ($row in $response.monitors) {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $completeMonitor = Invoke-RestMethod -Method GET -Uri "$uri/$($row.entityid)" -Headers $headers
    }
    else {
        $completeMonitor = Invoke-RestMethod -Method GET -Uri "$uri/$($row.entityid)" -Headers $headers -skipcertificatecheck
    }

    $monitorSummary = New-Object psobject
    $monitorSummary | Add-Member -MemberType NoteProperty -Name "Name" -Value $completeMonitor.name
    $monitorSummary | Add-Member -MemberType NoteProperty -Name "EntityId" -Value $completeMonitor.EntityId
    $monitorSummary | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $completeMonitor.Enabled
    $monitorSummary | Add-Member -MemberType NoteProperty -Name "Type" -Value $completeMonitor.type
    $monitorSummary | Add-Member -MemberType NoteProperty -Name "CreatedFrom" -Value $completeMonitor.CreatedFrom
    $monitorSummary | Add-Member -MemberType NoteProperty -Name "locations" -Value $completeMonitor.locations
    $monitorSummary | Add-Member -MemberType NoteProperty -Name "tags" -Value $completeMonitor.tags
    $monitorSummary | Add-Member -MemberType NoteProperty -Name "ManagementZone" -Value ($completeMonitor.managementZones.name, "" -ne $null)[0]
    $monitorSummary | Add-Member -MemberType NoteProperty -Name "manuallyAssignedApps" -Value $completeMonitor.manuallyAssignedApps
    $monitorSummary | Add-Member -MemberType NoteProperty -Name "automaticallyAssignedApps" -Value $completeMonitor.automaticallyAssignedApps
    $monitorSummary | Add-Member -MemberType NoteProperty -Name "requests" -Value $completeMonitor.requests
    $monitorSummary | Add-Member -MemberType NoteProperty -Name "script" -Value $completeMonitor.script

    $data += $monitorSummary
}

# If we need to output to file
if ($script:outfile) {
    if (!(Split-Path $script:outfile | Test-Path -PathType Container)) {
        New-Item -Path (Split-Path $script:outfile) -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
    }
    $outputFile = New-Item -Path $script:outfile -Force
    $data | ConvertTo-Csv -NoTypeInformation | out-file -FilePath $script:outfile
    write-host "Written to csv table to $($outputFile.fullname)" -ForegroundColor Green
}

# Output
if ($short) {
    $data | Select-Object -Property Name, enabled, type, frequencyMin | Sort-Object -Property owner, name
}
else {
    $data | Sort-Object -Property owner, name
}
