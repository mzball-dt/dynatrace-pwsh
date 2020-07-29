<#
    .Synopsis
        Return a list of monitored entities in a Dynatrace tenant that match the selector uses the v2 API

    .Description
        An environment exploration and listing tool that uses the v2 Entity API of Dynatrace 1.194.
        Currently just provides an interface useful for quering an environment for what's currently 
        being monitored, returning entityIds and monitored names

        Todo: 
            - Support page-overflow by warning of page overflow and providing switch to follow pages
            - 'List all' option?
            - flag to use the 'fields' option of the entities v2 APIs and provide more info
            - -showtypes option to query the API for currently available entity types
            - support being piped _into_

    .Notes
        Author: Michael Ball
        Version: 1.0.0 - 20200729

        ChangeLog
            1.0.0
                Extended explicit options for selector
                Added warning when there's no output
                Added examples to script
            0.1.0
                simple selector options
            
    .Example 
        pwsh>.\get-tenantMonitoredEntity.ps1 -type application

        Cluster Version Check: https://abc12345.live.dynatrace.com/api/v1/config/clusterversion
        Token Permissions Check: https://abc12345.live.dynatrace.com/api/v1/tokens/lookup
        https://abc12345.live.dynatrace.com/api/v2/entities?&pageSize=500&entitySelector=type("application")

        entityId                     displayName
        --------                     -----------
        APPLICATION-AFEA5298827361E4 Application 2
        APPLICATION-B5DC99F9E29F945F Application 1
    
    .Example
        pwsh>.\get-tenantMonitoredEntity.ps1 -type HOST -from now-8w -to now-4w -tag SableVM

        Cluster Version Check: https://abc12345.live.dynatrace.com/api/v1/config/clusterversion
        Token Permissions Check: https://abc12345.live.dynatrace.com/api/v1/tokens/lookup
        https://abc12345.live.dynatrace.com/api/v2/entities?&from=now-8w&to=now-4w&pageSize=500&entitySelector=type("HOST"),tag("SableVM")

        entityId              displayName
        --------              -----------
        HOST-38BA62219C87FDD5 uk8s
        HOST-47E6018D46B499FA minik8s
        HOST-8880B570AAE6FF6E splunk.local
        HOST-AA1CD53234EA8DDA dockerbox.sablecliff.local
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

    # Entity Selection options
    [ValidateNotNullOrEmpty()][String] $type,
    [ValidateNotNullOrEmpty()][String[]] $id,
    [ValidateNotNullOrEmpty()][String[]] $name,
    [ValidateNotNullOrEmpty()][String[]] $tag,
    [ValidateNotNullOrEmpty()][String] $mzId,
    [ValidateNotNullOrEmpty()][String] $mzName,
    [ValidateSet('HEALTHY', 'UNHEALTHY')][String] $healthState,

    # Explicity create an entity selector - other options will be ignored when used
    [ValidateNotNullOrEmpty()][String] $selector,
    
    # The time from which the query should start
    [ValidateNotNullOrEmpty()][string]$from,
    # The time to which the query should end
    [ValidateNotNullOrEmpty()][String]$to,
    # Number of results to pull back
    [int]$pageSize = 500,
    # Path to output a csv representation of the fetched data
    [ValidateNotNullOrEmpty()][string] $outfile,

    # Prints Help output
    [Alias('h')][switch] $help,
    # use this switch to tell this script to not check token or cluster viability
    [switch] $noCheckCompatibility,
    # use this switch to tell powershell to ignore ssl concerns
    [switch] $noCheckCertificate,

    # DO NOT USE - This is set by Script Author
    [String[]]$script:tokenPermissionRequirements = @('DataExport', 'entities.read')
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
    
    # Environment version check - cancel out if too old 
    $uri = "$baseURL/config/clusterversion"
    Write-Host -ForegroundColor cyan -Object "Cluster Version Check: $uri"
    $res = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri 
    $envVersion = $res.version -split '\.'
    if ($envVersion -and ([int]$envVersion[0]) -ne 1 -and ([int]$envVersion[1]) -lt 194) {
        write-host "Failed Environment version check - Expected: > 1.194 - Got: $($res.version)"
        return
    }

    # Token has required Perms Check - cancel out if it doesn't have what's required
    $uri = "$baseURL/tokens/lookup"
    Write-Host -ForegroundColor cyan -Object "Token Permissions Check: $uri"
    $res = Invoke-RestMethod -Method POST -Headers $headers -Uri $uri -body "{ `"token`": `"$script:token`"}"
    if (($script:tokenPermissionRequirements | Where-Object { $_ -notin $res.scopes }).count) {
        write-host "Failed Token Permission check. Token requires: $($script:tokenPermissionRequirements -join ',')"
        write-host "Token provided only had: $($res.scopes -join ',')"
        return
    }
}

function convertTo-jsDate($date) {
    return [Math]::Floor(1000 * (Get-Date ($date) -UFormat %s))
}

<#
###########################
# End of scaffold block #
###########################
#>

# Check that we have something to query with - #todo do we want to support 'all entities'?
if (!$script:type -and !$script:selector -and !$script:id) {
    return Write-Error "No selection parameters were provided. At least one of type,id or selector arguments must be present"
}

# Add the System.Web type - the lack of this will be a headache otherwise.
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue | Out-Null

## Form the base of the url endpoint to be queried
$baseURL = "$script:dtenv/api/v2/entities"

$uri = "$baseURL`?"

# Add the timestamps if they exist
$uri += if ($script:from) { "&from=" + [System.Web.HttpUtility]::UrlEncode($script:from) }
$uri += if ($script:to) { "&to=" + [System.Web.HttpUtility]::UrlEncode($script:to) }
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
    $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers    
}
catch {
    Write-Error $_
    exit 1
}

if (!$response.entities) {
    return Write-Warning "No Monitoring Entities Found"
}

# If we need to output to file
if ($script:outfile) {
    ## Additional condition to check output of Split-Path
    if (Split-Path $script:outfile) {
        if (!(Split-Path $script:outfile | Test-Path -PathType Container)) {
            New-Item -Path (Split-Path $script:outfile) -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
        }
    }
    $outputFile = New-Item -Path $script:outfile -Force
    $response.entities | ConvertTo-Csv -NoTypeInformation | out-file -FilePath $script:outfile
    write-host "Written to csv table to $($outputFile.fullname)" -ForegroundColor Green
}

$response.entities