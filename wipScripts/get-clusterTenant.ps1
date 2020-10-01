<#
.SYNOPSIS
    Retrieve a list of the tenants created in a Dynatrace Managed Cluster
.DESCRIPTION
    Uses the Cluster API to return information about the tenants currently configured in a Managed cluster.
    Output can be filtered via name (with wildcards) or tags and also to a specific environment id

    Designed to be used closely with a partner set-clusterTenant.ps1 script for configuration of Managed tenants

.NOTES
    Version: 1.0.0 - 20201001
    Author: Michael Ball
    Requirements: Powershell 5+
    ChangeLog: 
        1.0.0
            MVP
            Returns information from the cluster API based on string/tag/id filter
#>

<###########################
# Start of scaffold block #
###########################>

PARAM (
    # The URL of a Dynatrace Managed Cluster
    [Parameter()][ValidateNotNullOrEmpty()] $dtcluster = $env:dtcluster,
    # A token for the target Dynatrace Managed Cluster. Must have the 'ServiceProviderAPI' scope
    [Alias('dtclustertoken')][ValidateNotNullOrEmpty()][string] $clustertoken = $env:dtclustertoken,

    <##################################
    # Start of Script-specific params #
    ##################################>

    # A specific tenant (by name) from the list of known tenants
    [ValidateNotNullOrEmpty()][String] $tenantid,
    # A filter applied to Tenant names - can use '*' as wild cards
    [ValidateNotNullOrEmpty()][String] $filter,
    # A list of tags that tenants must match to be returned
    [ValidateNotNullOrEmpty()][String[]] $tag,

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
    [String[]]$script:tokenPermissionRequirements = @('ServiceProviderAPI')
)

# Help flag checks
if ($h -or $help) {
    Get-Help $script:MyInvocation.MyCommand.Path -Detailed
    exit 0
}

# Ensure that dtenv and token are both populated
if (!$script:dtcluster) {
    return Write-Error "dtcluster was not populated - unable to continue"
}
elseif (!$script:clustertoken) {
    return Write-Error "clustertoken/dtclustertoken was not populated - unable to continue"
}

# Try to 'fix' a missing https:// in the env
if ($script:dtcluster -notlike "https://*" -and $script:dtcluster -notlike "http://*") {
    Write-Host -ForegroundColor DarkYellow -Object "WARN: Environment URI was missing 'httpx://' prefix"
    $script:dtcluster = "https://$script:dtcluster"
    Write-host -ForegroundColor Cyan "New environment URL: $script:dtcluster"
}

# Try to 'fix' a trailing '/'
if ($script:dtcluster[$script:dtcluster.Length - 1] -eq '/') { 
    $script:dtcluster = $script:dtcluster.Substring(0, $script:dtcluster.Length - 1) 
    write-host -ForegroundColor DarkYellow -Object "WARNING: Removed trailing '/' from dtenv input"
}

$baseURL = "$script:dtcluster/api/cluster/v1"

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
    Authorization  = "Api-Token $script:clustertoken";
    Accept         = "application/json; charset=utf-8";
    "Content-Type" = "application/json; charset=utf-8"
}

function confirm-supportedClusterVersion ($minimumVersion = 176, $logmsg = '') {
    # Environment version check - cancel out if too old 
    $uri = "$script:dtcluster/api/v1.0/onpremise/cluster"
    Write-Host -ForegroundColor cyan -Object "Cluster Version Check$logmsg`: GET $uri"
    $res = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri 
    $envVersion = $res[0].buildVersion -split '\.'
    if ($envVersion -and ([int]$envVersion[0]) -ne 1 -and ([int]$envVersion[1]) -lt $minimumVersion) {
        write-host "Failed Environment version check - Expected: > 1.176 - Got: $($res.version)"
        exit
    }
}

function confirm-requireTokenPerms ($token, $requirePerms, $logmsg = '') {
    # Token has required Perms Check - cancel out if it doesn't have what's required
    $uri = "$baseURL/tokens/lookup"
    Write-Host -ForegroundColor cyan -Object "Token Permissions Check$logmsg`: POST $uri"
    $res = Invoke-RestMethod -Method POST -Headers $headers -Uri $uri -body "{ `"token`": `"$script:clustertoken`"}"
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
    if ($script:dtcluster -like "*.live.dynatrace.com") {
        $envType = 'env'
    }
    elseif ($script:dtcluster -like "http*://*/e/*") {
        $envType = 'env'
    }

    # Script won't work on a tenant
    if ($envType -ne 'cluster') {
        write-error "'$script:dtcluster' looks like an invalid URL (only Clusters are supported by this script)"
        return
    }
    
    confirm-supportedClusterVersion 184
    confirm-requireTokenPerms $script:clustertoken $script:tokenPermissionRequirements
}

<#########################
# Stop of scaffold block #
#########################>

# Assemble the list of tenants we're working on
$baseURL = "$script:dtcluster/api/cluster/v2"
$uri = "$baseURL/environments"

$script:tenantList = @()
# Did they specify an id?
if ( $script:id ) {
    $uri += "/$script:id"
    write-host -ForegroundColor Cyan "Fetching environment based on provided ID: GET $uri"
    $res = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri

    $script:tenantList = @($res)
}
# If they gave us something more generic
else {
    $uri += "?pageSize=500"
    $filtersPrefix = "&filter="
    $filters = @()
    $filters += if ($script:filter) { 'name("' + $script:filter + '")' }
    $filters += if ($script:tag) { 'tag("' + ($script:tag -join '","') + '")' }
    $filters += 'state(ENABLED)'
    $uri += ($filtersPrefix + ($filters -join ','))
    
    write-host -ForegroundColor Cyan "Fetching environments based on provided options: GET $uri"
    $res = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri

    if ($res.totalCount -lt 1) {
        write-host "Could not find any tenants matching your request" -ForegroundColor Red
        exit
    }

    $script:tenantList = $res.environments
}

return $tenantList