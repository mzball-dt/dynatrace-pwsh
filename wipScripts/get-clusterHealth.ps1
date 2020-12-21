<#
    .Synopsis
        A Basic Health Check script to quickly identify cluster / synthetic cluster activeGate issues
    .Description
        This script forms the basis (scaffold) for scripts to perform API calls
    .Notes
        Author: Adrian Chen
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
    [Parameter()][ValidateNotNullOrEmpty()] $dtcluster = $env:dtcluster,
    # Token must have Smartscape Read access for a tenant
    [Alias('dtclustertoken')][ValidateNotNullOrEmpty()][string] $clustertoken = $env:dtclustertoken,

    <##################################
    # Start of Script-specific params #
    ##################################>



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
    [String[]]$script:tokenPermissionRequirements = @('DataExport')
)

# Help flag checks
if ($h -or $help) {
    Get-Help $script:MyInvocation.MyCommand.Path -Detailed
    exit 0
}

# Ensure that dtcluster and token are both populated
if (!$script:dtcluster) {
    return Write-Error "Cluster URL was not populated - unable to continue"
}
elseif (!$script:token) {
    return Write-Error "token/dttoken was not populated - unable to continue"
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
    write-host -ForegroundColor DarkYellow -Object "WARNING: Removed trailing '/' from dtcluster input"
}

$baseURL = "$script:dtcluster/api/v1"

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

function confirm-requiredTokenPerms ($clustertoken, $requirePerms, $logmsg = '') {
    # Token has required Perms Check - cancel out if it doesn't have what's required
    $uri = "$baseURL/tokens/lookup"
    $headers = @{
        Authorization  = "Api-Token $clustertoken";
        Accept         = "application/json; charset=utf-8";
        "Content-Type" = "application/json; charset=utf-8"
    }
    Write-Host -ForegroundColor cyan -Object "Token Permissions Check$logmsg`: POST $uri"
    $res = Invoke-RestMethod -Method POST -Headers $headers -Uri $uri -body "{ `"token`": `"$clustertoken`"}"
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
    if ($script:dtcluster -like "*.live.dynatrace.com") {
        $envType = 'env'
    }
    elseif ($script:dtcluster -like "http*://*/e/*") {
        $envType = 'env'
    }

    # Script won't work on a cluster
    if ($envType -eq 'env') {
        write-error "'$script:dtcluster' looks like an invalid URL or environment url"
        exit
    }
    
    # check that other requirements are met
    confirm-supportedClusterVersion 192
    confirm-requiredTokenPerms $script:token $script:tokenPermissionRequirements
}

function convertTo-jsDate($date) {
    return [Math]::Floor(1000 * (Get-Date ($date) -UFormat %s))
}

## Cluster API could be api/v1.0 or api/cluster/v2

$baseURL = "$script:dtcluster/api/"

<#
###########################
# End of scaffold block #
###########################
#>

## Retrieve cluster node information
/api/v1.0/onpremise/cluster/configuration

## Cluster Node Status Check
<NODE_DIRECT_CNAME_OR_IP>/api/v1.0/onpremise/nodeManagement/nodeServerStatus

## Synthetics Nodes (Synthetic enabled Cluster ActiveGates' health)
/api/cluster/v2/synthetic/nodes