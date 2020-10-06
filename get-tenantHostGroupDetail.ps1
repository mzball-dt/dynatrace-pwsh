<#
.SYNOPSIS
    Fetch a report of how Host Units are consumed across a Dynatrace tenant

.DESCRIPTION
    Uses the Dynatrace Tenant API to report on the Host Unit utilization across hostGroups. 
    
    Required Permissions: 
            * Cluster Version >= 1.176
            * Token with base permissions - "Access problem and event feed, metrics and topology"

    Normal output is a list of all servers with the name,tags,hostgroup,hostunit,OS,host-ID and agent version number
    The -summary switch will present only values per host group - this is done to create faster reporting. 

.EXAMPLE
    .\get-tenantHostGroupDetail.ps1.ps1 -token JuroFUysdfduiSTOdI804l -dtenv https://dt-env.com/e/54df66-72bd-4ed5-8bf6-4251baf53979  -summary

    Name                           Value
    ----                           -----
    App1                            9.3
    thing-Web                       0.5
    app2_UAT                        4.75
    app4_env                        1.5
    noHostGroup                     3

.EXAMPLE
    $env:dtenv = 'https://dt-env.com/e/54df66-72bd-4ed5-8bf6-4251baf53979'; $env:dttoken = 'asdfu1139123019u23kl';
    PS > .\get-tenantHostGroupDetail.ps1 | format-table

    WARNING: Removed trailing '/' from dtenv input
    Cluster Version Check: https://lzq49041.live.dynatrace.com/api/v1/config/clusterversion
    Token Permissions Check: https://lzq49041.live.dynatrace.com/api/v1/tokens/lookup
    Host Entity information request: https://lzq49041.live.dynatrace.com/api/v1/entity/infrastructure/hosts?relativeTime=2hours&includeDetails=true

    displayName                tags       hostGroup     consumedHostUnits osType entityId              agentVersion
    -----------                ----       ---------     ----------------- ------ --------              ------------
    SableBeast                 HyperVisor                               2 LINUX  HOST-57B8A8BE4CD2EDCF 1.189.184
    dockerbox.sablecliff.local SableVM    sbeast_centos              0.25 LINUX  HOST-AA1CD53234EA8DDA 1.189.184
    quantisedself.local        SableVM    sbeast_centos              0.25 LINUX  HOST-AC4B294ECEB16E84 1.189.184
    sablevps                                                          0.5 LINUX  HOST-F0017F68B4D69557 1.189.184
    splunk.local               SableVM    sbeast_centos              0.25 LINUX  HOST-8880B570AAE6FF6E 1.189.184

.NOTES
    Author: michael.ball
    Version: 0.3 - 20200423
    Requirement: Powershell v5.0

    Changelog
        0.3.1
            Updated Script to include monitoringMode in the standard output - Note: I've not updated the examples
        0.3
            Further steps towards a unified framework/format for these scripts
                - noCheckCompatibility (turns off version, cluster type and token perms checks)
            Processes out the string version of 'agentVersion'
            Checks token for required perms (based on script:tokenPermissionRequirements)
            Updated input params names
            Added ability to use env:dtenv and env:dttoken as inputs environment inputs
        0.2
            MVP!
            implemented -Summary switch
            implemented basic -outfile 

#>

PARAM (
    # The cluster or tenant the HU report should be fetched from
    [Parameter()][ValidateNotNullOrEmpty()] $dtenv = $env:dtenv,
    # Token must have Smartscape Read access for a tenant
    [Alias('dttoken')][ValidateNotNullOrEmpty()][string] $token = $env:dttoken,

    # Do the calc of HU/HostGroup (is non-simple)
    [switch] $summary,
    # Path to output a csv representation of the fetched data.
    [string] $outfile,

    # Prints Help output
    [Alias('h')][switch] $help,
    # use this switch to tell this script to not check token or cluster viability
    [switch] $noCheckCompatibility,
    # use this switch to tell powershell to ignore ssl concerns
    [switch] $noCheckCertificate,

    # DO NOT USE - This is set by Script Author
    [String[]]$script:tokenPermissionRequirements = 'DataExport'
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
        Write-Error "Failed Token Permission check. Token requires: $($requirePerms -join ',')"
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

    confirm-supportedClusterVersion 176
    confirm-requireTokenPerms $script:token $script:tokenPermissionRequirements
}

function get-shrunkAgentVersion ([Parameter(ValueFromPipeline = $true)]$agentVersionObj) {
    return $agentVersionObj.major, $agentVersionObj.minor, $agentVersionObj.revision -join '.'
}

# Handles the fetching - used mostly by the cluster wide checks 
function Fetch-HostData($env, $token) {
    $headers = @{
        Authorization  = "Api-Token $token"
        "Content-Type" = "application/json"
    }
    $baseURL = "$env/api/v1"

    # create a baseURL for the API call
    $uri = "$baseURL/entity/infrastructure/hosts?relativeTime=2hours&includeDetails=true"
    write-host -ForegroundColor cyan "Host Entity information request: $uri"
    $res = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri
    $out = $res | Select-Object -Property displayName, @{L = "tags"; E = { $_.tags.key } }, @{L = "hostGroup"; E = { $_.hostGroup.name } }, consumedHostUnits, monitoringMode, osType, entityID, @{L = 'agentVersion'; E = { $_.agentVersion | get-shrunkAgentVersion } }
    $out
}

$hostInfo = Fetch-HostData $script:dtenv $script:token

if ($outfile) {
    $hostInfo | ConvertTo-Csv -NoTypeInformation | Out-File $outfile
}

if ($summary) {
    $summaryout = $hostInfo | Group-Object -Property hostGroup | ForEach-Object { $mr = @{} } {
        if ($_.Group.hostGroup -ne $null) {
            $mr[([array]$_.Group.hostGroup)[0]] = ($_.Group.consumedHostUnits | Measure-Object -Sum).sum
        }
        else {
            $mr['noHostGroup'] = ($_.Group.consumedHostUnits | Measure-Object -Sum).sum
        }
    } { $mr }
    return $summaryout
}
else {
    return $hostInfo
}
