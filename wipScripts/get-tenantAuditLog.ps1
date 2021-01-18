<#
.SYNOPSIS

.DESCRIPTION
    

.EXAMPLE
    
.NOTES
    Author: michael.ball
    Version: 0.1 - 20200526
    Requirement: Powershell v5.0

    Changelog
        0.1 - MVP!
#>

PARAM (
    # The cluster or tenant the HU report should be fetched from
    [Parameter()][ValidateNotNullOrEmpty()] $dtenv = $env:dtenv,
    # Token must have Smartscape Read access for a tenant
    [Alias('dttoken')][ValidateNotNullOrEmpty()][string] $token = $env:dttoken,

    # Prints Help output
    [Alias('h')][switch] $help,
    # use this switch to tell this script to not check token or cluster viability
    [switch] $noCheckCompatibility,
    # use this switch to tell powershell to ignore ssl concerns
    [switch] $noCheckCertificate,

    # DO NOT USE - This is set by Script Author
    [String[]]$script:tokenPermissionRequirements = @('DataExport', 'auditLogs.read')
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
    $vMaj, $vMinor, $vPatch, $vBuild = $res.version -split '\.'
    if ($vMaj -eq 1 -and $vMinor -ge $minimumVersion) {
        # We're Good - version is fine
    }
    else {
        Write-Host -ForegroundColor Red "Failed Environment version check - Expected: > 1.$minimumVersion.x - Got: $($res.version)"
        exit
    }
}

function confirm-requireTokenPerms ($token, $requirePerms, $envUrl = $script:dtenv, $logmsg = '') {
    # Token has required Perms Check - cancel out if it doesn't have what's required
    $uri = "$envUrl/api/v1/tokens/lookup"
    Write-Host -ForegroundColor cyan -Object "Token Permissions Check$logmsg`: POST $uri"
    $res = Invoke-RestMethod -Method POST -Headers $headers -Uri $uri -body "{ `"token`": `"$script:token`"}"
    if (($requirePerms | Where-Object { $_ -notin $res.scopes }).count) {
        write-host -ForegroundColor Red "Failed Token Permission check. Token requires: $($requirePerms -join ',')"
        write-host -ForegroundColor Red "Token provided only had: $($res.scopes -join ',')"
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
		
    $_eap = $ErrorActionPreference; $ErrorActionPreference = 'stop'
    confirm-supportedClusterVersion 206
    confirm-requireTokenPerms $script:token $script:tokenPermissionRequirements
    $ErrorActionPreference = $_eap
}

$baseURL = "$script:dtenv/api/v2"
$uri = "$baseURL/auditlogs"
try {
    $res = Invoke-RestMethod -uri $uri -Headers $headers -Method GET -ErrorAction Stop
}
catch {
    if (($_.Exception.Response.StatusCode | ConvertTo-Json) -eq '404') {
        Write-Host -ForegroundColor Red "Recieved a 404 Error for the Audit Log API - Is Audit Logging enabled for this Tenant?"
        exit
    }
    else {
        Write-host -ForegroundColor Red ($_.Exception)
        exit
    }
}

# $res.auditLogs

# if ($summary) {
#     $summaryout = $hostInfo | Group-Object -Property hostGroup | ForEach-Object {$mr = @{}}{
#         if($_.Group.hostGroup -ne $null){
#             $mr[([array]$_.Group.hostGroup)[0]] = ($_.Group.consumedHostUnits | Measure-Object -Sum).sum
#         } else {
#             $mr['noHostGroup'] = ($_.Group.consumedHostUnits | Measure-Object -Sum).sum
#         }
#     } {$mr}
#     return $summaryout
# } else {
#     return $hostInfo
# }
