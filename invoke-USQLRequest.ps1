<#
    .Synopsis
        For viewing or saving Dynatrace USQL queries as Powershell tables and csv files

    .Description
        There's currently no well-supported way to export USQL table to file. This is a problem this simple script resolves.

    .Notes
        Author: Michael Ball
        Version: 1.2.0 - 20200506

        ChangeLog
            1.2.0
                Updated with new standard scaffolding
                Implicitly loaded System.web prior to urlencode to hopefully prevent any issues with that being missing
            1.1.0
                - Added -periodType and timePeriod to specify time for reported data. 
                - Added pageSize to map to the dt api pagesize var
                - Minimal cleanup/checking of dtenv input (they come in all shapes and sizes)
                - Removed the return as a format-table -- this was a bad idea, users should be the one parsing the output to format-table
            1.0.0 
                MVP - Things work
            

    .Example
        ./invoke-usqlRequest.ps1 -dtenv id.live.dynatrace.com -token $(get-content token.file) -USQL 'select city from usersession'

        city
        ----
        Hong Kong (Azure)
        Sydney (Amazon)
        New South Wales (Azure)
        New South Wales (Azure)
        São Paulo (Amazon)
        Jakarta (Alibaba)
        ...
#>

PARAM (
    # The cluster or tenant the HU report should be fetched from
    [Parameter()][ValidateNotNullOrEmpty()] $dtenv = $env:dtenv,
    # Token must have Smartscape Read access for a tenant
    [Alias('dttoken')][ValidateNotNullOrEmpty()][string] $token = $env:dttoken,

    # The USQL Query to run against the cluster
    [ValidateNotNullOrEmpty()][String]$USQL,
    # What period length should be reported
    [ValidateSet('minute', 'hour', 'day', 'week')][string]$periodType = 'hour',
    # How many of these time periods back should be requested
    [String]$timePeriod = 2,
    # Number of results to pull back
    [int]$pageSize = 500,
    # Path to output a csv representation of the fetched data.
    [string] $outfile,

    # Prints Help output
    [Alias('h')][switch] $help,
    # use this switch to tell this script to not check token or cluster viability
    [switch] $noCheckCompatibility,
    # use this switch to tell powershell to ignore ssl concerns
    [switch] $noCheckCertificate,

    # DO NOT USE - This is set by Script Author
    [String[]]$script:tokenPermissionRequirements = @('DTAQLAccess', 'DataExport')
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
elseif (!$script:USQL) {
    return Write-Error "USQL argument was not populated - unable to continue"
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
    if ($envVersion -and ([int]$envVersion[0]) -ne 1 -and ([int]$envVersion[1]) -lt 176) {
        write-host "Failed Environment version check - Expected: > 1.176 - Got: $($res.version)"
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

$timePeriodHash = @{
    minute = 1000*60;
    hour   = 1000*60*60;
    day    = 1000*60*60*24;
    week   = 1000*60*60*24*7;
}

$baseURL = "$baseURL/userSessionQueryLanguage/table"

# Add the time and other params
$now = convertTo-jsDate ([datetime]::UtcNow)
$start = $now - $timePeriodHash[$script:periodType] * $script:timePeriod

$baseURL = $baseURL + "?startTimestamp=$start&endTimestamp=$now&pageSize=$script:pageSize"

# Add the System.Web type - the lack of this will be a headache otherwise.
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue | Out-Null

# Encode the query (required by the call)
$query = [System.Web.HttpUtility]::UrlEncode($script:USQL) -replace '\+', '%20'
 
# create the end URI
$uri = "$baseURL`&query=$query"
write-host $uri -ForegroundColor Cyan

# make the call, being aware of different pwsh versions
$response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers

# iterate through the returned data to construct a PWSH Object, output and possibly save it
$data = @()
Foreach ($row in $response.values) {
    $_row = New-Object PSObject
 
    for ($i = 0; $i -lt $response.columnNames.Length; $i++) {
        $_row | Add-Member -MemberType NoteProperty -Name $response.columnNames[$i] -Value $row[$i]
    }
   
    $data += $_row
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
$data