<#
    .Synopsis
        For viewing or saving a Dynatrace tenant problem feed as Powershell tables and csv files

    .Description
        This script is to extract the problems for an environment for designated entities and period.
        And also present in a powershell or csv format.

        todo: 
        - Add a human readable date as startTimeNice and endTimeNice
        - Nicely order the $data prior to returning
        - Option to fetch human readable name of the problem (for summarising options)
        - support tags for filtering of problem feed

    .Notes
        Author: Adrian, Michael Ball
        Version: 1.0.0 - 16062020
        ChangeLog
            1.0.0 
                MVP - Things work
            1.0.1
                Commenting - adding of todo list, 
                Removal of stray output
                show problem detail default is now false
            
    .Example
        ./get-tenantProblemFeed.ps1 -dtenv <env> -token <token> -periodType "week" -timePeriod 3 -outfile test.csv
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

    # What period length should be reported
    [ValidateSet('minute', 'hour', 'day', 'week')][string]$periodType = 'hour',
    # How many of these time periods back should be requested
    [String]$timePeriod = 2,
    # Number of results to pull back
    [int]$pageSize = 500,
    # Path to output a csv representation of the fetched data.
    [ValidateNotNullOrEmpty()][string] $outfile,

    # Prints Help output
    [Alias('h')][switch] $help,
    # use this switch to tell this script to not check token or cluster viability
    [switch] $noCheckCompatibility,
    # use this switch to tell powershell to ignore ssl concerns
    [switch] $noCheckCertificate,

    # Flag to expand the details of the problem feed
    [switch] $expandDetail,
    
    # String entity for tags to be used as a filter
    [string] $tags,

    # DO NOT USE - This is set by Script Author
    [String[]]$script:tokenPermissionRequirements = @('DataExport')
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
        exit
    }

    confirm-supportedClusterVersion 176
    confirm-requireTokenPerms $script:token $script:tokenPermissionRequirements
}

function convertTo-jsDate($date) {
    return [Math]::Floor(1000 * (Get-Date ($date) -UFormat %s))
}

$timePeriodHash = @{
    minute = 1000 * 60;
    hour   = 1000 * 60 * 60;
    day    = 1000 * 60 * 60 * 24;
    week   = 1000 * 60 * 60 * 24 * 7;
}

<#
###########################
# End of scaffold block #
###########################
#>

## Form the base of the url endpoint to be queried
$baseURL = "$baseURL/problem/feed"

# Add the time and other params
$now = convertTo-jsDate ([datetime]::UtcNow)
$start = $now - $timePeriodHash[$script:periodType] * $script:timePeriod

$baseURL = $baseURL + "?startTimestamp=$start&endTimestamp=$now&expandDetails=$([string] $expandDetail)"

# Add the System.Web type - the lack of this will be a headache otherwise.
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue | Out-Null

## TODO ###
# Encode the tags
<# $filterTags = [System.Web.HttpUtility]::UrlEncode($script:USQL) -replace '\+', '%20' #>
 
# create the end URI with tags as a filter

if ([string]::IsNullOrEmpty($tag)) {
    $uri = $baseURL  
}
else {
    $uri = $baseURL + "&tag="
}

# Output the uri used as information event
write-host $uri -ForegroundColor Cyan

# make the call, being aware of different pwsh versions
try {
    $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers    
}
catch {
    Write-Error $_
    exit 1
}

$response.result.problems

## Create columnName variable to loop through
$columnName = ($response.result.problems | Get-Member -MemberType "NoteProperty").name

# iterate through the returned data to construct a PWSH Object, output and possibly save it
$data = @()
Foreach ($row in $response.result.problems) {
    $_row = New-Object PSObject

    for ($i = 0; $i -lt $columnName.Length; $i++) {
        ## Reduce System.Object[]  in outputs
        ## Expand the object into strings.
        if (($row.($columnName[$i]).GetType().Name) -ieq "Object[]") {
            [string] $objValue = ""
            foreach ($objs in $row.($columnName[$i])) {

                $objValue += [string] ($objs)
            }
            $_row | Add-Member -MemberType NoteProperty -Name $columnName[$i] -Value $objValue
        }
        else {
            $_row | Add-Member -MemberType NoteProperty -Name $columnName[$i] -Value $row.($columnName[$i])
        }
    }

    $data += $_row
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
    $data | ConvertTo-Csv -NoTypeInformation | out-file -FilePath $script:outfile
    write-host "Written to csv table to $($outputFile.fullname)" -ForegroundColor Green
}

$data