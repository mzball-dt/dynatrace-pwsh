<#
.SYNOPSIS
    Take a backup of one, some or all configurations available through the Dynatrace Tenant API    

.DESCRIPTION
    Exports all the configurations available to a folder.

    Currently very barebones - doesn't do the whole environment.

.NOTES
    Author: michael.ball
    Version: 0.1 - 20200423
    Requirement: Powershell v5.0

    Changelog
        0.1 - MVP
            Initial MVP that mostly works

#>

PARAM (
    # The cluster or tenant the HU report should be fetched from
    [Parameter()][ValidateNotNullOrEmpty()] $dtenv = $env:dtenv,
    # Token must have Smartscape Read access for a tenant
    [Alias('dttoken')][ValidateNotNullOrEmpty()][string] $token = $env:dttoken,

    # Filter the api list with this string
    [string] $filter,
    # Path folder to place all exported tenant config in
    [string] $outputFolder,
    # Always create a file, even if there is no relevant config
    ##[switch] $createEmptyConfigFiles,

    # Prints Help output
    [Alias('h')][switch] $help,
    # use this switch to tell this script to not check token or cluster viability
    [switch] $noCheckCompatibility,
    # use this switch to tell powershell to ignore ssl concerns
    [switch] $noCheckCertificate,

    # DO NOT USE - This is set by Script Author
    [String[]]$script:tokenPermissionRequirements = @('DataExport', 'ReadConfig')
)

write-warning "I don't consider this script complete - it's unlikely to completely export the config of your environment at the moment"

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
    $script:envType = 'cluster'
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
    if ($envVersion -and ([int]$envVersion[0]) -ne 1 -and ([int]$envVersion[1]) -lt 180) {
        write-host "Failed Environment version check - Expected: > 1.180 - Got: $($res.version)"
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

$configApis = @"
[
    {uri: 'alertingProfiles', type: 'id_list'},
    {uri: 'anomalyDetection/applications', type: 'simple'},
    {uri: 'anomalyDetection/databaseServices', type: 'simple'},
    {uri: 'anomalyDetection/diskEvents', type: 'id_list'},
    {uri: 'anomalyDetection/hosts', type: 'simple'},
    {uri: 'anomalyDetection/metricEvents', type: 'id_list'},
    {uri: 'anomalyDetection/services', type: 'simple'},
    {uri: 'anomalyDetection/vmware', type: 'simple'},
    {uri: 'applicationDetectionRules', type: 'id_list'},
    {uri: 'autoTags', type: 'id_list'},
    {uri: 'aws/credentials', type: 'id_list'},
    {uri: 'azure/credentials', type: 'id_list'},
    {uri: 'calculatedMetrics/log', type: 'id_list'},
    {uri: 'calculatedMetrics/mobile', type: 'id_list'},
    {uri: 'calculatedMetrics/service', type: 'id_list'},
    {uri: 'calculatedMetrics/synthetic', type: 'id_list'},
    {uri: 'calculatedMetrics/rum', type: 'id_list'},
    {uri: 'cloudFoundry/credentials', type: 'id_list'},
    {uri: 'credentialVault', type: 'id_list'},
    {uri: 'dashboards', type: 'id_list'},
    {uri: 'dataPrivacy', type: 'id_list'},
    {uri: 'frequentIssueDetection', type: 'simple'},
    {uri: 'kubernetes/credentials', type: 'id_list'},
    {uri: 'maintenanceWindows', type: 'id_list'},
    {uri: 'managementZones', type: 'id_list'},
    {uri: 'notifications', type: 'id_list'},
    {uri: 'plugins', type: 'id_list'},
    {uri: 'remoteEnvironments', type: 'id_list'},
    {uri: 'reports', type: 'id_list'},
    {uri: 'service/customServices/dotNet', type: 'id_list'},
    {uri: 'service/customServices/go', type: 'id_list'},
    {uri: 'service/customServices/java', type: 'id_list'},
    {uri: 'service/customServices/nodeJS', type: 'id_list'},
    {uri: 'service/customServices/php', type: 'id_list'},
    {uri: 'service/detectionRules/FULL_WEB_REQUEST', type: 'id_list'},
    {uri: 'service/detectionRules/FULL_WEB_SERVICE', type: 'id_list'},
    {uri: 'service/detectionRules/OPAQUE_AND_EXTERNAL_REQUEST', type: 'id_list'},
    {uri: 'service/ibmMQTracing/queueManager', type: 'id_list'},
    {uri: 'service/ibmMQTracing/imsEntryQueue', type: 'id_list'},
    {uri: 'service/requestAttributes', type: 'id_list'},
    {uri: 'service/requestNaming', type: 'id_list'},
    {uri: 'applications/web', type: 'id_list', idSuffix: ['dataPrivacy']}
]
"@

# convert into usable format
$configApis = $configApis | ConvertFrom-Json

# Apply the optional filter to the list of config apis
if ($script:filter) {
    $configApis = $configApis | Where-Object -Property uri -Like -Value $script:filter
}

# setup an output folder if none was provided
if (!$script:outputfolder) {
    $currentLoc = Get-Location
    $tenantName = if ($script:dtenv -like "*live.dynatrace.com*") {
        [regex]::Match("$script:dtenv", "([a-z0-9]+)\.live\.dynatrace").Groups[1].value
    } else {
        [regex]::Match("$script:dtenv", "/e/([a-z0-9\-]+)").Groups[1].value
    }
    $date = get-date -Format yyyyMMdd

    # Make the output folder
    $script:outputfolder = Join-Path $currentLoc "configBackup-$tenantName-$date"
    $newlymadeFolder = New-Item -ItemType Directory -Path $script:outputfolder -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Green "Created output folder: $($newlymadeFolder.fullname)"
}

# get new baseURL
$baseURL = "$script:dtenv/api/config/v1"

foreach ($api in $configApis) {
    # create a baseURL for the API call
    $uri = "$baseURL/$($api.uri)"

    write-host -ForegroundColor cyan "Config Read Request from: $uri"
    $r = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri
    write-host -ForegroundColor White "Recieved $(($r | ConvertTo-Json -Depth 10 -Compress).length) Bytes of data"

    # do what's required for each API endpoint type
    switch ($api.type) {
        'simple' {
            # write the configuration as json to a file
            $_filename = $api.uri -replace '/','.'
            $outfile = Join-Path $script:outputFolder "$_filename.json"

            write-host "Saving to $outfile"
            $r | ConvertTo-Json -Depth 20 -Compress | Out-File -Encoding utf8 -FilePath $outfile
        }
        'id_list' { 
            # resolve each of the Ids and save
            foreach ($idval in $r.values) {
                $_uri = "$uri/$($idval.id)"
                write-host -ForegroundColor cyan "Config Read Request from: $_uri"
                $idr = Invoke-RestMethod -Method GET -Headers $headers -Uri $_uri
                
                $_filename = "$($api.uri)/$($idval.name)" -replace '/','.'
                $outfile = Join-Path $script:outputfolder "$_filename.json"

                write-host "Saving to $outfile"
                $idr | ConvertTo-Json -Depth 20 -Compress | Out-File -Encoding utf8 -FilePath $outfile

                if ($api.idSuffix) {
                    $_uri = "$uri/$($idval.id)/$($api.idSuffix)"
                    write-host -ForegroundColor cyan "Config Read Request from: $_uri"
                    $idr = Invoke-RestMethod -Method GET -Headers $headers -Uri $_uri
                    
                    $_filename = "$($api.uri)/$($idval.name)/$($api.idSuffix)" -replace '/','.'
                    $outfile = Join-Path $script:outputfolder "$_filename.json"

                    write-host "Saving to $outfile"
                    $idr | ConvertTo-Json -Depth 20 -Compress | Out-File -Encoding utf8 -FilePath $outfile
                }
            }
        }
        Default {
            Write-Error "$($api.uri) configuration had an unknown or invalid type of '$($api.type)')"
        }
    }
}