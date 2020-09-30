<#
    .Synopsis
        Return information about Maintenance Windows configured in a Dynatrace Tenant
    .Description
        Simple script to return information about configured Maintenance Windows.
        This script is read-only and requires users use the set-tenantMaintenanceWindow script to change things in the Dynatrace Tenant

        This script does it's best to follow the standards of the mzball-dt/utils repo and match the Get-*/Set-* cmdlets available in Powershell.

        Todo: 
            - implement -filter to filter the MW's on the initial get and then only expand upon those that match
            - implement -id to only return information about the id that's requested
    .Notes
        Author: Michael Ball
        Version: 0.1.0-beta - 20201001
        ChangeLog
            0.1.0-beta - 20201001
                Everything works but for requesting specific IDs or filtering on Name/description keywords
            
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

    [Parameter(ValueFromPipeline = $true)] $inputObject,
    [Parameter(ValueFromPipelineByPropertyName = $true)] $id,
    [switch] $short,

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
    [String[]]$script:tokenPermissionRequirements = @('DataExport', 'ReadConfig')
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
    if ($envVersion -and ([int]$envVersion[0]) -ne 1 -and ([int]$envVersion[1]) -lt $minimumVersion) {
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
    
    # check that other requirements are met
    confirm-supportedClusterVersion 184
    confirm-requiredTokenPerms $script:token $script:tokenPermissionRequirements
}

function convertTo-jsDate($date) {
    return [Math]::Floor(1000 * (Get-Date ($date) -UFormat %s))
}

<#
###########################
# End of scaffold block #
###########################
#>

## Add API CALL

$uri = "$script:dtenv/api/config/v1/maintenanceWindows"
Write-host -ForegroundColor cyan "Get list of Maintenance Windows: GET $uri"
$response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers

if ($short) {
    return $response.values
}

# iterate through the returned data to construct a PWSH Object, output and possibly save it
$data = @()
Foreach ($row in $response.values) {
    $mwData = Invoke-RestMethod -Method GET -Uri "$uri/$($row.id)" -Headers $headers
    
    $mwNice = New-Object psobject
    $mwNice | Add-Member -MemberType NoteProperty -Name "Name" -Value $mwData.name
    $mwNice | Add-Member -MemberType NoteProperty -Name "id" -Value $mwData.id
    $mwNice | Add-Member -MemberType NoteProperty -Name "Type" -Value $mwData.type
    $mwNice | Add-Member -MemberType NoteProperty -Name "Suppression" -Value $mwData.suppression
    $mwNice | Add-Member -MemberType NoteProperty -Name "Description" -Value $mwData.description
    $mwNice | Add-Member -MemberType NoteProperty -Name "Schedule-Type" -Value $mwData.schedule.recurrenceType
    $mwNice | Add-Member -MemberType NoteProperty -Name "Schedule-ReoccurancePattern" -Value $mwData.schedule.recurrence
    $mwNice | Add-Member -MemberType NoteProperty -Name "Schedule-Start" -Value $mwData.schedule.start
    $mwNice | Add-Member -MemberType NoteProperty -Name "Schedule-End" -Value $mwData.schedule.end
    $mwNice | Add-Member -MemberType NoteProperty -Name "Schedule-Timezone" -Value $mwData.schedule.zoneID
    $mwNice | Add-Member -MemberType NoteProperty -Name "Scope-Entities" -Value $mwData.scope.entities
    $mwNice | Add-Member -MemberType NoteProperty -Name "Scope-Matches" -Value $mwData.scope.matches

    $data += $mwNice
}

return $data
