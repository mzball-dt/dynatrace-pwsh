<#
.SYNOPSIS
    Create a location for a Cluster Synthetic ActiveGate

.DESCRIPTION
    Assigning a new cluster-level synthetic node to a location for Dynatrace Managed can only currently be done through the API.
    This script has been made to ease the process by showing all unassigned cluster synthetic nodes and pulling location data from a pre-filled csv file.
    When in a Dynatrace Managed scenario the CSV would be filled with the required information of the environment's locations.

    CSV File format: 
        Name, DynatraceCountryCode, DynatraceRegionCode, DynatraceCityCode, CENTRE_LATITUDE, CENTRE_LONGITUDE

    !!! Warning !!! The CSV Format is not checked and running with less than specified headers will result in undefined behaviour

    Changelog: 
        v2.1
            Added scriptmode switch to enable integration with other scripts/workflows
            Updated API version to v2 - 1.204
            Updated API payload to include status
            Updated by Adrian Chen
        v2.0
            Updated variable name mismatch
            Updated by Adrian Chen
        v1.0
            Initial MVP by Michael Ball


    Examples: 
        ::TODO::

.NOTES
    Author: michael.ball adrian.chen
    Version: 2.1 - 20201221
    Requirement: Powershell v5.0
#>

<###########################
# Start of scaffold block #
###########################>

PARAM (
    # The Cluster to query and update
    [Parameter()][ValidateNotNullOrEmpty()] $dtcluster = $env:dtcluster,
    # Token with serviceProviderAPI access to 
    [Alias('dtclustertoken')][ValidateNotNullOrEmpty()][string] $clustertoken = $env:dtclustertoken,

    <##################################
    # Start of Script-specific params #
    ##################################>

    # elementID of the Synthetic node to assign to a location
    [switch] $syntheticNode,
    # Name of Location to create and assign the Node too
    [string] $locationName,
    # CSV File containing the location data for the location environment
    [String] $geoLocationsCSV = './geoLocations.csv',
    # use this switch to be interaction less 
    [switch] $scriptmode,
    # use this switch to be push a location without enabling it
    [switch] $disabled,

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

function confirm-supportedClusterVersion ($minimumVersion = 204, $logmsg = '') {
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

function confirm-requiredTokenPerms ($token, $requirePerms, $logmsg = '') {
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
    confirm-requiredTokenPerms $script:clustertoken $script:tokenPermissionRequirements
}

<#########################
# Stop of scaffold block #
#########################>
    
# List available unassigned Synthetic nodes
    
# Collect Nodes
$headers = @{
    Authorization  = "Api-Token $clusterToken"
    "Content-Type" = "application/json"
}

## Get Synthetic Nodes 
$res = Invoke-RestMethod -Method GET -Headers $headers -Uri "$dtcluster/api/cluster/v2/synthetic/nodes"
$nodes = $res.nodes

if (!$nodes -or $nodes.count -eq 0) {
    write-Warning "No synthetic nodes available."
    return
}

## Get Synthetic Locations
$res = Invoke-RestMethod -Method GET -Headers $headers -Uri "$dtcluster/api/cluster/v2/synthetic/locations"

## Check locations for the node
if ($res.count -ne 0) {
    $locations = $res.locations
    foreach ($location in $locations) { 
        $res = Invoke-RestMethod -Method GET -Headers $headers -Uri "$dtcluster/api/cluster/v2/synthetic/locations/$($location.entityId)" 
        ## Remove Nodes with assigned to a location
        if ($res.nodes.count -ne 0) { $res.nodes | ForEach-Object { $nodes = Where-Object { $nodes.entityId -ne $_ } } }
    }
}

## Return when all node are already assigned
if (!$nodes -or $nodes.count -eq 0) {
    write-Warning "No nodes available for assignment"
    return
}

if (!$syntheticNode) {
    # List nodes without locations
    #$nodes = $nodes | Where-Object -Property haslocation -eq -Value $false | Sort-Object -Property hostname
    $nodes = $nodes | ForEach-Object { $i = 0 } { $_ | Add-Member -MemberType NoteProperty -Name ID -Value ($i++); $_ }
    $nodes | Select-Object -Property id, hostname, version | Format-Table

    $ans = read-host "Which of the above unassigned nodes should be assigned?"
    $syntheticNode = $nodes | Where-Object -Property id -EQ -Value $ans
    if (!$syntheticNode.hostname) {
        Write-warning "No valid choice was made - exiting"
        return
    }
}
else {
    $syntheticNode = $nodes | Where-Object -Property entityId -EQ -Value $syntheticNode
}

write-host "Selected synthetic Node:"
$syntheticNode | Format-Table

if (!$locationName) {
    $ans = read-host "Which locationName is this node located at?"
    if (!$ans -or $ans.Length -ne 3) {
        Write-Warning "No locationName was provided"
    }

    $locationName = $ans
}

$getcsv = Get-Content $geoLocationsCSV | convertFrom-CSV

$locData = $getcsv | Where-Object -Property 'Name' -EQ -Value $locationName

$locData | Format-Table

write-host "Tie site '$($locData.name)' with $($syntheticNode.hostname)"
if (!$scriptmode) {
    $ans = read-host "y/n [y]"
    if ($ans -ne 'y' -and $ans -ne '') {
        write-host "Exiting script with no changes" -ForegroundColor DarkMagenta
        return
    }
}

Write-host "Continuing with synthetic node assignment" -ForegroundColor green

$deployedStatus = If ($disabled) { "DISABLED" } Else { "ENABLED" }

$locTemplate = @"
{
  "type": "CLUSTER",
  "name": "$locationName",
  "countryCode": "$($locData.DynatraceCountryCode)",
  "regionCode": "$($locData.DynatraceRegionCode)",
  "city": "$($locData.DynatraceCityCode)",
  "latitude": $($locData.CENTRE_LATITUDE),
  "longitude": $($locData.CENTRE_LONGITUDE),
  "status": "$($deployedStatus)",
  "nodes": [
    "$($syntheticNode.entityID)"
  ]
}
"@

$locTemplate

$res = Invoke-RestMethod -Method POST -Uri "$dtcluster/api/cluster/v2/synthetic/locations" -Headers $headers -Body $locTemplate

If ($res.entityID) {
    Write-host "Successful. Node [$($syntheticNode.entityID)] assigned to [$locationName] in [$deployedStatus] state." -ForegroundColor Green
}
