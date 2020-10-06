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

    # Requires Updating

.NOTES
    Author: michael.ball
    Version: 0.1 - 20191206
    Requirement: Powershell v5.0
#>

PARAM (
    # The Cluster to query and update
    [Parameter(Mandatory = $true)]$cluster,
    # Token with serviceProviderAPI access to 
    [Parameter(Mandatory = $true)]$clustertoken,
    # elementID of the Synthetic node to assign to a location
    [switch] $syntheticNode,
    # Name of Location to create and assign the Node too
    [string] $locationName,
    # CSV File containing the location data for the location environment
    [String] $geoLocationsCSV = './geoLocations.csv',
    # use this switch to tell powershell to ignore ssl concerns
    [switch] $nocheckcertificate
)

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
    public static void UnsetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = null; }
}
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
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocoltype]::Tls12
}
    
# List available unassigned Synthetic nodes
    
# Collect Nodes
$headers = @{
    Authorization  = "Api-Token $clusterToken"
    "Content-Type" = "application/json"
}
$res = Invoke-RestMethod -Method GET -Headers $headers -Uri "$cluster/api/cluster/v1/synthetic/nodes"
$nodes = $res.nodes

if (!$nodes -or $nodes.count -eq 0) {
    write-Warning "No nodes available for assignment"
    return
}

$nodes | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name hasLocation -Value $false }

if (!$syntheticNode) {
    $res = Invoke-RestMethod -Method GET -Headers $headers -Uri "$cluster/api/cluster/v1/synthetic/locations"

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
$ans = read-host "y/n [y]"
if ($ans -ne 'y' -and $ans -ne '') {
    write-host "Exiting script with no changes" -ForegroundColor DarkMagenta
    return
}

Write-host "Continuing with synthetic node assignment" -ForegroundColor green

$locTemplate = @"
{
  "type": "CLUSTER",
  "name": "$locationName",
  "countryCode": "$($locData.DynatraceCountryCode)",
  "regionCode": "$($locData.DynatraceRegionCode)",
  "city": "$($locData.DynatraceCityCode)",
  "latitude": $($locData.CENTRE_LATITUDE),
  "longitude": $($locData.CENTRE_LONGITUDE),
  "nodes": [
    "$($syntheticNode.entityID)"
  ]
}
"@

$locTemplate

$res = Invoke-RestMethod -Method POST -Uri "$cluster/api/cluster/v1/synthetic/locations" -Headers $headers -Body $locTemplate

If ($res.entityID) {
    Write-host "Successful Location up" -ForegroundColor Green
}
