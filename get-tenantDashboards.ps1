<#
.Synopsis
    For reporting on all dashboards in a specific Dynatrace Tenant

.Description
    Very simple script to pull back information about the Dashboards created in a dynatrace tenant.

    Possible Extensions: 
        - Additional processing of the dashboard contents
        - Exporting all or specific dashboards to disk
        - reducing the number of api requests this script performs (not currently possible)

.Notes
    Author: Michael Ball
    Version: 1.0.0 - 20200323

    ChangeLog
        1.0.0
            MVP - Things work - basic script
        
.Example  
    ./get-tenantDashboards.ps1 -dtenv "https://lasjdh3.live.dynatrace.com/" -token 'asdfu12312938' | format-table
#>

param(
    # The Dynatrace environment to query - this is the 'homepage' of the target eg. https://lasjdh3.live.dynatrace.com/ or https://dynatrace-managed.com/e/UUID
    [Parameter(Mandatory = $true)][String]$dtenv,
    # The token to query the environment with - must have environment token config access
    [Parameter(Mandatory = $true)][String]$token,

    # Show a subset of information collected
    [switch]$short,
    
    # Export the collected USQL to csv
    [String]$OutFile
)

function convertTo-jsDate($date) {
    return [Math]::Floor(1000 * (Get-Date ($date) -UFormat %s))
}

# custom policy required required for old pwsh versions and bad SSLs
if ($PSVersionTable.PSVersion.Major -lt 6) {
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

# Construct the headers for this API request
$headers = @{
    Authorization  = "Api-Token $script:token"
    "Content-Type" = "application/json"
}

# Do some clean up on baseURL and then prep for the API call
$baseURL = $script:dtenv
if ($baseURL[$baseURL.Length - 1] -eq '/') { $baseURL = $baseURL.Substring(0, $baseURL.Length - 2) }
if ($baseURL -notmatch '^https?://') { $baseURL = "https://$baseURL" }
$baseURL = "$baseURL/api/config/v1/dashboards"

write-host -ForegroundColor cyan $baseURL
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $response = Invoke-RestMethod -Method GET -Uri $baseURL -Headers $headers
}
else {
    $response = Invoke-RestMethod -Method GET -Uri $baseURL -Headers $headers -skipcertificatecheck
}

# iterate through the returned data to construct a PWSH Object, output and possibly save it
$data = @()
Foreach ($row in $response.dashboards) {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $completeDashboard = Invoke-RestMethod -Method GET -Uri "$baseURL/$($row.id)" -Headers $headers
    }
    else {
        $completeDashboard = Invoke-RestMethod -Method GET -Uri "$baseURL/$($row.id)" -Headers $headers -skipcertificatecheck
    }

    $dashboardSummary = New-Object psobject
    $dashboardSummary | Add-Member -MemberType NoteProperty -Name "Owner" -Value $completeDashboard.dashboardMetadata.owner
    $dashboardSummary | Add-Member -MemberType NoteProperty -Name "Name" -Value $completeDashboard.dashboardMetadata.name
    $dashboardSummary | Add-Member -MemberType NoteProperty -Name "Shared" -Value $completeDashboard.dashboardMetadata.shared
    $dashboardSummary | Add-Member -MemberType NoteProperty -Name "SharedViaLink" -Value $completeDashboard.dashboardMetadata.sharingDetails.linkShared
    $dashboardSummary | Add-Member -MemberType NoteProperty -Name "Published" -Value $completeDashboard.dashboardMetadata.sharingDetails.published
    $dashboardSummary | Add-Member -MemberType NoteProperty -Name "ManagementZone" -Value ($completeDashboard.dashboardMetadata.dashboardFilter.managementZone.name, "" -ne $null)[0]
    $dashboardSummary | Add-Member -MemberType NoteProperty -Name "NumberOfTiles" -Value $completeDashboard.tiles.count
    $dashboardSummary | Add-Member -MemberType NoteProperty -Name "DefaultTimeFrame" -Value $completeDashboard.dashboardMetadata.dashboardFilter.timeframe
    $dashboardSummary | Add-Member -MemberType NoteProperty -Name "ManagementZoneID" -Value ($completeDashboard.dashboardMetadata.dashboardFilter.managementZone.id, "" -ne $null)[0]
    $dashboardSummary | Add-Member -MemberType NoteProperty -Name "id" -Value $completeDashboard.id

    $data += $dashboardSummary
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
if ($short) {
    $data | Select-Object -Property Owner,Name,Shared,Published,ManagementZone | Sort-Object -Property owner,name
} else {
    $data | Sort-Object -Property owner,name
}
