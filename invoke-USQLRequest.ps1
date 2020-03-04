<#
    .Synopsis
        Powershell script for viewing or saving Dynatrace USQL queries as Powershell tables and csv files

    .Description
        There's currently no well-supported way to export USQL table to file. This is a problem this simple script resolves.

        There is currently no checking done on inputs. Hopefully the Dynatrace server API will provide enough of an error.

    .Notes
        Author: Michael Ball
        Version: 1.1.0

        ChangeLog
            1.0.0 
                MVP - Things work
            1.1.0
                - Added -periodType and timePeriod to specify time for reported data. 
                - Added pageSize to map to the dt api pagesize var
                - Minimal cleanup/checking of dtenv input (they come in all shapes and sizes)
                - Removed the return as a format-table -- this was a bad idea, users should be the one parsing the output to format-table

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

param(
    # The Dynatrace environment to query - this is the 'homepage' of the target eg. https://lasjdh3.live.dynatrace.com/ or https://dynatrace-managed.com/e/UUID
    [Parameter(Mandatory=$true)][String]$dtenv,
    # The token to query the environment with - much have User Session access
    [Parameter(Mandatory=$true)][String]$token,
    # The USQL Query to run against the cluster
    [Parameter(Mandatory=$true)][String]$USQL,
    # What period length should be reported
    [ValidateSet('minute','hour','day', 'week')][string]$periodType = 'hour',
    # How many of these time periods back should be requested
    [String]$timePeriod = 2,
    # Number of results to pull back
    [int]$pageSize = 500,
    
    # Export the collected USQL to csv
    [String]$OutFile
)

function convertTo-jsDate($date) {
    return [Math]::Floor(1000 * (Get-Date ($date) -UFormat %s))
}

$timePeriodHash = @{
    minute = 1000*60;
    hour = 1000*60*60;
    day = 1000*60*60*24;
    week = 1000*60*60*24*7;
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
if ($baseURL[$baseURL.Length-1] -eq '/') {$baseURL = $baseURL.Substring(0, $baseURL.Length-2)}
if ($baseURL -notmatch '^https?://') {$baseURL = "https://$baseURL"}
$baseURL = "$baseURL/api/v1/userSessionQueryLanguage/table"

# Add the time and other params
$now = convertTo-jsDate ([datetime]::UtcNow)
$start = $now - $timePeriodHash[$script:periodType] * $script:timePeriod

$baseURL = $baseURL + "?startTimestamp=$start&endTimestamp=$now&pageSize=$script:pageSize"
 
# Encode the query (required by the call)
$query = [System.Web.HttpUtility]::UrlEncode($script:USQL) -replace '\+', '%20'
 
# create the end URI
$uri = "$baseURL`&query=$query"
write-host $uri -ForegroundColor Cyan

# make the call, being aware of different pwsh versions
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
} else {
    $response = Invoke-RestMethod -Method GET  -Uri $uri -Headers $headers -skipcertificatecheck
}

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
    if (!(Split-Path $script:outfile| Test-Path -PathType Container)) {
        New-Item -Path (Split-Path $script:outfile) -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
    }
    $outputFile = New-Item -Path $script:outfile -Force
    $data | ConvertTo-Csv -NoTypeInformation | out-file -FilePath $script:outfile
    write-host "Written to csv table to $($outputFile.fullname)" -ForegroundColor Green
}

# Output
$data