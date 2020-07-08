<#
.Synopsis
    Retrieve and nicely label the performance/availability of the synthetic monitors in an environment
    
.Description
    
.Notes
    Author: Michael Ball
    Version: 0.0.a

    ChangeLog
        0.0.a
            This is disgusting - ignore
        
.Example
#>

param(
    # The Dynatrace environment to query - this is the 'homepage' of the target eg. https://lasjdh3.live.dynatrace.com/ or https://dynatrace-managed.com/e/UUID
    [Parameter(Mandatory=$true)][String]$dtenv,
    # The token to query the environment with - much have User Session access
    [Parameter(Mandatory=$true)][String]$token,
        
    # Export the collected USQL to csv
    [String]$OutFile
)

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