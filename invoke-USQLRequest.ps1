<#
    .Synopsis
        Powershell script for viewing or saving Dynatrace USQL queries as Powershell tables and csv files

    .Description
        There's currently no well-supported way to export USQL table to file. This is a problem this simple script resolves.

        There is currently no checking done on inputs. Hopefully the Dynatrace server API will provide enough of an error.

        Future plans: 
            - Support timeperiod (currently stuck at last 2 hours)

    .Notes
        Author: Michael Ball
        Version: 1.0.0

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
    [Parameter(Mandatory=$true)][String]$dtenv,
    [Parameter(Mandatory=$true)][String]$token,
    [Parameter(Mandatory=$true)][String]$USQL,
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

# create a baseURL for the API call
$baseURL = "https://$script:dtenv/api/v1/userSessionQueryLanguage/table"
 
# Encode the query (required by the call)
$query = [System.Web.HttpUtility]::UrlEncode($script:USQL) -replace '\+', '%20'
 
# create the end URI
$uri = "$baseURL`?query=$query"
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
 
if ($script:outfile) {
    write-host "Writing to csv table to $script:outfile" -ForegroundColor red
    $data | ConvertTo-Csv -NoTypeInformation | out-file -FilePath $script:outfile
}

$data | Format-Table