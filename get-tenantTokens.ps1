<#
.Synopsis
    For auditing Tokens available in a given Dynatrace Tenant

.Description
    Very simple script to pull back information about the tokens created in a dynatrace tenant.

    Possible Extensions: 
        - Not squashing scopes?
        - reducing the number of api requests this script performs (not currently possible)

.Notes
    Author: Riley McClelland (original), Michael Ball (extension) 
    Version: 1.1.0

    ChangeLog
        1.1.0
            Added -outfile
            Added export to stdout
        1.0.0 MVP
            Things work - basic script


.Example  
    ./get-tenantTokens.ps1 -dtenv "https://lasjdh3.live.dynatrace.com/" -token 'asdfu12312938' | format-table

    revoked name                            userId                        created                       scopes                                                                                                                        id   
    ------- ----                            ------                        -------                       ------                                                                                                                        --    
    False Auto created memory dump token                                6/09/2017 8:07:46 AM +00:00   MemoryDump                                                                                                                    9d... 
    False devops-agent-registry-generated Cluster Token (name: DebugUI) 25/06/2018 10:47:00 AM +00:00 DiagnosticExport                                                                                                              82... 
    False devops-agent-registry-generated Cluster Token (name: DebugUI) 25/06/2018 10:33:23 AM +00:00 DiagnosticExport                                                                                                              47... 
    False all                             michael.ball@dynatrace.com    31/07/2018 1:11:39 AM +00:00  RumJavaScriptTagManagement,TenantTokenManagement,DataExport,LogExport,UserSessionAnonymization,MaintenanceWindows,DTAQLAccess a2... 
    False PoSH                            michael.ball@dynatrace.com    16/01/2018 1:21:44 PM +00:00  DataExport,MaintenanceWindows,RumJavaScriptTagManagement                                                                      31... 
    False K8s HOT                         michael.ball@dynatrace.com    14/08/2019 12:19:01 AM +00:00 InstallerDownload,SupportAlert                                                                                                4d...
    False K8s HOT Session                 michael.ball@dynatrace.com    14/08/2019 12:20:37 AM +00:00 DataExport                                                                                                                    e4... 
    False InstallerDownload               michael.ball@dynatrace.com    23/08/2017 12:00:20 PM +00:00 InstallerDownload                                                                                                             d6... 
    False dcrum                           michael.ball@dynatrace.com    23/08/2017 12:00:45 PM +00:00 DcrumIntegration                                                                                                              1d...
    False Synthetic Monitors Token        SyntheticTokenProviderWorker  1/03/2020 1:20:01 PM +00:00   WriteSyntheticData                                                                                                            7d... 
    False Synthetic Monitors Token        SyntheticTokenProviderWorker  3/03/2020 1:30:01 PM +00:00   WriteSyntheticData                                                                                                            77... 
    False Synthetic Monitors Token        SyntheticTokenProviderWorker  2/03/2020 1:25:01 PM +00:00   WriteSyntheticData                                                                                                            e3... 
#>

param(
    # The Dynatrace environment to query - this is the 'homepage' of the target eg. https://lasjdh3.live.dynatrace.com/ or https://dynatrace-managed.com/e/UUID
    [Parameter()][ValidateNotNullOrEmpty()] $dtenv = $env:dtenv,
    # The token to query the environment with - must have environment token config access
    [Alias('dttoken')][ValidateNotNullOrEmpty()][string] $token = $env:dttoken,

    # Path to output a csv representation of the fetched data.
    [string] $outfile,

    # Prints Help output
    [Alias('h')][switch] $help,
    # use this switch to tell this script to not check token or cluster viability
    [switch] $noCheckCompatibility,
    # use this switch to tell powershell to ignore ssl concerns
    [switch] $noCheckCertificate,

    # DO NOT USE - This is set by Script Author
    [String[]]$script:tokenPermissionRequirements = ('DataExport','TenantTokenManagement')
)

# Help flag checks
if ($h -or $help) {
    Get-Help $script:MyInvocation.MyCommand.Path -Detailed
    exit 0
}

# Ensure that dtenv and token are both populated
if (!$script:dtenv) {
    return Write-Error "dtenv was not populated - unable to continue"
    
} elseif (!$script:token) {
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
    $envType = 'cluster'
    if ($script:dtenv -like "*.live.dynatrace.com") {
        $envType = 'env'
    } elseif ($script:dtenv -like "http*://*/e/*") {
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
    if (($script:tokenPermissionRequirements | Where-Object {$_ -notin $res.scopes}).count) {
        write-host "Failed Token Permission check. Token requires: $($script:tokenPermissionRequirements -join ',')"
        write-host "Token provided only had: $($res.scopes -join ',')"
        return
    }
}

function convertTo-jsDate($date) {
    return [Math]::Floor(1000 * (Get-Date ($date) -UFormat %s))
}

$uri = "$baseURL/tokens"

write-host -ForegroundColor cyan $uri
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
}
else {
    $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -skipcertificatecheck
}

# iterate through the returned data to construct a PWSH Object, output and possibly save it
$data = @()
Foreach ($row in $response.values) {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $tokenDetail = Invoke-RestMethod -Method GET -Uri "$uri/$($row.id)" -Headers $headers
    }
    else {
        $tokenDetail = Invoke-RestMethod -Method GET -Uri "$uri/$($row.id)" -Headers $headers -skipcertificatecheck
    }

    $tokenDetail.created = [datetimeoffset]::FromUnixTimeMilliseconds($tokenDetail.created)
    if ($tokenDetail.lastUse) { $tokenDetail.lastUse = [datetimeoffset]::FromUnixTimeMilliseconds($tokenDetail.lastUse) }
    $tokenDetail.scopes = $tokenDetail.scopes -join ','
   
    $data += $tokenDetail
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
$data | Select-Object revoked,name,userId,created,scopes,id | Sort-Object -Property userId