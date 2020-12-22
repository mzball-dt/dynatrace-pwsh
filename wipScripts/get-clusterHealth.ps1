<#
    .Synopsis
        A Basic Health Check script to quickly identify cluster / activeGate issues
    .Description
        This script performs a health check and provideds output of the results. 
    .Notes
        Author: Adrian Chen
        Version: 1.0.0 - <date> ## No date until 1.0.0 is available ##
        ChangeLog
            1.0.0 
                MVP - Things work
            
    .Example
        <PLACEHOLDER> - insert sample usage here
#>


<###########################
# Start of scaffold block #
###########################>

PARAM (
    # The health check target cluster 
    [Parameter()][ValidateNotNullOrEmpty()] $dtcluster = $env:dtcluster,
    # Token for target cluster w/ ServiceProviderAPI perms
    [Alias('dtclustertoken')][ValidateNotNullOrEmpty()][string] $clustertoken = $env:dtclustertoken,

    <##################################
    # Start of Script-specific params #
    ##################################>

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

# Ensure that dtcluster and token are both populated
if (!$script:dtcluster) {
    return Write-Error "Cluster URL was not populated - unable to continue"
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
    write-host -ForegroundColor DarkYellow -Object "WARNING: Removed trailing '/' from dtcluster input"
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

function confirm-supportedClusterVersion ($minimumVersion = 194, $logmsg = '') {
    # Cluster version check - cancel out if too old 
    $uri = "$script:dtcluster/api/v1.0/onpremise/cluster"
    Write-Host -ForegroundColor cyan -Object "Cluster Version Check$logmsg`: GET $uri"
    $res = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri 
    $clusterVersion = $res[0].buildVersion -split '\.'
    if ($clusterVersion -and ([int]$clusterVersion[0]) -ne 1 -and ([int]$clusterVersion[1]) -lt $minimumVersion) {
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

$sslErrorMsg = "Could not establish trust relationship"

$nodeInfo = @()

## Redefine baseURL
## Shorten baseURL as a mix of v1 and v2 are used 
$baseURL = "$script:dtcluster/api"

## Get Config from current cluster

Write-host "[Info]: Retrieving current cluster configuration information."

try {
    $res = Invoke-RestMethod -uri "$baseURL/v1.0/onpremise/cluster/configuration" -Headers $headers -ErrorAction Continue
}
catch {
    if ($_ -ilike "*$sslErrorMsg*") {
        Write-Host "Error: SSL Error, try re-run the script with -nocheckcertificate." -ForegroundColor Red
        Write-Host "Details: $($_.Exception)"
    }
    else {
        Write-Host "Error: $_" -ForegroundColor Red
        Write-host "[Error]: Failed to retrieve current cluster configuration information."
        Write-host "`t Cluster : $($dtcluster)"
    }
}

## Get the state of each node from the node
foreach ($node in $res.clusterNodes) {
    $_currentNode = New-Object PSObject
    
    ## Set node details

    ## TODO
    ## There is a better way of assigning the values, use the other method in next iterations
    $_currentNode | Add-Member -MemberType NoteProperty -Name "webUI" -Value $node.webUI
    $_currentNode | Add-Member -MemberType NoteProperty -Name "agent" -Value $node.agent
    $_currentNode | Add-Member -MemberType NoteProperty -Name "datacenter" -Value $node.datacenter
    $_currentNode | Add-Member -MemberType NoteProperty -Name "kubernetesRole" -Value $node.kubernetesRole
    $_currentNode | Add-Member -MemberType NoteProperty -Name "Id" -Value $node.Id
    $_currentNode | Add-Member -MemberType NoteProperty -Name "ipAddress" -Value $node.ipAddress

    ## Cluster Node Status Check 
    ## Also find out which node is the master definitively
    try {
        $res = $null
        $res = Invoke-RestMethod -uri "https://$($node.ipAddress):8021/api/v1.0/onpremise/nodeManagement/nodeServerStatus" -Headers $headers
        $_currentNode | Add-Member -MemberType NoteProperty -Name "master" -Value $res.master
        $_currentNode | Add-Member -MemberType NoteProperty -Name "operationState" -Value $res.operationState
    }
    catch {
        if ($_ -ilike "*$sslErrorMsg*") {
            Write-Host "Error: SSL Error, try re-run the script with -nocheckcertificate." -ForegroundColor Red
            Write-Host "Details: $($_.Exception)"
        }
        else {
            Write-Host "Error: $_" -ForegroundColor Red
        }
    }
    $nodeInfo += $_currentNode
}

## Test only Output 
#$nodeInfo | Format-Table
## TODO 
## Evaluation for a healthy node - webUI = true, agent = true, operationState = running

## Get firewall rules 
## Mismatch would indicate a node is blocked
try {
    $res = $null
    $res = Invoke-RestMethod -uri "$baseURL/v1.0/onpremise/firewallManagement/clusterNodes" -Headers $headers -ErrorAction Continue
}
catch {
    if ($_ -ilike "*$sslErrorMsg*") {
        Write-Host "Error: SSL Error, try re-run the script with -nocheckcertificate." -ForegroundColor Red
        Write-Host "Details: $($_.Exception)"
    }
    else {
        Write-Host "Error: $_" -ForegroundColor Red
    }
}

$res | Format-Table

## Synthetics Nodes (Synthetic enabled Cluster ActiveGates' health)
try {
    $res = $null
    $res = Invoke-RestMethod -uri "$baseURL/cluster/v2/synthetic/nodes" -Headers $headers -ErrorAction Continue
}
catch {
    if ($_ -ilike "*$sslErrorMsg*") {
        Write-Host "Error: SSL Error, try re-run the script with -nocheckcertificate." -ForegroundColor Red
        Write-Host "Details: $($_.Exception)"
    }
    else {
        Write-Host "Error: $_" -ForegroundColor Red
    }
}

$res | Format-Table
$activeGate

## Cluster ActiveGates' health - Not Offline = Healthy
try {
    $res = $null
    $res = Invoke-RestMethod -uri "$baseURL/cluster/v2/activeGates" -Headers $headers -ErrorAction Continue
}
catch {
    if ($_ -ilike "*$sslErrorMsg*") {
        Write-Host "Error: SSL Error, try re-run the script with -nocheckcertificate." -ForegroundColor Red
        Write-Host "Details: $($_.Exception)"
    }
    else {
        Write-Host "Error: $_" -ForegroundColor Red
    }
}

$res | Format-Table

## AG Port Check
try {
    if ((Get-Command Test-NetConnection).count -ne 0) {
        ## Use test net connections
    }
}
catch {
    ## Old OS without test-netconnection Only 
    $tcpClient = New-Object System.Net.Sockets.tcpClient

    $testConnection = $tcpClient.ConnectAsync($Computername, $Port)

    if ($testConnection.IsFaulted -eq $true) {

        $issues = $testConnection.Exception.InnerException
  
        Write-Warning  $issues
  
    }
    $tcpClient.Dispose() 
   
}
## TODO 
## License Consumption Heads up

## TODO 
## Leverage existing self-mon if present