<#
.SYNOPSIS
    Helper script for running tenant targeted scripts against collections of tenants (such as all tenants in a Dynatrace Managed Cluster)

.DESCRIPTION
    This script takes a scriptblock (arbitrary powershell code enclosed with '{}') and then executes in a parrallel-esque manner. The critical piece is that the code in the scriptblock has access to 2 dynamic variables that represent a tenant and a token for use with that tenant. This enables scripts written to retrieve/set data in 1 tenant to be run against all tenants in a dynatrace managed cluster.

    Possible usecases
        * Renaming the default application
        * Setting a particular setting
        * making sure noone did something dumb with custom services
        * enabling auto-updates cluster wide
        * reporting on host config across a cluster
        * pulling back a complete smartscape view
        * anything you would want from more than one tenant
    
.EXAMPLE
./invoke-clusterwide.ps1 -scriptblock {
    & C:\scripts\set-dtconfiguration.ps1 -tenant $_tenant -tenanttoken $_token -file C:\scripts\config\PROD-ENV\prod.json    
} | format-table

.EXAMPLE 
./invoke-clusterwide.ps1 {
    $ "$_localdir\otherScript.ps1" -tenant $_tenant -token $_token -importantparam one -otherparam
} | sort-object -property tenant | format-table

.NOTES
    Author: michael.ball
    Version: 2.0.0 - 20200907
    Requirement: Powershell v5.0

    Changelog:  
        2.0.0
            By default 'discovers' and executes $Scriptblock against all tenants in the cluster
            Target tenants can be filtered using $tenantId/$filter/$tag parameters
            Creates and deletes a Environment Token Management Token during execution for token creation in tenants


        1.1.0
            Updated to use the Cluster v2 API
        1.0.0
            Don't know why this wasn't v1? 
            Now also passes through the name provided in the CSV structure for better naming reasons
                - $_envname and $env:dtenvname are now available to child scripts.      
        0.0.3
            Script block no starts in the same directory as the current shell
            Added -tenantsCSVFile for if someone wants to specify an alternate place the tenant data is stored
        0.0.2
            Added input checks
            Added -help switch
            script block now has access to the env:dtenv and env:dttoken envvars
        MVP
            Uses the jobbing system from Strippy to create a scripting environment for each tenant with 2 prefilled variables
            Returns all output from the jobs run for each tenant as an array.

#>

<###########################
# Start of scaffold block #
###########################>

PARAM (
    # The cluster or tenant the Dasboard will be placed in
    [Parameter()][ValidateNotNullOrEmpty()] $dtcluster = $env:dtcluster,
    # Token for the destination tenant w/ DataExport and WriteConfig perms
    [Alias('dtclustertoken')][ValidateNotNullOrEmpty()][string] $clustertoken = $env:dtclustertoken,

    <##################################
    # Start of Script-specific params #
    ##################################>

    # A specific tenant (by name) from the list of known tenants
    [ValidateNotNullOrEmpty()][String] $tenantid,
    # An 'include' filter applied to the tenant names in a cluster
    [ValidateNotNullOrEmpty()][String] $filter,
    # A list of tags must all be present for a tenant to be included
    [ValidateNotNullOrEmpty()][String[]] $tag,

    # The Script block to execute for each tenant
    [Parameter(ValueFromPipeline = $true)][scriptblock] $ScriptBlock,

    # required Token perms
    [ValidateNotNullOrEmpty()][String[]] $envtokenPerms = @("DataExport", "ReadConfig", "WriteConfig", "DTAQLAccess", "TenantTokenManagement", "ReadSyntheticData", "ReadAuditLogs", "entities.read", "networkZones.read", "activeGates.read"),
    # The token expiry time in seconds for any tokens we can't delete
    [ValidateNotNullOrEmpty()][String[]] $envTokenActiveTime = 60,

    # Use this switch to list the internal tenants (w/o tokens)
    [switch] $list,

    # Maximum Concurrent Jobs managed by this script
    [int] $maxJobs = 8,
    # Time between each loop of creating and checking jobs
    [int] $JobDelay = 100,

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
    [String[]]$script:tokenPermissionRequirements = @('ServiceProviderAPI', 'ClusterTokenManagement')
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

function confirm-supportedClusterVersion ($minimumVersion = 194, $logmsg = '') {
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

function confirm-requireTokenPerms ($token, $requirePerms, $logmsg = '') {
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
    confirm-requireTokenPerms $script:clustertoken $script:tokenPermissionRequirements
}

<#########################
# Stop of scaffold block #
#########################>

if ( -not $script:ScriptBlock -and -not $script:list) {
    write-host -ForegroundColor Red "No Script block was provided - nothing happened"
    exit
}

# Assemble the list of tenants we're working on
$baseURL = "$script:dtcluster/api/cluster/v2"
$uri = "$baseURL/environments"

$script:tenantList = @()
# Did they specify an id?
if ( $script:id ) {
    $uri += "/$script:id"
    write-host -ForegroundColor Cyan "Fetching environment based on provided ID: GET $uri"
    $res = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri

    $script:tenantList = @($res)
}
# If they gave us something more generic
else {
    $uri += "?pageSize=500"
    $filtersPrefix = "&filter="
    $filters = @()
    $filters += if ($script:filter) { 'name("' + $script:filter + '")' }
    $filters += if ($script:tag) { 'tag("' + ($script:tag -join '","') + '")' }
    $filters += 'state(ENABLED)'
    $uri += ($filtersPrefix + ($filters -join ','))
    
    write-host -ForegroundColor Cyan "Fetching environments based on provided options: GET $uri"
    $res = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri

    if ($res.totalCount -lt 1) {
        write-host "Could not find any tenants matching your request" -ForegroundColor Red
        exit
    }

    $script:tenantList = $res.environments
}

if ($script:list) {
    Write-host "Internal tenantlist contains the following:"
    return $script:tenantList
}

try {
    # Create a new EnvironmentTokenManagement token
    $body = @"
{
    "name": "_Transienttoken_ created by run-clusterwide.ps1",
    "expiresIn": {"value": 1,"unit": "HOURS"},
    "scopes": ["EnvironmentTokenManagement"]
}
"@
    $uri = "$baseURL/tokens"
    write-host -ForegroundColor Cyan "Creating temporary temporary management token: POST $uri"
    $res = Invoke-RestMethod -Method POST -Headers $headers -Uri $uri -Body $body -ErrorAction stop
    $script:ETMToken = $res.token
}
catch {
    return Write-Error "Unable to create a temporary token with the scope 'EnvironmentTokenManagement'`n$_"
}

$ETMHeader = @{
    'Authorization' = "Api-Token $script:ETMToken";
    'Accept'        = "application/json; charset=utf-8";
    "Content-Type"  = "application/json; charset=utf-8"
}
$ETMBody = @"
{
    "name": "!!Temporary Token!! - Created for run-clusterwide.ps1 - $(get-date -UFormat "%Y%m%d.%H%M")",
    "expiresIn": {"value": 3600,"unit": "SECONDS"}
}
"@

# Create a short-term token for each of the target environments
$tempEnvTokens = $tenantList | ForEach-Object { $o = @() } {
    # create a new token in the environment
    $uri = "$baseURL/environments/$($_.id)/tokenManagementToken"
    write-host -ForegroundColor Cyan "Creating TokenManagementToken: POST $uri"
    $TokenManagementRes = Invoke-RestMethod -Method POST -Headers $ETMHeader -Uri $uri -Body $ETMBody

    $rooturi = "$script:dtcluster/e/$($_.id)"
    $uri = "$rooturi/api/v1/tokens"
    $envHeader = @{
        'Authorization' = "Api-Token $($TokenManagementRes.token)";
        'Accept'        = "application/json; charset=utf-8";
        "Content-Type"  = "application/json; charset=utf-8"
    }
    $body = @"
    {
        "name": "Temporary ScriptToken",
        "expiresIn": {"value": 120,"unit": "SECONDS"},
        "scopes": $($envtokenPerms | ConvertTo-Json)
    }
"@
    write-host -ForegroundColor Cyan "Creating Token for execution against $($_.name): POST $uri"
    $envRes = Invoke-RestMethod -Method POST -Headers $envHeader -Uri $uri -Body $body

    $_o = New-Object -TypeName psobject 
    $_o | Add-Member -Type NoteProperty -Name env -Value $_.id
    $_o | Add-Member -Type NoteProperty -Name uri -Value $rooturi
    $_o | Add-Member -Type NoteProperty -Name scriptToken -Value $envRes.token
    $_o | Add-Member -Type NoteProperty -Name tokenManagementToken -Value $TokenManagementRes.token

    $o += $_o
    
} { $o }

$_tp = 710563
<#
    x = new job checking loop
    | = job completed
    . = job started
    Manage-Job taken from https://github.com/cavejay/strippy
#>
function Manage-Job ([System.Collections.Queue] $jobQ, [int] $MaxJobs = 8, $delay = 200) {
    write-host "[START] Managing Job Execution"
    write-information "Clearing all background jobs (again just in case)"
    Get-Job | Stop-Job
    Get-job | Remove-Job
    write-information "done"

    $totalJobs = $jobQ.count
    $ProgressInterval = 100 / $totalJobs
    # While there are still jobs to deploy or there are jobs still running
    While ($jobQ.Count -gt 0 -or $(get-job -State "Running").count -gt 0) {
        $JobsRunning = $(Get-Job -State 'Running').count
        write-host 'x' -NoNewline

        # For each job started and each child of those jobs
        ForEach ($Job in Get-Job) {
            ForEach ($Child in $Job.ChildJobs) {
                ## Get the latest progress object of the job
                $Progress = $Child.Progress[$Child.Progress.Count - 1]
                
                ## If there is a progress object returned write progress
                If ($Progress.Activity -ne $Null) {
                    Write-Progress -Activity $Job.Name -Status $Progress.StatusDescription -PercentComplete $Progress.PercentComplete -ID $Job.ID -ParentId $_tp
                    write-debug "Job '$($job.name)' is at $($Progress.PercentComplete)%"
                }
                
                ## If this child is complete then stop writing progress
                If ($Progress.PercentComplete -eq 100 -or $Progress.PercentComplete -eq -1) {
                    write-debug "Job '$($Job.name)' has finished"
                    write-host "|" -NoNewline
                    #Update total progress
                    $perc = $ProgressStart + $ProgressInterval * ($totalJobs - $jobQ.count)
                    Write-Progress -Activity "Running" -Id $_tp -PercentComplete $perc

                    Write-Progress -Activity $Job.Name -Status $Progress.StatusDescription  -PercentComplete $Progress.PercentComplete -ID $Job.ID -ParentId $_tp -Complete
                    ## Clear all progress entries so we don't process it again
                    $Child.Progress.Clear()
                }
            }
        }
        
        if ($JobsRunning -lt $MaxJobs -and $jobQ.Count -gt 0) {
            $NumJobstoRun = @(($MaxJobs - $JobsRunning), $jobQ.Count)[$jobQ.Count -lt ($MaxJobs - $JobsRunning)]
            write-debug "We've completed some jobs, we need to start $NumJobstoRun more"
            1..$NumJobstoRun | ForEach-Object {
                write-debug "iteration: $_ of $NumJobstoRun"
                if ($jobQ.Count -eq 0) {
                    write-debug "There are 0 jobs left. Skipping the loop"
                    return
                }
                $j = $jobQ.Dequeue()
                Start-Job -Name $j[0] -InitializationScript $j[1] -ScriptBlock $j[2] | Out-Null
                write-host -NoNewline '.'
                Write-Debug "Started Job named '$($j[0])'. There are $($jobQ.Count) jobs remaining"
            }
        }

        ## Setting for loop processing speed
        Start-Sleep -Milliseconds $delay
    }

    # Ensure all progress bars are cleared
    ForEach ($Job in Get-Job) {
        Write-Progress -Activity $Job.Name -ID $Job.ID -ParentId $_tp -Complete
    }
    write-host ''
    write-host "[END] Managing Job Execution"
}

#filter tenant list if necessary
if ( $script:id ) {
    $tenantList = $tenantList | Where-Object -Property name -eq -Value $script:id
}

$jobQueue = New-Object System.Collections.Queue
foreach ($t in $tenantList) {
    $prefilledVariables = [scriptblock]::Create(@"
`$env:dtenv = `$_env = '$($tempEnvTokens | Where-Object -Property env -EQ -Value $t.id | Select-Object -ExpandProperty uri)';
`$env:dttoken = `$_token = '$($tempEnvTokens | Where-Object -Property env -EQ -Value $t.id | Select-Object -ExpandProperty scripttoken)';
`$env:dtenvname = `$_envname = '$($t.Name)';

# CD to the current directory
Set-Location $(Get-Location)
"@)
    $jobQueue.Enqueue($($t.name, $prefilledVariables, $script:ScriptBlock))
}

Manage-Job $jobQueue $script:maxJobs $script:JobDelay

# Clean up the tokens we made everywhere

$ETMHeader = @{
    'Authorization' = "Api-Token $script:ETMToken";
    'Accept'        = "application/json; charset=utf-8";
    "Content-Type"  = "application/json; charset=utf-8"
}
# Create a short-term token for each of the target environments
$tempEnvTokens | ForEach-Object {
    
    # Clean up the script Token
    $envHeader = @{
        'Authorization' = "Api-Token $($_.tokenManagementToken)";
        'Accept'        = "application/json; charset=utf-8";
        "Content-Type"  = "application/json; charset=utf-8"
    }

    $uri = "$($_.uri)/api/v1/tokens/lookup"
    $body = "{`"token`": `"$($_.scriptToken)`"}"
    write-host -ForegroundColor Cyan "Get ID of script token: POST $uri"
    $scriptTokenDetails = Invoke-RestMethod -Method POST -Headers $envHeader -Uri $uri -Body $body

    $uri = "$($_.uri)/api/v1/tokens/$($scriptTokenDetails.id)"
    write-host -ForegroundColor cyan "Delete Token from $($_.env): DELETE $uri"
    $res = Invoke-RestMethod -Method Delete -Headers $envHeader -Uri $uri
    
}

# Clean up the global token
$uri = "$script:dtcluster/api/cluster/v2/tokens/lookup"
$body = "{`"token`": `"$($script:ETMToken)`"}"
write-host -ForegroundColor Cyan "Get ID of Environment Token Management Token: POST $uri"
$ETMtokenDetails = Invoke-RestMethod -Method POST -Headers $headers -Uri $uri -Body $body

$uri = "$script:dtcluster/api/cluster/v2/tokens/$($ETMtokenDetails.id)"
write-host -ForegroundColor cyan "Delete Token from cluster: DELETE $uri"
$res = Invoke-RestMethod -Method Delete -Headers $headers -Uri $uri
Write-Host $res

# Collect the output from each of the jobs
$jobs = Get-Job -State Completed
$outputs = @()
ForEach ($job in $jobs) {
    $o = Receive-Job -Keep -Job $job
    $outputs += $o
}

$outputs
