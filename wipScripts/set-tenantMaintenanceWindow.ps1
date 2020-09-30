<#
    .Synopsis
        Configure Maintenance Windows for a Dynatrace Tenant
    .Description


    .Notes
        Author: Michael Ball
        Version: 0.1.0-alpha - 20201001
        ChangeLog
            0.1.0-alpha - 20201001
                Still Working on Param input
            
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
    
    # The ID of the maintenance window
    [Parameter(ValueFromPipelineByPropertyName = $true)] $id,

    # Create a new Maintenance Window
    [Alias('newMW', 'new')][switch] $newMaintenanceWindow,
    # Delete this Maintenance Window
    [switch] $delete,

    # The catch all object for piping things through
    [Parameter(ValueFromPipeline = $true)] $inputObject,

    # The name of the maintenance window, displayed in the UI
    [string] $name,
    # A short description of the maintenance purpose
    [string] $description,
    # If the Maintenance Window is considered planned - the window will be unplanned if not present
    [switch] $planned,
    # The type of suppression of alerting and problem detection during the maintenance
    [ValidateSet('DETECT_PROBLEMS_AND_ALERT', 'DETECT_PROBLEMS_DONT_ALERT', 'DONT_DETECT_PROBLEMS')][string] $suppression,
    
    # A list of Dynatrace entities (for example, hosts or services) to be included in the scope
    [string[]] $entityScope,
    # A list of matching rules for dynamic scope formation
    [string[]] $tagScope,
    
    # Recurrence of the schedule
    [ValidateSet('DAILY', 'MONTHLY', 'ONCE', 'WEEKLY')][string] $ScheduleType,
    # The start date and time of the maintenance window
    [datetime] $startDate,
    # The end date and time of the maintenance window
    [datetime] $endDate, 
    # The time zone of the start and end time - will default to the local timezone
    [System.TimeZone] $timeZone = (Get-TimeZone),

    # The start time of the maintenance window. The format is HH:mm
    [string] $windowStart,
    # The duration of the maintenance window in minutes
    [string] $durationMinutes,
    # The day of the month for monthly maintenance
    [ValidateRange(0, 31)][int] $dayOfMonth,
    # The day of the week for weekly maintenance
    [ValidateSet('FRIDAY', 'MONDAY', 'SATURDAY', 'SUNDAY', 'THURSDAY', 'TUESDAY', 'WEDNESDAY')][string] $dayOfWeek,

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
    [String[]]$script:tokenPermissionRequirements = @('DataExport', 'WriteConfig', 'ReadConfig')
)

BEGIN {
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

    function parse-TagRules ($rules) {

    }

    $baseURL = "$script:dtenv/api/config/v1"
    Clear-Variable -Name 'res'
}
<#
###########################
# End of scaffold block #
###########################
#>

PROCESS {

    # Check that we have all the params that we require to function


    # Create a new Token JSON from params
    if ($script:newMaintenanceWindow) {
        $uri = "$baseURL/tokens"
        Write-host -ForegroundColor cyan -Object "Requesting creation of new token: POST $uri"
        $res = Invoke-RestMethod -Method POST -Headers $headers -uri $uri -Body $reqBody -ErrorAction Stop
        return $res
    
        # Delete the Token
    }
    elseif ($script:delete) {
        $uri = "$baseURL/maintenanceWindows/$script:id"
        Write-host -ForegroundColor cyan -Object "Permanently deleting Maintenance Window: DELETE $uri"
        $res = Invoke-RestMethod -Method Delete -Headers $headers -uri $uri -Body $reqBody -ErrorAction Stop
        return $res
    }

    # Edit what was provided and send it back
    else {
        if (!$script:id) { return Write-Error "No Maintenance Window Id was provided to set/update" }
        if ($script:expiryTimeValue) { Write-Warning "Expiry parameters are not supported for updates" }

        if (!$script:id -and $script:tokenValue) {
            # IF we don't have the id - get it now - this will also give us the JSON
            $uri = "$baseURL/tokens/lookup"
            Write-Host -ForegroundColor cyan -Object "Retrieving Token JSON from value: POST $uri"
            $tokenJson = Invoke-RestMethod -Method POST -Headers $headers -Uri $uri -body "{ `"token`": `"$script:tokenValue`"}"
        }
        elseif ($script:id) {
            $uri = "$baseURL/tokens/$script:id"
            Write-Host -ForegroundColor cyan -Object "Retrieving Token JSON from ID: GET $uri"
            $tokenJson = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri
        }

        $tokenJson = $tokenJson | Select-Object -Property id, name, revoked, scopes
        # Make the changes that you want based on switches
        if ($script:name) { $tokenJson.name = $script:name }
        if ($script:scopes) { $tokenJson.scopes = $script:scopes }
        if ($script:revoked) { $tokenJson.revoked = $true }
        if ($script:active) { $tokenJson.revoked = $false }

        # Send it back
        $uri = "$baseURL/tokens/$script:id"
        Write-Host -ForegroundColor cyan -Object "Update tenant token detail: PUT $uri"
        $res = Invoke-WebRequest -Method PUT -Headers $headers -Uri $uri -Body ($tokenJson | ConvertTo-Json -Depth 5 -Compress)
        if ($res.statusCode -eq 204) {
            return $tokenJson
        }
    }
}

END {}