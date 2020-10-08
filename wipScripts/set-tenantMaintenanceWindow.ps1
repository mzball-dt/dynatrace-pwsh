<#
    .Synopsis
        Configure Maintenance Windows for a Dynatrace Tenant

    .Description
        This script provides a CLI to modify the Maintenance windows in any given Dynatrace Tenant.
        Specifically, this CLI allows the creation, modification and removal of Maintenance Windows
        via the Dynatrace Tenant Configuration API.

        * Use the -newMaintenanceWindow or -new parameter to create a new Maintenance Window based on the
        other parameters provided to the script.
        * Use -delete parameter to permanently remove a Maintenance window based on id. This usage will also
        collect data from the pipeline, allowing for bulk deletion.
        * Where neither -delete or -new are provided the set-tenantMaintenanceWindow.ps1 will attempt to update
        the maintenanceWindow provided via either the -id param or pipeline.

    .Notes
        Author: Michael Ball
        Version: 0.1.0 - 20201005
        ChangeLog:
            0.1.0 - 20201005
                Basic Write/Delete/Read functionality is now working
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
    
    # The ID of a maintenance window to update
    [Parameter(ValueFromPipelineByPropertyName = $true)] $id,

    # The catch all object for piping things through
    [Parameter(ValueFromPipeline = $true)] $inputObject,

    # Create a new Maintenance Window
    [Alias('new')][switch] $newMaintenanceWindow,
    # Delete this Maintenance Window
    [switch] $delete,

    # The name of the maintenance window, displayed in the UI
    [ValidateNotNullOrEmpty()][string] $name,
    # A short description of the maintenance purpose
    [ValidateNotNullOrEmpty()][string] $description,
    # If the Maintenance Window is considered planned - the window will be unplanned if not present
    [switch] $planned,
    # The type of suppression of alerting and problem detection during the maintenance
    [ValidateSet('DETECT_PROBLEMS_AND_ALERT', 'DETECT_PROBLEMS_DONT_ALERT', 'DONT_DETECT_PROBLEMS')][string] $suppression,
    
    # A list of Dynatrace entities (for example, hosts or services) to be included in the scope
    [string[]] $entityScope,
    # A list of matching rules for dynamic scope formation
    [string[]] $tagScope,
    
    # Recurrence of the schedule
    [ValidateSet('DAILY', 'MONTHLY', 'ONCE', 'WEEKLY')][string] $recurrenceType,
    # The start date and time of the maintenance window
    [ValidateNotNullOrEmpty()][datetime] $startDate,
    # The end date and time of the maintenance window
    [ValidateNotNullOrEmpty()][datetime] $endDate, 
    # The time zone of the start and end time - will default to the local timezone
    [ValidateNotNullOrEmpty()][System.TimeZoneInfo] $timeZone = (Get-TimeZone),

    # The start time of the maintenance window. The format is HH:mm
    [ValidateNotNullOrEmpty()][string] $windowStart,
    # The duration of the maintenance window in minutes
    [ValidateNotNullOrEmpty()][string] $durationMinutes,
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
        if ($envVersion -and (([int]$envVersion[0]) -ne 1 -or ([int]$envVersion[1]) -lt $minimumVersion)) {
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
}
<#
###########################
# End of scaffold block #
###########################
#>

PROCESS {
    # Create a new Token JSON from params
    if ($script:newMaintenanceWindow) {

        # Check that we have all the params that we require to create a new MaintenanceWindow
        $requiredParams = 'name', 'description', 'suppression', 'recurrenceType', 'startDate', 'endDate'

        # different recurrences require different params
        if ($script:recurrenceType -ne 'ONCE') {
            $requiredParams += 'windowStart', 'durationMinutes'
            switch ($script:recurrenceType) {
                'WEEKLY' { $requiredParams += 'dayOfWeek' }
                'MONTHLY' { $requiredParams += 'dayOfMonth' }
            }
        }
        $badRequiredParams = @()
        foreach ($paramName in $requiredParams) {
            $paramVal = Get-Variable -Scope 'script' -Name $paramName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty value
            if ( $null -eq $paramVal -or $paramVal.ToString() -eq '') { $badRequiredParams += $paramName }
            if ($paramName -eq 'dayOfMonth' -and $paramVal -eq 0) { $badRequiredParams += $paramName } # dayOfMonth defaults to 0 due to int casting
        }
        if ($badRequiredParams) {
            Write-Error "Required Parameters are missing/invalid: $($badRequiredParams -join ', ')"
            exit
        }

        # Assemble a recurrence object if required
        $recurrenceDetails = if ($script:recurrenceType -ne 'ONCE') {
            $r = @{
                startTime       = $script:windowStart;
                durationMinutes = $script:durationMinutes; 
            }
            switch ($script:recurrenceType) {
                'WEEKLY' { $r.dayOfWeek = $script:dayOfWeek }
                'MONTHLY' { $r.dayOfMonth = $script:dayOfMonth }
            }
            "`"recurrence`": $($r | ConvertTo-Json -Compress),"
        }
        else { "" }

        $uri = "$baseURL/maintenanceWindows"
        $reqBody = @"
        {
            "name": "$script:name",
            "description": "$script:description",
            "type": "$(if($script:planned){'PLANNED'}else{'UNPLANNED'})",
            "suppression": "$script:suppression",
            "schedule": {
              "recurrenceType": "$script:recurrenceType",
              $recurrenceDetails
              "start": "$(get-date $script:startDate -Format 'yyyy-MM-dd HH:mm')",
              "end": "$(get-date $script:endDate -Format 'yyyy-MM-dd HH:mm')",
              "zoneId": "$("UTC+{0}:00" -f $script:timeZone.BaseUtcOffset.Hours)"
            }
        }
"@

        Write-host -ForegroundColor cyan -Object "Requesting creation of new maintenance Window: POST $uri"
        try {
            return Invoke-RestMethod -Method POST -Headers $headers -uri $uri -Body $reqBody -ErrorAction stop
        }
        catch {
            Write-Error $_
        }
        
    }
    # Delete the Token
    elseif ($script:delete) {
        $uri = "$baseURL/maintenanceWindows/$script:id"
        Write-host -ForegroundColor cyan -Object "Permanently deleting Maintenance Window: DELETE $uri"
        $res = Invoke-RestMethod -Method Delete -Headers $headers -uri $uri -Body $reqBody -ErrorAction Stop
        return $res
    }
    # Edit what was provided and send it back
    else {
        if (!$script:id) { return Write-Error "No Maintenance Window Id was provided to set/update" }

        $uri = "$baseURL/maintenanceWindows/$script:id"
        Write-Host -ForegroundColor cyan -Object "Retrieving Maintenance Window JSON from ID: GET $uri"
        $mwJson = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri

        # Make the changes that you want based on switches
        if ($script:name) { $mwJson.name = $script:name }
        if ($script:description) { $mwJson.description = $script:description }
        if ($script:suppression) { $mwJson.suppression = $script:suppression }
        if ($script:type) { $mwJson.type = if ($script:planned) { 'PLANNED' }else { 'UNPLANNED' } }
        if ($script:startDate) { $mwJson.schedule.start = (get-date $script:startDate -Format 'yyyy-MM-dd HH:mm') }
        if ($script:endDate) { $mwJson.schedule.end = (get-date $script:endDate -Format 'yyyy-MM-dd HH:mm') }
        if ($script:timeZone) { $mwJson.schedule.zoneId = ("UTC+{0}:00" -f $script:timeZone.BaseUtcOffset.Hours) }
        if ($script:recurrenceType) { 
            $mwJson.schedule.recurrenceType = $script:recurrenceType 
            
            switch ($script:recurrenceType) {
                'ONCE' { 
                    # WindowStart + Duration
                }
                'DAILY' { 
                    # WindowStart + Duration
                }
                'WEEKLY' { 
                    # WindowStart + Duration
                    # Day of the Week
                }
                'MONTHYLY' { 
                    # Window Start + Duration
                    # Day of the Month
                }
                Default {

                }
            }
        }

       
        # Send it back
        $uri = "$baseURL/maintenanceWindows/$script:id"
        Write-Host -ForegroundColor cyan -Object "Update Maintenance Window detail: PUT $uri"
        $res = Invoke-WebRequest -Method PUT -Headers $headers -Uri $uri -Body ($mwJson | ConvertTo-Json -Depth 10 -Compress)
        if ($res.statusCode -eq 204) {
            return $tokenJson
        }
    }
}

END {}