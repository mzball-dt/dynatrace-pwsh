<#
.Synopsis
    For configuring tokens available in a given Dynatrace Tenant

.Description
    Script to configure tokens in a Dynatrace tenant. 
    Attempts to work as well as possible with other mzball-dt scripts via PowerShell Pipes

    Possible Extensions: 
        - Extending Expiry
        - More foot-bullet checking?

.Notes
    Author: Michael Ball (extension) 
    Version: 1.0.0 - 20200701

    ChangeLog
        1.0.0
        - Fixed some unnecessary outputs
        0.2
        - Create Tokens
            - Scope, Name, Expiry val/unit
        - Update tokens
            - scope, name, revoke-ness
        - Delete tokens 
        - Fairly sane error checking


.Example /set-tenantToken.ps1 -id "c3275cc0-3334-48da-b4bc-c3275cc03755" -name "New name for old token"
Cluster Version Check: GET https://abc12345.live.dynatrace.com/api/v1/config/clusterversion
Token Permissions Check: POST https://abc12345.live.dynatrace.com/api/v1/tokens/lookup
Retrieving Token JSON from ID: GET https://abc12345.live.dynatrace.com/api/v1/tokens/c3275cc0-3454-48da-b4bc-25cf84433755
Update tenant token detail: PUT https://abc12345.live.dynatrace.com/api/v1/tokens/c3275cc0-3454-48da-b4bc-25cf84433755

id                                   name                   revoked scopes
--                                   ----                   ------- ------
c3275cc0-3454-48da-b4bc-c3275cc03755 New name for old token    True {DataExport, ReadConfig, WriteConfig}

.Example \get-tenantTokens.ps1 | ? { $_.name -match 'new token' } | .\set-tenantToken.ps1 -revoked | format-table
Cluster Version Check: GET https://abc12345.live.dynatrace.com/api/v1/config/clusterversion
Token Permissions Check: POST https://abc12345.live.dynatrace.com/api/v1/tokens/lookup
Cluster Version Check: GET https://abc12345.live.dynatrace.com/api/v1/config/clusterversion
Token Permissions Check: POST https://abc12345.live.dynatrace.com/api/v1/tokens/lookup
Retrieving Token data: GET https://abc12345.live.dynatrace.com/api/v1/tokens
id                                   name             revoked scopes
--                                   ----             ------- ------
c5c98bde-13bc-426b-4443-545484e397fc new token please    True {DataExport, ReadConfig, WriteConfig}
5ad365ce-8a04-4d69-8bfc-ad40354355e4 new token please    True {DataExport, ReadConfig, WriteConfig}
c3275cc0-3454-4124-b4bc-25cf84445355 new token please    True {DataExport, ReadConfig, WriteConfig}
dfc22985-f514-40ed-6646-6b2718ec4837 new token please    True {DataExport, ReadConfig, WriteConfig}

#>

[CmdletBinding()]
PARAM (
    # The Dynatrace environment to query - this is the 'homepage' of the target eg. https://lasjdh3.live.dynatrace.com/ or https://dynatrace-managed.com/e/UUID
    [Parameter()][ValidateNotNullOrEmpty()] $dtenv = $env:dtenv,
    # The token to query the environment with
    [Alias('dttoken')][ValidateNotNullOrEmpty()][string] $token = $env:dttoken,

    # Which Token are we setting?
    [Parameter(ValueFromPipelineByPropertyName = $true)][Alias('TokenId')] $id,
    [Parameter(ValueFromPipelineByPropertyName = $true)][String] $tokenValue,
    
    # The catch all for pushing things through
    [Parameter(ValueFromPipeline = $true)][psobject] $InputObject,

    # Create a new token from the input
    [switch] $newToken,
    # Mark the Token as Revoked
    [switch] $revoked,
    # Mark the Token as active (unrevoked)
    [switch] $active,
    # The UI-visible name of the token
    [ValidateNotNullOrEmpty()][String] $name,
    # The Token Permission Scopes this token has access to
    [ValidateNotNullOrEmpty()][String[]] $scopes,

    # The number of units (default of seconds) before this token is automatically revoked (only for new tokens)
    [Int] $expiryTimeValue,
    # The unit used by -expiryTimeValue (only for new tokens)
    [ValidateSet('MINUTES', 'SECONDS', 'HOURS')][String] $expiryTimeUnit = 'SECONDS',
    
    # Delete the Token specified
    [switch] $delete,

    # Prints Help output
    [Alias('h')][switch] $help,
    # use this switch to tell this script to not check token or cluster viability
    [switch] $noCheckCompatibility,
    # use this switch to tell powershell to ignore ssl concerns
    [switch] $noCheckCertificate,

    # DO NOT USE - This is set by Script Author
    [String[]] $script:tokenPermissionRequirements = ('DataExport', 'TenantTokenManagement')
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
        }
        elseif ($script:dtenv -like "http*://*/e/*") {
            $envType = 'env'
        }

        # Script won't work on a cluster
        if ($envType -eq 'cluster') {
            write-error "'$script:dtenv' looks like an invalid URL (and Clusters are not supported by this script)"
            return
        }
    
        # Environment version check - cancel out if too old 
        $uri = "$baseURL/config/clusterversion"
        Write-Host -ForegroundColor cyan -Object "Cluster Version Check: GET $uri"
        $res = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri
        $envVersion = $res.version -split '\.'
        if ($envVersion -and ([int]$envVersion[0]) -ne 1 -and ([int]$envVersion[1]) -lt 176) {
            write-error "Failed Environment version check - Expected: > 1.176 - Got: $($res.version)"
            return
        }

        # Token has required Perms Check - cancel out if it doesn't have what's required
        $uri = "$baseURL/tokens/lookup"
        Write-Host -ForegroundColor cyan -Object "Token Permissions Check: POST $uri"
        $res = Invoke-RestMethod -Method POST -Headers $headers -Uri $uri -body "{ `"token`": `"$script:token`"}"
        if (($script:tokenPermissionRequirements | Where-Object { $_ -notin $res.scopes }).count) {
            write-host "Failed Token Permission check. Token requires: $($script:tokenPermissionRequirements -join ',')"
            write-error "Token provided only had: $($res.scopes -join ',')"
            return
        }

        # Can't edit a token with itself
        if ($res.id -eq $script:id -or $script:token -eq $script:tokenValue) {
            return write-error "A token cannot change it's own settings"
        }
    }

    function convertTo-jsDate($date) {
        return [Math]::Floor(1000 * (Get-Date ($date) -UFormat %s))
    }

    $uri = "$baseURL/tokens"
    Clear-Variable -Name 'res'
}

Process {    
    # Created for 1.192
    $validTokenPerms = @("AdvancedSyntheticIntegration", "AppMonIntegration", "CaptureRequestData", "DTAQLAccess", "DataExport", "DataImport", "DataPrivacy", "Davis", "DcrumIntegration", "DeploymentManagement", "DiagnosticExport", "DssFileManagement", "ExternalSyntheticIntegration", "InstallerDownload", "LogExport", "LogImport", "MemoryDump", "Mobile", "PluginUpload", "ReadAuditLogs", "ReadConfig", "ReadSyntheticData", "RestRequestForwarding", "RumBrowserExtension", "RumJavaScriptTagManagement", "SupportAlert", "TenantTokenManagement", "UserSessionAnonymization", "ViewDashboard", "WriteConfig", "WriteSyntheticData", "entities.read", "entities.write")

    if (($script:scopes | Where-Object { $_ -cnotin $validTokenPerms }).count) {
        $script:scopes | Where-Object { $_ -cnotin $validTokenPerms } | ForEach-Object {
            Write-Error "Unknown/Invalid Token scope '$_'"
            if ($script:scopes | Where-Object { $_ -in $validTokenPerms }) {
                Write-Error "This was a capitalisation problem"
            }
        }
        return
    }

    # Create a new Token JSON from params
    if ($script:newToken) {
        if (!$script:scopes) { return Write-Error "New tokens must be created with scoping. Script is missing the -scopes parameter"; }

        #Do we need an expiry section?
        $expiryDetails = if ($script:expiryTimeValue) {
            @"
,
"expiresIn": {
    "value": "$script:expiryTimeValue",
    "unit": "$script:expiryTimeUnit"
}
"@
        }
        else { "" }

        # assemble the rest of the body
        $reqBody = @"
    {
        "name": "$script:name",
        "scopes": ["$($scopes -join '","')"]$expiryDetails
    }
"@

        $uri = "$baseURL/tokens"
        Write-host -ForegroundColor cyan -Object "Requesting creation of new token: POST $uri"
        $res = Invoke-RestMethod -Method POST -Headers $headers -uri $uri -Body $reqBody -ErrorAction Stop
        return $res
    
    # Delete the Token
    } elseif ($script:delete) {
        $uri = "$baseURL/tokens/$script:id"
        Write-host -ForegroundColor cyan -Object "Permanently deleting token: DELETE $uri"
        $res = Invoke-RestMethod -Method Delete -Headers $headers -uri $uri -Body $reqBody -ErrorAction Stop
        return $res
    }

    # Edit what was provided and send it back
    else {
        if (!$script:id -and !$script:tokenValue) { return Write-Error "No Token ID or Value was provided to set/update" }
        if ($script:expiryTimeValue) { Write-Warning "Expiry parameters are not supported for updates"}

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

        $tokenJson = $tokenJson | Select-Object -Property id,name,revoked,scopes
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

End {
}