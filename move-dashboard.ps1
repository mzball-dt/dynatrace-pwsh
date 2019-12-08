<#
.SYNOPSIS
    Move a Dashboard from one Tenant to another

.DESCRIPTION
    This script provides a simple interface to move dashboards cleanly between clusters and tenants.

    The process is streamlined if the source dashboard is specified through an argument. 
    If a source dashboard is not provided then a limited interface is provided to select a source dashboard
    from the dashboards available on the source tenant.

    There is no remediation or process to resolve dashboards that Dynatrace Managed will not accept as-is.

    Possible future features: 
        - Validation of provided tokens pre-attempts
        - Selection of source and destination tenant and dashboard from provided clusters
        - General export of Dashboard json to file

    Changelog: 
        v1.0:
            Dashboard movement works as expected with user interface


.NOTES
    Version: v1.0 - 20191205
    Author: michael.ball8
    Requirements: Powershell 5+

.EXAMPLE
    ./move-DMODashboard.ps1 -sourceEnvironment "https://server.example.com/e/f9degggf-1115-468a-a997-f9degggfc64a" -sourceToken "asdfa23123jlkf" -sourceDashboardID "123123-123jlkj-123-3-213" -destinationEnvironment "https://server.example1.com/e/e2a187ff-ba0f-4078-e2b8-126e2b8ba187" -destinationToken "adf1231414"

    Moves a dashboard between 2 different environments

.EXAMPLE
    ./move-DMODashboard.ps1 -sourceEnvironment "https://server.example.com/e/f92341bf-1435-468a-a997-ecd4f9degggf" -sourceToken "asdfa23123jlkf" -sourceDashboardID "123123-123jlkj-123-3-213" 

    When no destination Environment is set the destination will be the same as the source environment
#>

param (
    # The full URL for the environment to take a Dashboard from
    [Parameter(Mandatory=$true)][String]$sourceEnvironment,
    # A Token with at least read access to the source Environment
    [Parameter(Mandatory=$true)][String]$sourceToken,
    # The Dashboard ID of the Dashboard to copy somewhere else
    [String]$sourceDashboardID,
    # The Environment to move the selected dashboard too. If not supplied defaults to the source environment
    [String]$destinationEnvironment,
    # A token with at least config write access to the destination Environment. Will use the source token when destination environment is not set
    [String]$destinationToken,
    # A shortcut for specifying a new name for the created report
    [string]$destinationReportName,
    # use this switch to tell powershell to ignore ssl concerns
    [switch]$nocheckcertificate
)

if ($nocheckcertificate) {
    # SSL and other compatability settings
    function Disable-SslVerification
    {
        if (-not ([System.Management.Automation.PSTypeName]"TrustEverything").Type)
        {
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

    function Enable-SslVerification
    {
        if (([System.Management.Automation.PSTypeName]"TrustEverything").Type)
        {
            [TrustEverything]::UnsetCallback()
        }
    }

    Disable-SslVerification
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocoltype]::Tls12

}

# if no destination this is an intra Environment move/copy
if (!$destinationEnvironment) {
    $script:destinationEnvironment = $script:sourceEnvironment
    $script:destinationToken = $script:sourceToken
}


# List all tenants with names
    # Can't do until 1.184

function import-DashboardJSON ($environment, $token, [String]$dashboardJSON) {
    $headers = @{
        Authorization = "Api-Token $Token"
        "Content-Type" = "application/json"
    }
    $url = "$environment/api/config/v1/dashboards"

    $dashboardJSON = $dashboardJSON -replace '%%ENV%%',$environment

    $res = @()
    try {
        $response = Invoke-WebRequest -Method POST -Headers $headers -Uri $url -Body $dashboardJSON -UseBasicParsing -ErrorAction Stop
        $res = $response.content | ConvertFrom-Json
        Write-host "Dashboard created successfully. Name: " -nonewline 
        write-host $res.name -NoNewline -ForegroundColor Gray
        write-host ") - ID: " -NoNewline
        write-host $res.id -ForegroundColor Gray
        Write-host "Access URL: " -NoNewline -ForegroundColor Gray
        write-host "$environment/#dashboard;id=$($res.id)" -ForegroundColor cyan

    } catch [System.Net.WebException] {
        $respStream = $_.Exception.Response.getResponseStream()
        $reader = New-Object System.IO.StreamReader($respStream)
        $reader.baseStream.Position = 0
        $res = $reader.ReadToEnd() | ConvertFrom-Json

        write-host "Error attempting to import: $($res.error.code)"
        write-host "Message: $($res.error.message)" -ForegroundColor Red

        Write-error "Import failed - No changes made"
    }
}

function export-Dashboard ($environment, $token, $dashboardID) {
    $headers = @{
        Authorization = "Api-Token $Token"
        "Content-Type" = "application/json"
    }
    $url = "$environment/api/config/v1/dashboards/$dashboardID"

    write-host "Exporting Dashboard ID provided (" -NoNewline
    write-host "$dashboardID" -NoNewline -ForegroundColor Gray
    write-host ") from " -NoNewline
    write-host "$environment" -ForegroundColor Gray
    $response = Invoke-RestMethod -Method GET -Headers $headers -Uri $url

    return $response
}

if ($script:sourceDashboardID) {
    $export = export-Dashboard $sourceEnvironment $sourceToken $sourceDashboardID

    # update the output for importing
    $export.PSObject.properties.remove('id')
    $export.dashboardMetadata.owner = ''
    if ($script:destinationReportName) { $export.dashboardMetadata.name = $script:destinationReportName }

    # Convert the exported PSObject back to JSON
    $json = $export | ConvertTo-Json -Depth 20 -Compress 
    write-host "Dashboard Export is $($json | Measure-Object -Character | Select-Object -ExpandProperty characters) bytes"
    
    # import the dashboard
    import-DashboardJSON $destinationEnvironment $destinationToken $json

} else {
    write-host "Fetching all available dashboards from source tenant"
    $headers = @{
        Authorization = "Api-Token $script:sourceToken"
        "Content-Type" = "application/json"
    }

    # list all dashboards + names in current tenant
    $url = "$script:sourceEnvironment$dashboardAPI"
    $res = Invoke-RestMethod -Method GET -Headers $headers -Uri $url
    $i = 1
    foreach ($dashboard in ($res.dashboards | Sort-Object -Property owner)) {
        $dashboard | Add-Member -MemberType NoteProperty -Name Choice -Value $i
        $i++
    }
    $res.dashboards | Select-Object -Property Choice, name, owner, id | Sort-Object -Property Choice | Format-Table

    $choice = Read-Host -Prompt "Enter the choice that represents the dashboard you wish to move"
    $dashboardToExport = $res.dashboards | Where-Object -Property choice -eq -value $choice

    Write-host "Continue with choice $choice`: '$($dashboardToExport.name)' by $($dashboardToExport.owner)"
    $ans = read-host -Prompt "y/n [y]"
    if ($ans -ne 'y' -and $ans -ne '') {
        write-host "Exiting script with no changes" -ForegroundColor DarkMagenta
        return
    }

    $export = export-Dashboard $sourceEnvironment $sourceToken $($dashboardToExport.id)

    # update the output for importing
    $export.PSObject.properties.remove('id')
    $export.dashboardMetadata.owner = ''

    $ans = read-host "Name of new Dashboard [$($dashboardToExport.name)]"
    if ($ans) {
        $export.dashboardMetadata.name = $ans
    }

    # Convert the exported PSObject back to JSON
    $json = $export | ConvertTo-Json -Depth 20 -Compress 
    write-host "Dashboard Import will be $($json | Measure-Object -Character | Select-Object -ExpandProperty characters) bytes"
    
    import-DashboardJSON $script:destinationEnvironment $script:destinationToken $json
}


# export chosen dashboard

# list all tenants on target server
    # Can't do until 1.184

# import chosen dashboard to chosen tenant
    