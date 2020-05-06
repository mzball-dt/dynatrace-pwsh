<#
.SYNOPSIS
    Maintain a 'default' dashboard published to all environments 

.DESCRIPTION
    

.NOTES
    Version: alpha - 20200323
    Author: michael.ball8
    Requirements: Powershell 5+
    Changelog:        

#>

param (
    # The Environment to move the selected dashboard too. If not supplied defaults to the source environment
    [String]$dtenv,
    # A token with at least config write access to the destination Environment. Will use the source token when destination environment is not set
    [String]$token,

    # The json file that represents the source dashboard
    [String]$sourceFile
    # The full URL of the Source Dashboard - just like if you wanted to open it in browser
    [String]$sourceDashboard,
    # A Token with at least read access to the source Environment
    [String]$sourceToken,
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

