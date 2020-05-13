<#
.SYNOPSIS
    From the output of get-tenantHostGroupDetail returns the Sum of HUs for each value of $property

.DESCRIPTION
    #todo

.NOTES
    Author: michael.ball
    Version: 0.0.2 - 20200504

    Changelog:
        0.0.2
            Added the help switch
            Changed output method to support csv and PSObject strings
        0.0.1 - MVP
            Effectively MAP-REDUCEs an array of Host property data.

    Possible Future Features
    - Make this more generically a map-reduce?
    - Support for more than just SUM
    - output as csv format

.EXAMPLE
    PS C:\Users\michael.ball\proj\utils> .\get-tenantHostGroupDetail.ps1 | .\measure-HUperProperty.ps1

    Cluster Version Check: https://abc12334.live.dynatrace.com/api/v1/config/clusterversion
    Token Permissions Check: https://abc12334.live.dynatrace.com/api/v1/tokens/lookup
    Host Entity information request: https://abc12334.live.dynatrace.com/api/v1/entity/infrastructure/hosts?relativeTime=2hours&includeDetails=true

    Name                           Value
    ----                           -----
    FULL_STACK                     3.25

.EXAMPLE
    PS C:\Users\michael.ball\proj\utils> .\get-tenantHostGroupDetail.ps1 | .\measure-HUperProperty.ps1 -property displayName

    Cluster Version Check: https://abc12334.live.dynatrace.com/api/v1/config/clusterversion
    Token Permissions Check: https://abc12334.live.dynatrace.com/api/v1/tokens/lookup
    Host Entity information request: https://abc12334.live.dynatrace.com/api/v1/entity/infrastructure/hosts?relativeTime=2hours&includeDetails=true

    Name                           Value
    ----                           -----
    Machine1                       0.25
    Machine2                       2
    Machine3                       0.5
    Machine4                       0.25
    Machine5                       0.25

.EXAMPLE
    PS C:\Users\michael.ball\proj\utils> .\run-clusterwide.ps1 -tenantsCSVFile .\testTenantList.csv -ScriptBlock { .\get-tenantHostGroupDetail.ps1 } | .\measure-HUperProperty.ps1 

    [START] Managing Job Execution
    x.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    [END] Managing Job Execution
    Cluster Version Check: https://abc12334.live.dynatrace.com/api/v1/config/clusterversion
    Token Permissions Check: https://abc12334.live.dynatrace.com/api/v1/tokens/lookup
    Host Entity information request: https://abc12334.live.dynatrace.com/api/v1/entity/infrastructure/hosts?relativeTime=2hours&includeDetails=true

    Name                           Value
    ----                           -----
    FULL_STACK                     3.25

#>

PARAM (
    [Parameter(ValueFromPipeline = $true)][array] $inputObject,
    [String] $property = 'monitoringMode',

    # Output as CSV
    [switch] $outputCSV,

    # Prints Help output
    [Alias('h')][switch] $help
)

Begin {
    # Help flag checks
    if ($h -or $help) {
        Get-Help $script:MyInvocation.MyCommand.Path -Detailed
        exit 0
    }

    $Hostdetails = @()
}

# Collect all the pipeline input
Process {
    $Hostdetails += $inputObject
}

# Then Process it all at once
End {
    # Check that the property being grouped by exists.
    if ( $Hostdetails[0].$script:property -eq $null ) {
        return Write-Error "Unable to find $script:property in input - unable to continue"
    }

    $output = $Hostdetails | Group-Object -Property "$script:property" | ForEach-Object { $o = @() } {
        $_t = New-Object -TypeName psobject 
        if ($_.Group."$script:property" -ne $null) {
            $propertyInstance = ([array]$_.group."$script:property")[0]
            $_t | Add-Member -MemberType NoteProperty -Name Value -Value $propertyInstance
            $_t | Add-Member -MemberType NoteProperty -Name Sum -Value ($_.group.consumedHostUnits | Measure-Object -sum).sum
        }
        else {
            $_t | Add-Member -MemberType NoteProperty -Name Value -Value 'unlabelled'
            $_t | Add-Member -MemberType NoteProperty -Name Sum -Value ($_.group.consumedHostunits | Measure-Object -Sum).sum
        }
        $o += $_t
    } { $o }

    if ($script:outputCSV) {
        $output | ConvertTo-Csv
    } else {
        $output
    }
}
