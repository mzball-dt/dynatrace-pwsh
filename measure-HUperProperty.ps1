<#
.SYNOPSIS
    From the output of get-tenantHostGroupDetail returns the Sum of HUs for each value of $property

.DESCRIPTION
    #todo

.NOTES
    Author: michael.ball
    Version: 0.0.1 - 20200504

    Changelog: 
        v0.0.1 - MVP
            Effectively MAP-REDUCES an array of Host property data.

    Possible Future Features
    - Significant Error checking & failing out more generally
    - Make this more generically a map-reduce?
    - Support for more than just SUM

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
    [String] $property = 'monitoringMode'
)

Begin {
    $Hostdetails = @()
}

# Collect all the pipeline input
Process {
    $Hostdetails += $inputObject
}

# Then Process it all at once
End {
    $Hostdetails | Group-Object -Property "$script:property" | ForEach-Object { $o = @{ } } {
        if ($_.Group."$script:property" -ne $null) {
            $o[([array]$_.group."$script:property")[0]] = ($_.group.consumedHostUnits | Measure-Object -sum).sum
        }
        else {
            $o['unlabelled'] = ($_.group.consumedHostunits | Measure-Object -Sum).sum
        }
    } { $o }
}
