<#
.SYNOPSIS
    Helper script for running tenant targeted scripts against all tenants in a Dynatrace Managed Cluster

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
    Version: 0.1 - 20200218
    Requirement: Powershell v5.0

    Changelog:
        MVP
            Uses the jobbing system from Strippy to create a scripting environment for each tenant with 2 prefilled variables
            Returns all output from the jobs run for each tenant as an array.
#>

PARAM (
    # The tenant from the list of internal tenants
    [String] $tenant,
    [int] $tenantIndex,
    # use this switch to tell powershell to ignore ssl concerns
    [switch] $nocheckcertificate,
    [Parameter(ValueFromPipeline = $true)][scriptblock] $ScriptBlock,
    # Do the calc of HU/HostGroup (is non-simple)
    [int] $maxJobs = 8, 
    [int] $JobDelay = 100
)

# A csv styled list of environment URLs w/ tokens that have base permissions
$completeTenantList_text = @"
name,environment,token
"@

$tenantList = $completeTenantList_text | ConvertFrom-Csv -Delimiter ','

if ($tenantList.length -lt 1) {
    write-error "The internal tenantlist CSV string is empty. No tenants to run against."
}

$_tp = 7856413
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
                    Write-Progress -Activity "Sanitising" -Id $_tp -PercentComplete $perc

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
    write-host "[END] Managing Job Execution"
}

#filter tenant list if necessary
if ( $tenant ) {
    $tenantList = $tenantList | Where-Object -Property name -eq -Value $tenant
} elseif ( $tenantIndex ) {
    # index is valid
    If (0..($tenantList.length-1) -notcontains $tenantIndex) {
        Write-Error "Invalid $tenantIndex."
        Exit # return early
    }
    $tenantList = $tenantList[$tenantIndex]
}

$jobQueue = New-Object System.Collections.Queue
foreach ($t in $tenantList) {
    $prefilledVariables = [scriptblock]::Create("`$_env = '$($t.environment)'; `$_token = '$($t.token)'")
    $jobQueue.Enqueue($($t.name, $prefilledVariables, $script:ScriptBlock))
}

Manage-Job $jobQueue $script:maxJobs $script:JobDelay

# Collect the output from each of the jobs
$jobs = Get-Job -State Completed
$outputs = @()
ForEach ($job in $jobs) {
    $o = Receive-Job -Keep -Job $job
    $outputs += $o
}

$outputs

