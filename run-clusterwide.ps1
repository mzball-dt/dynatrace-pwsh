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
    Version: 0.0.2 - 20200218
    Requirement: Powershell v5.0

    Changelog:
        MVP
            Uses the jobbing system from Strippy to create a scripting environment for each tenant with 2 prefilled variables
            Returns all output from the jobs run for each tenant as an array.
        0.0.2
            Added input checks
            Added -help switch
            script block now has access to the env:dtenv and env:dttoken envvars
        0.0.3
            Script block no starts in the same directory as the current shell
            Added -tenantsCSVFile for if someone wants to specify an alternate place the tenant data is stored
#>

PARAM (
    # A specific tenant (by name) from the list of known tenants
    [String] $tenant,
    # A specific tenant (by index) from the list of known tenants
    [int] $tenantIndex,
    # The Script block to execute for each tenant
    [Parameter(ValueFromPipeline = $true)][scriptblock] $ScriptBlock,
    
    # External CSV list of Dynatrace Tenants
    [String] $tenantsCSVFile,

    # Use this switch to list the internal tenants (w/o tokens)
    [switch] $list,

    # Maximum Concurrent Jobs managed by this script
    [int] $maxJobs = 8, 
    # Time between each loop of creating and checking jobs
    [int] $JobDelay = 100,

    # List detailed help
    [switch] $help,    
    # use this switch to tell powershell to ignore ssl concerns
    [switch] $nocheckcertificate
)

# Help flag checks
if ($h -or $help) {
    Get-Help $(join-path $(Get-Location) $MyInvocation.MyCommand.Name) -Detailed
    exit 0
}


# A csv styled list of environment URLs w/ tokens that have base permissions
$completeTenantList_text = @"
Name,Environment,token
"@

$tenantList = if ($script:tenantsCSVFile -and (Test-Path $script:tenantsCSVFile)) {
    get-content -Raw -Path $script:tenantsCSVFile | ConvertFrom-Csv -Delimiter ','
} else {
    $completeTenantList_text | ConvertFrom-Csv -Delimiter ','
}


if ($tenantList.length -eq 0) {
    write-host "The internal tenantlist CSV string is empty. No tenants to run against." -ForegroundColor Red
    exit
}

if ($script:list) {
    Write-host "Internal tenantlist contains the following:"
    $tenantList | 
    ForEach-Object { $i } { $_ | Add-Member -Type NoteProperty -Name 'Index' -Value ($i++) -PassThru } | 
    Select-Object -property index, name, environment | 
    Format-table -AutoSize
    exit
}

if ( -not $script:ScriptBlock) {
    write-host -ForegroundColor Red "No Script block was provided - nothing happened"
    exit
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
    write-host ''
    write-host "[END] Managing Job Execution"
}

#filter tenant list if necessary
if ( $tenant ) {
    $tenantList = $tenantList | Where-Object -Property name -eq -Value $tenant
}
elseif ( $tenantIndex ) {
    # index is valid
    If (0..($tenantList.length - 1) -notcontains $tenantIndex) {
        Write-Error "Invalid $tenantIndex."
        Exit # return early
    }
    $tenantList = $tenantList[$tenantIndex]
}

$jobQueue = New-Object System.Collections.Queue
foreach ($t in $tenantList) {
    $prefilledVariables = [scriptblock]::Create(@"
`$env:dtenv = `$_env = '$($t.environment)'; 
`$env:dttoken = `$_token = '$($t.token)';

# CD to the current directory
Set-Location $(Get-Location)
"@)
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

