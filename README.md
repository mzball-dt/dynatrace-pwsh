# Dynatrace API Scripts

## API Interfaces

A Powershell interface to Dynatrace Monitoring environments, in a similar way to the default powershell cmdlets that provide: `Get-Process`, `Get-<item>`, `Set-Service`, `Set-<item>` et al.

All scripts will:

- Use a clear naming system using the standard Powershell verbs and a 'tenant' or 'cluster' declaration
- Check input data (env,token,general input) to fail early and minimise time looking at server generated errors
- Make use of environment variables and piping to minimise unnecessary typing
  - Set `$env:dtenv` and `$env:dttoken` at the start of your session (or in your `$profile`) to never have to specify these arguments
- Provide strong compatibility with `get-help`, providing simple and extended examples of use

| Script | Details |
| --- | --- |
| get-tenantMonitoredEntity.ps1 | For retrieving entities currently monitored in a Dynatrace Environment<p>Usecases:</p><ul><li>Exploration of a monitoring environment via the API</li><li>Reporting on how many X in an environment</li><li>To collect information required for further scripts (piping further into a chain)</li></ul>|
| get-tenantToken.ps1 | For auditing Tokens available in a given Dynatrace<p>Usecases:</p><ul><li>Reviewing users that have created tokens</li></ul> |
| set-tenantToken.ps1 | For configuring tokens in a given Dynatrace Tenant. Created to function with the output directly from get-tenantTokens or via a filtering step<p>Usecases:</p><ul><li>Programmatically create new tokens</li><li>Revoke tokens belonging to a certain user</li><li>Update names for tokens</li><li>Remove problematic scopes from tokens found in Dynatrace tenants</li></ul> |
| get-tenantTokenDetail.ps1 | For when you only want information about a specific tenant token<p>Usecases:</p><ul><li>Checking scopes assigned to a token</li><li>Checking scopes of tokens listed for use by run-clusterwide.ps1.</li></ul> |
| get-tenantDashboard.ps1 | For auditing or reporting of who has created/shared dashboards in a given Dynatrace Tenant<p>Usecases:</p><ul><li>Reviewing users that have created Dashboards</li><li>Reviewing the sharing of dashboards</li><li>Accessing user dashboards to support configuration</li></ul> |
| get-tenantHostGroupDetail.ps1 |For reporting on all hosts in an environment, particularly for HU consumption by HostGroup<p>Usecases:</p><ul><li>What is the distribution of HU in my environment?</li><li>What is the newest and oldest Agent version running in my environment?</li><li>What Host Groups have the oldest agent version?</li></ul>|
| get-tenantProblemFeed.ps1|For reporting on all problems in an environment, particularly<p>Usecases:</p><ul><li>What are the problems report for an enviornment in the last X period?</li></ul>|
| Invoke-USQLRequest.ps1 |Powershell script for saving or viewing USQL queries as PS Tables or CSV files<p>Usecases:</p><ul><li>Extract USQL data from a tenant in a standard format</li></ul> |
| Export-TenantConfig.ps1 | Powershell script that exports all (or a filterable subset) of the config accessible through the Dynatrace Configuration API<p>Usecases:</p><ul><li>Backing up an in the case of disaster</li><li>Exporting a Tenant's configuration for re-use in another tenant</li><li>Exporting a Tenant's configuration for use with [Dynatrace's Monitoring as Code Tool](https://github.com/dynatrace-oss/dynatrace-monitoring-as-code)</li></ul> |


## Other Scripts

### copy-dashboard.ps1

Powershell script for moving Dynatrace Managed Dashboards between Managed clusters or tenants

Use case:

- After creating a standard report, copying it to another tenant to share value

### set-defaultDashboard.ps1

Script that creates or updates a Dynatrace Managed Dashboard based on a different/pre-existing. 
Designed for nightly executions that update 'client-facing', published dashboards from a template.

Use case: 
- Keeping other dashboards in-sync with a specific 'special' dashboard
- Maintaining a 'Default' dashboard provided to all Dynatrace Managed Tenants
- Updating a 'Things you should know' or 'Public Announcement' dashboard in a scalable way 

### assign-syntheticClusterLocation.ps1

Powershell script for assigning a Synthetic Location to a Dynatrace Managed Synthetic Cluster Node.
This needs to be converted to `set-clusterSyntheticLocation.ps1`

Use case:

- Providing a better system to add new cluster synthetic nodes - currently there's no UI

### run-clusterWide.ps1

Powershell script for running arbitary code against a collection of Dynatrace tenants.

Use case:

- Copying a new standard Dashboard to all tenants in a cluster or customer environment
- Exporting Config from all tenants in a cluster or customer environment
- Gathering Audit logs from all tenants in a cluster or customer environment
- Creating a new token for use by a data ingestion group across the customer environment
- Use any of the other scripts above across multiple tenants

### measure-HUperProperty.ps1

Pipeline script for performing simple (but irritating to type out) calculations on Host Meta-data

Use case:

- How many HU in my tenant/cluster/grouping per OS/MonitoringType/environment

### export-tenantConfig.ps1

For exporting tenant configuration to disk for archiving or other purposes.

Use case:

- Nightly tenant configuration dump to reduce risk of unwanted or mistaken changes
- Any reason you'd want to have a tenant-specific backup of configuration

### templateScaffold.ps1

Template for new scripts

Use case:

- When writing new powershell scripts