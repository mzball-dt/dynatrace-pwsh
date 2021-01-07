<#
.SYNOPSIS
	Take a backup of one, some or all configurations available through the Dynatrace Tenant API    

.DESCRIPTION
	Exports all the configurations available to a folder.

	Todo List:
		- improve filtering by generating all the GET URLs first (by hitting up the idlist endpoints), filtering and then doing the config data GET requests.
			- This would greatly improve the usability of the filter, exclude and include args. It would bring them up to actually matching the expectation of what they're doing

	Changelog
		1.0 - 20200107
			Added checks around custom output folder
			Updated all the config APIs known by the script
			Updated the uriSuffix logic to work with lists of urisuffix's
			Implemented filter argument, extended to include uriSuffix's - when matched though this includes the rest of the base uri's data
			Implemented exclude argument

		0.1 - MVP
			Initial MVP that mostly works		

.NOTES
	Author: michael.ball
	Version: 1.0 - 20200107
	Requirement: Powershell v5.0
#>

PARAM (
	# The cluster or tenant the HU report should be fetched from
	[Parameter()][ValidateNotNullOrEmpty()] $dtenv = $env:dtenv,
	# Token must have Smartscape Read access for a tenant
	[Alias('dttoken')][ValidateNotNullOrEmpty()][string] $token = $env:dttoken,

	# Filter the api list with this string
	[string] $filter,
	# Exclude things that contain this string. Applied after any filter
	[string[]] $exclude,
	# Include things that contain these strings. Applied after the exclude list
	[string[]] $include,
	# Path folder to place all exported tenant config in
	[string] $outputFolder,
	# Always create a file, even if there is no relevant config
	##[switch] $createEmptyConfigFiles,
	[switch] $includeMobileSymbolManagementConfig,

	# Prints Help output
	[Alias('h')][switch] $help,
	# use this switch to tell this script to not check token or cluster viability
	[switch] $noCheckCompatibility,
	# use this switch to tell powershell to ignore ssl concerns
	[switch] $noCheckCertificate,

	# DO NOT USE - This is set by Script Author
	[String[]]$script:tokenPermissionRequirements = @('DataExport', 'ReadConfig')
)

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

# Make sure to increase the perms required of the token if we're also retrieving the mobile symbol file config
if ($includeMobileSymbolManagementConfig) {
	$script:tokenPermissionRequirements += 'DssFileManagement'
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

function confirm-supportedClusterVersion ($minimumVersion = 176, $logmsg = '') {
	# Environment version check - cancel out if too old 
	$uri = "$baseURL/config/clusterversion"
	Write-Host -ForegroundColor cyan -Object "Cluster Version Check$logmsg`: GET $uri"
	$res = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri
	$envVersion = $res.version -split '\.'
	if ($envVersion -and ([int]$envVersion[0]) -ne 1 -and ([int]$envVersion[1]) -lt $minimumVersion) {
		write-host "Failed Environment version check - Expected: > 1.$minimumVersion - Got: $($res.version)"
		exit
	}
}

function confirm-requireTokenPerms ($token, $requirePerms, $envUrl = $script:dtenv, $logmsg = '') {
	# Token has required Perms Check - cancel out if it doesn't have what's required
	$uri = "$envUrl/api/v1/tokens/lookup"
	Write-Host -ForegroundColor cyan -Object "Token Permissions Check$logmsg`: POST $uri"
	$res = Invoke-RestMethod -Method POST -Headers $headers -Uri $uri -body "{ `"token`": `"$script:token`"}"
	if (($requirePerms | Where-Object { $_ -notin $res.scopes }).count) {
		write-host "Failed Token Permission check. Token requires: $($requirePerms -join ',')"
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
		
	$_eap = $ErrorActionPreference; $ErrorActionPreference = 'stop'
	confirm-supportedClusterVersion 204
	confirm-requireTokenPerms $script:token $script:tokenPermissionRequirements
	$ErrorActionPreference = $_eap
}

$configApis = @"
[
	{
		'type': 'id_list',
		'uri': '/alertingProfiles'
	},
	{
		'type': 'simple',
		'uri': '/allowedBeaconOriginsForCors'
	},
	{
		'type': 'simple',
		'uri': '/anomalyDetection/applications'
	},
	{
		'type': 'simple',
		'uri': '/anomalyDetection/aws'
	},
	{
		'type': 'simple',
		'uri': '/anomalyDetection/databaseServices'
	},
	{
		'type': 'id_list',
		'uri': '/anomalyDetection/diskEvents'
	},
	{
		'type': 'simple',
		'uri': '/anomalyDetection/hosts'
	},
	{
		'type': 'id_list',
		'uri': '/anomalyDetection/metricEvents'
	},
	{
		'type': 'simple',
		'uri': '/anomalyDetection/services'
	},
	{
		'type': 'simple',
		'uri': '/anomalyDetection/vmware'
	},
	{
		'type': 'simple',
		'uri': '/applicationDetectionRules/hostDetection'
	},
	{
		'type': 'id_list',
		'uri': '/applicationDetectionRules'
	},
	{
		'type': 'id_list',
		'uri': '/applications/mobile'
	},
	{
		'type': 'simple',
		'uri': '/applications/web/dataPrivacy'
	},
	{
		'type': 'simple',
		'uri': '/applications/web/default'
	},
	{
		'type': 'simple',
		'uri': '/applications/web/default/dataPrivacy'
	},
	{
		'uriSuffix': [
			'dataPrivacy',
			'errorRules',
			'keyUserActions'
		],
		'type': 'id_list',
		'uri': '/applications/web'
	},
	{
		'type': 'id_list',
		'uri': '/autoTags'
	},
	{
		'type': 'id_list',
		'uri': '/aws/credentials'
	},
	{
		'type': 'simple',
		'uri': '/aws/iamExternalId'
	},
	{
		'type': 'simple',
		'uri': '/aws/privateLink/whitelistedAccounts'
	},
	{
		'type': 'simple',
		'uri': '/aws/privateLink'
	},
	{
		'type': 'id_list',
		'uri': '/azure/credentials'
	},
	{
		'type': 'id_list',
		'uri': '/calculatedMetrics/log'
	},
	{
		'type': 'id_list',
		'uri': '/calculatedMetrics/mobile'
	},
	{
		'type': 'id_list',
		'uri': '/calculatedMetrics/rum'
	},
	{
		'type': 'id_list',
		'uri': '/calculatedMetrics/service'
	},
	{
		'type': 'id_list',
		'uri': '/calculatedMetrics/synthetic'
	},
	{
		'type': 'id_list',
		'uri': '/cloudFoundry/credentials'
	},
	{
		'type': 'id_list',
		'uri': '/conditionalNaming/host'
	},
	{
		'type': 'id_list',
		'uri': '/conditionalNaming/processGroup'
	},
	{
		'type': 'id_list',
		'uri': '/conditionalNaming/service'
	},
	{
		'type': 'simple',
		'uri': '/contentResources'
	},
	{
		'type': 'id_list',
		'uri': '/dashboards'
	},
	{
		'type': 'simple',
		'uri': '/dataPrivacy'
	},
	{
		'type': 'simple',
		'uri': '/extensions/activeGateExtensionModules'
	},
	{
		'uriSuffix': [
			'binary',
			'global',
			'instances',
			'states'
		],
		'type': 'id_list',
		'uri': '/extensions'
	},
	{
		'type': 'simple',
		'uri': '/frequentIssueDetection'
	},
	{
		'type': 'simple',
		'uri': '/geographicRegions/ipAddressMappings'
	},
	{
		'type': 'simple',
		'uri': '/geographicRegions/ipDetectionHeaders'
	},
	{
		'type': 'simple',
		'uri': '/hosts/autoupdate'
	},
	{
		'type': 'id_list',
		'uri': '/kubernetes/credentials'
	},
	{
		'type': 'id_list',
		'uri': '/maintenanceWindows'
	},
	{
		'type': 'id_list',
		'uri': '/managementZones'
	},
	{
		'type': 'id_list',
		'uri': '/notifications'
	},
	{
		'type': 'simple',
		'uri': '/plugins/activeGatePluginModules'
	},
	{
		'uriSuffix': [
			'states'
		],
		'type': 'id_list',
		'uri': '/plugins'
	},
	{
		'type': 'id_list',
		'uri': '/remoteEnvironments'
	},
	{
		'type': 'id_list',
		'uri': '/reports'
	},
	{
		'type': 'id_list',
		'uri': '/service/customServices/dotNet'
	},
	{
		'type': 'id_list',
		'uri': '/service/customServices/go'
	},
	{
		'type': 'id_list',
		'uri': '/service/customServices/java'
	},
	{
		'type': 'id_list',
		'uri': '/service/customServices/nodeJS'
	},
	{
		'type': 'id_list',
		'uri': '/service/customServices/php'
	},
	{
		'type': 'id_list',
		'uri': '/service/detectionRules/FULL_WEB_REQUEST'
	},
	{
		'type': 'id_list',
		'uri': '/service/detectionRules/FULL_WEB_SERVICE'
	},
	{
		'type': 'id_list',
		'uri': '/service/detectionRules/OPAQUE_AND_EXTERNAL_WEB_REQUEST'
	},
	{
		'type': 'id_list',
		'uri': '/service/detectionRules/OPAQUE_AND_EXTERNAL_WEB_SERVICE'
	},
	{
		'type': 'id_list',
		'uri': '/service/ibmMQTracing/imsEntryQueue'
	},
	{
		'type': 'id_list',
		'uri': '/service/ibmMQTracing/queueManager'
	},
	{
		'type': 'id_list',
		'uri': '/service/requestAttributes'
	},
	{
		'type': 'id_list',
		'uri': '/service/requestNaming'
	},
	{
		'type': 'simple',
		'uri': '/service/resourceNaming'
	},
	{
		'type': 'simple',
		'uri': '/symfiles/dtxdss-download'
	},
	{
		'type': 'simple',
		'uri': '/symfiles/info'
	},
	{
		'type': 'simple',
		'uri': '/symfiles/ios/supportedversion'
	},
	{
		'type': 'id_list',
		'uri': '/symfiles'
	},
	{
		'type': 'simple',
		'uri': '/technologies'
	}
]
"@

function out-json ($filename, $object) {
	$filename = if ($filename[0] -eq '.') {
		($filename -split '' | Select-Object -Skip 2) -join ''
	}
	else { $filename }
	$outfile = Join-Path $script:outputfolder "$filename.json"

	write-host "Saving to $outfile"
	$object | ConvertTo-Json -Depth 20 | Out-File -Encoding utf8 -FilePath $outfile
}

# convert into usable format
$selectedApis = $configApis = $configApis | ConvertFrom-Json

# Apply the optional filter to the list of config apis
if ($script:filter) {
	$selectedApis = $selectedApis | Where-Object { $_.uri -match $script:filter -or $_.uriSuffix -join '' -match $script:filter }
}

foreach ($excludeTest in $exclude) {
	$selectedApis = $selectedApis | Where-Object { $_.uri -notmatch $excludeTest }
}

foreach ($includeTest in $include) {
	$selectedApis += $configApis | Where-Object { $_.uri -match $includeTest }
}

if (!$script:includeMobileSymbolManagementConfig) {
	$selectedApis = $selectedApis | Where-Object -Property 'uri' -NotMatch -Value 'symfiles'
}

# setup an output folder if none was provided
if (!$script:outputfolder) {
	$currentLoc = Get-Location
	$tenantName = if ($script:dtenv -like "*live.dynatrace.com*") {
		[regex]::Match("$script:dtenv", "([a-z0-9]+)\.live\.dynatrace").Groups[1].value
	}
	else {
		[regex]::Match("$script:dtenv", "/e/([a-z0-9\-]+)").Groups[1].value
	}
	$date = get-date -Format yyyyMMdd

	# Make the output folder
	$script:outputfolder = Join-Path $currentLoc "configBackup-$tenantName-$date"
	$newlymadeFolder = New-Item -ItemType Directory -Path $script:outputfolder -ErrorAction SilentlyContinue

	Write-Host -ForegroundColor Green "Created output folder: $($newlymadeFolder.fullname)"
}
else {
	$newlymadeFolder = New-Item -ItemType Directory -Path $script:outputfolder -force -ErrorAction Stop

	if (!(Test-Path -Path $script:outputfolder)) {
		Write-Error "Failed to create the output folder specified: $script:outputfolder"
		exit -1
	}

	Write-Host -ForegroundColor Green "Created output folder: $($newlymadeFolder.fullname)"
}

# get new baseURL
$baseURL = "$script:dtenv/api/config/v1"

foreach ($api in $selectedApis) {
	# create a baseURL for the API call
	$uri = "$baseURL$($api.uri)"

	write-host -ForegroundColor cyan "Config Read Request from: $uri"
	$r = Invoke-RestMethod -Method GET -Headers $headers -Uri $uri
	write-host -ForegroundColor White "Recieved $(($r | ConvertTo-Json -Depth 10 -Compress).length) Bytes of data"

	# do what's required for each API endpoint type
	switch ($api.type) {
		'simple' {
			# write the configuration as json to a file
			$fn = $api.uri -replace '/', '.'
			out-json -filename $fn -object $r
		}
		'id_list' { 
			# resolve each of the Ids and save
			foreach ($idval in $r.values) {
				$_uri = "$uri/$($idval.id)"
				write-host -ForegroundColor cyan "Config Read Request from: $_uri"
				$idr = Invoke-RestMethod -Method GET -Headers $headers -Uri $_uri
				$fn = "$($api.uri)/$($idval.id)" -replace '/', '.'
				out-json -filename $fn -object $idr

				if ($api.uriSuffix) {
					foreach ($s in $api.uriSuffix) {
						$_uri = "$uri/$($idval.id)/$($s)"
						write-host -ForegroundColor cyan "Config Read Request from: $_uri"
						$idr = Invoke-RestMethod -Method GET -Headers $headers -Uri $_uri		
						$fn = "$($api.uri)/$($idval.id)/$($s)" -replace '/', '.'
						out-json -filename $fn -object $idr
					}
				}
			}
		}
		Default {
			Write-Error "$($api.uri) configuration had an unknown or invalid type of '$($api.type)')"
		}
	}
}