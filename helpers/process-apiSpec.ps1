<#
.Synopsis
    Processes a spec3.json file from <env>/rest/v2/rest-api-docs/config/v1/spec3.json into a format usabled by export-tenantConfig.ps1
    
.Description
    The Dynatrace API is made available to users via a 'Swagger' Interface. 
    These interfaces are built off open API documentation standards that require a JSON 'spec' or specification file.
    This spec contains everything needed to understand what's available from the API and how to use it.

    The Dynatrace-pwsh script 'export-tenantConfig.ps1' benefits from the complete understanding of the API that this spec file provides, but cannot reach the spec file normally.
    Instead, we have this script to process out the spec file into a format that we (the repo owners) can use to ensure that export-tenantConfig.ps1 is kept as up to date as possible.

    The OpenAPI spec file must have the following:
        * OpenAPI version
        * Info
        * servers (unique for each instance)
        * security (unique for each instance)
        * tags
        * paths
        * components

    What Export-tenantconfig requires is each of the GET-able endpoints that return information along with: 
        * How to retrieve the id's of each instance of config
        * How to apply the id for each config endpoint
        * if there are any additional ways to use the id

    This information is stored in the Export-TenantConfig.ps1 in a JSON structure that can be easily updated as the spec changes

    This script is currently only proven to work for OpenAPI Spec 3.0.1 - it's assume that 3.x.x will be supported naturally.

.Notes
    Author: Michael.Ball
    Version: 0.0.1

#>

PARAM(
    [Parameter(ValueFromPipeline = $true)] [String] $inputObject, 
    [Alias('file', 'filepath')] [String] $path,

    [String[]] $ignoredAPIs = @('plugins/{id}/endpoints', 'plugins/{id}/binary', '/extensions/{id}/instances/{configurationId}', '{applicationId}/keyUserActions', 'userActionAndSessionProperties', 'symfiles/{applicationId}/{packageName}')
)

# Don't continue if something fails
$ErrorActionPreference = 'Stop'

if ($inputObject) {
    # if it's a path then we'll load it in (unlikely, but nice to be safe)
    if (Test-path -PathType Leaf -Path $script:inputObject) {
        $script:spec = Get-Content -Path $script:inputObject | ConvertFrom-Json
    } # Else assume that it's an object that should be converted and loaded 
    else {
        $script:spec = $script:inputObject | ConvertFrom-Json
    }
}
elseif ($path) {
    $script:spec = Get-Content -Path $script:path | ConvertFrom-Json
}

if (!$script:spec) {
    Write-Error "Failed to load spec file"
    return
}

# Warn if the file's version is possibly not compatible 
if ($script:spec.openapi -notlike '3.*.*') {
    Write-Warning "The provided spec is not using OpenAPI version 3 and may not work. Execution will continue but please make sure to use a compatible spec file or report this problem to the script owner"
}

# Do a quick check to make sure $spec is the expected content
if ($script:spec.info.title -ne 'Dynatrace Configuration API') {
    Write-Error "Info.Title was not 'Dynatrace Configuration API' - Please use the OpenAPI spec3.json file for the Dynatrace configuration API with this script."
    return
}

# # Filter out all the paths that end in 'Validator'
$nonValidatorPaths = $spec.paths | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty name | Where-Object { $_ -notlike '*/validator' }
$filteredPaths = $spec.paths | Select-Object -Property $nonValidatorPaths

# Skip any apis that have been marked as ignored
$unIgnoredAPIs = $filteredPaths | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty name | Where-Object { $api = $_; ($ignoredAPIs | Where-Object { $api -match $_ }).count -eq 0 }
$filteredPaths = $spec.paths | Select-Object -Property $unIgnoredAPIs

# Filter out all the paths that aren't get-able
$unGetablePaths = $filteredPaths | Get-Member -MemberType NoteProperty | ForEach-Object {
    @{name = $_.name; opts = Select-Object -InputObject $spec.paths -ExpandProperty $_.name }
} | Where-Object {
    ($_.opts | Get-Member | Select-Object -ExpandProperty name) -contains 'get' 
} | ForEach-Object { $_.name } | Sort-Object
$filteredPaths = $spec.paths | Select-Object -Property $unGetablePaths

# Get some important enums
$technologyEnums = $spec.paths.'/service/customServices/{technology}'.get.parameters.schema.enum
$conditionalNamingTypeEnum = $filteredPaths.'/conditionalNaming/{type}'.get.parameters.schema.enum

$apis = $unGetablePaths | Where-Object { $_ -notin ('/service/customServices/{technology}', '/conditionalNaming/{type}', '/service/customServices/{technology}/{id}', '/conditionalNaming/{type}/{id}') }
$apis += $technologyEnums | ForEach-Object { "/service/customServices/$_", "/service/customServices/$_/{id}" }
$apis += $conditionalNamingTypeEnum | ForEach-Object { "/conditionalNaming/$_", "/conditionalNaming/$_/{id}" }
$apis = $apis | Sort-Object

# now determine which of these are special and then transform them
# [
#     {uri: 'anomalyDetection/hosts', type: 'simple'},
#     {uri: 'anomalyDetection/metricEvents', type: 'id_list'},
#     {uri: 'applications/web', type: 'id_list', uriSuffix: ['dataPrivacy']}
# ]

$apiMetadata = @()
for ($i = 0; $i -lt $apis.length; $i++ ) {
    # each new type
    $_api = @{
        uri  = $apis[$i];
        type = 'simple';
    }

    WRite-host "Processing $($_api.uri)"

    $j = $i + 1
    $nextapi = $apis[$j++]
    while ($nextapi -like "$($_api.uri)*") {
        write-host "`t$nextapi"

        if ($nextapi -match "{id}$") {
            write-host "`t`tset as id_list"
            $_api.type = 'id_list'
        }
        elseif ($nextapi -match "{id}/(\w+)$") {
            write-host "`t`tFound suffix: $($matches.1)"
            $_api.uriSuffix = if ($_api.uriSuffix) { $_api.uriSuffix + $matches.1 } else { @($matches.1) }
        }

        $nextapi = $apis[$j++]
    }

    $i = $j - 2
    $apiMetadata += $_api
    
    # write-host "-- ($($_api.uri))"
}

$apiMetadata