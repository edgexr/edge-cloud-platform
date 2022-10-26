# Go API client for fedewapi

# Introduction
---
RESTful APIs that allow an OP to share the edge cloud resources and capabilities securely to other partner OPs over E/WBI. 

---
# API Scope

---
APIs defined in this version of the specification can be categorized into the following areas:
* __FederationManagement__ - Create and manage directed federation relationship with a partner OP
* __AvailabilityZoneInfoSynchronization__ - Management of resources of partner OP zones and status updates 
* __ArtifactManagement__ - Upload, remove, retrieve and update application descriptors, charts and packages over E/WBI towards a partner OP
* __FileManagement__ - Upload, remove, retrieve and update  application binaries over E/WBI towards a partner OP
* __ApplicationOnboardingManagement__ - Register, retrieve, update and remove applications over E/WBI towards a partner OP
* __ApplicationDeploymentManagement__ - Create, update, retrieve and terminate application instances over E/WBI towards a partner OP
* __AppProviderResourceManagement__ -  Static resource reservation for an application provider over E/WBI for partner OP zones
* __EdgeNodeSharing__ - Edge discovery procedures towards partner OP over E/WBI.
* __LBORoamingAuthentication__ -  Validation of user client authentication from home OP

---
# Definitions
---
This section provides definitions of terminologies commonly referred to throughout the API descriptions.

* __Accepted Zones__  - List of partner OP zones, which the originating OP has confirmed to use for its edge applications
* __Anchoring__ - Partner OP capability to serve application clients (still in their home location) from application instances running on partner zones. 
* __Application Provider__ - An application developer, onboarding his/her edge application on a partner operator platform (MEC).        
* __Artefact__ - Descriptor, charts or any other package associated with the application.
* __Availability Zone__ - Zones that partner OP can offer to share with originating OP.
* __Device__ - Refers to user equipment like mobile phone, tablet, IOT kit, AR/VR device etc. In context of MEC users use these devices to access edge applications
* __Directed Federation__ - A Federation between two OP instances A and B, in which edge compute resources are shared by B to A, but not from A to B.
* __Edge Application__ - Application designed to run on MEC edge cloud  
* __Edge Discovery Service__ - Partner OP service responsible to select most optimal edge( within partner OP) for edge application instantiation. Edge discovery service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP.
* __E/WBI__ - East west bound interface.
* __Federation__ - Relationship among member OPs who agrees to offer  services and capabilities to the application providers and end users of member OPs  
* __FederationContextId__ - Partner OP defined string identifier representing a certain federation relationship.
* __Federation Identifier__ - Identify an operator platform in federation context.
* __FileId__ - An OP defined string identifier representing a certain application image uploaded by an application provider
* __Flavour__ - A group of compute, network and storage resources that can be requested or granted as a single unit
* __FlavourIdentifier__ - An OP defined string identifier representing a set of compute, storage  and networking resources
* __Home OP__ - Used in federation context to identify the OP with which the application developers or user clients are registered.
* __Home Routing__ - Partner OP capability to direct roaming user client traffic towards application instances running on home OP zones. 
* __Instance__ - Application process running on an edge
* __LCM Service__ -  Partner OP service responsible for life cycle management of edge applications. LCM service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP.
* __Offered Zones__ - Zones that partner OP offer to share  to the Originating OP based on the prior agreement and local configuration.   
* __Onboarding__ - Submitting an application to MEC platform 
* __OP__ - Operator platform.
* __OperatorIdentfier__ - String identifier representing the owner of MEC platform. Owner could  be an enterprise, a TSP or some other organization
* __Originating OP__ - The OP when initiating the federation creation request towards the partner OP is defined as the Originating OP
* __Partner OP__ - Operator Platform which offers its Edge Cloud capabilities to the other Operator Platforms via E/WBI.     
* __Resource__ - Compute, networking and storage resources.
* __Resource Pool__ -  A group of  compute, networking and storage resources. Application provider  pre-reserve resources on partner OP zone, these resources are reserved in terms of flavours. 
* __ZoneIdentifier__ - An OP defined string identifier representing a certain geographical or logical area where edge resources and services are provided
* __Zone Confirmation__ - Procedure via which originating OP acknowledges partner OP about the partner zones it wishes to use.
* __User Clients__ -  Lightweight client applications used to access edge applications. Application users run these clients on their devices (UE, IOT device, AR/VR device etc)

 
---
# API Operations
---  

__FederationManagement__
* __CreateFederation__  Creates a directed federation relationship with a partner OP
* __GetFederationDetails__  Retrieves details about the federation relationship with the partner OP. The response shall provide info about the zones offered by the partner, partner OP network codes, information about edge discovery and LCM service etc.
* __DeleteFederationDetails__  Remove existing federation with the partner OP
* __NotifyFederationUpdates__ Call back notification used by partner OP to update originating OP about any change in existing federation relationship.
* __UpdateFederation__ API used by the Originating OP towards the partner OP, to update the parameters associated to the existing federation

__AvailabilityZoneInfoSynchronization__
* __ZoneSubscribe__  Informs partner OP that originating OP is willing to access the specified zones  and partner OP shall reserve compute and network resources for these zones.
* __ZoneUnsubscribe__  Informs partner OP that originating OP will no longer access the specified partner OP zone.
* __GetZoneData__  Retrieves details about the computation and network resources that partner OP has reserved for an partner OP  zone.
* __Notify Zone Information__ Call back notification used by partner OP to update originating OP about changes in the resources reserved on a partner zone.

__ArtefactManagement__
* __UploadArtefact__  Uploads application artefact  on partner operator platform.
* __RemoveArtefact__  Removes an artefact from partner operator platform.
* __GetArtefact__  Retrieves details about an artefact from partner operator platform.
* __UploadFile__ Upload application binaries to partner operator platform
* __RemoveFile__  Removes application binaries from partner operator platform
* __ViewFile__  Retrieves details about binaries assosiated with an application from partner operator platform

__ApplicationOnboardingManagement__
* __OnboardApplication__ - Submits an application details to a partner OP. Based on the details provided,  partner OP shall do bookkeeping, resource validation and other pre-deployment operations
* __UpdateApplication__ - Updates partner OP about changes in  application compute resource requirements, QOS Profile, associated descriptor or change in assosiated components
* __DeboardApplication__ - Removes an application from partner OP
* __ViewApplication__ - Retrieves application details from partner OP
* __OnboardExistingAppNewZones__ - Make an application available on new additional zones
* __LockUnlockApplicationZone__ - Forbid or permit instantiation of application on a zone

__Application Instance Lifecycle Management__
* __InstallApp__ - Instantiates an application on a partner OP zone.
* __GetAppInstanceDetails__ - Retrieves an application instance details from partner OP.
* __RemoveApp__ - Terminate an application instance on a partner OP zone.
* __GetAllAppInstances__ - Retrieves details about all instances of the application running on partner OP zones.


__AppProviderResourceManagement__
* __CreateResourcePools__  Reserves resources (compute, network and storage)  on a partner OP zone. ISVs registered with home OP reserves resurces on a partner OP zone.
* __UpdateISVResPool__  Updates resources reserved for a pool by an ISV
* __ViewISVResPool__  Retrieves the resource pool reserved by an ISV
* __RemoveISVResPool__ Deletes the resource pool reserved by an ISV


__EdgeNodeSharing__
*__GetCandidateZones__ Edge discovery procedures towards partner OP over E/WBI. Originating OP request partner OP to provide a list of candidate zones where an application instance can be created. 


__LBORoamingAuthentication__
*__AuthenticateDevice__ Validates the authenticity of a roaming user from home OP


© 2022 GSM Association.
All rights reserved.


## Overview
This API client was generated by the [OpenAPI Generator](https://openapi-generator.tech) project.  By using the [OpenAPI-spec](https://www.openapis.org/) from a remote server, you can easily generate an API client.

- API version: 1.0.0
- Package version: 1.0.0
- Build package: org.openapitools.codegen.languages.GoClientCodegen

## Installation

Install the following dependencies:

```shell
go get github.com/stretchr/testify/assert
go get golang.org/x/oauth2
go get golang.org/x/net/context
```

Put the package under your project folder and add the following in import:

```golang
import fedewapi "github.com/GIT_USER_ID/GIT_REPO_ID"
```

To use a proxy, set the environment variable `HTTP_PROXY`:

```golang
os.Setenv("HTTP_PROXY", "http://proxy_name:proxy_port")
```

## Configuration of Server URL

Default configuration comes with `Servers` field that contains server objects as defined in the OpenAPI specification.

### Select Server Configuration

For using other server than the one defined on index 0 set context value `sw.ContextServerIndex` of type `int`.

```golang
ctx := context.WithValue(context.Background(), fedewapi.ContextServerIndex, 1)
```

### Templated Server URL

Templated server URL is formatted using default variables from configuration or from context value `sw.ContextServerVariables` of type `map[string]string`.

```golang
ctx := context.WithValue(context.Background(), fedewapi.ContextServerVariables, map[string]string{
	"basePath": "v2",
})
```

Note, enum values are always validated and all unused variables are silently ignored.

### URLs Configuration per Operation

Each operation can use different server URL defined using `OperationServers` map in the `Configuration`.
An operation is uniquely identified by `"{classname}Service.{nickname}"` string.
Similar rules for overriding default operation server index and variables applies by using `sw.ContextOperationServerIndices` and `sw.ContextOperationServerVariables` context maps.

```golang
ctx := context.WithValue(context.Background(), fedewapi.ContextOperationServerIndices, map[string]int{
	"{classname}Service.{nickname}": 2,
})
ctx = context.WithValue(context.Background(), fedewapi.ContextOperationServerVariables, map[string]map[string]string{
	"{classname}Service.{nickname}": {
		"port": "8443",
	},
})
```

## Documentation for API Endpoints

All URIs are relative to *https://operatorplatform.com/operatorplatform/federation/v1*

Class | Method | HTTP request | Description
------------ | ------------- | ------------- | -------------
*AppProviderResourceManagementApi* | [**CreateResourcePools**](docs/AppProviderResourceManagementApi.md#createresourcepools) | **Post** /{federationContextId}/isv/resource/zone/{zoneId}/appProvider/{appProviderId} | Reserves resources (compute, network and storage)  on a partner OP zone.   ISVs registered with home OP reserves resources on a partner OP zone.
*AppProviderResourceManagementApi* | [**RemoveISVResPool**](docs/AppProviderResourceManagementApi.md#removeisvrespool) | **Delete** /{federationContextId}/isv/resource/zone/{zoneId}/appProvider/{appProviderId}/pool/{poolId} | Deletes the resource pool reserved by an ISV
*AppProviderResourceManagementApi* | [**UpdateISVResPool**](docs/AppProviderResourceManagementApi.md#updateisvrespool) | **Patch** /{federationContextId}/isv/resource/zone/{zoneId}/appProvider/{appProviderId}/pool/{poolId} | Updates resources reserved for a pool by an ISV
*AppProviderResourceManagementApi* | [**ViewISVResPool**](docs/AppProviderResourceManagementApi.md#viewisvrespool) | **Get** /{federationContextId}/isv/resource/zone/{zoneId}/appProvider/{appProviderId} | Retrieves the resource pool reserved by an ISV
*ApplicationDeploymentManagementApi* | [**GetAllAppInstances**](docs/ApplicationDeploymentManagementApi.md#getallappinstances) | **Get** /{federationContextId}/application/lcm/app/{appId}/appProvider/{appProviderId} | Retrieves all application instance of partner OP
*ApplicationDeploymentManagementApi* | [**GetAppInstanceDetails**](docs/ApplicationDeploymentManagementApi.md#getappinstancedetails) | **Get** /{federationContextId}/application/lcm/app/{appId}/instance/{appInstanceId}/zone/{zoneId} | Retrieves an application instance details from partner OP.
*ApplicationDeploymentManagementApi* | [**InstallApp**](docs/ApplicationDeploymentManagementApi.md#installapp) | **Post** /{federationContextId}/application/lcm | Instantiates an application on a partner OP zone.
*ApplicationDeploymentManagementApi* | [**RemoveApp**](docs/ApplicationDeploymentManagementApi.md#removeapp) | **Delete** /{federationContextId}/application/lcm/app/{appId}/instance/{appInstanceId}/zone/{zoneId} | Terminate an application instance on a partner OP zone.
*ApplicationOnboardingManagementApi* | [**DeboardApplication**](docs/ApplicationOnboardingManagementApi.md#deboardapplication) | **Delete** /{federationContextId}/application/onboarding/app/{appId}/zone/{zoneId} | Deboards an application from partner OP zones
*ApplicationOnboardingManagementApi* | [**LockUnlockApplicationZone**](docs/ApplicationOnboardingManagementApi.md#lockunlockapplicationzone) | **Post** /{federationContextId}/application/onboarding/app/{appId}/zoneForbid | Forbid/allow application instantiation on a partner zone
*ApplicationOnboardingManagementApi* | [**OnboardApplication**](docs/ApplicationOnboardingManagementApi.md#onboardapplication) | **Post** /{federationContextId}/application/onboarding | Submits an application details to a partner OP. Based on the details provided,  partner OP shall do bookkeeping, resource validation and other pre-deployment operations.
*ApplicationOnboardingManagementApi* | [**OnboardExistingAppNewZones**](docs/ApplicationOnboardingManagementApi.md#onboardexistingappnewzones) | **Post** /{federationContextId}/application/onboarding/app/{appId}/additionalZones | Onboards an existing application to a new zone within partner OP.
*ApplicationOnboardingManagementApi* | [**UpdateApplication**](docs/ApplicationOnboardingManagementApi.md#updateapplication) | **Patch** /{federationContextId}/application/onboarding/app/{appId} | Updates partner OP about changes in  application compute resource requirements, QOS Profile, associated descriptor or change in associated components
*ApplicationOnboardingManagementApi* | [**ViewApplication**](docs/ApplicationOnboardingManagementApi.md#viewapplication) | **Get** /{federationContextId}/application/onboarding/app/{appId} | Retrieves application details from partner OP
*ArtefactManagementApi* | [**GetArtefact**](docs/ArtefactManagementApi.md#getartefact) | **Get** /{federationContextId}/artefact/{artefactId} | Retrieves details about an artefact.
*ArtefactManagementApi* | [**RemoveArtefact**](docs/ArtefactManagementApi.md#removeartefact) | **Delete** /{federationContextId}/artefact/{artefactId} | Removes an artefact from partner OP.
*ArtefactManagementApi* | [**RemoveFile**](docs/ArtefactManagementApi.md#removefile) | **Delete** /{federationContextId}/files/{fileId} | Removes an image file from partner OP.
*ArtefactManagementApi* | [**UploadArtefact**](docs/ArtefactManagementApi.md#uploadartefact) | **Post** /{federationContextId}/artefact | Uploads application artefact  on partner OP. Artefact is a zip file containing  scripts and/or packaging files like Terraform or Helm which are required to create an instance of an application.
*ArtefactManagementApi* | [**UploadFile**](docs/ArtefactManagementApi.md#uploadfile) | **Post** /{federationContextId}/files | Uploads an image file. Originating OP uses this api to onboard an application image to partner OP.
*ArtefactManagementApi* | [**ViewFile**](docs/ArtefactManagementApi.md#viewfile) | **Get** /{federationContextId}/files/{fileId} | View an image file from partner OP.
*AvailabilityZoneInfoSynchronizationApi* | [**GetZoneData**](docs/AvailabilityZoneInfoSynchronizationApi.md#getzonedata) | **Get** /{federationContextId}/zones/{zoneId} | Retrieves details about the computation and network resources that partner OP has reserved for this zone.
*AvailabilityZoneInfoSynchronizationApi* | [**ZoneSubscribe**](docs/AvailabilityZoneInfoSynchronizationApi.md#zonesubscribe) | **Post** /{federationContextId}/zones | Originating OP informs partner OP that it is willing to access the specified zones  and partner OP shall reserve compute and network resources for these zones.
*AvailabilityZoneInfoSynchronizationApi* | [**ZoneUnsubscribe**](docs/AvailabilityZoneInfoSynchronizationApi.md#zoneunsubscribe) | **Delete** /{federationContextId}/zones/{zoneId} | Asservate usage of  a partner OP zone. Originating OP informs partner OP that it will no longer access the specified zone.
*EdgeNodeSharingApi* | [**GetCandidateZones**](docs/EdgeNodeSharingApi.md#getcandidatezones) | **Post** /{federationContextId}/edgenodesharing/edgeDiscovery | Edge discovery procedures towards partner OP over E/WBI. Originating OP request partner OP to provide a list of candidate zones where an application instance can be created. Partner OP applies a set of filtering criteria’s to select candidate zones.
*FederationManagementApi* | [**CreateFederation**](docs/FederationManagementApi.md#createfederation) | **Post** /partner | Creates one direction federation with partner operator platform.
*FederationManagementApi* | [**DeleteFederationDetails**](docs/FederationManagementApi.md#deletefederationdetails) | **Delete** /{federationContextId}/partner | Remove existing federation with the partner OP
*FederationManagementApi* | [**GetFederationDetails**](docs/FederationManagementApi.md#getfederationdetails) | **Get** /{federationContextId}/partner | Retrieves details about the federation context with the partner OP. The response shall provide info about the zones offered by the partner, partner OP network codes, information about edge discovery and LCM service etc.
*FederationManagementApi* | [**UpdateFederation**](docs/FederationManagementApi.md#updatefederation) | **Patch** /{federationContextId}/partner | API used by the Originating OP towards the partner OP, to update the parameters associated to the existing federation
*LBORoamingAuthenticationApi* | [**AuthenticateDevice**](docs/LBORoamingAuthenticationApi.md#authenticatedevice) | **Get** /{federationContextId}/roaminguserauth/device/{deviceId}/token/{authToken} | Validates the authenticity of a roaming user from home OP


## Documentation For Models

 - [CPUArchType](docs/CPUArchType.md)
 - [ClientLocation](docs/ClientLocation.md)
 - [ClientLocationRadLocationInner](docs/ClientLocationRadLocationInner.md)
 - [ComputeResourceInfo](docs/ComputeResourceInfo.md)
 - [CreateResourcePools200Response](docs/CreateResourcePools200Response.md)
 - [CreateResourcePoolsRequest](docs/CreateResourcePoolsRequest.md)
 - [CreateResourcePoolsRequestResRequest](docs/CreateResourcePoolsRequestResRequest.md)
 - [CreateResourcePoolsRequestResRequestFlavoursInner](docs/CreateResourcePoolsRequestResRequestFlavoursInner.md)
 - [DiscoveredEdgeNodesInner](docs/DiscoveredEdgeNodesInner.md)
 - [FederationContextIdApplicationLcmPostRequest](docs/FederationContextIdApplicationLcmPostRequest.md)
 - [FederationContextIdApplicationLcmPostRequestAppInstanceInfo](docs/FederationContextIdApplicationLcmPostRequestAppInstanceInfo.md)
 - [FederationContextIdApplicationLcmPostRequestAppInstanceInfoAccesspointInfoInner](docs/FederationContextIdApplicationLcmPostRequestAppInstanceInfoAccesspointInfoInner.md)
 - [FederationContextIdApplicationOnboardingPostRequest](docs/FederationContextIdApplicationOnboardingPostRequest.md)
 - [FederationContextIdApplicationOnboardingPostRequestStatusInfoInner](docs/FederationContextIdApplicationOnboardingPostRequestStatusInfoInner.md)
 - [FederationContextIdIsvResourceZoneZoneIdAppProviderAppProviderIdGetRequest](docs/FederationContextIdIsvResourceZoneZoneIdAppProviderAppProviderIdGetRequest.md)
 - [FederationContextIdIsvResourceZoneZoneIdAppProviderAppProviderIdGetRequestGrantedFlavoursInner](docs/FederationContextIdIsvResourceZoneZoneIdAppProviderAppProviderIdGetRequestGrantedFlavoursInner.md)
 - [FederationContextIdZonesPostRequest](docs/FederationContextIdZonesPostRequest.md)
 - [FederationContextIdZonesPostRequestZoneResUpdInfoInner](docs/FederationContextIdZonesPostRequestZoneResUpdInfoInner.md)
 - [FederationContextIdZonesPostRequestZoneResUpdInfoInnerAvailableNetResources](docs/FederationContextIdZonesPostRequestZoneResUpdInfoInnerAvailableNetResources.md)
 - [FederationRequestData](docs/FederationRequestData.md)
 - [FederationResponseData](docs/FederationResponseData.md)
 - [Flavour](docs/Flavour.md)
 - [GetAllAppInstances200ResponseInner](docs/GetAllAppInstances200ResponseInner.md)
 - [GetAllAppInstances200ResponseInnerAppInstanceInfoInner](docs/GetAllAppInstances200ResponseInnerAppInstanceInfoInner.md)
 - [GetAppInstanceDetails200Response](docs/GetAppInstanceDetails200Response.md)
 - [GetAppInstanceDetails200ResponseAccesspointInfoInner](docs/GetAppInstanceDetails200ResponseAccesspointInfoInner.md)
 - [GetArtefact200Response](docs/GetArtefact200Response.md)
 - [GetArtefact200ResponseArtefactRepoLocation](docs/GetArtefact200ResponseArtefactRepoLocation.md)
 - [GetCandidateZonesRequest](docs/GetCandidateZonesRequest.md)
 - [GetCandidateZonesRequestEdgeDiscoveryFilters](docs/GetCandidateZonesRequestEdgeDiscoveryFilters.md)
 - [GetFederationDetails200Response](docs/GetFederationDetails200Response.md)
 - [GpuInfo](docs/GpuInfo.md)
 - [HugePage](docs/HugePage.md)
 - [InstallApp202Response](docs/InstallApp202Response.md)
 - [InstallAppRequest](docs/InstallAppRequest.md)
 - [InstallAppRequestZoneInfo](docs/InstallAppRequestZoneInfo.md)
 - [InstanceState](docs/InstanceState.md)
 - [InvalidParam](docs/InvalidParam.md)
 - [Ipv6Addr](docs/Ipv6Addr.md)
 - [MobileNetworkIds](docs/MobileNetworkIds.md)
 - [OSType](docs/OSType.md)
 - [OnboardApplicationRequest](docs/OnboardApplicationRequest.md)
 - [OnboardApplicationRequestAppComponentSpecsInner](docs/OnboardApplicationRequestAppComponentSpecsInner.md)
 - [OnboardApplicationRequestAppDeploymentZonesInner](docs/OnboardApplicationRequestAppDeploymentZonesInner.md)
 - [OnboardApplicationRequestAppMetaData](docs/OnboardApplicationRequestAppMetaData.md)
 - [OnboardApplicationRequestAppQoSProfile](docs/OnboardApplicationRequestAppQoSProfile.md)
 - [PartnerPostRequest](docs/PartnerPostRequest.md)
 - [PartnerPostRequestZoneStatusInner](docs/PartnerPostRequestZoneStatusInner.md)
 - [ProblemDetails](docs/ProblemDetails.md)
 - [ResourceReservationDuration](docs/ResourceReservationDuration.md)
 - [ServiceEndpoint](docs/ServiceEndpoint.md)
 - [Status](docs/Status.md)
 - [UpdateApplicationRequest](docs/UpdateApplicationRequest.md)
 - [UpdateApplicationRequestAppComponentSpecsInner](docs/UpdateApplicationRequestAppComponentSpecsInner.md)
 - [UpdateApplicationRequestAppUpdQoSProfile](docs/UpdateApplicationRequestAppUpdQoSProfile.md)
 - [UpdateFederationRequest](docs/UpdateFederationRequest.md)
 - [UpdateISVResPoolRequestInner](docs/UpdateISVResPoolRequestInner.md)
 - [ViewApplication200Response](docs/ViewApplication200Response.md)
 - [ViewApplication200ResponseAppDeploymentZonesInner](docs/ViewApplication200ResponseAppDeploymentZonesInner.md)
 - [ViewApplication200ResponseAppDeploymentZonesInnerZoneInfo](docs/ViewApplication200ResponseAppDeploymentZonesInnerZoneInfo.md)
 - [ViewFile200Response](docs/ViewFile200Response.md)
 - [ViewISVResPool200Response](docs/ViewISVResPool200Response.md)
 - [ViewISVResPool200ResponseReservedFlavoursInner](docs/ViewISVResPool200ResponseReservedFlavoursInner.md)
 - [ZoneDetails](docs/ZoneDetails.md)
 - [ZoneRegisterationRequestData](docs/ZoneRegisterationRequestData.md)
 - [ZoneRegisterationResponseData](docs/ZoneRegisterationResponseData.md)
 - [ZoneRegisteredData](docs/ZoneRegisteredData.md)
 - [ZoneRegisteredDataNetworkResources](docs/ZoneRegisteredDataNetworkResources.md)


## Documentation For Authorization



### oAuth2ClientCredentials


- **Type**: OAuth
- **Flow**: application
- **Authorization URL**: 
- **Scopes**: 
 - **fed-mgmt**: Access to the federation APIs

Example

```golang
auth := context.WithValue(context.Background(), sw.ContextAccessToken, "ACCESSTOKENSTRING")
r, err := client.Service.Operation(auth, args)
```

Or via OAuth2 module to automatically refresh tokens and perform user authentication.

```golang
import "golang.org/x/oauth2"

/* Perform OAuth2 round trip request and obtain a token */

tokenSource := oauth2cfg.TokenSource(createContext(httpClient), &token)
auth := context.WithValue(oauth2.NoContext, sw.ContextOAuth2, tokenSource)
r, err := client.Service.Operation(auth, args)
```


## Documentation for Utility Methods

Due to the fact that model structure members are all pointers, this package contains
a number of utility functions to easily obtain pointers to values of basic types.
Each of these functions takes a value of the given basic type and returns a pointer to it:

* `PtrBool`
* `PtrInt`
* `PtrInt32`
* `PtrInt64`
* `PtrFloat`
* `PtrFloat32`
* `PtrFloat64`
* `PtrString`
* `PtrTime`

## Author


