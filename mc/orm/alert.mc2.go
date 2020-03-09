// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alert.proto

/*
Package orm is a generated protocol buffer package.

It is generated from these files:
	alert.proto
	app.proto
	appinst.proto
	appinstclient.proto
	autoprovpolicy.proto
	autoscalepolicy.proto
	cloudlet.proto
	cloudletpool.proto
	cluster.proto
	clusterinst.proto
	common.proto
	controller.proto
	debug.proto
	developer.proto
	exec.proto
	flavor.proto
	metric.proto
	node.proto
	notice.proto
	operator.proto
	privacypolicy.proto
	refs.proto
	restagtable.proto
	result.proto
	settings.proto
	version.proto

It has these top-level messages:
	Alert
	AppKey
	ConfigFile
	App
	AppInstKey
	AppInst
	AppInstRuntime
	AppInstInfo
	AppInstMetrics
	AppInstClientKey
	AppInstClient
	AutoProvPolicy
	AutoProvCloudlet
	AutoProvCount
	AutoProvCounts
	AutoProvPolicyCloudlet
	PolicyKey
	AutoScalePolicy
	CloudletKey
	OperationTimeLimits
	CloudletInfraCommon
	AzureProperties
	GcpProperties
	OpenStackProperties
	CloudletInfraProperties
	PlatformConfig
	CloudletResMap
	Cloudlet
	FlavorMatch
	FlavorInfo
	OSAZone
	OSImage
	CloudletInfo
	CloudletMetrics
	CloudletPoolKey
	CloudletPool
	CloudletPoolMember
	ClusterKey
	ClusterInstKey
	ClusterInst
	ClusterInstInfo
	StatusInfo
	ControllerKey
	Controller
	DebugRequest
	DebugReply
	DeveloperKey
	Developer
	RunCmd
	RunVMConsole
	ShowLog
	ExecRequest
	FlavorKey
	Flavor
	MetricTag
	MetricVal
	Metric
	NodeKey
	Node
	Notice
	OperatorKey
	Operator
	OperatorCode
	OutboundSecurityRule
	PrivacyPolicy
	CloudletRefs
	ClusterRefs
	ResTagTableKey
	ResTagTable
	Result
	Settings
*/
package orm

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "github.com/labstack/echo"
import "context"
import "io"
import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func ShowAlert(c echo.Context) error {
	ctx := GetContext(c)
	rc := &RegionContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.username = claims.Username

	in := ormapi.RegionAlert{}
	success, err := ReadConn(c, &in)
	if !success {
		return err
	}
	defer CloseConn(c)
	rc.region = in.Region

	err = ShowAlertStream(ctx, rc, &in.Alert, func(res *edgeproto.Alert) {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		WriteStream(c, &payload)
	})
	if err != nil {
		WriteError(c, err)
	}
	return nil
}

type ShowAlertAuthz interface {
	Ok(obj *edgeproto.Alert) bool
}

func ShowAlertStream(ctx context.Context, rc *RegionContext, obj *edgeproto.Alert, cb func(res *edgeproto.Alert)) error {
	var authz ShowAlertAuthz
	var err error
	if !rc.skipAuthz {
		authz, err = newShowAlertAuthz(ctx, rc.region, rc.username, ResourceAlert, ActionView)
		if err == echo.ErrForbidden {
			return nil
		}
		if err != nil {
			return err
		}
	}
	if rc.conn == nil {
		conn, err := connectController(ctx, rc.region)
		if err != nil {
			return err
		}
		rc.conn = conn
		defer func() {
			rc.conn.Close()
			rc.conn = nil
		}()
	}
	api := edgeproto.NewAlertApiClient(rc.conn)
	stream, err := api.ShowAlert(ctx, obj)
	if err != nil {
		return err
	}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			return err
		}
		if !rc.skipAuthz {
			if !authz.Ok(res) {
				continue
			}
		}
		cb(res)
	}
	return nil
}

func ShowAlertObj(ctx context.Context, rc *RegionContext, obj *edgeproto.Alert) ([]edgeproto.Alert, error) {
	arr := []edgeproto.Alert{}
	err := ShowAlertStream(ctx, rc, obj, func(res *edgeproto.Alert) {
		arr = append(arr, *res)
	})
	return arr, err
}

func addControllerApis(method string, group *echo.Group) {
	// swagger:route POST /auth/ctrl/ShowAlert Alert ShowAlert
	// Show alerts.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowAlert", ShowAlert)
	// swagger:route POST /auth/ctrl/CreateFlavor Flavor CreateFlavor
	// Create a Flavor.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/CreateFlavor", CreateFlavor)
	// swagger:route POST /auth/ctrl/DeleteFlavor Flavor DeleteFlavor
	// Delete a Flavor.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DeleteFlavor", DeleteFlavor)
	// swagger:route POST /auth/ctrl/UpdateFlavor Flavor UpdateFlavor
	// Update a Flavor.
	// The following values should be added to `Flavor.fields` field array to specify which fields will be updated.
	// ```
	// Key: 2
	// KeyName: 2.1
	// Ram: 3
	// Vcpus: 4
	// Disk: 5
	// OptResMap: 6
	// OptResMapKey: 6.1
	// OptResMapValue: 6.2
	// ```
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/UpdateFlavor", UpdateFlavor)
	// swagger:route POST /auth/ctrl/ShowFlavor Flavor ShowFlavor
	// Show Flavors.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowFlavor", ShowFlavor)
	// swagger:route POST /auth/ctrl/AddFlavorRes Flavor AddFlavorRes
	// Add Optional Resource.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/AddFlavorRes", AddFlavorRes)
	// swagger:route POST /auth/ctrl/RemoveFlavorRes Flavor RemoveFlavorRes
	// Remove Optional Resource.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/RemoveFlavorRes", RemoveFlavorRes)
	// swagger:route POST /auth/ctrl/CreateApp App CreateApp
	// Create Application.
	//  Creates a definition for an application instance for Cloudlet deployment.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/CreateApp", CreateApp)
	// swagger:route POST /auth/ctrl/DeleteApp App DeleteApp
	// Delete Application.
	//  Deletes a definition of an Application instance. Make sure no other application instances exist with that definition. If they do exist, you must delete those Application instances first.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DeleteApp", DeleteApp)
	// swagger:route POST /auth/ctrl/UpdateApp App UpdateApp
	// Update Application.
	//  Updates the definition of an Application instance.
	// The following values should be added to `App.fields` field array to specify which fields will be updated.
	// ```
	// Key: 2
	// KeyDeveloperKey: 2.1
	// KeyDeveloperKeyName: 2.1.2
	// KeyName: 2.2
	// KeyVersion: 2.3
	// ImagePath: 4
	// ImageType: 5
	// AccessPorts: 7
	// DefaultFlavor: 9
	// DefaultFlavorName: 9.1
	// AuthPublicKey: 12
	// Command: 13
	// Annotations: 14
	// Deployment: 15
	// DeploymentManifest: 16
	// DeploymentGenerator: 17
	// AndroidPackageName: 18
	// DelOpt: 20
	// Configs: 21
	// ConfigsKind: 21.1
	// ConfigsConfig: 21.2
	// ScaleWithCluster: 22
	// InternalPorts: 23
	// Revision: 24
	// OfficialFqdn: 25
	// Md5Sum: 26
	// DefaultSharedVolumeSize: 27
	// AutoProvPolicy: 28
	// AccessType: 29
	// DefaultPrivacyPolicy: 30
	// ```
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/UpdateApp", UpdateApp)
	// swagger:route POST /auth/ctrl/ShowApp App ShowApp
	// Show Applications.
	//  Lists all Application definitions managed from the Edge Controller. Any fields specified will be used to filter results.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowApp", ShowApp)
	// swagger:route POST /auth/ctrl/CreateOperatorCode OperatorCode CreateOperatorCode
	// Create a code for an Operator.
	//
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/CreateOperatorCode", CreateOperatorCode)
	// swagger:route POST /auth/ctrl/DeleteOperatorCode OperatorCode DeleteOperatorCode
	// Delete a code for an Operator.
	//
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DeleteOperatorCode", DeleteOperatorCode)
	// swagger:route POST /auth/ctrl/ShowOperatorCode OperatorCode ShowOperatorCode
	// Show OperatorCodes.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowOperatorCode", ShowOperatorCode)
	// swagger:route POST /auth/ctrl/CreateResTagTable ResTagTable CreateResTagTable
	// Create TagTable.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/CreateResTagTable", CreateResTagTable)
	// swagger:route POST /auth/ctrl/DeleteResTagTable ResTagTable DeleteResTagTable
	// Delete TagTable.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DeleteResTagTable", DeleteResTagTable)
	// swagger:route POST /auth/ctrl/UpdateResTagTable ResTagTable UpdateResTagTable
	// .
	// The following values should be added to `ResTagTable.fields` field array to specify which fields will be updated.
	// ```
	// Key: 2
	// KeyName: 2.1
	// KeyOperatorKey: 2.2
	// KeyOperatorKeyName: 2.2.1
	// Tags: 3
	// TagsKey: 3.1
	// TagsValue: 3.2
	// Azone: 4
	// ```
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/UpdateResTagTable", UpdateResTagTable)
	// swagger:route POST /auth/ctrl/ShowResTagTable ResTagTable ShowResTagTable
	// show TagTable.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowResTagTable", ShowResTagTable)
	// swagger:route POST /auth/ctrl/AddResTag ResTagTable AddResTag
	// add new tag(s) to TagTable.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/AddResTag", AddResTag)
	// swagger:route POST /auth/ctrl/RemoveResTag ResTagTable RemoveResTag
	// remove existing tag(s) from TagTable.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/RemoveResTag", RemoveResTag)
	// swagger:route POST /auth/ctrl/GetResTagTable ResTagTableKey GetResTagTable
	// Fetch a copy of the TagTable.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/GetResTagTable", GetResTagTable)
	// swagger:route POST /auth/ctrl/CreateCloudlet Cloudlet CreateCloudlet
	// Create Cloudlet.
	//  Sets up Cloudlet services on the Operators compute resources, and integrated as part of MobiledgeX edge resource portfolio. These resources are managed from the Edge Controller.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/CreateCloudlet", CreateCloudlet)
	group.Match([]string{method}, "/ctrl/StreamCloudlet", StreamCloudlet)
	// swagger:route POST /auth/ctrl/DeleteCloudlet Cloudlet DeleteCloudlet
	// Delete Cloudlet.
	//  Removes the Cloudlet services where they are no longer managed from the Edge Controller.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DeleteCloudlet", DeleteCloudlet)
	// swagger:route POST /auth/ctrl/UpdateCloudlet Cloudlet UpdateCloudlet
	// Update Cloudlet.
	//  Updates the Cloudlet configuration and manages the upgrade of Cloudlet services.
	// The following values should be added to `Cloudlet.fields` field array to specify which fields will be updated.
	// ```
	// Key: 2
	// KeyOperatorKey: 2.1
	// KeyOperatorKeyName: 2.1.1
	// KeyName: 2.2
	// Location: 5
	// LocationLatitude: 5.1
	// LocationLongitude: 5.2
	// LocationHorizontalAccuracy: 5.3
	// LocationVerticalAccuracy: 5.4
	// LocationAltitude: 5.5
	// LocationCourse: 5.6
	// LocationSpeed: 5.7
	// LocationTimestamp: 5.8
	// LocationTimestampSeconds: 5.8.1
	// LocationTimestampNanos: 5.8.2
	// IpSupport: 6
	// StaticIps: 7
	// NumDynamicIps: 8
	// TimeLimits: 9
	// TimeLimitsCreateClusterInstTimeout: 9.1
	// TimeLimitsUpdateClusterInstTimeout: 9.2
	// TimeLimitsDeleteClusterInstTimeout: 9.3
	// TimeLimitsCreateAppInstTimeout: 9.4
	// TimeLimitsUpdateAppInstTimeout: 9.5
	// TimeLimitsDeleteAppInstTimeout: 9.6
	// Errors: 10
	// Status: 11
	// StatusTaskNumber: 11.1
	// StatusMaxTasks: 11.2
	// StatusTaskName: 11.3
	// StatusStepName: 11.4
	// State: 12
	// CrmOverride: 13
	// DeploymentLocal: 14
	// PlatformType: 15
	// NotifySrvAddr: 16
	// Flavor: 17
	// FlavorName: 17.1
	// PhysicalName: 18
	// EnvVar: 19
	// EnvVarKey: 19.1
	// EnvVarValue: 19.2
	// ContainerVersion: 20
	// Config: 21
	// ConfigContainerRegistryPath: 21.1
	// ConfigCloudletVmImagePath: 21.2
	// ConfigNotifyCtrlAddrs: 21.3
	// ConfigVaultAddr: 21.4
	// ConfigTlsCertFile: 21.5
	// ConfigEnvVar: 21.6
	// ConfigEnvVarKey: 21.6.1
	// ConfigEnvVarValue: 21.6.2
	// ConfigPlatformTag: 21.8
	// ConfigTestMode: 21.9
	// ConfigSpan: 21.10
	// ConfigCleanupMode: 21.11
	// ConfigRegion: 21.12
	// ResTagMap: 22
	// ResTagMapKey: 22.1
	// ResTagMapValue: 22.2
	// ResTagMapValueName: 22.2.1
	// ResTagMapValueOperatorKey: 22.2.2
	// ResTagMapValueOperatorKeyName: 22.2.2.1
	// AccessVars: 23
	// AccessVarsKey: 23.1
	// AccessVarsValue: 23.2
	// VmImageVersion: 24
	// PackageVersion: 25
	// ```
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/UpdateCloudlet", UpdateCloudlet)
	// swagger:route POST /auth/ctrl/ShowCloudlet Cloudlet ShowCloudlet
	// Show Cloudlets.
	//  Lists all the cloudlets managed from Edge Controller.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowCloudlet", ShowCloudlet)
	// swagger:route POST /auth/ctrl/AddCloudletResMapping CloudletResMap AddCloudletResMapping
	// Add Optional Resource tag table.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/AddCloudletResMapping", AddCloudletResMapping)
	// swagger:route POST /auth/ctrl/RemoveCloudletResMapping CloudletResMap RemoveCloudletResMapping
	// Add Optional Resource tag table.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/RemoveCloudletResMapping", RemoveCloudletResMapping)
	// swagger:route POST /auth/ctrl/FindFlavorMatch FlavorMatch FindFlavorMatch
	// Discover if flavor produces a matching platform flavor.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/FindFlavorMatch", FindFlavorMatch)
	// swagger:route POST /auth/ctrl/ShowCloudletInfo CloudletInfo ShowCloudletInfo
	// Show CloudletInfos.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowCloudletInfo", ShowCloudletInfo)
	// swagger:route POST /auth/ctrl/CreateClusterInst ClusterInst CreateClusterInst
	// Create Cluster Instance.
	//  Creates an instance of a Cluster on a Cloudlet, defined by a Cluster Key and a Cloudlet Key. ClusterInst is a collection of compute resources on a Cloudlet on which AppInsts are deployed.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/CreateClusterInst", CreateClusterInst)
	group.Match([]string{method}, "/ctrl/StreamClusterInst", StreamClusterInst)
	// swagger:route POST /auth/ctrl/DeleteClusterInst ClusterInst DeleteClusterInst
	// Delete Cluster Instance.
	//  Deletes an instance of a Cluster deployed on a Cloudlet.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DeleteClusterInst", DeleteClusterInst)
	// swagger:route POST /auth/ctrl/UpdateClusterInst ClusterInst UpdateClusterInst
	// Update Cluster Instance.
	//  Updates an instance of a Cluster deployed on a Cloudlet.
	// The following values should be added to `ClusterInst.fields` field array to specify which fields will be updated.
	// ```
	// Key: 2
	// KeyClusterKey: 2.1
	// KeyClusterKeyName: 2.1.1
	// KeyCloudletKey: 2.2
	// KeyCloudletKeyOperatorKey: 2.2.1
	// KeyCloudletKeyOperatorKeyName: 2.2.1.1
	// KeyCloudletKeyName: 2.2.2
	// KeyDeveloper: 2.3
	// Flavor: 3
	// FlavorName: 3.1
	// Liveness: 9
	// Auto: 10
	// State: 4
	// Errors: 5
	// CrmOverride: 6
	// IpAccess: 7
	// AllocatedIp: 8
	// NodeFlavor: 11
	// Deployment: 15
	// NumMasters: 13
	// NumNodes: 14
	// Status: 16
	// StatusTaskNumber: 16.1
	// StatusMaxTasks: 16.2
	// StatusTaskName: 16.3
	// StatusStepName: 16.4
	// ExternalVolumeSize: 17
	// AutoScalePolicy: 18
	// AvailabilityZone: 19
	// ImageName: 20
	// Reservable: 21
	// ReservedBy: 22
	// SharedVolumeSize: 23
	// PrivacyPolicy: 24
	// MasterNodeFlavor: 25
	// ```
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/UpdateClusterInst", UpdateClusterInst)
	// swagger:route POST /auth/ctrl/ShowClusterInst ClusterInst ShowClusterInst
	// Show Cluster Instances.
	//  Lists all the cluster instances managed by Edge Controller.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowClusterInst", ShowClusterInst)
	// swagger:route POST /auth/ctrl/CreateAppInst AppInst CreateAppInst
	// Create Application Instance.
	//  Creates an instance of an App on a Cloudlet where it is defined by an App plus a ClusterInst key. Many of the fields here are inherited from the App definition.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/CreateAppInst", CreateAppInst)
	group.Match([]string{method}, "/ctrl/StreamAppInst", StreamAppInst)
	// swagger:route POST /auth/ctrl/DeleteAppInst AppInst DeleteAppInst
	// Delete Application Instance.
	//  Deletes an instance of the App from the Cloudlet.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DeleteAppInst", DeleteAppInst)
	// swagger:route POST /auth/ctrl/RefreshAppInst AppInst RefreshAppInst
	// Refresh Application Instance.
	//  Restarts an App instance with new App settings or image.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/RefreshAppInst", RefreshAppInst)
	// swagger:route POST /auth/ctrl/UpdateAppInst AppInst UpdateAppInst
	// Update Application Instance.
	//  Updates an Application instance and then refreshes it.
	// The following values should be added to `AppInst.fields` field array to specify which fields will be updated.
	// ```
	// Key: 2
	// KeyAppKey: 2.1
	// KeyAppKeyDeveloperKey: 2.1.1
	// KeyAppKeyDeveloperKeyName: 2.1.1.2
	// KeyAppKeyName: 2.1.2
	// KeyAppKeyVersion: 2.1.3
	// KeyClusterInstKey: 2.4
	// KeyClusterInstKeyClusterKey: 2.4.1
	// KeyClusterInstKeyClusterKeyName: 2.4.1.1
	// KeyClusterInstKeyCloudletKey: 2.4.2
	// KeyClusterInstKeyCloudletKeyOperatorKey: 2.4.2.1
	// KeyClusterInstKeyCloudletKeyOperatorKeyName: 2.4.2.1.1
	// KeyClusterInstKeyCloudletKeyName: 2.4.2.2
	// KeyClusterInstKeyDeveloper: 2.4.3
	// CloudletLoc: 3
	// CloudletLocLatitude: 3.1
	// CloudletLocLongitude: 3.2
	// CloudletLocHorizontalAccuracy: 3.3
	// CloudletLocVerticalAccuracy: 3.4
	// CloudletLocAltitude: 3.5
	// CloudletLocCourse: 3.6
	// CloudletLocSpeed: 3.7
	// CloudletLocTimestamp: 3.8
	// CloudletLocTimestampSeconds: 3.8.1
	// CloudletLocTimestampNanos: 3.8.2
	// Uri: 4
	// Liveness: 6
	// MappedPorts: 9
	// MappedPortsProto: 9.1
	// MappedPortsInternalPort: 9.2
	// MappedPortsPublicPort: 9.3
	// MappedPortsPathPrefix: 9.4
	// MappedPortsFqdnPrefix: 9.5
	// MappedPortsEndPort: 9.6
	// MappedPortsTls: 9.7
	// Flavor: 12
	// FlavorName: 12.1
	// State: 14
	// Errors: 15
	// CrmOverride: 16
	// RuntimeInfo: 17
	// RuntimeInfoContainerIds: 17.1
	// CreatedAt: 21
	// CreatedAtSeconds: 21.1
	// CreatedAtNanos: 21.2
	// AutoClusterIpAccess: 22
	// Status: 23
	// StatusTaskNumber: 23.1
	// StatusMaxTasks: 23.2
	// StatusTaskName: 23.3
	// StatusStepName: 23.4
	// Revision: 24
	// ForceUpdate: 25
	// UpdateMultiple: 26
	// Configs: 27
	// ConfigsKind: 27.1
	// ConfigsConfig: 27.2
	// SharedVolumeSize: 28
	// HealthCheck: 29
	// PrivacyPolicy: 30
	// PowerState: 31
	// ExternalVolumeSize: 32
	// AvailabilityZone: 33
	// VmFlavor: 34
	// ```
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/UpdateAppInst", UpdateAppInst)
	// swagger:route POST /auth/ctrl/ShowAppInst AppInst ShowAppInst
	// Show Application Instances.
	//  Lists all the Application instances managed by the Edge Controller. Any fields specified will be used to filter results.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowAppInst", ShowAppInst)
	// swagger:route POST /auth/ctrl/ShowAppInstClient AppInstClientKey ShowAppInstClient
	// Show application instance clients.
	//
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowAppInstClient", ShowAppInstClient)
	// swagger:route POST /auth/ctrl/CreateAutoScalePolicy AutoScalePolicy CreateAutoScalePolicy
	// Create an Auto Scale Policy.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/CreateAutoScalePolicy", CreateAutoScalePolicy)
	// swagger:route POST /auth/ctrl/DeleteAutoScalePolicy AutoScalePolicy DeleteAutoScalePolicy
	// Delete an Auto Scale Policy.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DeleteAutoScalePolicy", DeleteAutoScalePolicy)
	// swagger:route POST /auth/ctrl/UpdateAutoScalePolicy AutoScalePolicy UpdateAutoScalePolicy
	// Update an Auto Scale Policy.
	// The following values should be added to `AutoScalePolicy.fields` field array to specify which fields will be updated.
	// ```
	// Key: 2
	// KeyDeveloper: 2.1
	// KeyName: 2.2
	// MinNodes: 3
	// MaxNodes: 4
	// ScaleUpCpuThresh: 5
	// ScaleDownCpuThresh: 6
	// TriggerTimeSec: 7
	// ```
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/UpdateAutoScalePolicy", UpdateAutoScalePolicy)
	// swagger:route POST /auth/ctrl/ShowAutoScalePolicy AutoScalePolicy ShowAutoScalePolicy
	// Show Auto Scale Policies.
	//  Any fields specified will be used to filter results.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowAutoScalePolicy", ShowAutoScalePolicy)
	// swagger:route POST /auth/ctrl/CreateAutoProvPolicy AutoProvPolicy CreateAutoProvPolicy
	// Create an Auto Provisioning Policy.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/CreateAutoProvPolicy", CreateAutoProvPolicy)
	// swagger:route POST /auth/ctrl/DeleteAutoProvPolicy AutoProvPolicy DeleteAutoProvPolicy
	// Delete an Auto Provisioning Policy.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DeleteAutoProvPolicy", DeleteAutoProvPolicy)
	// swagger:route POST /auth/ctrl/UpdateAutoProvPolicy AutoProvPolicy UpdateAutoProvPolicy
	// Update an Auto Provisioning Policy.
	// The following values should be added to `AutoProvPolicy.fields` field array to specify which fields will be updated.
	// ```
	// Key: 2
	// KeyDeveloper: 2.1
	// KeyName: 2.2
	// DeployClientCount: 3
	// DeployIntervalCount: 4
	// Cloudlets: 5
	// CloudletsKey: 5.1
	// CloudletsKeyOperatorKey: 5.1.1
	// CloudletsKeyOperatorKeyName: 5.1.1.1
	// CloudletsKeyName: 5.1.2
	// CloudletsLoc: 5.2
	// CloudletsLocLatitude: 5.2.1
	// CloudletsLocLongitude: 5.2.2
	// CloudletsLocHorizontalAccuracy: 5.2.3
	// CloudletsLocVerticalAccuracy: 5.2.4
	// CloudletsLocAltitude: 5.2.5
	// CloudletsLocCourse: 5.2.6
	// CloudletsLocSpeed: 5.2.7
	// CloudletsLocTimestamp: 5.2.8
	// CloudletsLocTimestampSeconds: 5.2.8.1
	// CloudletsLocTimestampNanos: 5.2.8.2
	// ```
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/UpdateAutoProvPolicy", UpdateAutoProvPolicy)
	// swagger:route POST /auth/ctrl/ShowAutoProvPolicy AutoProvPolicy ShowAutoProvPolicy
	// Show Auto Provisioning Policies.
	//  Any fields specified will be used to filter results.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowAutoProvPolicy", ShowAutoProvPolicy)
	// swagger:route POST /auth/ctrl/AddAutoProvPolicyCloudlet AutoProvPolicyCloudlet AddAutoProvPolicyCloudlet
	// Add a Cloudlet to the Auto Provisioning Policy.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/AddAutoProvPolicyCloudlet", AddAutoProvPolicyCloudlet)
	// swagger:route POST /auth/ctrl/RemoveAutoProvPolicyCloudlet AutoProvPolicyCloudlet RemoveAutoProvPolicyCloudlet
	// Remove a Cloudlet from the Auto Provisioning Policy.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/RemoveAutoProvPolicyCloudlet", RemoveAutoProvPolicyCloudlet)
	// swagger:route POST /auth/ctrl/CreateCloudletPool CloudletPool CreateCloudletPool
	// Create a CloudletPool.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/CreateCloudletPool", CreateCloudletPool)
	// swagger:route POST /auth/ctrl/DeleteCloudletPool CloudletPool DeleteCloudletPool
	// Delete a CloudletPool.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DeleteCloudletPool", DeleteCloudletPool)
	// swagger:route POST /auth/ctrl/ShowCloudletPool CloudletPool ShowCloudletPool
	// Show CloudletPools.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowCloudletPool", ShowCloudletPool)
	// swagger:route POST /auth/ctrl/CreateCloudletPoolMember CloudletPoolMember CreateCloudletPoolMember
	// Add a Cloudlet to a CloudletPool.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/CreateCloudletPoolMember", CreateCloudletPoolMember)
	// swagger:route POST /auth/ctrl/DeleteCloudletPoolMember CloudletPoolMember DeleteCloudletPoolMember
	// Remove a Cloudlet from a CloudletPool.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DeleteCloudletPoolMember", DeleteCloudletPoolMember)
	// swagger:route POST /auth/ctrl/ShowCloudletPoolMember CloudletPoolMember ShowCloudletPoolMember
	// Show the Cloudlet to CloudletPool relationships.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowCloudletPoolMember", ShowCloudletPoolMember)
	// swagger:route POST /auth/ctrl/ShowPoolsForCloudlet CloudletKey ShowPoolsForCloudlet
	// Show CloudletPools that have Cloudlet as a member.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowPoolsForCloudlet", ShowPoolsForCloudlet)
	// swagger:route POST /auth/ctrl/ShowCloudletsForPool CloudletPoolKey ShowCloudletsForPool
	// Show Cloudlets that belong to the Pool.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowCloudletsForPool", ShowCloudletsForPool)
	// swagger:route POST /auth/ctrl/ShowNode Node ShowNode
	// Show all Nodes connected to all Controllers.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowNode", ShowNode)
	// swagger:route POST /auth/ctrl/EnableDebugLevels DebugRequest EnableDebugLevels
	// .
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/EnableDebugLevels", EnableDebugLevels)
	// swagger:route POST /auth/ctrl/DisableDebugLevels DebugRequest DisableDebugLevels
	// .
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DisableDebugLevels", DisableDebugLevels)
	// swagger:route POST /auth/ctrl/ShowDebugLevels DebugRequest ShowDebugLevels
	// .
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowDebugLevels", ShowDebugLevels)
	// swagger:route POST /auth/ctrl/RunDebug DebugRequest RunDebug
	// .
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/RunDebug", RunDebug)
	// swagger:route POST /auth/ctrl/RunCommand ExecRequest RunCommand
	// Run a Command or Shell on a container.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/RunCommand", RunCommand)
	// swagger:route POST /auth/ctrl/RunConsole ExecRequest RunConsole
	// Run console on a VM.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/RunConsole", RunConsole)
	// swagger:route POST /auth/ctrl/ShowLogs ExecRequest ShowLogs
	// View logs for AppInst.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowLogs", ShowLogs)
	// swagger:route POST /auth/ctrl/CreatePrivacyPolicy PrivacyPolicy CreatePrivacyPolicy
	// Create a Privacy Policy.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/CreatePrivacyPolicy", CreatePrivacyPolicy)
	// swagger:route POST /auth/ctrl/DeletePrivacyPolicy PrivacyPolicy DeletePrivacyPolicy
	// Delete a Privacy policy.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/DeletePrivacyPolicy", DeletePrivacyPolicy)
	// swagger:route POST /auth/ctrl/UpdatePrivacyPolicy PrivacyPolicy UpdatePrivacyPolicy
	// Update a Privacy policy.
	// The following values should be added to `PrivacyPolicy.fields` field array to specify which fields will be updated.
	// ```
	// Key: 2
	// KeyDeveloper: 2.1
	// KeyName: 2.2
	// OutboundSecurityRules: 3
	// OutboundSecurityRulesProtocol: 3.1
	// OutboundSecurityRulesPortRangeMin: 3.2
	// OutboundSecurityRulesPortRangeMax: 3.3
	// OutboundSecurityRulesRemoteCidr: 3.4
	// ```
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/UpdatePrivacyPolicy", UpdatePrivacyPolicy)
	// swagger:route POST /auth/ctrl/ShowPrivacyPolicy PrivacyPolicy ShowPrivacyPolicy
	// Show Privacy Policies.
	//  Any fields specified will be used to filter results.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowPrivacyPolicy", ShowPrivacyPolicy)
	// swagger:route POST /auth/ctrl/ShowCloudletRefs CloudletRefs ShowCloudletRefs
	// Show CloudletRefs (debug only).
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowCloudletRefs", ShowCloudletRefs)
	// swagger:route POST /auth/ctrl/ShowClusterRefs ClusterRefs ShowClusterRefs
	// Show ClusterRefs (debug only).
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowClusterRefs", ShowClusterRefs)
	// swagger:route POST /auth/ctrl/UpdateSettings Settings UpdateSettings
	// Update settings.
	// The following values should be added to `Settings.fields` field array to specify which fields will be updated.
	// ```
	// ShepherdMetricsCollectionInterval: 2
	// ShepherdHealthCheckRetries: 3
	// ShepherdHealthCheckInterval: 4
	// AutoDeployIntervalSec: 5
	// AutoDeployOffsetSec: 6
	// AutoDeployMaxIntervals: 7
	// CreateAppInstTimeout: 8
	// UpdateAppInstTimeout: 9
	// DeleteAppInstTimeout: 10
	// CreateClusterInstTimeout: 11
	// UpdateClusterInstTimeout: 12
	// DeleteClusterInstTimeout: 13
	// MasterNodeFlavor: 14
	// LoadBalancerMaxPortRange: 15
	// MaxTrackedDmeClients: 16
	// ```
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/UpdateSettings", UpdateSettings)
	// swagger:route POST /auth/ctrl/ResetSettings Settings ResetSettings
	// Reset all settings to their defaults.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ResetSettings", ResetSettings)
	// swagger:route POST /auth/ctrl/ShowSettings Settings ShowSettings
	// Show settings.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	group.Match([]string{method}, "/ctrl/ShowSettings", ShowSettings)
}
