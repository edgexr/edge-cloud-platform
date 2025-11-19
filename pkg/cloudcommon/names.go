// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudcommon

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	yaml "gopkg.in/yaml.v2"
)

// special operator types
var OperatorGCP = "gcp"
var OperatorAzure = "azure"
var OperatorAWS = "aws"

const DefaultClust string = "defaultclust"
const DefaultMultiTenantCluster string = "defaultmtclust"

// platform apps
var PlatosEnablingLayer = "PlatosEnablingLayer"

// cloudlet types
var CloudletKindOpenStack = "openstack"
var CloudletKindAzure = "azure"
var CloudletKindAws = "aws"
var CloudletKindGCP = "gcp"
var CloudletKindDIND = "dind"
var CloudletKindFake = "fake"

var OperatingSystemMac = "mac"
var OperatingSystemLinux = "linux"

// Cloudlet Platform nodes -- update IsPlatformNode if adding to this list

type NodeType int

const (
	NodeTypeAppVM NodeType = iota
	NodeTypeSharedRootLB
	NodeTypeDedicatedRootLB
	NodeTypePlatformVM
	NodeTypePlatformHost
	NodeTypePlatformK8sClusterMaster
	NodeTypePlatformK8sClusterPrimaryNode
	NodeTypePlatformK8sClusterSecondaryNode
	// Cloudlet Compute nodes
	NodeTypeK8sClusterMaster
	NodeTypeK8sClusterNode
	NodeTypeDockerClusterNode
)

func (n NodeType) String() string {
	switch n {
	case NodeTypeAppVM:
		return "appvm"
	case NodeTypeSharedRootLB:
		return "sharedrootlb"
	case NodeTypeDedicatedRootLB:
		return "dedicatedrootlb"
	case NodeTypePlatformVM:
		return "platformvm"
	case NodeTypePlatformHost:
		return "platformhost"
	case NodeTypePlatformK8sClusterMaster:
		return "platform-k8s-cluster-master"
	case NodeTypePlatformK8sClusterPrimaryNode:
		return "platform-k8s-cluster-primary-node"
	case NodeTypePlatformK8sClusterSecondaryNode:
		return "platform-k8s-cluster-secondary-node"
	case NodeTypeK8sClusterMaster:
		return "k8s-cluster-master"
	case NodeTypeK8sClusterNode:
		return "k8s-cluster-node"
	case NodeTypeDockerClusterNode:
		return "docker-cluster-node"
	}
	return "unknown node type"
}

// NodeRole specifies the role for provisioning a node from ansible
type NodeRole string

const (
	NodeRoleBase             NodeRole = "base"
	NodeRoleDockerCrm        NodeRole = "dockercrm"        // crm and shepherd on platform VM
	NodeRoleDockerShepherdLB NodeRole = "dockershepherdlb" // shepherd on root LB
	NodeRoleK8sCrm           NodeRole = "k8scrm"
	NodeRoleK8sCrmWorker     NodeRole = "k8scrmworker"
)

func (s NodeRole) String() string {
	return string(s)
}

// resource types
var ResourceTypeK8sLBSvc = "k8s-lb-svc"

const AutoProvPrefix = "autoprov"
const ReservableClusterPrefix = "reservable"
const ReserveClusterEvent = "Reserve ClusterInst"
const FreeClusterEvent = "Free ClusterInst reservation"

// network schemes for use by standalone deployments (e.g. DIND)
var NetworkSchemePublicIP = "publicip"
var NetworkSchemePrivateIP = "privateip"

// Metrics common variables - TODO move to edge-cloud-infra after metrics-exporter chagnes
var DeveloperMetricsDbName = "metrics"
var MEXPrometheusAppName = "MEXPrometheusAppName"
var PrometheusPort = int32(9090)
var NFSAutoProvisionAppName = "NFSAutoProvision"
var ProxyMetricsPort = int32(65121)
var ProxyMetricsDefaultListenIP = "127.0.0.1"
var ProxyMetricsListenUDS = "MetricsUDS" // Unix Domain Socket
var InternalDockerRegistry = "internal-docker-registry"
var InternalVMRegistry = "internal-vm-registry"

var AutoProvMeasurement = "auto-prov-counts"

// AppLabels for the application containers
var MexAppInstNameLabel = "mexAppInstName" // deprecated, use AppInstNameLabel
var MexAppInstOrgLabel = "mexAppInstOrg"   // deprecated, use AppInstOrgLabel
var MexAppNameLabel = "mexAppName"
var MexAppVersionLabel = "mexAppVersion"
var MexMetricEndpoint = "mexMetricsEndpoint"

const AppInstNameLabel = "app.edgexr.org/appinst-name"
const AppInstOrgLabel = "app.edgexr.org/appinst-org"

// Instance Lifecycle variables
var EventsDbName = "events"
var CloudletEvent = "cloudlet"
var ClusterInstEvent = "clusterinst"
var ClusterInstCheckpoints = "clusterinst-checkpoints"
var AppInstEvent = "appinst"
var AppInstCheckpoints = "appinst-checkpoints"
var MonthlyInterval = "MONTH"
var DmeApiMeasurement = "dme-api"

// Influx metrics selectors
var AppInstEventSelectors = []string{
	edgeproto.AppInstKeyTagName,
	edgeproto.AppInstKeyTagOrganization,
	edgeproto.CloudletKeyTagName,
	edgeproto.CloudletKeyTagOrganization,
	edgeproto.CloudletKeyTagFederatedOrganization,
}
var ClusterInstEventSelectors = []string{
	edgeproto.ClusterKeyTagName,
	edgeproto.ClusterKeyTagOrganization,
	edgeproto.CloudletKeyTagName,
	edgeproto.CloudletKeyTagOrganization,
	edgeproto.CloudletKeyTagFederatedOrganization,
}

const (
	MetricTagRegion           = "region"
	MetricTagOrg              = "org"
	MetricTagEvent            = "event"
	MetricTagStatus           = "status"
	MetricTagStart            = "start"
	MetricTagEnd              = "end"
	MetricTagStartTime        = "starttime"
	MetricTagEndTime          = "endtime"
	MetricTagDuration         = "duration"
	MetricTagUptime           = "uptime"
	MetricTagFlavor           = "flavor"
	MetricTagDeployment       = "deployment"
	MetricTagRAM              = "ram"
	MetricTagVCPU             = "vcpu"
	MetricTagGPUs             = "gpus"
	MetricTagDisk             = "disk"
	MetricTagNodeCount        = "nodecount"
	MetricTagNumNodes         = "numnodes"
	MetricTagOther            = "other"
	MetricTagNote             = "note"
	MetricTagIpAccess         = "ipaccess"
	MetricTagPort             = "port"
	MetricTagDmeId            = "dmeId"
	MetricTagMethod           = "method"
	MetricTagLocationTile     = "locationtile"
	MetricTagDataNetworkType  = "datanetworktype"
	MetricTagDeviceCarrier    = "devicecarrier"
	MetricTagDeviceOS         = "deviceos"
	MetricTagDeviceModel      = "devicemodel"
	MetricTagFoundCloudlet    = "foundCloudlet"
	MetricTagFoundAppInstName = "foundappinstname"
	MetricTagFoundAppInstOrg  = "foundappinstorg"
	MetricTagFoundZoneName    = "foundzone"
	MetricTagFoundZoneOrg     = "foundzoneorg"
	MetricTagFoundOperator    = "foundOperator"
	MetricTagDmeCloudlet      = "dmecloudlet"
	MetricTagDmeCloudletOrg   = "dmecloudletorg"
	MetricTagStatName         = "statname"
)

// Cloudlet resource usage
var CloudletResourceUsageDbName = "cloudlet_resource_usage"
var CloudletFlavorUsageMeasurement = "cloudlet-flavor-usage"

// EdgeEvents Metrics Influx variables
var EdgeEventsMetricsDbName = "edgeevents_metrics"
var LatencyMetric = "latency-metric"
var DeviceMetric = "device-metric"
var CustomMetric = "custom-metric"

// Common API paths
var VmRegPath = "/storage/v1/artifacts"
var VmRegPullPath = "/storage/v1/pull"
var VmRegHeaderMD5 = "X-Checksum-Md5"
var ControllerEdgeprotoRESTPath = "/edgeproto/v1"
var NBIRootPath = "/edge-application-management/vwip"

// Map used to identify which metrics should go to persistent_metrics db. Value represents the measurement creation status
var EdgeEventsMetrics = map[string]struct{}{
	LatencyMetric: struct{}{},
	DeviceMetric:  struct{}{},
	CustomMetric:  struct{}{},
}

var DownsampledMetricsDbName = "downsampled_metrics"

var IPAddrAllInterfaces = "0.0.0.0"
var IPV6AddrAllInterfaces = "::"
var IPAddrLocalHost = "127.0.0.1"
var RemoteServerNone = ""

// Client type to access cluster nodes
var ClientTypeRootLB string = "rootlb"
var ClientTypeClusterVM string = "clustervm"

type InstanceEvent string

const (
	CREATED           InstanceEvent = "CREATED"
	UPDATE_START      InstanceEvent = "UPDATE_START"
	UPDATE_ERROR      InstanceEvent = "UPDATE_ERROR"
	UPDATE_COMPLETE   InstanceEvent = "UPDATE_COMPLETE"
	DELETED           InstanceEvent = "DELETED"
	DELETE_ERROR      InstanceEvent = "DELETE_ERROR"
	HEALTH_CHECK_FAIL InstanceEvent = "HEALTH_CHECK_FAIL"
	HEALTH_CHECK_OK   InstanceEvent = "HEALTH_CHECK_OK"
	RESERVED          InstanceEvent = "RESERVED"
	UNRESERVED        InstanceEvent = "UNRESERVED"
)

const (
	AnnotationCloudletScopedName      = "cloudlet-scoped-name"
	AnnotationBadUpgrade55Name        = "bad-upgrade55-name"
	AnnotationPreviousDNSName         = "previous-dns-name"
	AnnotationFedPartnerAppProviderID = "fed-partner-app-provider-id"
	AnnotationKubernetesVersion       = "kubernetes-version"
	AnnotationKeepNamespaceOnDelete   = "keep-namespace-on-delete"
	AnnotationControlVIP              = "control-vip"
)

type ErrorAction string

const (
	AbortOnError    ErrorAction = "abort"
	ContinueOnError ErrorAction = "continue"
)

var InstanceUp = "UP"
var InstanceDown = "DOWN"

// DIND script to pull from kubeadm-dind-cluster
var DindScriptName = "dind-cluster-v1.14.sh"

var MexNodePrefix = "mex-k8s-node-"

// GCP limits to 40, Azure has issues above 54.  For consistency go with the lower limit
const MaxClusterNameLength = 40

// UnknownOwner for ObjID
const UnknownOwner = "unknown"

// Common cert name. Cannot use common name as filename since envoy doesn't know if the app is dedicated or not
const CertName = "envoyTlsCerts"

// PlatformApps is the set of all special "platform" developers.   Key
// is DeveloperName:AppName.  Currently only platos's Enabling layer is included.
var platformApps = map[string]bool{
	edgeproto.OrganizationPlatos + ":" + PlatosEnablingLayer: true,
}

// IsPlatformApp true if the developer/app combo is a platform app
func IsPlatformApp(devname string, appname string) bool {
	_, ok := platformApps[devname+":"+appname]
	return ok
}

var AllocatedIpDynamic = "dynamic"

var RootLBHostname = "shared"

// These alphabets are used for generating random strings with gonanoid.
const IdAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const IdAlphabetLC = "0123456789abcdefghijklmnopqrstuvwxyz"

type CommonContextKey string

var ContextKeyUndo = CommonContextKey("undo")

// Fully Qualified Domain Names (FQDNs) primarily come in the
// the following format of 4 "labels" (where domain can actually
// be more than one label itself, i.e. edgecloud.net):
// cloudletobject.cloudlet.region.domain
// In some cases, another label will be prepended
// (such as for ip-per-k8s-services, the service name is prepended).
// To help avoid the total length limit of 253 when prepending additional
// labels, we restrict the base labels to less than the DNS spec
// per-label restriction of 63, based on how long we expect those
// labels to be in general. For example, we expect most region names to
// be 3-4 characters, while appname+version+org is likely to be much
// longer.
const DnsDomainLabelMaxLen = 40
const DnsRegionLabelMaxLen = 10
const DnsCloudletLabelMaxLen = 50
const DnsCloudletObjectLabelMaxLen = 63
const AppFederatedIdMaxLen = 50

// Values for QOS Priority Session API
const TagPrioritySessionId string = "priority_session_id"
const TagQosProfileName string = "qos_profile_name"
const TagIpUserEquipment string = "ip_user_equipment"

var DefaultPlatformFlavorKey = edgeproto.FlavorKey{
	Name: "DefaultPlatformFlavor",
}

// Wildcard cert for all LBs both shared and dedicated
func GetRootLBFQDNWildcard(cloudlet *edgeproto.Cloudlet) string {
	names := strings.Split(cloudlet.RootLbFqdn, ".")
	names[0] = "*"
	return strings.Join(names, ".")
}

// Old version of getting the shared root lb, does not match wildcard cert.
func GetRootLBFQDNOld(key *edgeproto.CloudletKey, domain string) string {
	loc := util.DNSSanitize(key.Name)
	oper := util.DNSSanitize(key.Organization)
	return fmt.Sprintf("%s.%s.%s", loc, oper, domain)
}

// FqdnPrefix is used only for IP-per-service platforms that allocate
// an IP for each kubernetes service. Because it adds an extra level of
// DNS label hierarchy and cannot match the wildcard cert, we do not
// support TLS for it.
func FqdnPrefix(svcName string) string {
	return svcName + "."
}

func ServiceFQDN(svcName, baseFQDN string) string {
	return fmt.Sprintf("%s%s", FqdnPrefix(svcName), baseFQDN)
}

// DNS names must have labels <= 63 chars, and the total length
// <= 255 octets (which works out to 253 chars).
func CheckFQDNLengths(prefix, uri string) error {
	fqdn := prefix + uri
	if len(fqdn) > 253 {
		return fmt.Errorf("DNS name %q exceeds 253 chars, please shorten some names", fqdn)
	}
	for _, label := range strings.Split(fqdn, ".") {
		if len(label) > 63 {
			return fmt.Errorf("Label %q of DNS name %q exceeds 63 chars, please shorten it", label, fqdn)
		}
	}
	return nil
}

// For the DME and CRM that require a cloudlet key to be specified
// at startup, this function parses the string argument.
func ParseMyCloudletKey(standalone bool, keystr *string, mykey *edgeproto.CloudletKey) {
	if *keystr == "" {
		log.FatalLog("cloudletKey not specified")
	}

	err := json.Unmarshal([]byte(*keystr), mykey)
	if err != nil {
		err = yaml.Unmarshal([]byte(*keystr), mykey)
	}
	if err != nil {
		log.FatalLog("Failed to parse cloudletKey", "err", err)
	}

	err = mykey.ValidateKey()
	if err != nil {
		log.FatalLog("Invalid cloudletKey", "key", mykey, "err", err)
	}
}

func IsClusterInstReqd(app *edgeproto.App) bool {
	if app.Deployment == DeploymentTypeVM {
		return false
	}
	return true
}

func IsSideCarApp(app *edgeproto.App) bool {
	if edgeproto.IsEdgeCloudOrg(app.Key.Organization) && app.DelOpt == edgeproto.DeleteType_AUTO_DELETE {
		return true
	}
	return false
}

func GetSideCarAppFilter() *edgeproto.App {
	return &edgeproto.App{
		Key:    edgeproto.AppKey{Organization: edgeproto.OrganizationEdgeCloud},
		DelOpt: edgeproto.DeleteType_AUTO_DELETE,
	}
}

func Hostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "nohostname"
	}
	return hostname
}

func GetAppClientType(app *edgeproto.App) string {
	clientType := ClientTypeRootLB
	if app.Deployment == DeploymentTypeDocker &&
		app.AccessType != edgeproto.AccessType_ACCESS_TYPE_DIRECT {
		// docker commands can be run on either the rootlb or on the docker
		// vm. The default is to run on the rootlb client
		// If using a load balancer access, a separate VM is always used for
		// docker vs the LB, and we always use host networking mode
		clientType = ClientTypeClusterVM
	}
	return clientType
}

// GetCertsDirAndFiles returns certsDir, certFile, keyFile
func GetCertsDirAndFiles(pwd string) (string, string, string) {
	pwd = strings.TrimSpace(pwd)
	certsDir := pwd + "/envoy/certs"
	certFile := certsDir + "/" + CertName + ".crt"
	keyFile := certsDir + "/" + CertName + ".key"
	return certsDir, certFile, keyFile
}

func GetCloudletResourceUsageMeasurement(pfType string) string {
	return fmt.Sprintf("%s-resource-usage", pfType)
}

func GetGPUDriverStoragePath(key *edgeproto.GPUDriverKey, region string) (string, error) {
	orgName := key.Organization
	if key.Organization == "" {
		orgName = edgeproto.OrganizationEdgeCloud
	}
	sPath := StoragePath{}
	err := sPath.AppendPaths(region, orgName, key.Name)
	if err != nil {
		return "", err
	}
	return sPath.String(), nil
}

func GetGPUDriverLicenseStoragePath(key *edgeproto.GPUDriverKey, region string) (string, error) {
	driverStoragePath, err := GetGPUDriverStoragePath(key, region)
	if err != nil {
		return "", err
	}
	sPath := StoragePath{}
	err = sPath.AppendPaths("licenseconfig", edgeproto.GPUDriverLicenseConfig)
	if err != nil {
		return "", err
	}
	return driverStoragePath + "/" + sPath.String(), nil
}

func GetGPUDriverLicenseCloudletStoragePath(key *edgeproto.GPUDriverKey, region string, cloudletKey *edgeproto.CloudletKey) (string, error) {
	if key.Organization != "" && key.Organization != cloudletKey.Organization {
		return "", fmt.Errorf("Can only use %s or '' org gpu drivers", key.Organization)
	}
	driverStoragePath, err := GetGPUDriverStoragePath(key, region)
	if err != nil {
		return "", err
	}
	// If GPU driver org is empty i.e. it is owned by edge cloud org, then add cloudletOrg to storage path
	cloudletOrg := ""
	if key.Organization == "" {
		cloudletOrg = cloudletKey.Organization
	}
	sPath := StoragePath{}
	err = sPath.AppendPaths("cloudlet", "licenseconfig", cloudletOrg, cloudletKey.Name, edgeproto.GPUDriverLicenseConfig)
	if err != nil {
		return "", err
	}
	return driverStoragePath + "/" + sPath.String(), nil
}

func GetGPUDriverBuildStoragePath(key *edgeproto.GPUDriverKey, region, buildName, ext string) (string, error) {
	driverStoragePath, err := GetGPUDriverStoragePath(key, region)
	if err != nil {
		return "", err
	}
	sPath := StoragePath{}
	err = sPath.AppendPaths("build", buildName+ext)
	if err != nil {
		return "", err
	}
	return driverStoragePath + "/" + sPath.String(), nil
}

func IsPlatformNode(nodeTypeStr string) bool {
	switch nodeTypeStr {
	case NodeTypePlatformVM.String():
		fallthrough
	case NodeTypePlatformHost.String():
		fallthrough
	case NodeTypePlatformK8sClusterMaster.String():
		fallthrough
	case NodeTypePlatformK8sClusterPrimaryNode.String():
		fallthrough
	case NodeTypePlatformK8sClusterSecondaryNode.String():
		return true
	}
	return false
}

func IsLBNode(nodeTypeStr string) bool {
	return nodeTypeStr == NodeTypeDedicatedRootLB.String() || nodeTypeStr == NodeTypeSharedRootLB.String()
}

func GetArtifactOrgPath(org, path string) string {
	orgpath := "/" + org
	if path != "" {
		if path[0] == '/' {
			orgpath += path
		} else {
			orgpath += "/" + path
		}
	}
	return orgpath
}

func GetArtifactStoragePath(addr, org, path string) string {
	addr = strings.TrimRight(addr, "/")
	return addr + VmRegPath + GetArtifactOrgPath(org, path)
}

func GetArtifactPullPath(addr, org, path string) string {
	addr = strings.TrimRight(addr, "/")
	return addr + VmRegPullPath + GetArtifactOrgPath(org, path)
}

// AppInstLabels are for labeling objects to track that they
// belong to an AppInst. The cloudlet key information is omitted
// because objects to track are on a particular cloudlet, so the
// cloudlet info is fixed.
type AppInstLabels struct {
	AppInstNameLabel string
	AppInstOrgLabel  string
}

func GetAppInstLabels(appInst *edgeproto.AppInst) AppInstLabels {
	return AppInstLabels{
		AppInstNameLabel: util.K8SLabelValueSanitize(appInst.Key.Name),
		AppInstOrgLabel:  util.K8SLabelValueSanitize(appInst.Key.Organization),
	}
}

func (s *AppInstLabels) Map() map[string]string {
	return map[string]string{
		MexAppInstNameLabel: s.AppInstNameLabel,
		MexAppInstOrgLabel:  s.AppInstOrgLabel,
	}
}

func (s *AppInstLabels) FromMap(labels map[string]string) {
	if labels == nil {
		return
	}
	// for backwards compatibility we support the old labels as well
	s.AppInstNameLabel = labels[MexAppInstNameLabel]
	s.AppInstOrgLabel = labels[MexAppInstOrgLabel]
	if v, ok := labels[AppInstNameLabel]; ok {
		s.AppInstNameLabel = v
	}
	if v, ok := labels[AppInstOrgLabel]; ok {
		s.AppInstOrgLabel = v
	}
}

// AppInstLabelsOld are the version of AppInstLabels before the
// AppInstUniqueNameKey upgrade.
type AppInstLabelsOld struct {
	AppNameLabel    string
	AppVersionLabel string
}

func GetAppInstLabelsOld(appInst *edgeproto.AppInst) AppInstLabelsOld {
	return AppInstLabelsOld{
		AppNameLabel:    util.DNSSanitize(appInst.AppKey.Name),
		AppVersionLabel: util.DNSSanitize(appInst.AppKey.Version),
	}
}

func (s *AppInstLabelsOld) Map() map[string]string {
	return map[string]string{
		MexAppNameLabel:    s.AppNameLabel,
		MexAppVersionLabel: s.AppVersionLabel,
	}
}

func (s *AppInstLabelsOld) FromMap(labels map[string]string) {
	s.AppNameLabel = labels[MexAppNameLabel]
	s.AppVersionLabel = labels[MexAppVersionLabel]
}

// GetCloudletKeyHash returns a short hash of the cloudlet key to allow
// for a deterministic string representing the cloudlet, that does not
// reveal the cloudlet name (which would likely reveal its location).
func GetCloudletKeyHash(key *edgeproto.CloudletKey) string {
	cname := key.Name + "::" + key.Organization
	return getShortHash(cname)
}

// GetZoneKeyHash returns a short hash of the zone key to allow
// for a deterministic string representing the zone, that is just
// shorter than appending the zone name plus org. Also, in case the
// underlying cloudlet is changed to a different zone, the name
// doesn't confuse the user by referencing the old zone by name.
func GetZoneKeyHash(key *edgeproto.ZoneKey) string {
	zname := key.Name + "::" + key.Organization
	return getShortHash(zname)
}

func getShortHash(str string) string {
	h := sha256.New()
	h.Write([]byte(str))
	bytesum := h.Sum(nil)
	strsum := fmt.Sprintf("%x", bytesum)
	num := len(strsum)
	if num > 8 {
		num = 8
	}
	return strsum[:num]
}

func BuildReservableClusterName(id int, cloudletKey *edgeproto.CloudletKey) string {
	// name must be unique within the region
	// append hash to conceal cloudlet name from developers
	return fmt.Sprintf("%s%d-%s", ReservableClusterPrefix, id, GetCloudletKeyHash(cloudletKey))
}

func ParseReservableClusterName(name string) (int, string, error) {
	idAndHash := strings.TrimPrefix(name, ReservableClusterPrefix)
	parts := strings.Split(idAndHash, "-")
	id, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", fmt.Errorf("parse reservable cluster name failed to extract numeric id %s from %s, %s", parts[0], name, err)
	}
	// Note: parser MUST be able to handle old name format, which was
	// reservable<ID>, where ID is a positive integer.
	hash := ""
	if len(parts) > 1 {
		hash = parts[1]
	}
	return id, hash, nil
}

func GetDefaultMTClustKey(cloudletKey edgeproto.CloudletKey) *edgeproto.ClusterKey {
	// name must be unique within the region
	// append hash to conceal cloudlet name from developers
	return &edgeproto.ClusterKey{
		Name:         DefaultMultiTenantCluster + "-" + GetCloudletKeyHash(&cloudletKey),
		Organization: edgeproto.OrganizationEdgeCloud,
	}
}

func GetDefaultClustKey(cloudletKey edgeproto.CloudletKey, ownerOrg string) *edgeproto.ClusterKey {
	// name must be unique within the region
	// append hash to conceal cloudlet name from developers
	if ownerOrg == "" {
		ownerOrg = edgeproto.OrganizationEdgeCloud
	}
	return &edgeproto.ClusterKey{
		Name:         DefaultClust + "-" + GetCloudletKeyHash(&cloudletKey),
		Organization: ownerOrg,
	}
}

func IsDefaultClustKey(clusterKey edgeproto.ClusterKey, cloudletKey edgeproto.CloudletKey) bool {
	if clusterKey.Organization == edgeproto.OrganizationEdgeCloud && strings.HasPrefix(clusterKey.Name, DefaultClust) {
		parts := strings.Split(clusterKey.Name, "-")
		if parts[1] == GetCloudletKeyHash(&cloudletKey) {
			return true
		}
	}
	return false
}

// GetAppInstCloudletScopedName gets the previous key name that was scoped
// to the cloudlet, if it exists. The current name is scoped to the region
// and may have been renamed on upgrade.
func GetAppInstCloudletScopedName(appInst *edgeproto.AppInst) string {
	if appInst.Annotations != nil {
		if n, ok := appInst.Annotations[AnnotationCloudletScopedName]; ok && n != "" {
			return n
		}
	}
	return appInst.Key.Name
}

// GetClusterInstCloudletScopedName gets the previous key name that was scoped
// to the cloudlet, if it exists. The current name is scoped to the region
// and may have been renamed on upgrade.
func GetClusterInstCloudletScopedName(clusterInst *edgeproto.ClusterInst) string {
	if clusterInst.Annotations != nil {
		if n, ok := clusterInst.Annotations[AnnotationCloudletScopedName]; ok && n != "" {
			return n
		}
	}
	return clusterInst.Key.Name
}
