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

package vmlayer

//
// This file contains the functionality needed to input data into the VMProvider orchestrator.   There are 2 categories of structs:
// 1) Request Specs.  These contain high level info used by client code to request the creation of VMs and Groups of VMs
// 2) Orchestration Params.   These contain detailed level info used by the orchestrator to instantiate all the resources related to creating VMs,
//    including Subnets, Ports, Security Groups, etc.  Orchestration Params are derived by code here from Request Specs

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/confignode"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
)

type ActionType string

const (
	ActionCreate ActionType = "create"
	ActionUpdate ActionType = "update"
	ActionDelete ActionType = "delete"
)

const TestCACert = "ssh-rsa DUMMYTESTCACERT"

var ClusterTypeKubernetesMasterLabel = "mex-k8s-master"
var ClusterTypeDockerVMLabel = "mex-docker-vm"

type SkipK8sChoice string

const (
	SkipK8sNo  SkipK8sChoice = "no"
	SkipK8sYes SkipK8sChoice = "yes"
)

type VMRole string

var RoleAgent VMRole = "mex-agent-node"
var RoleMaster VMRole = "k8s-master"
var RoleK8sNode VMRole = "k8s-node"
var RoleDockerNode VMRole = "docker-node"
var RoleVMApplication VMRole = "vmapp"
var RoleVMPlatform VMRole = "platform"
var RoleMatchAny VMRole = "any" // not a real role, used for matching

type NetworkType string

const NetworkTypeExternalPrimary NetworkType = "external-primary"
const NetworkTypeExternalSecondary NetworkType = "external-secondary"
const NetworkTypeExternalAdditionalRootLb NetworkType = "rootlb"
const NetworkTypeExternalAdditionalClusterNode NetworkType = "cluster-node"
const NetworkTypeExternalAdditionalPlatform NetworkType = "platform"
const NetworkTypeInternalPrivate NetworkType = "internal-private"    // internal network for only one cluster
const NetworkTypeInternalSharedLb NetworkType = "internal-shared-lb" // internal network connected to shared rootlb

// NextAvailableResource means the orchestration code needs to find an available
// resource of the given type as the calling code won't know what is free
var NextAvailableResource = "NextAvailable"

const ClusterMasterIPLastIPOctet uint32 = 10

// ResourceReference identifies a resource that is referenced by another resource. The
// Preexisting flag indicates whether the resource is already present or is being created
// as part of this operation.  How the resource is referred to during the orchestration process
// may be different for preexisting vs new resources.
type ResourceReference struct {
	Name        string
	Id          string
	Preexisting bool
}

// PortResourceReference needs also a network id
type PortResourceReference struct {
	Name         string
	Id           string
	NetworkId    string
	SubnetId     string
	SubnetIdIPV6 string
	Preexisting  bool
	NetType      NetworkType
	PortGroup    string
}

func (v *VMProperties) GetNodeTypeForVmNameAndRole(vmname, role string) cloudcommon.NodeType {
	switch role {
	case string(RoleAgent):
		if v.SharedRootLBName == vmname {
			return cloudcommon.NodeTypeSharedRootLB
		}
		return cloudcommon.NodeTypeDedicatedRootLB
	case string(RoleMaster):
		return cloudcommon.NodeTypeK8sClusterMaster
	case string(RoleK8sNode):
		return cloudcommon.NodeTypeK8sClusterNode
	case string(RoleDockerNode):
		return cloudcommon.NodeTypeDockerClusterNode
	case string(RoleVMApplication):
		return cloudcommon.NodeTypeAppVM
	case string(RoleVMPlatform):
		return cloudcommon.NodeTypePlatformVM
	}
	return -1
}

func GetPortName(vmname, netname string) string {
	return fmt.Sprintf("%s-%s-port", vmname, netname)
}

func GetPortNameFromSubnet(vmname string, subnetNames SubnetNames) string {
	// port is always based off of the ipv4 subnet, since both subnets
	// are connected to a single port.
	return fmt.Sprintf("%s-%s-port", vmname, subnetNames[0])
}

func NewResourceReference(name string, id string, preexisting bool) ResourceReference {
	return ResourceReference{Name: name, Id: id, Preexisting: preexisting}
}

func NewPortResourceReference(name string, id string, netid string, subnetIds SubnetNames, preexisting bool, netType NetworkType) PortResourceReference {
	return PortResourceReference{Name: name, Id: id, NetworkId: netid, SubnetId: subnetIds.IPV4(), SubnetIdIPV6: subnetIds.IPV6(), Preexisting: preexisting, NetType: netType}
}

// VMRequestSpec has the infromation which the caller needs to provide when creating a VM.
type VMRequestSpec struct {
	Name                    string
	Type                    cloudcommon.NodeType
	FlavorName              string
	ImageName               string
	ImageFolder             string
	ComputeAvailabilityZone string
	AuthPublicKey           string
	ExternalVolumeSize      uint64
	SharedVolumeSize        uint64
	DeploymentManifest      string
	Command                 string
	ConnectToExternalNet    bool
	CreatePortsOnly         bool
	ConnectToSubnets        SubnetNames
	ConfigureNodeVars       *confignode.ConfigureNodeVars
	OptionalResource        string
	AccessKey               string
	AdditionalNetworks      map[string]NetworkType
	Routes                  map[string][]edgeproto.Route
	VmAppOsType             edgeproto.VmAppOsType
}

type VMReqOp func(vmp *VMRequestSpec) error

func WithPublicKey(authPublicKey string) VMReqOp {
	return func(vmo *VMRequestSpec) error {
		if authPublicKey == "" {
			return nil
		}
		convKey, err := util.ConvertPEMtoOpenSSH(authPublicKey)
		if err != nil {
			return err
		}
		vmo.AuthPublicKey = convKey
		return nil
	}
}

func WithDeploymentManifest(deploymentManifest string) VMReqOp {
	return func(vrs *VMRequestSpec) error {
		vrs.DeploymentManifest = deploymentManifest
		return nil
	}
}
func WithCommand(command string) VMReqOp {
	return func(vrs *VMRequestSpec) error {
		vrs.Command = command
		return nil
	}
}
func WithComputeAvailabilityZone(zone string) VMReqOp {
	return func(vrs *VMRequestSpec) error {
		vrs.ComputeAvailabilityZone = zone
		return nil
	}
}
func WithExternalVolume(size uint64) VMReqOp {
	return func(s *VMRequestSpec) error {
		s.ExternalVolumeSize = size
		return nil
	}
}
func WithSharedVolume(size uint64) VMReqOp {
	return func(s *VMRequestSpec) error {
		s.SharedVolumeSize = size
		return nil
	}
}
func WithSubnetConnection(subnetNames SubnetNames) VMReqOp {
	return func(s *VMRequestSpec) error {
		s.ConnectToSubnets = subnetNames
		return nil
	}
}
func WithCreatePortsOnly(portsonly bool) VMReqOp {
	return func(s *VMRequestSpec) error {
		s.CreatePortsOnly = portsonly
		return nil
	}
}
func WithImageFolder(folder string) VMReqOp {
	return func(s *VMRequestSpec) error {
		s.ImageFolder = folder
		return nil
	}
}
func WithConfigureNodeVars(v *VMPlatform, nodeRole cloudcommon.NodeRole, ckey *edgeproto.CloudletKey, ownerKey objstore.ObjKey) VMReqOp {
	return func(s *VMRequestSpec) error {
		s.ConfigureNodeVars = &confignode.ConfigureNodeVars{
			Key: edgeproto.CloudletNodeKey{
				CloudletKey: *ckey,
			},
			NodeRole:          nodeRole,
			OwnerKey:          ownerKey,
			AnsiblePublicAddr: v.VMProperties.CommonPf.PlatformConfig.AnsiblePublicAddr,
		}
		return nil
	}
}
func WithOptionalResource(optRes string) VMReqOp {
	return func(s *VMRequestSpec) error {
		s.OptionalResource = optRes
		return nil
	}
}
func WithAccessKey(accessKey string) VMReqOp {
	return func(s *VMRequestSpec) error {
		s.AccessKey = accessKey
		return nil
	}
}
func WithAdditionalNetworks(networks map[string]NetworkType) VMReqOp {
	return func(s *VMRequestSpec) error {
		s.AdditionalNetworks = networks
		return nil
	}
}
func WithRoutes(routes map[string][]edgeproto.Route) VMReqOp {
	return func(s *VMRequestSpec) error {
		s.Routes = routes
		return nil
	}
}
func WithVmAppOsType(osType edgeproto.VmAppOsType) VMReqOp {
	return func(s *VMRequestSpec) error {
		s.VmAppOsType = osType
		return nil
	}
}

// VMGroupRequestSpec is used to specify a set of VMs to be created.  It is used as input to create VMGroupOrchestrationParams
type VMGroupRequestSpec struct {
	GroupName                     string
	VMs                           []*VMRequestSpec
	NewSubnetNames                SubnetNames
	NewSecgrpName                 string
	AccessPorts                   string
	EnableIPV6                    bool
	TrustPolicy                   *edgeproto.TrustPolicy
	SkipDefaultSecGrp             bool
	SkipSubnetGateway             bool
	SkipInfraSpecificCheck        bool
	InitOrchestrator              bool
	Domain                        string
	NodeUpdateActions             map[string]string
	SkipCleanupOnFailure          bool
	AntiAffinity                  bool
	AntiAffinityEnabledInCloudlet bool
}

type VMGroupReqOp func(vmp *VMGroupRequestSpec) error

func WithTrustPolicy(pp *edgeproto.TrustPolicy) VMGroupReqOp {
	return func(s *VMGroupRequestSpec) error {
		s.TrustPolicy = pp
		return nil
	}
}
func WithAccessPorts(ports string) VMGroupReqOp {
	return func(s *VMGroupRequestSpec) error {
		s.AccessPorts = ports
		return nil
	}
}
func WithNewSubnet(sn SubnetNames) VMGroupReqOp {
	return func(s *VMGroupRequestSpec) error {
		s.NewSubnetNames = sn
		return nil
	}
}
func WithEnableIPV6(enable bool) VMGroupReqOp {
	return func(s *VMGroupRequestSpec) error {
		s.EnableIPV6 = enable
		return nil
	}
}
func WithNewSecurityGroup(sg string) VMGroupReqOp {
	return func(s *VMGroupRequestSpec) error {
		s.NewSecgrpName = sg
		return nil
	}
}
func WithSkipDefaultSecGrp(skip bool) VMGroupReqOp {
	return func(s *VMGroupRequestSpec) error {
		s.SkipDefaultSecGrp = skip
		return nil
	}
}
func WithSkipSubnetGateway(skip bool) VMGroupReqOp {
	return func(s *VMGroupRequestSpec) error {
		s.SkipSubnetGateway = skip
		return nil
	}
}
func WithSkipInfraSpecificCheck(skip bool) VMGroupReqOp {
	return func(s *VMGroupRequestSpec) error {
		s.SkipInfraSpecificCheck = skip
		return nil
	}
}
func WithInitOrchestrator(init bool) VMGroupReqOp {
	return func(s *VMGroupRequestSpec) error {
		s.InitOrchestrator = init
		return nil
	}
}
func WithNodeUpdateActions(updateActions map[string]string) VMGroupReqOp {
	return func(s *VMGroupRequestSpec) error {
		s.NodeUpdateActions = updateActions
		return nil
	}
}
func WithSkipCleanupOnFailure(skip bool) VMGroupReqOp {
	return func(s *VMGroupRequestSpec) error {
		s.SkipCleanupOnFailure = skip
		return nil
	}
}
func WithAntiAffinity(anti bool) VMGroupReqOp {
	return func(s *VMGroupRequestSpec) error {
		s.AntiAffinity = anti
		return nil
	}
}

type SubnetOrchestrationParams struct {
	Id                string
	Name              string
	ReservedName      string
	NetworkName       string
	CIDR              string
	IPVersion         infracommon.IPVersion
	NodeIPPrefix      string
	GatewayIP         string
	DNSServers        []string
	DHCPEnabled       string
	Vlan              uint32
	SkipGateway       bool
	SecurityGroupName string
}

type FixedIPOrchestrationParams struct {
	LastIPOctet uint32
	Address     string
	Mask        string
	Subnet      ResourceReference
	Gateway     string
	IPVersion   infracommon.IPVersion
}

type PortOrchestrationParams struct {
	Name                        string
	Id                          string
	SubnetIds                   SubnetNames
	NetworkName                 string
	NetworkId                   string
	NetType                     NetworkType
	VnicType                    string
	SkipAttachVM                bool
	FixedIPs                    []FixedIPOrchestrationParams
	SecurityGroups              []ResourceReference
	IsAdditionalExternalNetwork bool
}

type FloatingIPOrchestrationParams struct {
	Name         string
	ParamName    string
	Port         ResourceReference
	FloatingIpId string
}

type RouterInterfaceOrchestrationParams struct {
	RouterName string
	RouterPort ResourceReference
}

type AccessPortSpec struct {
	Ports []util.PortSpec
}

type SecurityGroupOrchestrationParams struct {
	Name        string
	AccessPorts AccessPortSpec
	EgressRules []SecurityRule
}

type SecurityRule struct {
	Protocol     string
	PortRangeMin int
	PortRangeMax int
	RemoteCidr   string
	IPVersion    infracommon.IPVersion
}

type SecgrpParamsOp func(vmp *SecurityGroupOrchestrationParams) error

func convertSecurityRule(rule edgeproto.SecurityRule) SecurityRule {
	// add in ipversion which is needed by Openstack for IPv6
	ipversion := infracommon.IPV4
	addr, err := netip.ParseAddr(strings.Split(rule.RemoteCidr, "/")[0])
	if err == nil && addr.Is6() {
		ipversion = infracommon.IPV6
	}
	return SecurityRule{
		RemoteCidr:   rule.RemoteCidr,
		PortRangeMin: int(rule.PortRangeMin),
		PortRangeMax: int(rule.PortRangeMax),
		Protocol:     rule.Protocol,
		IPVersion:    ipversion,
	}
}

func SecGrpWithEgressRules(rules []edgeproto.SecurityRule, egressRestricted, enableIPV6 bool) SecgrpParamsOp {
	return func(sp *SecurityGroupOrchestrationParams) error {
		if len(rules) == 0 {
			// ensure at least one rule is present so that the orchestrator
			// does not auto-create an empty allow-all rule
			if egressRestricted {
				allowNoneRule := SecurityRule{
					RemoteCidr: infracommon.RemoteCidrNone,
					IPVersion:  infracommon.IPV4,
				}
				sp.EgressRules = append(sp.EgressRules, allowNoneRule)
			} else {
				allowAllRule := SecurityRule{
					RemoteCidr: infracommon.RemoteCidrAll,
					IPVersion:  infracommon.IPV4,
				}
				sp.EgressRules = append(sp.EgressRules, allowAllRule)
				if enableIPV6 {
					allowAllRuleIPV6 := SecurityRule{
						RemoteCidr: infracommon.RemoteCidrAllIPV6,
						IPVersion:  infracommon.IPV6,
					}
					sp.EgressRules = append(sp.EgressRules, allowAllRuleIPV6)
				}
			}
		} else {
			for _, rule := range rules {
				srule := convertSecurityRule(rule)
				if !enableIPV6 && srule.IPVersion == infracommon.IPV6 {
					continue
				}
				sp.EgressRules = append(sp.EgressRules, srule)
			}
		}
		return nil
	}
}

func SecGrpWithAccessPorts(ports string) SecgrpParamsOp {
	return func(sgp *SecurityGroupOrchestrationParams) error {
		if ports == "" {
			return nil
		}
		parsedAccessPorts, err := util.ParsePorts(ports)
		if err != nil {
			return err
		}
		for _, port := range parsedAccessPorts {
			endPort, err := strconv.ParseInt(port.EndPort, 10, 32)
			if err != nil {
				return err
			}
			if endPort == 0 {
				port.EndPort = port.Port
			}
			sgp.AccessPorts.Ports = append(sgp.AccessPorts.Ports, port)
		}
		return nil
	}
}

func GetSecGrpParams(name string, opts ...SecgrpParamsOp) (*SecurityGroupOrchestrationParams, error) {
	var sgp SecurityGroupOrchestrationParams
	sgp.Name = name
	for _, op := range opts {
		if err := op(&sgp); err != nil {
			return nil, err
		}
	}
	return &sgp, nil
}

type VolumeOrchestrationParams struct {
	Name               string
	ImageName          string
	Size               uint64
	AvailabilityZone   string
	DeviceName         string
	AttachExternalDisk bool
	UnitNumber         uint64
}
type VolumeOrchestrationParamsOp func(vmp *VolumeOrchestrationParams) error

type TagOrchestrationParams struct {
	Id       string
	Name     string
	Category string
}

type VMCloudConfigParams struct {
	ExtraBootCommands []string
	ConfigureNodeVars *confignode.ConfigureNodeVars
	CACert            string
	AccessKey         string
	PrimaryDNS        string
	FallbackDNS       string
	NtpServers        string
	AnsiblePkgURL     string
	CloudletVarsURL   string
}

// VMOrchestrationParams contains all details  that are needed by the orchestator
type VMOrchestrationParams struct {
	Id                      string
	Name                    string
	Role                    VMRole
	ImageName               string
	ImageFolder             string
	HostName                string
	DNSDomain               string
	FlavorName              string
	Vcpus                   uint64
	Ram                     uint64
	Disk                    uint64
	ComputeAvailabilityZone string
	UserData                string
	MetaData                string
	SharedVolume            bool
	AuthPublicKey           string
	DeploymentManifest      string
	Command                 string
	Volumes                 []VolumeOrchestrationParams
	Ports                   []PortResourceReference      // depending on the orchestrator, IPs may be assigned to ports or
	FixedIPs                []FixedIPOrchestrationParams // to VMs directly
	AttachExternalDisk      bool
	CloudConfigParams       VMCloudConfigParams
	VmAppOsType             edgeproto.VmAppOsType
	Routes                  map[string][]edgeproto.Route // map of network name to routes
	ExistingVm              bool
}

// VMGroupOrchestrationParams contains all the details used by the orchestator to create a set of associated VMs
type VMGroupOrchestrationParams struct {
	GroupName                     string
	Subnets                       []SubnetOrchestrationParams
	Ports                         []PortOrchestrationParams
	RouterInterfaces              []RouterInterfaceOrchestrationParams
	VMs                           []VMOrchestrationParams
	FloatingIPs                   []FloatingIPOrchestrationParams
	SecurityGroups                []SecurityGroupOrchestrationParams
	Netspec                       *NetSpecInfo
	Tags                          []TagOrchestrationParams
	SkipInfraSpecificCheck        bool
	SkipSubnetGateway             bool
	InitOrchestrator              bool
	NodeUpdateActions             map[string]string
	ConnectsToSharedRootLB        bool
	SkipCleanupOnFailure          bool
	AntiAffinitySpecified         bool
	AntiAffinityEnabledInCloudlet bool
	EnableIPV6                    bool
}

// connectsToSharedRootLB detects if the request spec is connecting to a shared rootLb.  To determine
// this we look for an LB VM which has CreatePortsOnly.  This means the LB VM is not going to
// be created and not included in the orch params, but ports are specified to connect to it.
func (v *VMPlatform) connectsToSharedRootLB(ctx context.Context, groupSpec *VMGroupRequestSpec) bool {

	log.SpanLog(ctx, log.DebugLevelInfra, "connectsToSharedRootLB", "Name", groupSpec.GroupName)
	for _, vm := range groupSpec.VMs {
		if vm.Type == cloudcommon.NodeTypeSharedRootLB && vm.CreatePortsOnly {
			log.SpanLog(ctx, log.DebugLevelInfra, "found shared rootlb ports", "GroupName", groupSpec.GroupName)
			return true
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "ConnectsToSharedRootLB false", "GroupName", groupSpec.GroupName)
	return false

}

func (v *VMPlatform) GetVMRequestSpec(ctx context.Context, nodeType cloudcommon.NodeType, serverName, flavorName string, imageName string, connectExternal bool, opts ...VMReqOp) (*VMRequestSpec, error) {
	var vrs VMRequestSpec
	for _, op := range opts {
		if err := op(&vrs); err != nil {
			return nil, err
		}
	}
	vrs.Name = serverName
	vrs.Type = nodeType
	vrs.FlavorName = flavorName
	vrs.ImageName = imageName
	vrs.ConnectToExternalNet = connectExternal
	if vrs.ConfigureNodeVars != nil {
		vrs.ConfigureNodeVars.Key.Name = serverName
		vrs.ConfigureNodeVars.NodeType = nodeType
	}
	return &vrs, nil
}

func (v *VMPlatform) getVMGroupRequestSpec(ctx context.Context, name string, vms []*VMRequestSpec, opts ...VMGroupReqOp) (*VMGroupRequestSpec, error) {
	var vmgrs VMGroupRequestSpec
	vmgrs.GroupName = name
	vmgrs.VMs = vms
	for _, op := range opts {
		if err := op(&vmgrs); err != nil {
			return nil, err
		}
	}
	return &vmgrs, nil
}

// GetVMGroupOrchestrationParamsFromTrustPolicy returns an set of orchestration params for just a privacy policy egress rules
func GetVMGroupOrchestrationParamsFromTrustPolicy(ctx context.Context, name string, rules []edgeproto.SecurityRule, egressRestricted, cloudletEnableIPV6 bool, opts ...SecgrpParamsOp) (*VMGroupOrchestrationParams, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVMGroupOrchestrationParamsFromTrustPolicy", "name", name)
	var vmgp VMGroupOrchestrationParams
	opts = append(opts, SecGrpWithEgressRules(rules, egressRestricted, cloudletEnableIPV6))
	externalSecGrp, err := GetSecGrpParams(name, opts...)
	if err != nil {
		return nil, err
	}
	vmgp.SecurityGroups = append(vmgp.SecurityGroups, *externalSecGrp)
	return &vmgp, nil
}

func (v *VMPlatform) GetVMGroupOrchestrationParamsFromVMSpec(ctx context.Context, name string, vms []*VMRequestSpec, opts ...VMGroupReqOp) (*VMGroupOrchestrationParams, error) {
	spec, err := v.getVMGroupRequestSpec(ctx, name, vms, opts...)
	if err != nil {
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "getVMGroupOrchestrationParamsFromGroupSpec", "spec", spec)
	enableIPV6 := spec.EnableIPV6

	vmgp := VMGroupOrchestrationParams{
		GroupName:             spec.GroupName,
		InitOrchestrator:      spec.InitOrchestrator,
		SkipCleanupOnFailure:  spec.SkipCleanupOnFailure,
		AntiAffinitySpecified: spec.AntiAffinity,
		EnableIPV6:            spec.EnableIPV6,
	}
	vmgp.AntiAffinityEnabledInCloudlet = v.VMProperties.GetEnableAntiAffinity()

	internalNetName := v.VMProperties.GetCloudletMexNetwork()
	internalNetId := v.VMProvider.NameSanitize(internalNetName)
	externalNetName := v.VMProperties.GetCloudletExternalNetwork()
	externalNetNameSecondary := v.VMProperties.GetCloudletExternalNetworkSecondary()
	ntpServers := strings.Join(v.VMProperties.GetNtpServers(), " ")
	vmgp.ConnectsToSharedRootLB = v.connectsToSharedRootLB(ctx, spec)
	internalNetworkType := NetworkTypeInternalPrivate
	if vmgp.ConnectsToSharedRootLB {
		internalNetworkType = NetworkTypeInternalSharedLb
	}
	vmDns := strings.Split(v.VMProperties.GetCloudletDNS(), ",")
	if len(vmDns) > 2 {
		return nil, fmt.Errorf("Too many DNS servers specified in MEX_DNS")
	}
	vmDnsIPV6 := strings.Split(v.VMProperties.GetCloudletDNSIPV6(), ",")
	if len(vmDnsIPV6) > 2 {
		return nil, fmt.Errorf("Too many DNS servers specified in MEX_DNS_IPV6")
	}
	if spec.AntiAffinity && len(spec.VMs) < 2 {
		return nil, fmt.Errorf("Anti affinity cannot be specified with less than 2 VMs")
	}

	subnetDns := []string{}
	subnetDnsIPV6 := []string{}
	cloudletSecGrpID := v.VMProperties.CloudletSecgrpName
	if !spec.SkipDefaultSecGrp {
		cloudletSecGrpID, err = v.VMProvider.GetResourceID(ctx, ResourceTypeSecurityGroup, v.VMProperties.CloudletSecgrpName)
	}
	internalSecgrpID := ""
	internalSecgrpPreexisting := false
	cloudletComputeAZ := v.VMProperties.GetCloudletComputeAvailabilityZone()
	cloudletVolumeAZ := v.VMProperties.GetCloudletVolumeAvailabilityZone()

	if err != nil {
		return nil, err
	}
	if v.VMProperties.GetSubnetDNS() != NoSubnetDNS {
		// Contrail workaround, see EDGECLOUD-2420 for details
		subnetDns = vmDns
	}
	if enableIPV6 {
		subnetDnsIPV6 = vmDnsIPV6
	}

	vmgp.Netspec, err = ParseNetSpec(ctx, v.VMProperties.GetCloudletNetworkScheme())
	if err != nil {
		return nil, err
	}
	if spec.SkipInfraSpecificCheck {
		vmgp.SkipInfraSpecificCheck = true
	}
	if spec.NodeUpdateActions != nil {
		vmgp.NodeUpdateActions = spec.NodeUpdateActions
	}
	subnetIds := spec.NewSubnetNames.Sanitize(v.VMProvider.IdSanitize)

	rtrInUse := false
	rtr := v.VMProperties.GetCloudletExternalRouter()
	if rtr == NoConfigExternalRouter {
		log.SpanLog(ctx, log.DebugLevelInfra, "NoConfigExternalRouter in use")
	} else if rtr == NoExternalRouter {
		log.SpanLog(ctx, log.DebugLevelInfra, "NoExternalRouter in use ")
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "External router in use")
		if spec.NewSubnetNames.IsSet() {
			internalSecgrpID = cloudletSecGrpID
			internalSecgrpPreexisting = true

			rtrInUse = true
			routerPortName := spec.NewSubnetNames.IPV4() + "-rtr-port"
			routerPort := PortOrchestrationParams{
				Name:        routerPortName,
				Id:          v.VMProvider.IdSanitize(routerPortName),
				NetworkName: internalNetName,
				NetworkId:   v.VMProvider.IdSanitize(internalNetName),
				SubnetIds:   subnetIds,
				FixedIPs: []FixedIPOrchestrationParams{
					{
						Address:     NextAvailableResource,
						LastIPOctet: 1,
						Subnet:      NewResourceReference(spec.NewSubnetNames.IPV4(), spec.NewSubnetNames.IPV4(), false),
					},
				},
			}
			if enableIPV6 {
				ipv6 := FixedIPOrchestrationParams{
					Address:     NextAvailableResource,
					LastIPOctet: 1,
					Subnet:      NewResourceReference(spec.NewSubnetNames.IPV6(), spec.NewSubnetNames.IPV6(), false),
				}
				routerPort.FixedIPs = append(routerPort.FixedIPs, ipv6)
			}
			routerPort.SecurityGroups = append(routerPort.SecurityGroups, NewResourceReference(cloudletSecGrpID, cloudletSecGrpID, true))
			vmgp.Ports = append(vmgp.Ports, routerPort)
			newRouterIf := RouterInterfaceOrchestrationParams{
				RouterName: v.VMProperties.GetCloudletExternalRouter(),
				RouterPort: NewResourceReference(routerPortName, routerPortName, false),
			}
			vmgp.RouterInterfaces = append(vmgp.RouterInterfaces, newRouterIf)
		}
	}

	var egressRules []edgeproto.SecurityRule
	if spec.TrustPolicy != nil {
		egressRules = spec.TrustPolicy.OutboundSecurityRules
	}
	if spec.NewSecgrpName != "" {
		// egress is always restricted on per-cluster groups.  If egress is allowed, it is done on the cloudlet level group,
		// unless there is no cloudlet group applied (in which case SkipDefaultSecGrp is true)
		egressRestricted := !spec.SkipDefaultSecGrp
		externalSecGrp, err := GetSecGrpParams(spec.NewSecgrpName, SecGrpWithAccessPorts(spec.AccessPorts), SecGrpWithEgressRules(egressRules, egressRestricted, enableIPV6))
		if err != nil {
			return nil, err
		}
		vmgp.SecurityGroups = append(vmgp.SecurityGroups, *externalSecGrp)
	}

	if err != nil {
		return nil, err
	}
	vmAppSubnet := false
	for _, vm := range spec.VMs {
		if vm.Type == cloudcommon.NodeTypeAppVM {
			vmAppSubnet = true
			break
		}
	}
	dhcpEnabled := "no"
	if vmAppSubnet && v.VMProperties.GetVMAppSubnetDHCPEnabled() != "no" {
		dhcpEnabled = "yes"
	}
	if spec.NewSubnetNames.IsSet() {
		newSubnet := SubnetOrchestrationParams{
			Name:              spec.NewSubnetNames.IPV4(),
			Id:                subnetIds.IPV4(),
			CIDR:              NextAvailableResource,
			IPVersion:         infracommon.IPV4,
			DHCPEnabled:       dhcpEnabled,
			DNSServers:        subnetDns,
			NetworkName:       v.VMProperties.GetCloudletMexNetwork(),
			SecurityGroupName: spec.NewSecgrpName,
		}
		if spec.SkipSubnetGateway {
			newSubnet.SkipGateway = true
		}
		vmgp.Subnets = append(vmgp.Subnets, newSubnet)
		// For IPv6, cloud-init can figure out the static IP assignment from
		// Openstack. For other platforms we may need to use radvd to enable slaac,
		// but on Openstack we only have a single internal network so radvd on
		// one LB ends up broadcasting across all tenants, taking over other
		// shared/dedicated LBs as the gateway.
		if enableIPV6 {
			newSubnetV6 := SubnetOrchestrationParams{
				Name:              spec.NewSubnetNames.IPV6(),
				Id:                subnetIds.IPV6(),
				CIDR:              NextAvailableResource,
				IPVersion:         infracommon.IPV6,
				DHCPEnabled:       "no",
				DNSServers:        subnetDnsIPV6,
				NetworkName:       v.VMProperties.GetCloudletMexNetwork(),
				SecurityGroupName: spec.NewSecgrpName,
			}
			if spec.SkipSubnetGateway {
				newSubnetV6.SkipGateway = true
			}
			vmgp.Subnets = append(vmgp.Subnets, newSubnetV6)
		}
	}

	var vaultSSHCert string
	if v.VMProperties.CommonPf.PlatformConfig.TestMode {
		vaultSSHCert = TestCACert
	} else {
		accessApi := v.VMProperties.CommonPf.PlatformConfig.AccessApi
		publicSSHKey, err := accessApi.GetSSHPublicKey(ctx)
		if err != nil {
			return nil, err
		}
		vaultSSHCert = publicSSHKey
	}

	var internalPortNextOctet uint32 = 101
	var fipid int = 1
	for _, vm := range spec.VMs {
		computeAZ := vm.ComputeAvailabilityZone
		if computeAZ == "" {
			computeAZ = cloudletComputeAZ
		}
		volumeAZ := cloudletVolumeAZ
		log.SpanLog(ctx, log.DebugLevelInfra, "Defining VM", "vm", vm, "computeAZ", computeAZ, "volumeAZ", volumeAZ)
		var role VMRole
		var newPorts []PortOrchestrationParams
		internalPortName := GetPortNameFromSubnet(vm.Name, vm.ConnectToSubnets)

		connectToPreexistingSubnet := false
		if vm.ConnectToSubnets.IsSet() && !spec.NewSubnetNames.Matches(vm.ConnectToSubnets) {
			// we have specified a subnet to connect to which is not one we are creating
			// It therefore has to be a preexisting subnet
			connectToPreexistingSubnet = true
		}
		switch vm.Type {
		case cloudcommon.NodeTypePlatformVM:
			fallthrough
		case cloudcommon.NodeTypeSharedRootLB:
			fallthrough
		case cloudcommon.NodeTypeDedicatedRootLB:
			role = RoleAgent
			// do not attach the port to the VM if the policy is to do it after creation
			skipAttachVM := true
			var internalPortSubnets SubnetNames
			if v.VMProvider.GetInternalPortPolicy() == AttachPortDuringCreate {
				skipAttachVM = false
				internalPortSubnets = spec.NewSubnetNames.Sanitize(v.VMProvider.NameSanitize)
			}
			// if the router is used we don't create an internal port for rootlb
			if vm.ConnectToSubnets.IsSet() && !rtrInUse {
				// no router means rootlb must be connected to other VMs directly
				internalPort := PortOrchestrationParams{
					Name:        internalPortName,
					Id:          v.VMProvider.NameSanitize(internalPortName),
					NetworkName: internalNetName,
					NetType:     internalNetworkType,
					NetworkId:   internalNetId,
					SubnetIds:   internalPortSubnets,
					VnicType:    vmgp.Netspec.VnicType,
					FixedIPs: []FixedIPOrchestrationParams{
						{
							Address:     NextAvailableResource,
							IPVersion:   infracommon.IPV4,
							LastIPOctet: 1,
							Subnet:      NewResourceReference(vm.ConnectToSubnets.IPV4(), vm.ConnectToSubnets.IPV4(), connectToPreexistingSubnet),
						},
					},
					SkipAttachVM: skipAttachVM, //rootlb internal ports are attached in a separate step
				}
				if enableIPV6 {
					ipv6 := FixedIPOrchestrationParams{
						Address:     NextAvailableResource,
						IPVersion:   infracommon.IPV6,
						LastIPOctet: 1,
						Subnet:      NewResourceReference(vm.ConnectToSubnets.IPV6(), vm.ConnectToSubnets.IPV6(), connectToPreexistingSubnet),
					}
					internalPort.FixedIPs = append(internalPort.FixedIPs, ipv6)
				}
				newPorts = append(newPorts, internalPort)
			}

		case cloudcommon.NodeTypeAppVM:
			role = RoleVMApplication
			if vm.ConnectToSubnets.IsSet() {
				// connect via internal network to LB
				internalPort := PortOrchestrationParams{
					Name:        internalPortName,
					Id:          v.VMProvider.NameSanitize(internalPortName),
					SubnetIds:   spec.NewSubnetNames.Sanitize(v.VMProvider.NameSanitize),
					NetworkName: internalNetName,
					NetType:     internalNetworkType,
					NetworkId:   internalNetId,
					VnicType:    vmgp.Netspec.VnicType,
					FixedIPs: []FixedIPOrchestrationParams{
						{
							Address:     NextAvailableResource,
							IPVersion:   infracommon.IPV4,
							LastIPOctet: internalPortNextOctet,
							Subnet:      NewResourceReference(vm.ConnectToSubnets.IPV4(), vm.ConnectToSubnets.IPV4(), connectToPreexistingSubnet),
						},
					},
				}
				if enableIPV6 {
					ipv6 := FixedIPOrchestrationParams{
						Address:     NextAvailableResource,
						IPVersion:   infracommon.IPV6,
						LastIPOctet: internalPortNextOctet,
						Subnet:      NewResourceReference(vm.ConnectToSubnets.IPV6(), vm.ConnectToSubnets.IPV6(), connectToPreexistingSubnet),
					}
					internalPort.FixedIPs = append(internalPort.FixedIPs, ipv6)
				}
				internalPortNextOctet++
				newPorts = append(newPorts, internalPort)
			}

		case cloudcommon.NodeTypePlatformK8sClusterMaster:
			fallthrough
		case cloudcommon.NodeTypeK8sClusterMaster:
			role = RoleMaster
			if vm.ConnectToSubnets.IsSet() {
				// connect via internal network to LB
				internalPort := PortOrchestrationParams{
					Name:        internalPortName,
					Id:          v.VMProvider.NameSanitize(internalPortName),
					SubnetIds:   spec.NewSubnetNames.Sanitize(v.VMProvider.NameSanitize),
					NetworkId:   internalNetId,
					NetworkName: internalNetName,
					NetType:     internalNetworkType,
					FixedIPs: []FixedIPOrchestrationParams{
						{
							Address:     NextAvailableResource,
							IPVersion:   infracommon.IPV4,
							LastIPOctet: ClusterMasterIPLastIPOctet,
							Subnet:      NewResourceReference(vm.ConnectToSubnets.IPV4(), vm.ConnectToSubnets.IPV4(), connectToPreexistingSubnet),
						},
					},
				}
				if enableIPV6 {
					ipv6 := FixedIPOrchestrationParams{
						Address:     NextAvailableResource,
						IPVersion:   infracommon.IPV6,
						LastIPOctet: ClusterMasterIPLastIPOctet,
						Subnet:      NewResourceReference(vm.ConnectToSubnets.IPV6(), vm.ConnectToSubnets.IPV6(), connectToPreexistingSubnet),
					}
					internalPort.FixedIPs = append(internalPort.FixedIPs, ipv6)
				}
				if v.VMProperties.UseSecgrpForInternalSubnet {
					internalPort.SecurityGroups = append(internalPort.SecurityGroups, NewResourceReference(cloudletSecGrpID, cloudletSecGrpID, true))
					if spec.NewSecgrpName != "" {
						// connect internal ports to the new secgrp
						internalPort.SecurityGroups = append(internalPort.SecurityGroups, NewResourceReference(spec.NewSecgrpName, spec.NewSecgrpName, false))
					}
				}
				newPorts = append(newPorts, internalPort)

			} else {
				return nil, fmt.Errorf("k8s master not specified to be connected to internal network")
			}
		case cloudcommon.NodeTypeDockerClusterNode:
			fallthrough
		case cloudcommon.NodeTypePlatformK8sClusterPrimaryNode:
			fallthrough
		case cloudcommon.NodeTypePlatformK8sClusterSecondaryNode:
			fallthrough
		case cloudcommon.NodeTypeK8sClusterNode:
			if vm.Type == cloudcommon.NodeTypeDockerClusterNode {
				role = RoleDockerNode
			} else {
				role = RoleK8sNode
			}
			if vm.ConnectToSubnets.IsSet() {
				// connect via internal network to LB
				internalPort := PortOrchestrationParams{
					Name:        internalPortName,
					Id:          v.VMProvider.IdSanitize(internalPortName),
					SubnetIds:   spec.NewSubnetNames.Sanitize(v.VMProvider.NameSanitize),
					NetworkName: internalNetName,
					NetType:     internalNetworkType,
					NetworkId:   internalNetId,
					VnicType:    vmgp.Netspec.VnicType,
					FixedIPs: []FixedIPOrchestrationParams{
						{
							Address:     NextAvailableResource,
							IPVersion:   infracommon.IPV4,
							LastIPOctet: internalPortNextOctet,
							Subnet:      NewResourceReference(vm.ConnectToSubnets.IPV4(), vm.ConnectToSubnets.IPV4(), connectToPreexistingSubnet),
						},
					},
				}
				if enableIPV6 {
					ipv6 := FixedIPOrchestrationParams{
						Address:     NextAvailableResource,
						IPVersion:   infracommon.IPV6,
						LastIPOctet: internalPortNextOctet,
						Subnet:      NewResourceReference(vm.ConnectToSubnets.IPV6(), vm.ConnectToSubnets.IPV6(), connectToPreexistingSubnet),
					}
					internalPort.FixedIPs = append(internalPort.FixedIPs, ipv6)
				}
				internalPortNextOctet++
				if v.VMProperties.UseSecgrpForInternalSubnet {
					internalPort.SecurityGroups = append(internalPort.SecurityGroups, NewResourceReference(cloudletSecGrpID, cloudletSecGrpID, true))
					if spec.NewSecgrpName != "" {
						// connect internal ports to the new secgrp
						internalPort.SecurityGroups = append(internalPort.SecurityGroups, NewResourceReference(spec.NewSecgrpName, spec.NewSecgrpName, false))
					}
				}
				newPorts = append(newPorts, internalPort)
			} else {
				return nil, fmt.Errorf("k8s node not specified to be connected to internal network")
			}
		default:
			return nil, fmt.Errorf("unexpected VM type: %s", vm.Type)
		}
		// ports contains only internal ports at this point. Optionally add the internal
		// security group which is used when we have a router
		if internalSecgrpID != "" {
			for i := range newPorts {
				sec := NewResourceReference(internalSecgrpID, internalSecgrpID, internalSecgrpPreexisting)
				newPorts[i].SecurityGroups = append(newPorts[i].SecurityGroups, sec)
			}
		}
		extNets := make(map[string]NetworkType)

		if vm.ConnectToExternalNet {
			extNets[externalNetName] = NetworkTypeExternalPrimary
			if externalNetNameSecondary != "" {
				extNets[externalNetNameSecondary] = NetworkTypeExternalSecondary
			}
		}

		if len(vm.AdditionalNetworks) > 0 {
			err = v.VMProvider.ValidateAdditionalNetworks(ctx, vm.AdditionalNetworks)
			if err != nil {
				return nil, err
			}
			for net, ntype := range vm.AdditionalNetworks {
				extNets[net] = ntype
			}
		}
		for netName, netType := range extNets {
			portName := GetPortName(vm.Name, netName)
			useCloudletSecgrpForExtPort := false
			if spec.NewSecgrpName == "" {
				if netType == NetworkTypeExternalPrimary || netType == NetworkTypeExternalSecondary {
					return nil, fmt.Errorf("primary or secondary external network specified with no security group: %s", vm.Name)
				} else {
					useCloudletSecgrpForExtPort = true
				}
			}

			isAdditionalExternal := netType != NetworkTypeExternalPrimary
			var externalport PortOrchestrationParams
			if vmgp.Netspec.FloatingIPNet != "" {
				externalport = PortOrchestrationParams{
					Name:                        portName,
					Id:                          v.VMProvider.NameSanitize(portName),
					NetworkName:                 vmgp.Netspec.FloatingIPNet,
					NetworkId:                   v.VMProvider.NameSanitize(vmgp.Netspec.FloatingIPNet),
					VnicType:                    vmgp.Netspec.VnicType,
					NetType:                     netType,
					IsAdditionalExternalNetwork: isAdditionalExternal,
				}
				fip := FloatingIPOrchestrationParams{
					Name:         portName + "-fip",
					FloatingIpId: NextAvailableResource,
					Port:         NewResourceReference(externalport.Name, externalport.Id, false),
				}
				fip.ParamName = fmt.Sprintf("floatingIpId%d", fipid)
				fipid++
				vmgp.FloatingIPs = append(vmgp.FloatingIPs, fip)

			} else {
				externalport = PortOrchestrationParams{
					Name:                        portName,
					Id:                          v.VMProvider.IdSanitize(portName),
					NetworkName:                 netName,
					NetworkId:                   v.VMProvider.IdSanitize(netName),
					VnicType:                    vmgp.Netspec.VnicType,
					NetType:                     netType,
					IsAdditionalExternalNetwork: isAdditionalExternal,
				}
			}
			if spec.NewSecgrpName != "" {
				externalport.SecurityGroups = []ResourceReference{
					NewResourceReference(spec.NewSecgrpName, spec.NewSecgrpName, false),
				}
			}
			if useCloudletSecgrpForExtPort || !spec.SkipDefaultSecGrp {
				externalport.SecurityGroups = append(externalport.SecurityGroups, NewResourceReference(cloudletSecGrpID, cloudletSecGrpID, true))
			}
			newPorts = append(newPorts, externalport)
		}
		sort.Slice(newPorts, func(i, j int) bool {
			return newPorts[i].Name < newPorts[j].Name
		})

		if !vm.CreatePortsOnly {
			log.SpanLog(ctx, log.DebugLevelInfra, "Defining new VM orch param", "vm.Name", vm.Name, "ports", newPorts)
			hostName := util.HostnameSanitize(strings.Split(vm.Name, ".")[0])
			vccp := VMCloudConfigParams{}
			if vm.ConfigureNodeVars != nil {
				vccp.ConfigureNodeVars = vm.ConfigureNodeVars
			}
			vccp.CACert = vaultSSHCert
			vccp.AccessKey = vm.AccessKey
			if len(vmDns) > 0 {
				vccp.PrimaryDNS = vmDns[0]
				if len(vmDns) > 1 {
					vccp.FallbackDNS = vmDns[1]
				}
			}
			if enableIPV6 && len(vmDnsIPV6) > 0 {
				vccp.PrimaryDNS += " " + vmDnsIPV6[0]
				if len(vmDnsIPV6) > 1 {
					vccp.FallbackDNS += " " + vmDnsIPV6[1]
				}
			}
			vccp.NtpServers = ntpServers
			// gpu
			if vm.OptionalResource == "gpu" {
				gpuCmds := getGpuExtraCommands()
				vccp.ExtraBootCommands = append(vccp.ExtraBootCommands, gpuCmds...)
			}
			newVM := VMOrchestrationParams{
				Name:                    v.VMProvider.NameSanitize(vm.Name),
				Id:                      v.VMProvider.IdSanitize(vm.Name),
				Role:                    role,
				ImageName:               vm.ImageName,
				ImageFolder:             vm.ImageFolder,
				FlavorName:              vm.FlavorName,
				HostName:                hostName,
				DNSDomain:               v.VMProperties.CommonPf.GetCloudletDNSZone(),
				DeploymentManifest:      vm.DeploymentManifest,
				Command:                 vm.Command,
				ComputeAvailabilityZone: computeAZ,
				CloudConfigParams:       vccp,
				Routes:                  vm.Routes,
			}
			if vm.ExternalVolumeSize > 0 {
				externalVolume := VolumeOrchestrationParams{
					Name:             vm.Name + "-volume",
					Size:             vm.ExternalVolumeSize,
					ImageName:        vm.ImageName,
					DeviceName:       "vda",
					AvailabilityZone: volumeAZ,
				}
				newVM.ImageName = ""
				newVM.Volumes = append(newVM.Volumes, externalVolume)
			}
			if vm.SharedVolumeSize > 0 {
				sharedVolume := VolumeOrchestrationParams{
					Name:             vm.Name + "-shared-volume",
					Size:             vm.SharedVolumeSize,
					DeviceName:       "vdb",
					UnitNumber:       1,
					AvailabilityZone: volumeAZ,
				}
				newVM.Volumes = append(newVM.Volumes, sharedVolume)
				newVM.SharedVolume = true
			}
			if newVM.Role == RoleVMApplication {
				newVM.AttachExternalDisk = true
				newVM.VmAppOsType = vm.VmAppOsType
			} else {
				newVM.VmAppOsType = edgeproto.VmAppOsType_VM_APP_OS_LINUX
			}
			for _, p := range newPorts {
				if !p.SkipAttachVM {
					newVM.Ports = append(newVM.Ports, NewPortResourceReference(p.Name, p.Id, p.NetworkId, p.SubnetIds, false, p.NetType))
					newVM.FixedIPs = append(newVM.FixedIPs, p.FixedIPs...)
				}
			}
			vmgp.VMs = append(vmgp.VMs, newVM)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "Preexisting vm not added to group params", "vm.Name", vm.Name, "ports", newPorts)
		}
		vmgp.Ports = append(vmgp.Ports, newPorts...)
	}
	sort.Slice(vmgp.Ports, func(i, j int) bool {
		return vmgp.Ports[i].Name < vmgp.Ports[j].Name
	})
	sort.Slice(vmgp.FloatingIPs, func(i, j int) bool {
		return vmgp.FloatingIPs[i].Name < vmgp.FloatingIPs[j].Name
	})

	return &vmgp, nil
}

// OrchestrateVMsFromVMSpec calls the provider function to do the orchestation of the VMs.  It returns the updated VM group spec
func (v *VMPlatform) OrchestrateVMsFromVMSpec(ctx context.Context, name string, vms []*VMRequestSpec, action ActionType, updateCallback edgeproto.CacheUpdateCallback, opts ...VMGroupReqOp) (*VMGroupOrchestrationParams, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "OrchestrateVMsFromVMSpec", "name", name)
	gp, err := v.GetVMGroupOrchestrationParamsFromVMSpec(ctx, name, vms, opts...)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetVMGroupOrchestrationParamsFromVMSpec failed", "error", err)
		return gp, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created vm group spec", "gp", gp)
	accessApi := v.VMProperties.CommonPf.PlatformConfig.AccessApi
	switch action {
	case ActionCreate:
		for _, vm := range vms {
			if vm.CreatePortsOnly || vm.Type == cloudcommon.NodeTypeAppVM {
				continue
			}
			if vm.ConfigureNodeVars == nil {
				return gp, fmt.Errorf("node params don't exist for %s", vm.Name)
			}
			err := infracommon.CreateCloudletNode(ctx, vm.ConfigureNodeVars, accessApi)
			if err != nil {
				return gp, err
			}
		}
		err = v.VMProvider.CreateVMs(ctx, gp, updateCallback)
	case ActionUpdate:
		if gp.NodeUpdateActions != nil {
			for _, vm := range vms {
				if vm.CreatePortsOnly || vm.Type == cloudcommon.NodeTypeAppVM {
					continue
				}
				actionType, ok := gp.NodeUpdateActions[vm.Name]
				if !ok || actionType != ActionAdd {
					continue
				}
				if vm.ConfigureNodeVars == nil {
					return gp, fmt.Errorf("node params doesn't exist for %s", vm.Name)
				}
				err := infracommon.CreateCloudletNode(ctx, vm.ConfigureNodeVars, accessApi)
				if err != nil {
					return gp, err
				}
			}
			for vmName, actionType := range gp.NodeUpdateActions {
				if actionType != ActionRemove {
					continue
				}
				cloudletKey := v.VMProperties.CommonPf.PlatformConfig.CloudletKey
				nodeKey := &edgeproto.CloudletNodeKey{
					Name:        vmName,
					CloudletKey: *cloudletKey,
				}
				err = accessApi.DeleteCloudletNode(ctx, nodeKey)
				if err != nil {
					return gp, err
				}
			}
		}
		err = v.VMProvider.UpdateVMs(ctx, gp, updateCallback)

	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error while orchestrating vms", "name", name, "action", action, "err", err)
		return gp, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "VM action done", "action", action)
	return gp, nil
}

func (v *VMPlatform) GetSubnetGatewayFromVMGroupParms(ctx context.Context, subnetNames SubnetNames, vmgp *VMGroupOrchestrationParams) (infracommon.IPs, error) {
	ips := infracommon.IPs{}
	for ii := range subnetNames {
		if subnetNames[ii] == "" {
			continue
		}
		for _, s := range vmgp.Subnets {
			if s.Name == subnetNames[ii] {
				ips[ii] = s.GatewayIP
				break
			}
		}
	}
	if !ips.IsSet() {
		return ips, fmt.Errorf("Subnets: %v not found in vm group params", subnetNames)
	}
	return ips, nil
}

func getGpuExtraCommands() []string {
	dockerDaemonJson :=
		`{
	"log-driver": "json-file",
	"log-opts": {
		"max-size": "50m",
		"max-file": "20"
	},
	"runtimes": {
		"nvidia": {
			"path": "/usr/bin/nvidia-container-runtime",
			"runtimeArgs": []
		}
	}
}`
	jsonB64 := b64.StdEncoding.EncodeToString([]byte(dockerDaemonJson))
	var commands = []string{
		"echo \"updating docker daemon.json\"",
		"echo " + jsonB64 + "|base64 -d > /etc/docker/daemon.json",
	}
	return commands
}
