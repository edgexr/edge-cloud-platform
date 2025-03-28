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

package k8sbm

import (
	"context"
	"fmt"
	"strconv"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	k8scommon "github.com/edgexr/edge-cloud-platform/pkg/platform/k8s-common"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	certscache "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs-cache"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	ssh "github.com/edgexr/golang-ssh"
)

var k8sControlHostNodeType = "k8sbmcontrolhost"

var DockerUser string

// The K8sBareMetalPlatform is a single Kubernetes cluster running on
// bare metal. The Controller will create a single ClusterInst that
// represents this entire Cloudlet. The ClusterInst may either be multi-tenant,
// or (TODO) it may be non-MT but dedicated to a single organization.
type K8sBareMetalPlatform struct {
	commonPf           infracommon.CommonPlatform
	caches             *platform.Caches
	FlavorList         []*edgeproto.FlavorInfo
	sharedLBName       string
	cloudletKubeConfig string
	externalIps        []string
}

func NewPlatform() platform.Platform {
	return &K8sBareMetalPlatform{}
}

func (k *K8sBareMetalPlatform) GetDefaultCluster(cloudletKey *edgeproto.CloudletKey) *edgeproto.ClusterInst {
	defCluster := edgeproto.ClusterInst{
		Key:         *cloudcommon.GetDefaultClustKey(*cloudletKey, ""),
		CloudletKey: *cloudletKey,
	}
	return &defCluster
}

// GetCloudletKubeConfig returns the kconf for the default cluster
func (k *K8sBareMetalPlatform) GetCloudletKubeConfig(cloudletKey *edgeproto.CloudletKey) string {
	return k8smgmt.GetKconfName(k.GetDefaultCluster(cloudletKey))
}

func (o *K8sBareMetalPlatform) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:               platform.PlatformTypeK8SBareMetal,
		SupportsKubernetesOnly:     true,
		IsSingleKubernetesCluster:  true,
		SupportsAppInstDedicatedIp: true,
		NoClusterSupport:           true,
		Properties:                 k8sbmProps,
		ResourceQuotaProperties:    quotaProps,
	}
}

func (k *K8sBareMetalPlatform) IsCloudletServicesLocal() bool {
	return false
}

func platformName() string {
	return "platform.PlatformTypeK8SBareMetal"
}

func UpdateDockerUser(ctx context.Context, client ssh.Client) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "update docker user")
	cmd := "id -u"
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("Fail to get docker user id: %s - %v", out, err)
	}
	// we keep id as a string but make sure it parses as an int
	_, err = strconv.ParseUint(out, 10, 64)
	if err != nil {
		return fmt.Errorf("Fail to parse docker user id: %s - %v", out, err)
	}
	DockerUser = out
	log.SpanLog(ctx, log.DebugLevelInfra, "set docker user", "DockerUser", DockerUser)
	return nil
}

func (k *K8sBareMetalPlatform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Init start")
	k.caches = caches
	if err := k.commonPf.InitInfraCommon(ctx, platformConfig, k8sbmProps); err != nil {
		return err
	}
	externalIps, err := infracommon.ParseIpRanges(k.GetExternalIpRanges())
	if err != nil {
		return err
	}
	k.externalIps = externalIps
	k.sharedLBName = platformConfig.RootLBFQDN
	k.cloudletKubeConfig = k.GetCloudletKubeConfig(platformConfig.CloudletKey)

	client, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: platformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
	if err != nil {
		return err
	}
	err = UpdateDockerUser(ctx, client)
	if err != nil {
		return err
	}
	err = k.SetupLb(ctx, client, k.sharedLBName)
	if err != nil {
		return err
	}
	return nil
}

func (k *K8sBareMetalPlatform) InitHAConditional(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (k *K8sBareMetalPlatform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "k8s-baremetal-1.0"
}

func (k *K8sBareMetalPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo")
	var err error
	info.Flavors, err = k8scommon.GetFlavorList(ctx, k.caches)
	if err != nil {
		return err
	}
	info.NodeInfos, err = k.GetNodeInfos(ctx)
	return err
}

// TODO
func (k *K8sBareMetalPlatform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	var resources edgeproto.InfraResourcesSnapshot
	return &resources, nil
}

// TODO
func (k *K8sBareMetalPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource {
	resInfo := make(map[string]edgeproto.InfraResource)
	return resInfo
}

// TODO
func (k *K8sBareMetalPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

// TODO
func (k *K8sBareMetalPlatform) GetClusterInfraResources(ctx context.Context, cluster *edgeproto.ClusterInst) (*edgeproto.InfraResources, error) {
	var resources edgeproto.InfraResources
	return &resources, nil
}

func (k *K8sBareMetalPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetClusterPlatformClient")
	return k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
}

func (k *K8sBareMetalPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNodePlatformClient", "node", node)
	if node == nil {
		return nil, fmt.Errorf("cannot GetNodePlatformClient, as node details are empty")
	}
	nodeName := node.Name
	if nodeName == "" && node.Type == cloudcommon.NodeTypeSharedRootLB.String() {
		nodeName = k.commonPf.PlatformConfig.RootLBFQDN
	}
	if nodeName == "" {
		return nil, fmt.Errorf("cannot GetNodePlatformClient, must specify node name")
	}
	controlIp := k.GetControlAccessIp()
	return k.commonPf.GetSSHClientFromIPAddr(ctx, controlIp, ops...)
}

func (k *K8sBareMetalPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ListCloudletMgmtNodes", "clusterInsts", clusterInsts, "vmAppInsts", vmAppInsts)
	mgmt_nodes := []edgeproto.CloudletMgmtNode{
		{
			Type: "platformhost",
			Name: k.commonPf.PlatformConfig.CloudletKey.Name,
		},
	}
	return mgmt_nodes, nil
}

func (k *K8sBareMetalPlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	return "", fmt.Errorf("GetConsoleUrl not supported on BareMetal")
}

func (k *K8sBareMetalPlatform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("SetPowerState not supported on BareMetal")
}

func (k *K8sBareMetalPlatform) runDebug(ctx context.Context, req *edgeproto.DebugRequest) string {
	return "runDebug TODO on bare metal"
}

func (k *K8sBareMetalPlatform) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PerformUpgrades", "state", cloudletState)
	return nil
}

func (k *K8sBareMetalPlatform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest", "cloudletName", cloudlet.Key.Name)
	return &edgeproto.CloudletManifest{Manifest: "GetCloudletManifest TODO\n" + pfConfig.CrmAccessPrivateKey}, nil
}

func (k *K8sBareMetalPlatform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	return nil
}

func (k *K8sBareMetalPlatform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (k *K8sBareMetalPlatform) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return nil, nil
}

func (k *K8sBareMetalPlatform) GetVersionProperties(ctx context.Context) map[string]string {
	return map[string]string{}
}

func (s *K8sBareMetalPlatform) RefreshCerts(ctx context.Context, certsCache *certscache.ProxyCertsCache) error {
	return nil
}
