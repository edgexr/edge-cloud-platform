// Copyright 2025 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package mockmanagedk8s provides a mock managed k8s platform
package mockmanagedk8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/fakecommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	k8scommon "github.com/edgexr/edge-cloud-platform/pkg/platform/k8s-common"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	certscache "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs-cache"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	ssh "github.com/edgexr/golang-ssh"
)

type Platform struct {
	caches    *platform.Caches
	CommonPf  infracommon.CommonPlatform
	resources fakecommon.Resources
}

func NewPlatform() platform.Platform {
	return &Platform{}
}

const (
	FLAVORS = "FLAVORS"
)

var Props = map[string]*edgeproto.PropertyInfo{
	FLAVORS: {
		Name:        "List of flavors in JSON format",
		Description: `JSON formatted list of edgeproto.FlavorInfo. If no flavors specified, flavors will be derived from platform flavors. Example: [{"name":"Standard_D2s_v3","vcpus":2,"ram":8192,"disk":16}]`,
	},
}

func (s *Platform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "init mock managed K8S cloudlet")
	s.caches = caches
	if err := s.CommonPf.InitInfraCommon(ctx, platformConfig, Props); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon failed", "err", err)
		return err
	}
	return nil
}

func (s *Platform) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:                  platform.PlatformTypeMockManagedK8S,
		SupportsMultiTenantCluster:    true,
		SupportsKubernetesOnly:        true,
		KubernetesManagedControlPlane: true,
		IpAllocatedPerService:         true,
		ManagesK8SControlNodes:        true,
		RequiresCrmOffEdge:            true,
		ResourceQuotaProperties:       cloudcommon.CommonResourceQuotaProps,
		Properties:                    Props,
	}
}

func (s *Platform) InitHAConditional(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *Platform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "Mock-1.0"
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	flavorsJSON, ok := s.CommonPf.Properties.GetValue(FLAVORS)
	if ok && flavorsJSON != "" {
		flavors := []*edgeproto.FlavorInfo{}
		if err := json.Unmarshal([]byte(flavorsJSON), &flavors); err != nil {
			return fmt.Errorf("failed to unmarshal %s: %s, %s", FLAVORS, flavorsJSON, err)
		}
		info.Flavors = flavors
	} else {
		var err error
		info.Flavors, err = k8scommon.GetFlavorList(ctx, s.caches)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Platform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (map[string]string, error) {
	s.resources.AddClusterResources(clusterInst)
	return nil, nil
}

func (s *Platform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	s.resources.RemoveClusterResources(&clusterInst.Key)
	s.resources.AddClusterResources(clusterInst)
	return nil, nil
}

func (s *Platform) ChangeClusterInstDNS(ctx context.Context, clusterInst *edgeproto.ClusterInst, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	_, err := s.UpdateClusterInst(ctx, clusterInst, updateCallback)
	return err
}

func (s *Platform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	s.resources.RemoveClusterResources(&clusterInst.Key)
	return nil
}

func (s *Platform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	return s.resources.GetSnapshot(), nil
}

func (s *Platform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource {
	return map[string]edgeproto.InfraResource{}
}

func (s *Platform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

func (s *Platform) GetClusterInfraResources(ctx context.Context, cluster *edgeproto.ClusterInst) (*edgeproto.InfraResources, error) {
	return s.resources.GetClusterResources(&cluster.Key), nil
}

func (s *Platform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateSender edgeproto.AppInstInfoSender) error {
	return nil
}

func (s *Platform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *Platform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (v *Platform) ChangeAppInstDNS(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, OldURI string, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *Platform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	return &edgeproto.AppInstRuntime{}, nil
}

func (s *Platform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

func (s *Platform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return "", nil
}

func (s *Platform) GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	return "", nil
}

func (s *Platform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, flavor *edgeproto.Flavor, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "create Mock cloudlet", "key", cloudlet.Key)
	return true, nil
}

func (s *Platform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *Platform) ChangeCloudletDNS(ctx context.Context, cloudlet *edgeproto.Cloudlet, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *Platform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "delete Mock cloudlet", "key", cloudlet.Key)
	return nil
}

func (s *Platform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest", "cloudletName", cloudlet.Key.Name)
	return &edgeproto.CloudletManifest{Manifest: "Mock manifest\n"}, nil
}

func (s *Platform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	return nil
}

func (s *Platform) UpdateTrustPolicyException(ctx context.Context, tpe *edgeproto.TrustPolicyException, clusterKey *edgeproto.ClusterKey) error {
	return nil
}

func (s *Platform) DeleteTrustPolicyException(ctx context.Context, tpeKey *edgeproto.TrustPolicyExceptionKey, clusterKey *edgeproto.ClusterKey) error {
	return nil
}

func (s *Platform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Setting power state", "state", appInst.PowerState)
	return nil
}

func (s *Platform) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	return nil
}

func (s *Platform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	return nil
}

func (s *Platform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "Setting up cloudlet")
	return nil
}

func (s *Platform) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return nil, nil
}

func (s *Platform) GetVersionProperties(ctx context.Context) map[string]string {
	return map[string]string{}
}

func (s *Platform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &edgeproto.Flavor{}, nil
}

func (s *Platform) ActiveChanged(ctx context.Context, platformActive bool) error {
	return nil
}

func (s *Platform) NameSanitize(name string) string {
	return util.K8SSanitize(name)
}

func (s *Platform) HandleFedAppInstCb(ctx context.Context, msg *edgeproto.FedAppInstEvent) {}

func (s *Platform) RefreshCerts(ctx context.Context, certsCache *certscache.ProxyCertsCache) error {
	return nil
}

func (s *Platform) GetCloudletManagedClusters(ctx context.Context) ([]*edgeproto.CloudletManagedCluster, error) {
	return nil, errors.New("not supported")
}

func (s *Platform) GetCloudletManagedClusterInfo(ctx context.Context, in *edgeproto.ClusterInst) (*edgeproto.CloudletManagedClusterInfo, error) {
	return nil, errors.New("not supported")
}
