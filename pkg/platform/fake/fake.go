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

package fake

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/crmutil"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/fakecommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	ssh "github.com/edgexr/golang-ssh"
)

type Platform struct {
	consoleServer *httptest.Server
	caches        *platform.Caches
	clusterTPEs   map[cloudcommon.TrustPolicyExceptionKeyClusterInstKey]struct{}
	mux           sync.Mutex
	cloudletKey   *edgeproto.CloudletKey
	crmServiceOps []process.CrmServiceOp
	resources     fakecommon.Resources
}

var (
	FakeRamMax         = uint64(40960)
	FakeVcpusMax       = uint64(50)
	FakeDiskMax        = uint64(5000)
	FakeExternalIpsMax = uint64(30)
)

var FakeAppDNSRoot = "fake.net"

var FakeFlavorList = []*edgeproto.FlavorInfo{
	&edgeproto.FlavorInfo{
		Name:  "x1.tiny",
		Vcpus: uint64(1),
		Ram:   uint64(1024),
		Disk:  uint64(20),
	},
	&edgeproto.FlavorInfo{
		Name:  "x1.small",
		Vcpus: uint64(2),
		Ram:   uint64(4096),
		Disk:  uint64(40),
	},
}

var rootLbFlavor = FakeFlavorList[1]

var fakeProps = map[string]*edgeproto.PropertyInfo{
	// Property: Default-Value
	"PROP_1": &edgeproto.PropertyInfo{
		Name:        "Property 1",
		Description: "First Property",
		Secret:      true,
		Mandatory:   true,
	},
	"PROP_2": &edgeproto.PropertyInfo{
		Name:        "Property 2",
		Description: "Second Property",
		Mandatory:   true,
	},
}

var quotaProps = cloudcommon.GetCommonResourceQuotaProps(
	cloudcommon.ResourceInstances,
)

var maxPrimaryCrmStartupWait = 10 * time.Second

func NewPlatform() platform.Platform {
	return &Platform{}
}

func UpdateResourcesMax() error {
	// Make fake resource limits configurable for QA testing
	ramMax := os.Getenv("FAKE_RAM_MAX")
	if ramMax != "" {
		ram, err := strconv.Atoi(ramMax)
		if err != nil {
			return err
		}
		if ram > 0 {
			FakeRamMax = uint64(ram)
		}
	}
	vcpusMax := os.Getenv("FAKE_VCPUS_MAX")
	if vcpusMax != "" {
		vcpus, err := strconv.Atoi(vcpusMax)
		if err != nil {
			return err
		}
		if vcpus > 0 {
			FakeVcpusMax = uint64(vcpus)
		}
	}
	diskMax := os.Getenv("FAKE_DISK_MAX")
	if diskMax != "" {
		disk, err := strconv.Atoi(diskMax)
		if err != nil {
			return err
		}
		if disk > 0 {
			FakeDiskMax = uint64(disk)
		}
	}
	return nil
}

func (s *Platform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "running in fake cloudlet mode")
	platformConfig.NodeMgr.Debug.AddDebugFunc("fakecmd", s.runDebug)

	s.caches = caches
	s.cloudletKey = platformConfig.CloudletKey
	updateCallback(edgeproto.UpdateTask, "Done initializing fake platform")
	s.consoleServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Console Content")
	}))
	s.resources.Init()
	s.resources.SetCloudletFlavors(FakeFlavorList, rootLbFlavor.Name)
	// Update resource info for platformVM and RootLBVM
	platvm := edgeproto.VmInfo{
		Name:        "fake-platform-vm",
		Type:        cloudcommon.NodeTypePlatformVM.String(),
		InfraFlavor: "x1.small",
		Status:      "ACTIVE",
		Ipaddresses: []edgeproto.IpAddr{
			{ExternalIp: "10.101.100.10"},
		},
	}
	rlbvm := edgeproto.VmInfo{
		Name:        "fake-rootlb-vm",
		Type:        cloudcommon.NodeTypeDedicatedRootLB.String(),
		InfraFlavor: "x1.small",
		Status:      "ACTIVE",
		Ipaddresses: []edgeproto.IpAddr{
			{ExternalIp: "10.101.100.11"},
		},
	}
	s.resources.AddPlatformVM(platvm)
	s.resources.AddPlatformVM(rlbvm)
	s.resources.UpdateExternalIP(fakecommon.ResourceAdd)

	err := UpdateResourcesMax()
	if err != nil {
		return err
	}
	s.resources.SetMaxResources(FakeRamMax, FakeVcpusMax, FakeDiskMax, FakeExternalIpsMax)
	s.clusterTPEs = make(map[cloudcommon.TrustPolicyExceptionKeyClusterInstKey]struct{})

	return nil
}

func (s *Platform) InitHAConditional(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	return s.updateResourceCounts(ctx)
}

func (s *Platform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "fake-1.0"
}

func (s *Platform) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:                             platform.PlatformTypeFake,
		SupportsMultiTenantCluster:               true,
		SupportsSharedVolume:                     true,
		SupportsTrustPolicy:                      true,
		CloudletServicesLocal:                    true,
		IsFake:                                   true,
		SupportsAdditionalNetworks:               true,
		SupportsPlatformHighAvailabilityOnDocker: true,
		SupportsPlatformHighAvailabilityOnK8S:    true,
		Properties:                               fakeProps,
		ResourceQuotaProperties:                  quotaProps,
	}
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	info.OsMaxRam = FakeRamMax
	info.OsMaxVcores = FakeVcpusMax
	info.OsMaxVolGb = FakeDiskMax
	info.Flavors = FakeFlavorList
	return nil
}

func (s *Platform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "fake UpdateClusterInst", "clusterInst", clusterInst)
	updateCallback(edgeproto.UpdateTask, "Updating Cluster Inst")
	s.resources.RemoveClusterResources(&clusterInst.Key)
	s.resources.AddClusterResources(clusterInst)
	return nil
}

func (s *Platform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "fake CreateClusterInst", "clusterInst", clusterInst)
	updateCallback(edgeproto.UpdateTask, "First Create Task")
	updateCallback(edgeproto.UpdateTask, "Second Create Task")
	s.resources.AddClusterResources(clusterInst)

	// verify we can find any provisioned networks
	if len(clusterInst.Networks) > 0 {
		networks, err := crmutil.GetNetworksForClusterInst(ctx, clusterInst, s.caches.NetworkCache)
		if err != nil {
			return fmt.Errorf("Error getting cluster networks - %v", err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "found networks from cache", "networks", networks)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "fake ClusterInst ready")
	return nil
}

func (s *Platform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "First Delete Task")
	updateCallback(edgeproto.UpdateTask, "Second Delete Task")
	s.resources.RemoveClusterResources(&clusterInst.Key)

	log.SpanLog(ctx, log.DebugLevelInfra, "fake ClusterInst deleted")
	return nil
}

func (s *Platform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	return s.resources.GetSnapshot(), nil
}

// called by controller, make sure it doesn't make any calls to infra API
func (s *Platform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	// resource name -> resource units
	cloudletRes := map[string]string{
		cloudcommon.ResourceInstances: "",
	}
	resInfo := make(map[string]edgeproto.InfraResource)
	for resName, resUnits := range cloudletRes {
		resMax := uint64(0)
		if infraRes, ok := infraResMap[resName]; ok {
			resMax = infraRes.InfraMaxValue
		}
		resInfo[resName] = edgeproto.InfraResource{
			Name:          resName,
			InfraMaxValue: resMax,
			Units:         resUnits,
		}
	}

	out, ok := resInfo[cloudcommon.ResourceInstances]
	if ok {
		out.Value += uint64(len(vmResources))
		resInfo[cloudcommon.ResourceInstances] = out
	}
	return resInfo
}

func (s *Platform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	instancesUsed := uint64(len(resources))
	resMetric.AddIntVal(cloudcommon.ResourceMetricInstances, instancesUsed)
	return nil
}

func (s *Platform) GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error) {
	return s.resources.GetClusterResources(clusterKey), nil
}

func (s *Platform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	clusterSvcAppInstFail := os.Getenv("FAKE_PLATFORM_APPINST_CREATE_FAIL")
	if clusterSvcAppInstFail != "" {
		return errors.New("FAKE_PLATFORM_APPINST_CREATE_FAIL")
	}
	updateCallback(edgeproto.UpdateTask, "Creating App Inst")
	log.SpanLog(ctx, log.DebugLevelInfra, "fake AppInst ready")
	s.resources.AddVmAppResCount(ctx, app, appInst)
	return nil
}

func (s *Platform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "First Delete Task")
	updateCallback(edgeproto.UpdateTask, "Second Delete Task")
	log.SpanLog(ctx, log.DebugLevelInfra, "fake AppInst deleted")
	s.resources.RemoveVmAppResCount(ctx, app, appInst)
	return nil
}

func (s *Platform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "fake appInst updated")
	return nil
}

func (s *Platform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	if app.Deployment == cloudcommon.DeploymentTypeKubernetes {
		rt := &edgeproto.AppInstRuntime{}
		for ii := uint32(0); ii < clusterInst.NumNodes; ii++ {
			rt.ContainerIds = append(rt.ContainerIds, fmt.Sprintf("appOnClusterNode%d", ii))
		}
		return rt, nil
	}
	return &edgeproto.AppInstRuntime{}, nil
}

func (s *Platform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{
		edgeproto.CloudletMgmtNode{
			Type: cloudcommon.NodeTypePlatformVM.String(),
			Name: "platformvmname",
		},
	}, nil
}

func (s *Platform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	if req.Cmd != nil {
		return req.Cmd.Command, nil
	}
	if req.Log != nil {
		return "echo \"here's some logs\"", nil
	}
	return "", fmt.Errorf("no cmd or log specified in exec request")
}

func (s *Platform) GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	if s.consoleServer != nil {
		return s.consoleServer.URL + "?token=xyz", nil
	}
	return "", fmt.Errorf("no console server to fetch URL from")
}

func (s *Platform) AddCrmServiceOps(ops ...process.CrmServiceOp) {
	s.crmServiceOps = append(s.crmServiceOps, ops...)
}

func (s *Platform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "create fake cloudlet", "key", cloudlet.Key)
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		return true, nil
	}
	updateCallback(edgeproto.UpdateTask, "Creating Cloudlet")
	updateCallback(edgeproto.UpdateTask, "Starting CRMServer")
	var redisCfg rediscache.RedisConfig
	if cloudlet.PlatformHighAvailability {
		redisCfg.StandaloneAddr = rediscache.DefaultRedisStandaloneAddr
	}
	err := process.StartCRMService(ctx, cloudlet, pfConfig, process.HARolePrimary, &redisCfg, s.crmServiceOps...)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "fake cloudlet create failed to start CRM", "err", err)
		return true, err
	}
	if cloudlet.PlatformHighAvailability {
		log.SpanLog(ctx, log.DebugLevelInfra, "creating 2 instances for H/A", "key", cloudlet.Key)
		// Pause before starting the secondary to let the primary become active first for the sake of
		// e2e tests that need consistent ordering. Secondary will be started up in a separate thread after
		// cloudletInfo shows up from the primary
		go func() {
			start := time.Now()
			var err error
			var cloudletInfo edgeproto.CloudletInfo
			for {
				time.Sleep(time.Millisecond * 200)
				elapsed := time.Since(start)
				if elapsed >= (maxPrimaryCrmStartupWait) {
					log.SpanLog(ctx, log.DebugLevelInfra, "timed out waiting for primary CRM to report cloudlet info")
					err = fmt.Errorf("timed out waiting for primary CRM to report cloudlet info")
					break
				}
				if !caches.CloudletInfoCache.Get(&cloudlet.Key, &cloudletInfo) {
					log.SpanLog(ctx, log.DebugLevelInfra, "failed to get cloudlet info after starting primary CRM, will retry", "cloudletKey", s.cloudletKey)
				} else {
					log.SpanLog(ctx, log.DebugLevelInfra, "got cloudlet info from primary CRM, will start secondary", "cloudletKey", cloudlet.Key, "active", cloudletInfo.ActiveCrmInstance, "ci", cloudletInfo)
					err = process.StartCRMService(ctx, cloudlet, pfConfig, process.HARoleSecondary, &redisCfg, s.crmServiceOps...)
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfra, "fake cloudlet create failed to start secondary CRM", "err", err)
					}
					break
				}
			}
			if err != nil {
				cloudletInfo.Key = cloudlet.Key
				cloudletInfo.Errors = append(cloudletInfo.Errors, "fake cloudlet create failed to start secondary CRM: "+err.Error())
				cloudletInfo.State = dme.CloudletState_CLOUDLET_STATE_ERRORS
				caches.CloudletInfoCache.Update(ctx, &cloudletInfo, 0)
			}
		}()
	}
	return true, nil
}

func (s *Platform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	log.DebugLog(log.DebugLevelInfra, "update fake Cloudlet", "cloudlet", cloudlet)
	for key, val := range cloudlet.EnvVar {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Updating envvar, %s=%s", key, val))
	}
	return nil
}

func (s *Platform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	log.DebugLog(log.DebugLevelInfra, "fake UpdateTrustPolicy begin", "policy", TrustPolicy)
	return nil
}

func (s *Platform) UpdateTrustPolicyException(ctx context.Context, tpe *edgeproto.TrustPolicyException, clusterInstKey *edgeproto.ClusterInstKey) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	key := cloudcommon.TrustPolicyExceptionKeyClusterInstKey{
		TpeKey:         tpe.Key,
		ClusterInstKey: *clusterInstKey,
	}
	s.clusterTPEs[key] = struct{}{}
	log.SpanLog(ctx, log.DebugLevelInfra, "fake UpdateTrustPolicyException", "ADD_TPE policyKey", key)
	return nil
}

func (s *Platform) DeleteTrustPolicyException(ctx context.Context, tpeKey *edgeproto.TrustPolicyExceptionKey, clusterInstKey *edgeproto.ClusterInstKey) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	key := cloudcommon.TrustPolicyExceptionKeyClusterInstKey{
		TpeKey:         *tpeKey,
		ClusterInstKey: *clusterInstKey,
	}
	delete(s.clusterTPEs, key)
	log.SpanLog(ctx, log.DebugLevelInfra, "fake DeleteTrustPolicyException", "DELETE_TPE policyKey", key)
	return nil
}

func (s *Platform) HasTrustPolicyException(ctx context.Context, tpeKey *edgeproto.TrustPolicyExceptionKey, clusterInst *edgeproto.ClusterInst) bool {
	s.mux.Lock()
	defer s.mux.Unlock()
	key := cloudcommon.TrustPolicyExceptionKeyClusterInstKey{
		TpeKey:         *tpeKey,
		ClusterInstKey: clusterInst.Key,
	}
	_, found := s.clusterTPEs[key]
	log.SpanLog(ctx, log.DebugLevelInfra, "fake HasTrustPolicyException", "policyKey", tpeKey, "found", found)

	return found
}

func (s *Platform) WaitHasTrustPolicyException(ctx context.Context, tpeKey *edgeproto.TrustPolicyExceptionKey, clusterInst *edgeproto.ClusterInst) bool {
	for ii := 0; ii < 10; ii++ {
		if s.HasTrustPolicyException(ctx, tpeKey, clusterInst) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return s.HasTrustPolicyException(ctx, tpeKey, clusterInst)
}

func (s *Platform) TrustPolicyExceptionCount(ctx context.Context) int {
	s.mux.Lock()
	defer s.mux.Unlock()
	count := len(s.clusterTPEs)
	log.SpanLog(ctx, log.DebugLevelInfra, "fake TrustPolicyExceptionCount", "count", count)
	return count
}

func (s *Platform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	log.DebugLog(log.DebugLevelInfra, "delete fake Cloudlet", "key", cloudlet.Key)
	updateCallback(edgeproto.UpdateTask, "Deleting Cloudlet")
	updateCallback(edgeproto.UpdateTask, "Stopping CRMServer")
	err := process.StopCRMService(ctx, cloudlet, process.HARoleAll, s.crmServiceOps...)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "fake cloudlet delete failed", "err", err)
		return err
	}

	return nil
}

func (s *Platform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Setting power state", "state", appInst.PowerState)
	return nil
}

func (s *Platform) runDebug(ctx context.Context, req *edgeproto.DebugRequest) string {
	return "ran some debug"
}
func (s *Platform) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	return nil
}

func (s *Platform) updateResourceCounts(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "updateResourceCounts")
	if s.caches == nil {
		return fmt.Errorf("caches is nil")
	}
	s.resources.SetUserResources(ctx, s.caches)
	return nil
}

func (s *Platform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest", "cloudletName", cloudlet.Key.Name)
	return &edgeproto.CloudletManifest{Manifest: "fake manifest\n" + pfConfig.CrmAccessPrivateKey}, nil
}

func (s *Platform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	for _, vm := range vms {
		// For unit testing
		if vm.Name == "vmFailVerification" {
			return fmt.Errorf("failed to verify VM")
		}
	}
	return nil
}

func (s *Platform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "Setting up cloudlet")
	return nil
}

func (s *Platform) GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	return nil, nil
}

func (s *Platform) GetVersionProperties(ctx context.Context) map[string]string {
	return map[string]string{}
}

func (s *Platform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &edgeproto.Flavor{
		Key: edgeproto.FlavorKey{
			Name: rootLbFlavor.Name,
		},
		Vcpus: rootLbFlavor.Vcpus,
		Ram:   rootLbFlavor.Ram,
		Disk:  rootLbFlavor.Disk,
	}, nil
}

func (s *Platform) ActiveChanged(ctx context.Context, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChanged", "platformActive", platformActive)
	return nil
}

func (s *Platform) NameSanitize(name string) string {
	return name
}
