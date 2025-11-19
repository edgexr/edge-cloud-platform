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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/fakecommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	certscache "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs-cache"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	ssh "github.com/edgexr/golang-ssh"
)

type Platform struct {
	consoleServer  *httptest.Server
	caches         *platform.Caches
	clusterTPEs    map[cloudcommon.TrustPolicyExceptionKeyClusterKey]struct{}
	mux            sync.Mutex
	cloudletKey    *edgeproto.CloudletKey
	crmServiceOps  []process.CrmServiceOp
	resources      fakecommon.Resources
	platformConfig *platform.PlatformConfig
	commonPf       infracommon.CommonPlatform
	// settings used for unit testing
	simulateAppCreateFailure     bool
	simulateAppDeleteFailure     bool
	simulateClusterCreateFailure bool
	simulateClusterDeleteFailure bool
	pause                        sync.WaitGroup
	CustomFlavorList             []*edgeproto.FlavorInfo
	simPublicCloud               bool
	cloudletManagedClusters      []*edgeproto.CloudletManagedCluster
}

const (
	FakeRamMax         = uint64(40960)
	FakeVcpusMax       = uint64(50)
	FakeDiskMax        = uint64(5000)
	FakeExternalIpsMax = uint64(30)
)

var FakeGPUsMax = []*edgeproto.GPUResource{{
	ModelId: "nvidia-t4",
	Count:   4,
}}

var FakeAppDNSRoot = "fake.net"

var DefaultFlavorList = []*edgeproto.FlavorInfo{{
	Name:  "x1.tiny",
	Vcpus: uint64(1),
	Ram:   uint64(1024),
	Disk:  uint64(20),
}, {
	Name:  "x1.small",
	Vcpus: uint64(2),
	Ram:   uint64(4096),
	Disk:  uint64(40),
}, {
	Name:  "x1.small.gpu",
	Vcpus: uint64(2),
	Ram:   uint64(4096),
	Disk:  uint64(40),
	Gpus: []*edgeproto.GPUResource{{
		ModelId: "nvidia-t4",
		Vendor:  cloudcommon.GPUVendorNVIDIA,
		Count:   1,
		Memory:  4,
	}},
},
}

var fakeProps = map[string]*edgeproto.PropertyInfo{
	// Property: Default-Value
	"PROP_1": &edgeproto.PropertyInfo{
		Name:        "Property 1",
		Description: "First Property",
		Secret:      true,
		Mandatory:   false,
	},
	"PROP_2": &edgeproto.PropertyInfo{
		Name:        "Property 2",
		Description: "Second Property",
		Mandatory:   false,
	},
	"FLAVORS": &edgeproto.PropertyInfo{
		Name:        "Flavors JSON",
		Description: "[]edgeproto.FlavorInfo as JSON string",
		Mandatory:   false,
	},
	"FAKE_RAM_MAX": {
		Name: "Fake RAM max",
	},
	"FAKE_VCPUS_MAX": {
		Name: "Fake VCPUs max",
	},
	"FAKE_DISK_MAX": {
		Name: "Fake VCPUs max",
	},
	"foo": {
		Name: "foo",
	},
	"FAKE_PLATFORM_APPINST_CREATE_FAIL": {
		Name:        "fake platform appinst create fail",
		Description: "for e2e tests, make appinst create fail",
	},
	"LOAD_MANAGED_CLUSTERS": {
		Name: "Load fake managed clusters",
	},
	cloudcommon.FloatingVIPs: {
		Name: "Floating VIPs",
	},
}

var AccessVarProps = map[string]*edgeproto.PropertyInfo{
	"APIKey": &edgeproto.PropertyInfo{
		Name:        "API Key",
		Description: "API Key for authentication",
		Secret:      true,
	},
}

var quotaProps = cloudcommon.GetCommonResourceQuotaProps(
	cloudcommon.ResourceInstances,
)

var CloudletManagedClusters = []*edgeproto.CloudletManagedCluster{}

func NewPlatform() platform.Platform {
	return &Platform{}
}

func (s *Platform) UpdateResourcesMax(envVars map[string]string) error {
	// Make fake resource limits configurable for QA testing
	ramMax := FakeRamMax
	vcpusMax := FakeVcpusMax
	diskMax := FakeDiskMax

	ramMaxStr := envVars["FAKE_RAM_MAX"]
	if ramMaxStr != "" {
		ram, err := strconv.Atoi(ramMaxStr)
		if err != nil {
			return err
		}
		if ram > 0 {
			ramMax = uint64(ram)
		}
	}
	vcpusMaxStr := envVars["FAKE_VCPUS_MAX"]
	if vcpusMaxStr != "" {
		vcpus, err := strconv.Atoi(vcpusMaxStr)
		if err != nil {
			return err
		}
		if vcpus > 0 {
			vcpusMax = uint64(vcpus)
		}
	}
	diskMaxStr := envVars["FAKE_DISK_MAX"]
	if diskMaxStr != "" {
		disk, err := strconv.Atoi(diskMaxStr)
		if err != nil {
			return err
		}
		if disk > 0 {
			diskMax = uint64(disk)
		}
	}
	s.resources.SetMaxResources(ramMax, vcpusMax, diskMax, FakeExternalIpsMax, FakeGPUsMax)
	return nil
}

func GetPlatformVMs() []edgeproto.VmInfo {
	return []edgeproto.VmInfo{{
		Name:        "fake-platform-vm",
		Type:        cloudcommon.NodeTypePlatformVM.String(),
		InfraFlavor: "x1.small",
		Status:      "ACTIVE",
		Ipaddresses: []edgeproto.IpAddr{
			{ExternalIp: "10.101.100.10"},
		},
	}, {
		Name:        "fake-rootlb-vm",
		Type:        cloudcommon.NodeTypeDedicatedRootLB.String(),
		InfraFlavor: "x1.small",
		Status:      "ACTIVE",
		Ipaddresses: []edgeproto.IpAddr{
			{ExternalIp: "10.101.100.11"},
		},
	}}
}

func (s *Platform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "running in fake cloudlet mode", "envVars", platformConfig.EnvVars)
	platformConfig.NodeMgr.Debug.AddDebugFunc("fakecmd", s.runDebug)
	platformConfig.DeploymentTag = "test"

	s.caches = caches
	s.cloudletKey = platformConfig.CloudletKey
	s.platformConfig = platformConfig
	updateCallback(edgeproto.UpdateTask, "Done initializing fake platform")
	s.consoleServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Console Content")
	}))
	if err := s.commonPf.InitInfraCommon(ctx, platformConfig, fakeProps); err != nil {
		return err
	}
	flavors, err := s.getInfraFlavors()
	if err != nil {
		return err
	}
	rootLbFlavor := flavors[1]
	s.resources.Init()
	s.resources.SetCloudletFlavors(flavors, rootLbFlavor.Name)
	// Update resource info for platformVM and RootLBVM
	if !s.simPublicCloud {
		for _, vm := range GetPlatformVMs() {
			s.resources.AddPlatformVM(vm)
		}
		s.resources.UpdateExternalIP(fakecommon.ResourceAdd)
	}
	if _, ok := s.commonPf.Properties.GetValue("LOAD_MANAGED_CLUSTERS"); ok {
		s.cloudletManagedClusters = CloudletManagedClusters
	}

	err = s.UpdateResourcesMax(platformConfig.EnvVars)
	if err != nil {
		return err
	}
	s.clusterTPEs = make(map[cloudcommon.TrustPolicyExceptionKeyClusterKey]struct{})

	return nil
}

func (s *Platform) InitHAConditional(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) error {
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
		SupportsMultipleNodePools:                true,
		UsesRootLb:                               true,
		SupportsCloudletManagedClusters:          true,
		ManagesK8SControlNodes:                   s.simPublicCloud,
		Properties:                               fakeProps,
		ResourceQuotaProperties:                  quotaProps,
		AccessVars:                               AccessVarProps,
	}
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	ramMax, vcpusMax, diskMax, _ := s.resources.GetMaxResources()
	info.OsMaxRam = ramMax
	info.OsMaxVcores = vcpusMax
	info.OsMaxVolGb = diskMax
	log.SpanLog(ctx, log.DebugLevelApi, "fake gather cloudlet info")
	flavors, err := s.getInfraFlavors()
	if err != nil {
		return err
	}
	info.Flavors = flavors
	// in case flavors changed, update resources
	rootLbFlavor := flavors[1]
	s.resources.SetCloudletFlavors(flavors, rootLbFlavor.Name)
	return nil
}

// getInfraFlavors emulates querying underlying infrastructure API for flavors
func (s *Platform) getInfraFlavors() ([]*edgeproto.FlavorInfo, error) {
	flavorsJSON, ok := s.commonPf.Properties.GetValue("FLAVORS")
	if ok && flavorsJSON != "" {
		flavors := []*edgeproto.FlavorInfo{}
		err := json.Unmarshal([]byte(flavorsJSON), &flavors)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal FLAVORS env var: %s, %s", flavorsJSON, err)
		}
		return flavors, nil
	}
	if s.CustomFlavorList != nil {
		return s.CustomFlavorList, nil
	}
	return DefaultFlavorList, nil
}

func (s *Platform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "fake UpdateClusterInst", "clusterInst", clusterInst)
	updateCallback(edgeproto.UpdateTask, "Updating Cluster Inst")
	s.resources.RemoveClusterResources(&clusterInst.Key)
	s.resources.AddClusterResources(clusterInst)
	return nil, nil
}

func (s *Platform) ChangeClusterInstDNS(ctx context.Context, clusterInst *edgeproto.ClusterInst, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	_, err := s.UpdateClusterInst(ctx, clusterInst, updateCallback)
	return err
}

func (s *Platform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "fake CreateClusterInst", "clusterInst", clusterInst)
	updateCallback(edgeproto.UpdateTask, "First Create Task")
	updateCallback(edgeproto.UpdateTask, "Second Create Task")
	s.pause.Wait()
	if s.simulateClusterCreateFailure {
		return nil, errors.New("fake platform create ClusterInst failed")
	}
	if clusterInst.IsCloudletManaged() {
		// ensure cluster exists
		found := false
		for _, cluster := range s.cloudletManagedClusters {
			if cluster.Key.Id == clusterInst.CloudletManagedClusterId || cluster.Key.Name == clusterInst.CloudletManagedClusterName {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("cloudlet managed cluster name %q or id %q not found", clusterInst.CloudletManagedClusterName, clusterInst.CloudletManagedClusterId)
		}
	} else {
		s.resources.AddClusterResources(clusterInst)
	}
	// verify we can find any provisioned networks
	if len(clusterInst.Networks) > 0 {
		networks, err := edgeproto.GetNetworksForClusterInst(ctx, clusterInst, s.caches.NetworkCache)
		if err != nil {
			return nil, fmt.Errorf("Error getting cluster networks - %v", err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "found networks from cache", "networks", networks)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "fake ClusterInst ready")
	return nil, nil
}

func (s *Platform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "First Delete Task")
	updateCallback(edgeproto.UpdateTask, "Second Delete Task")
	s.pause.Wait()
	if s.simulateClusterDeleteFailure {
		return errors.New("fake platform delete ClusterInst failed")
	}
	if !clusterInst.IsCloudletManaged() {
		s.resources.RemoveClusterResources(&clusterInst.Key)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "fake ClusterInst deleted")
	return nil
}

func (s *Platform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	return s.resources.GetSnapshot(), nil
}

// called by controller, make sure it doesn't make any calls to infra API
func (s *Platform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource {
	// resource name -> resource units
	cloudletRes := map[string]string{
		cloudcommon.ResourceInstances: "",
	}
	resInfo := make(map[string]edgeproto.InfraResource)
	for resName, resUnits := range cloudletRes {
		resInfo[resName] = edgeproto.InfraResource{
			Name:  resName,
			Units: resUnits,
		}
	}

	out, ok := resInfo[cloudcommon.ResourceInstances]
	if ok {
		instCount := 0
		for _, vmRes := range vmResources {
			instCount += int(vmRes.Count)
		}
		out.Value += uint64(instCount)
		resInfo[cloudcommon.ResourceInstances] = out
	}
	return resInfo
}

func (s *Platform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	instCount := 0
	for _, vmRes := range resources {
		instCount += int(vmRes.Count)
	}
	instancesUsed := uint64(instCount)
	resMetric.AddIntVal(cloudcommon.ResourceMetricInstances, instancesUsed)
	return nil
}

func (s *Platform) GetClusterInfraResources(ctx context.Context, cluster *edgeproto.ClusterInst) (*edgeproto.InfraResources, error) {
	return s.resources.GetClusterResources(&cluster.Key), nil
}

func (s *Platform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateSender edgeproto.AppInstInfoSender) error {
	updateCallback := updateSender.SendStatusIgnoreErr
	clusterSvcAppInstFail := s.platformConfig.EnvVars["FAKE_PLATFORM_APPINST_CREATE_FAIL"]
	if clusterSvcAppInstFail != "" {
		return errors.New("FAKE_PLATFORM_APPINST_CREATE_FAIL")
	}
	s.pause.Wait()
	if s.simulateAppCreateFailure {
		return errors.New("fake platform create app inst failed")
	}
	updateCallback(edgeproto.UpdateTask, "Creating App Inst")
	log.SpanLog(ctx, log.DebugLevelInfra, "fake AppInst ready")
	s.resources.AddVmAppResCount(ctx, app, appInst)
	return nil
}

func (s *Platform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "First Delete Task")
	updateCallback(edgeproto.UpdateTask, "Second Delete Task")
	s.pause.Wait()
	if s.simulateAppDeleteFailure {
		return errors.New("fake platform delete app inst failed")
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "fake AppInst deleted")
	s.resources.RemoveVmAppResCount(ctx, app, appInst)
	return nil
}

func (s *Platform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "fake appInst updated")
	return nil
}

func (v *Platform) ChangeAppInstDNS(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, OldURI string, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "fake appinst dns updated")
	return nil
}

func (s *Platform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	if app.Deployment == cloudcommon.DeploymentTypeKubernetes {
		rt := &edgeproto.AppInstRuntime{}
		for _, pool := range clusterInst.NodePools {
			for ii := uint32(0); ii < pool.NumNodes; ii++ {
				poolTag := "-" + pool.Name
				if pool.Name == edgeproto.DefaultNodePoolName {
					poolTag = ""
				}
				rt.ContainerIds = append(rt.ContainerIds, fmt.Sprintf("appOnClusterNode%s%d", poolTag, ii))
			}
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

func (s *Platform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, flavor *edgeproto.Flavor, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
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
	var err error
	if cloudlet.PlatformHighAvailability {
		err = process.StartCRMServicesHA(ctx, cloudlet, pfConfig, &redisCfg, s.crmServiceOps...)
	} else {
		err = process.StartCRMService(ctx, cloudlet, pfConfig, process.HARolePrimary, &redisCfg, s.crmServiceOps...)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "fake cloudlet create failed to start CRM", "err", err)
		return true, err
	}
	return true, nil
}

func (s *Platform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "update fake Cloudlet", "cloudlet", cloudlet)
	for key, val := range cloudlet.EnvVar {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Updating envvar, %s=%s", key, val))
	}
	return nil
}

func (s *Platform) ChangeCloudletDNS(ctx context.Context, cloudlet *edgeproto.Cloudlet, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "update fake Cloudlet fqdn", "cloudlet", cloudlet)
	return nil
}

func (s *Platform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "fake UpdateTrustPolicy begin", "policy", TrustPolicy)
	return nil
}

func (s *Platform) UpdateTrustPolicyException(ctx context.Context, tpe *edgeproto.TrustPolicyException, clusterKey *edgeproto.ClusterKey) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	key := cloudcommon.TrustPolicyExceptionKeyClusterKey{
		TpeKey:     tpe.Key,
		ClusterKey: *clusterKey,
	}
	s.clusterTPEs[key] = struct{}{}
	log.SpanLog(ctx, log.DebugLevelInfra, "fake UpdateTrustPolicyException", "ADD_TPE policyKey", key)
	return nil
}

func (s *Platform) DeleteTrustPolicyException(ctx context.Context, tpeKey *edgeproto.TrustPolicyExceptionKey, clusterKey *edgeproto.ClusterKey) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	key := cloudcommon.TrustPolicyExceptionKeyClusterKey{
		TpeKey:     *tpeKey,
		ClusterKey: *clusterKey,
	}
	delete(s.clusterTPEs, key)
	log.SpanLog(ctx, log.DebugLevelInfra, "fake DeleteTrustPolicyException", "DELETE_TPE policyKey", key)
	return nil
}

func (s *Platform) HasTrustPolicyException(ctx context.Context, tpeKey *edgeproto.TrustPolicyExceptionKey, clusterInst *edgeproto.ClusterInst) bool {
	s.mux.Lock()
	defer s.mux.Unlock()
	key := cloudcommon.TrustPolicyExceptionKeyClusterKey{
		TpeKey:     *tpeKey,
		ClusterKey: clusterInst.Key,
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

func (s *Platform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "delete fake Cloudlet", "key", cloudlet.Key)
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
	s.resources.SetUserResources(ctx, s.cloudletKey, s.caches)
	return nil
}

func (s *Platform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
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

func (s *Platform) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return nil, nil
}

func (s *Platform) GetVersionProperties(ctx context.Context) map[string]string {
	return map[string]string{}
}

func (s *Platform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	flavors, err := s.getInfraFlavors()
	if err != nil {
		return nil, err
	}
	rootLbFlavor := flavors[1]
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

func (s *Platform) RefreshCerts(ctx context.Context, certsCache *certscache.ProxyCertsCache) error {
	return nil
}

func (s *Platform) NameSanitize(name string) string {
	return name
}

func (s *Platform) HandleFedAppInstCb(ctx context.Context, msg *edgeproto.FedAppInstEvent) {}

func (s *Platform) GetResources() *fakecommon.Resources {
	return &s.resources
}

func (s *Platform) SetSimulateAppCreateFailure(state bool) {
	s.simulateAppCreateFailure = state
}

func (s *Platform) SetSimulateAppDeleteFailure(state bool) {
	s.simulateAppDeleteFailure = state
}

func (s *Platform) SetSimulateClusterCreateFailure(state bool) {
	s.simulateClusterCreateFailure = state
}

func (s *Platform) SetSimulateClusterDeleteFailure(state bool) {
	s.simulateClusterDeleteFailure = state
}

// SetPause pauses responder until unpaused.
// Warning: don't double-pause or double-unpause.
func (s *Platform) SetPause(enable bool) {
	if enable {
		s.pause.Add(1)
	} else {
		s.pause.Done()
	}
}

func (s *Platform) GetCloudletManagedClusters(ctx context.Context) ([]*edgeproto.CloudletManagedCluster, error) {
	return s.cloudletManagedClusters, nil
}

func (s *Platform) GetCloudletManagedClusterInfo(ctx context.Context, in *edgeproto.ClusterInst) (*edgeproto.CloudletManagedClusterInfo, error) {
	for _, cmc := range s.cloudletManagedClusters {
		if cmc.Key.Id == in.CloudletManagedClusterId || cmc.Key.Name == in.CloudletManagedClusterName {
			return &edgeproto.CloudletManagedClusterInfo{
				KubernetesVersion: "1.31",
				NodePools: []*edgeproto.NodePool{{
					Name:     "cpupool",
					NumNodes: 2,
					NodeResources: &edgeproto.NodeResources{
						Vcpus: 2,
						Ram:   4096,
						Disk:  20,
					},
				}},
			}, nil
		}
	}
	return nil, errors.New("cloudlet managed cluster not found")
}
