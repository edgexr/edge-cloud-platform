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

package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/util/tasks"
	"github.com/gogo/protobuf/types"
	"github.com/oklog/ulid/v2"
	"github.com/opentracing/opentracing-go"
	"go.etcd.io/etcd/client/v3/concurrency"
	"google.golang.org/grpc"
)

type ClusterInstApi struct {
	all            *AllApis
	sync           *regiondata.Sync
	store          edgeproto.ClusterInstStore
	dnsLabelStore  *edgeproto.CloudletObjectDnsLabelStore
	cache          edgeproto.ClusterInstCache
	cleanupWorkers tasks.KeyWorkers
}

var ObjBusyDeletionMsg = "busy, cannot be deleted"
var ActionInProgressMsg = "action is already in progress"

// Transition states indicate states in which the CRM is still busy.
var CreateClusterInstTransitions = map[edgeproto.TrackedState]struct{}{
	edgeproto.TrackedState_CREATING: struct{}{},
}
var UpdateClusterInstTransitions = map[edgeproto.TrackedState]struct{}{
	edgeproto.TrackedState_UPDATING: struct{}{},
}
var DeleteClusterInstTransitions = map[edgeproto.TrackedState]struct{}{
	edgeproto.TrackedState_DELETING: struct{}{},
}

type GenerateResourceAlerts int

const (
	NoGenResourceAlerts = 0
	GenResourceAlerts   = 1
)

func NewClusterInstApi(sync *regiondata.Sync, all *AllApis) *ClusterInstApi {
	clusterInstApi := ClusterInstApi{}
	clusterInstApi.all = all
	clusterInstApi.sync = sync
	clusterInstApi.store = edgeproto.NewClusterInstStore(sync.GetKVStore())
	clusterInstApi.dnsLabelStore = &all.cloudletApi.objectDnsLabelStore
	edgeproto.InitClusterInstCache(&clusterInstApi.cache)
	sync.RegisterCache(&clusterInstApi.cache)
	clusterInstApi.cleanupWorkers.Init("ClusterInst-cleanup", clusterInstApi.cleanupClusterInst)
	return &clusterInstApi
}

func (s *ClusterInstApi) HasKey(key *edgeproto.ClusterKey) bool {
	return s.cache.HasKey(key)
}

func (s *ClusterInstApi) Get(key *edgeproto.ClusterKey, buf *edgeproto.ClusterInst) bool {
	return s.cache.Get(key, buf)
}

func (s *ClusterInstApi) UsesFlavor(key *edgeproto.FlavorKey) *edgeproto.ClusterKey {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for k, data := range s.cache.Objs {
		cluster := data.Obj
		if cluster.Flavor.Matches(key) {
			return &k
		}
	}
	return nil
}

func (s *ClusterInstApi) UsesAutoScalePolicy(key *edgeproto.PolicyKey) *edgeproto.ClusterKey {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for k, data := range s.cache.Objs {
		cluster := data.Obj
		if cluster.AutoScalePolicy == key.Name {
			return &k
		}
	}
	return nil
}

func (s *ClusterInstApi) deleteCloudletOk(stm concurrency.STM, refs *edgeproto.CloudletRefs, dynInsts map[edgeproto.ClusterKey]struct{}) error {
	for _, clusterKey := range refs.ClusterInsts {
		ci := edgeproto.ClusterInst{}
		if !s.all.clusterInstApi.store.STMGet(stm, &clusterKey, &ci) {
			continue
		}
		if ci.Reservable && ci.Auto && ci.ReservedBy == "" {
			// auto-delete unused reservable autoclusters
			// since they are created automatically by
			// the system.
			dynInsts[ci.Key] = struct{}{}
			continue
		}
		if ci.Key.Matches(cloudcommon.GetDefaultMTClustKey(refs.Key)) {
			// delete default multi-tenant cluster
			dynInsts[ci.Key] = struct{}{}
			continue
		}

		// report usage of reservable ClusterInst by the reservation owner.
		if ci.Reservable && ci.ReservedBy != "" {
			return fmt.Errorf("Cloudlet in use by ClusterInst name %s, reserved by Organization %s", clusterKey.Name, ci.ReservedBy)
		}
		return fmt.Errorf("Cloudlet in use by ClusterInst name %s Organization %s", clusterKey.Name, clusterKey.Organization)
	}
	return nil
}

func (s *ClusterInstApi) UsesNetwork(networkKey *edgeproto.NetworkKey) *edgeproto.ClusterKey {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for k, data := range s.cache.Objs {
		val := data.Obj
		if val.CloudletKey == networkKey.CloudletKey {
			for _, n := range val.Networks {
				if n == networkKey.Name {
					return &k
				}
			}
		}
	}
	return nil
}

// validateAndDefaultIPAccess checks that the IP access type is valid if it is set.  If it is not set
// it returns the new value based on the other parameters
func validateAndDefaultIPAccess(ctx context.Context, clusterInst *edgeproto.ClusterInst, platformType string, features *edgeproto.PlatformFeatures, cb edgeproto.ClusterInstApi_CreateClusterInstServer) (edgeproto.IpAccess, error) {

	platName := platformType

	// Operators such as GCP and Azure must be dedicated as they allocate a new IP per service
	if isIPAllocatedPerService(ctx, platformType, features, clusterInst.CloudletKey.Organization) {
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_UNKNOWN {
			cb.Send(&edgeproto.Result{Message: "Defaulting IpAccess to IpAccessDedicated for platform: " + platName})
			return edgeproto.IpAccess_IP_ACCESS_DEDICATED, nil
		}
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_SHARED {
			return clusterInst.IpAccess, fmt.Errorf("IpAccessShared not supported for platform: %s", platName)
		}
		return clusterInst.IpAccess, nil
	}
	if features.CloudletServicesLocal && !features.IsFake {
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_UNKNOWN {
			cb.Send(&edgeproto.Result{Message: "Defaulting IpAccess to IpAccessShared for platform " + platName})
			return edgeproto.IpAccess_IP_ACCESS_SHARED, nil
		}
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			return clusterInst.IpAccess, fmt.Errorf("IpAccessDedicated not supported platform: %s", platformType)
		}
	}
	switch clusterInst.Deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.DeploymentTypeHelm:
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_UNKNOWN {
			cb.Send(&edgeproto.Result{Message: "Defaulting IpAccess to IpAccessShared for deployment " + clusterInst.Deployment})
			return edgeproto.IpAccess_IP_ACCESS_SHARED, nil
		}
		return clusterInst.IpAccess, nil
	case cloudcommon.DeploymentTypeDocker:
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_UNKNOWN {
			cb.Send(&edgeproto.Result{Message: "Defaulting IpAccess to IpAccessDedicated for deployment " + clusterInst.Deployment})
			return edgeproto.IpAccess_IP_ACCESS_SHARED, nil
		}
	}
	return clusterInst.IpAccess, nil
}

func (s *ClusterInstApi) startClusterInstStream(ctx context.Context, cctx *CallContext, streamCb *CbWrapper, modRev int64) (*streamSend, error) {
	streamSendObj, err := s.all.streamObjApi.startStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to start ClusterInst stream", "err", err)
		return nil, err
	}
	return streamSendObj, err
}

func (s *ClusterInstApi) stopClusterInstStream(ctx context.Context, cctx *CallContext, key *edgeproto.ClusterKey, streamSendObj *streamSend, objErr error, cleanupStream CleanupStreamAction) {
	if err := s.all.streamObjApi.stopStream(ctx, cctx, key.StreamKey(), streamSendObj, objErr, cleanupStream); err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to stop ClusterInst stream", "err", err)
	}
}

func (s *StreamObjApi) StreamClusterInst(key *edgeproto.ClusterKey, cb edgeproto.StreamObjApi_StreamClusterInstServer) error {
	return s.StreamMsgs(cb.Context(), key.StreamKey(), cb)
}

func (s *ClusterInstApi) CreateClusterInst(in *edgeproto.ClusterInst, cb edgeproto.ClusterInstApi_CreateClusterInstServer) error {
	in.Auto = false
	if strings.HasPrefix(in.Key.Name, cloudcommon.ReservableClusterPrefix) {
		// User cannot specify a cluster name that will conflict with
		// reservable cluster names.
		return fmt.Errorf("Invalid cluster name, prefix %q is reserved for internal use", cloudcommon.ReservableClusterPrefix)
	}
	if strings.HasPrefix(in.Key.Name, cloudcommon.DefaultClust) {
		return fmt.Errorf("Invalid cluster name, %s is reserved for internal use", cloudcommon.DefaultClust)
	}
	return s.createClusterInstInternal(DefCallContext(), in, cb)
}

// Validate resource requirements for the VMs on the cloudlet
func (s *ClusterInstApi) validateCloudletInfraResources(ctx context.Context, stm concurrency.STM, cloudlet *edgeproto.Cloudlet, infraResources *edgeproto.InfraResourcesSnapshot, allClusterResources, reqdVmResources []edgeproto.VMResource) ([]string, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "Validate cloudlet resources", "vm resources", reqdVmResources, "cloudlet resources", infraResources)

	infraResInfo := make(map[string]edgeproto.InfraResource)
	for _, resInfo := range infraResources.Info {
		infraResInfo[resInfo.Name] = resInfo
	}
	log.SpanLog(ctx, log.DebugLevelApi, "infra reported resources", "resources", infraResInfo)

	reqdResInfo, err := s.all.cloudletApi.GetCloudletResourceInfo(ctx, stm, cloudlet, reqdVmResources, infraResInfo)
	if err != nil {
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "calculated required resources", "resources", reqdResInfo)

	allResInfo, err := s.all.cloudletApi.GetCloudletResourceInfo(ctx, stm, cloudlet, allClusterResources, infraResInfo)
	if err != nil {
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "calculated all resources", "resources", allResInfo)

	warnings := []string{}

	// Theoretical Validation
	errsStr := []string{}
	for resName, resInfo := range allResInfo {
		max := resInfo.QuotaMaxValue
		if max == 0 {
			max = resInfo.InfraMaxValue
		}
		if max == 0 {
			// no validation can be done
			continue
		}
		resReqd, ok := reqdResInfo[resName]
		if !ok {
			// this resource is not tracked by controller, skip it
			continue
		}
		if resInfo.QuotaMaxValue > 0 && resInfo.InfraMaxValue > 0 {
			if resInfo.QuotaMaxValue > resInfo.InfraMaxValue {
				warnings = append(warnings, fmt.Sprintf("[Quota] Invalid quota set for %s, quota max value %d is more than infra max value %d", resName, resInfo.QuotaMaxValue, resInfo.InfraMaxValue))
			}
		}
		thAvailableResVal := uint64(0)
		if resInfo.Value > max {
			warnings = append(warnings, fmt.Sprintf("[Quota] Invalid quota set for %s, quota max value %d is less than used resource value %d", resName, max, resInfo.Value))
		} else {
			thAvailableResVal = max - resInfo.Value
		}
		if float64(resInfo.Value*100)/float64(max) > float64(resInfo.AlertThreshold) {
			warnings = append(warnings, fmt.Sprintf("More than %d%% of %s is used by the cloudlet", resInfo.AlertThreshold, resName))
		}
		if resReqd.Value > thAvailableResVal {
			errsStr = append(errsStr, fmt.Sprintf("required %s is %d%s but only %d%s out of %d%s is available", resName, resReqd.Value, resInfo.Units, thAvailableResVal, resInfo.Units, max, resInfo.Units))
		}
	}

	err = nil
	if len(errsStr) > 0 {
		errsOut := strings.Join(errsStr, ", ")
		err = fmt.Errorf("Not enough resources available: %s", errsOut)
	}
	if err != nil {
		return warnings, err
	}

	resQuotasInfo := make(map[string]edgeproto.InfraResource)
	for _, resQuota := range cloudlet.ResourceQuotas {
		resQuotasInfo[resQuota.Name] = edgeproto.InfraResource{
			Name:           resQuota.Name,
			Value:          resQuota.Value,
			AlertThreshold: resQuota.AlertThreshold,
		}
	}

	// Infra based validation
	errsStr = []string{}
	for resName, resInfo := range infraResInfo {
		if resInfo.InfraMaxValue == 0 {
			// no validation can be done
			continue
		}
		resInfo.AlertThreshold = cloudlet.DefaultResourceAlertThreshold
		if quota, ok := resQuotasInfo[resInfo.Name]; ok {
			if quota.AlertThreshold > 0 {
				resInfo.AlertThreshold = quota.AlertThreshold
			}
		}
		resReqd, ok := reqdResInfo[resName]
		if !ok {
			// this resource is not tracked by controller, skip it
			continue
		}
		infraAvailableResVal := resInfo.InfraMaxValue - resInfo.Value
		if float64(resInfo.Value*100)/float64(resInfo.InfraMaxValue) > float64(resInfo.AlertThreshold) {
			warnings = append(warnings, fmt.Sprintf("More than %d%% of %s is used on the infra managed by the cloudlet", resInfo.AlertThreshold, resName))
		}
		if resReqd.Value > infraAvailableResVal {
			errsStr = append(errsStr, fmt.Sprintf("required %s is %d%s but only %d%s out of %d%s is available", resName, resReqd.Value, resInfo.Units, infraAvailableResVal, resInfo.Units, resInfo.InfraMaxValue, resInfo.Units))
		}
	}
	err = nil
	if len(errsStr) > 0 {
		errsOut := strings.Join(errsStr, ", ")
		err = fmt.Errorf("[Infra] Not enough resources available: %s", errsOut)
	}

	return warnings, err
}

// getClusterFlavorInfo returns nodeFlavorInfo, masterNodeFlavorInfo.  It first looks at platform flavors and if not found there gets it from
// the cache
func (s *ClusterInstApi) getClusterFlavorInfo(ctx context.Context, stm concurrency.STM, pfFlavorList []*edgeproto.FlavorInfo, clusterInst *edgeproto.ClusterInst) (*edgeproto.FlavorInfo, *edgeproto.FlavorInfo, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "getClusterFlavorInfo", "clusterinst", clusterInst)

	var nodeFlavorInfo *edgeproto.FlavorInfo
	var masterFlavorInfo *edgeproto.FlavorInfo

	for _, flavor := range pfFlavorList {
		if flavor.Name == clusterInst.NodeFlavor {
			nodeFlavorInfo = flavor
			log.SpanLog(ctx, log.DebugLevelApi, "found node flavor from platform list", "nodeFlavor", nodeFlavorInfo.Name)
		}
		if flavor.Name == clusterInst.MasterNodeFlavor {
			masterFlavorInfo = flavor
			log.SpanLog(ctx, log.DebugLevelApi, "found master flavor from platform list", "masterFlavorInfo", masterFlavorInfo.Name)

		}
	}
	if nodeFlavorInfo == nil {
		// get from stm
		nodeFlavor := edgeproto.Flavor{}
		nodeFlavorKey := edgeproto.FlavorKey{}
		nodeFlavorKey.Name = clusterInst.NodeFlavor
		if !s.all.flavorApi.store.STMGet(stm, &nodeFlavorKey, &nodeFlavor) {
			return nil, nil, fmt.Errorf("node flavor %s not found", clusterInst.MasterNodeFlavor)
		}
		nodeFlavorInfo = &edgeproto.FlavorInfo{
			Name:  nodeFlavor.Key.Name,
			Vcpus: nodeFlavor.Vcpus,
			Ram:   nodeFlavor.Ram,
			Disk:  nodeFlavor.Disk,
		}
	}
	if masterFlavorInfo == nil {
		if clusterInst.MasterNodeFlavor == "" {
			// use node flavor
			masterFlavorInfo = nodeFlavorInfo
		} else {
			// get from stm
			masterNodeFlavor := edgeproto.Flavor{}
			masterNodeFlavorKey := edgeproto.FlavorKey{}
			masterNodeFlavorKey.Name = clusterInst.MasterNodeFlavor
			if !s.all.flavorApi.store.STMGet(stm, &masterNodeFlavorKey, &masterNodeFlavor) {
				return nil, nil, fmt.Errorf("master node flavor %s not found", clusterInst.MasterNodeFlavor)
			}
			masterFlavorInfo = &edgeproto.FlavorInfo{
				Name:  masterNodeFlavor.Key.Name,
				Vcpus: masterNodeFlavor.Vcpus,
				Ram:   masterNodeFlavor.Ram,
				Disk:  masterNodeFlavor.Disk,
			}
		}
	}
	return nodeFlavorInfo, masterFlavorInfo, nil
}

func (s *ClusterInstApi) GetRootLBFlavorInfo(ctx context.Context, stm concurrency.STM, cloudlet *edgeproto.Cloudlet, cloudletInfo *edgeproto.CloudletInfo) (*edgeproto.FlavorInfo, error) {
	features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
	if err != nil {
		return nil, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, s.all.settingsApi.Get().CcrmApiTimeout.TimeDuration())
	defer cancel()
	conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewCloudletPlatformAPIClient(conn)
	rootlbFlavor, err := api.GetRootLbFlavor(reqCtx, &cloudlet.Key)
	if err != nil {
		return nil, cloudcommon.GRPCErrorUnwrap(err)
	}
	lbFlavor := &edgeproto.FlavorInfo{}
	if rootlbFlavor != nil {
		vmspec, err := s.all.resTagTableApi.GetVMSpec(ctx, stm, *rootlbFlavor, "", *cloudlet, *cloudletInfo)
		if err != nil {
			return nil, err
		}
		lbFlavor = vmspec.FlavorInfo
	}
	return lbFlavor, nil
}

// getAllCloudletResources
// Returns all the VM resources on the cloudlet
func (s *ClusterInstApi) getAllCloudletResources(ctx context.Context, stm concurrency.STM, cloudlet *edgeproto.Cloudlet, cloudletInfo *edgeproto.CloudletInfo, cloudletRefs *edgeproto.CloudletRefs) ([]edgeproto.VMResource, error) {
	allVmResources := []edgeproto.VMResource{}

	// Historical note: We removed the diff calculation between etcd reported
	// AppInsts/ClusterInsts vs CRM reported AppInsts/ClusterInsts
	// (from CRM's info caches). It did not seem useful, given:
	// 1. What's in the CRM info cache doesn't necessarily equate to what's
	// on the infra. What's in the controller etcd db is just as accurate a
	// measure. In any case the info caches are supposed to be in sync
	// with the object db in etcd.
	// 2. The info caches on the CRM are ephemeral - if the CRM restarts, all
	// that data is cleared until a request for an appInst/clusterInst comes
	// in from the controller.
	// 3. This resource calculation becomes wrong if old data from the
	// CRM's info caches, or old data in the cloudletInfo.ResourcesSnapshot
	// is not removed in a timely manner. It then over calculates the used
	// resources.

	// get all cloudlet resources (platformVM, sharedRootLB, etc)
	cloudletRes, err := GetPlatformVMsResources(ctx, cloudletInfo)
	if err != nil {
		return nil, err
	}
	allVmResources = append(allVmResources, cloudletRes...)

	lbFlavor, err := s.GetRootLBFlavorInfo(ctx, stm, cloudlet, cloudletInfo)
	if err != nil {
		return nil, err
	}

	// get all cluster resources (clusterVM, dedicatedRootLB, etc)
	clusterKeys := cloudletRefs.ClusterInsts
	ctrlClusters := make(map[edgeproto.ClusterKey]struct{})
	for _, clusterKey := range clusterKeys {
		ci := edgeproto.ClusterInst{}
		if !s.all.clusterInstApi.store.STMGet(stm, &clusterKey, &ci) {
			continue
		}
		ctrlClusters[clusterKey] = struct{}{}
		// Ignore state and consider all clusterInsts present in DB
		// We are being conservative here. If clusterInst exists in DB, then we should
		// assume it's taking up resources, or going to take up resources (CreateRequested),
		// or may not actually be able to free up resources yet (DeleteRequested, etc)
		nodeFlavorInfo, masterFlavorInfo, err := s.getClusterFlavorInfo(ctx, stm, cloudletInfo.Flavors, &ci)
		if err != nil {
			return nil, err
		}
		features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
		if err != nil {
			return nil, fmt.Errorf("Failed to get features for platform: %s", err)
		}
		isManagedK8s := false
		if features.KubernetesRequiresWorkerNodes {
			isManagedK8s = true
		}
		ciRes, err := cloudcommon.GetClusterInstVMRequirements(ctx, &ci, nodeFlavorInfo, masterFlavorInfo, lbFlavor, isManagedK8s)
		if err != nil {
			return nil, err
		}
		allVmResources = append(allVmResources, ciRes...)
	}
	// get all VM app inst resources
	ctrlVmAppInsts := make(map[edgeproto.AppInstKey]struct{})
	for _, appInstKey := range cloudletRefs.VmAppInsts {
		appInst := edgeproto.AppInst{}
		if !s.all.appInstApi.store.STMGet(stm, &appInstKey, &appInst) {
			continue
		}
		ctrlVmAppInsts[appInstKey] = struct{}{}
		// Ignore state and consider all VMAppInsts present in DB
		// We are being conservative here. If VMAppInst exists in DB, then we should
		// assume it's taking up resources, or going to take up resources (CreateRequested),
		// or may not actually be able to free up resources yet (DeleteRequested, etc)
		app := edgeproto.App{}
		if !s.all.appApi.store.STMGet(stm, &appInst.AppKey, &app) {
			return nil, fmt.Errorf("App not found: %v", appInst.AppKey)
		}
		vmRes, err := cloudcommon.GetVMAppRequirements(ctx, &app, &appInst, cloudletInfo.Flavors, lbFlavor)
		if err != nil {
			return nil, err
		}
		allVmResources = append(allVmResources, vmRes...)
	}
	// get all K8s app inst resources
	ctrlK8sAppInsts := make(map[edgeproto.AppInstKey]struct{})
	for _, appInstKey := range cloudletRefs.K8SAppInsts {
		appInst := edgeproto.AppInst{}
		if !s.all.appInstApi.store.STMGet(stm, &appInstKey, &appInst) {
			continue
		}
		ctrlK8sAppInsts[appInstKey] = struct{}{}
		// Ignore state and consider all K8sAppInsts present in DB
		// We are being conservative here. If K8sAppInst exists in DB, then we should
		// assume it's taking up resources, or going to take up resources (CreateRequested),
		// or may not actually be able to free up resources yet (DeleteRequested, etc)
		app := edgeproto.App{}
		if !s.all.appApi.store.STMGet(stm, &appInst.AppKey, &app) {
			return nil, fmt.Errorf("App not found: %v", appInst.AppKey)
		}
		k8sRes, err := cloudcommon.GetK8sAppRequirements(ctx, &app)
		if err != nil {
			return nil, err
		}
		allVmResources = append(allVmResources, k8sRes...)
	}
	log.SpanLog(ctx, log.DebugLevelApi, "GetAllCloudletResources", "key", cloudlet.Key,
		"allVMResources", allVmResources)
	return allVmResources, nil
}

func (s *ClusterInstApi) handleResourceUsageAlerts(ctx context.Context, stm concurrency.STM, key *edgeproto.CloudletKey, warnings []string) {
	alerts := cloudcommon.CloudletResourceUsageAlerts(ctx, key, warnings)
	staleAlerts := make(map[edgeproto.AlertKey]struct{})
	s.all.alertApi.cache.GetAllKeys(ctx, func(k *edgeproto.AlertKey, modRev int64) {
		staleAlerts[*k] = struct{}{}
	})
	for _, alert := range alerts {
		s.all.alertApi.setAlertMetadata(&alert)
		s.all.alertApi.store.STMPut(stm, &alert)
		delete(staleAlerts, alert.GetKeyVal())
	}
	delAlert := edgeproto.Alert{}
	for alertKey, _ := range staleAlerts {
		edgeproto.AlertKeyStringParse(string(alertKey), &delAlert)
		if alertName, found := delAlert.Labels["alertname"]; !found ||
			alertName != cloudcommon.AlertCloudletResourceUsage {
			continue
		}
		if cloudletName, found := delAlert.Labels[edgeproto.CloudletKeyTagName]; !found ||
			cloudletName != key.Name {
			continue
		}
		if cloudletOrg, found := delAlert.Labels[edgeproto.CloudletKeyTagOrganization]; !found ||
			cloudletOrg != key.Organization {
			continue
		}
		s.all.alertApi.store.STMDel(stm, &alertKey)
	}
}

func (s *ClusterInstApi) validateResources(ctx context.Context, stm concurrency.STM, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, cloudlet *edgeproto.Cloudlet, cloudletInfo *edgeproto.CloudletInfo, cloudletRefs *edgeproto.CloudletRefs, genAlerts GenerateResourceAlerts) error {
	log.SpanLog(ctx, log.DebugLevelApi, "validate resources", "cloudlet", cloudlet.Key, "clusterinst", clusterInst, "appinst", appInst, "app", app)
	lbFlavor, err := s.GetRootLBFlavorInfo(ctx, stm, cloudlet, cloudletInfo)
	if err != nil {
		return err
	}
	reqdVmResources := []edgeproto.VMResource{}
	if clusterInst != nil {
		nodeFlavorInfo, masterFlavorInfo, err := s.getClusterFlavorInfo(ctx, stm, cloudletInfo.Flavors, clusterInst)
		if err != nil {
			return err
		}
		features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
		if err != nil {
			return fmt.Errorf("Failed to get features for platform: %s", err)
		}
		isManagedK8s := false
		if features.KubernetesRequiresWorkerNodes {
			isManagedK8s = true
		}
		ciResources, err := cloudcommon.GetClusterInstVMRequirements(ctx, clusterInst, nodeFlavorInfo, masterFlavorInfo, lbFlavor, isManagedK8s)
		if err != nil {
			return err
		}
		reqdVmResources = append(reqdVmResources, ciResources...)
	}
	if appInst != nil {
		if app == nil {
			return fmt.Errorf("valid app required with appInst")
		}
		if app.Deployment == cloudcommon.DeploymentTypeVM {
			// appinst_api usage has app, use it here
			appResources, err := cloudcommon.GetVMAppRequirements(ctx, app, appInst, cloudletInfo.Flavors, lbFlavor)
			if err != nil {
				return err
			}
			reqdVmResources = append(reqdVmResources, appResources...)
		}
	}
	if app != nil && (app.Deployment == cloudcommon.DeploymentTypeKubernetes ||
		app.Deployment == cloudcommon.DeploymentTypeHelm) {
		appResources, err := cloudcommon.GetK8sAppRequirements(ctx, app)
		if err != nil {
			return err
		}
		reqdVmResources = append(reqdVmResources, appResources...)
	}

	// get all cloudlet resources (platformVM, sharedRootLB, clusterVms, AppVMs, etc)
	allVmResources, err := s.getAllCloudletResources(ctx, stm, cloudlet, cloudletInfo, cloudletRefs)
	if err != nil {
		return err
	}

	warnings, err := s.validateCloudletInfraResources(ctx, stm, cloudlet, &cloudletInfo.ResourcesSnapshot, allVmResources, reqdVmResources)
	if err != nil {
		return err
	}
	if genAlerts == GenResourceAlerts {
		// generate alerts for these warnings
		// clear off those alerts which are no longer firing
		s.handleResourceUsageAlerts(ctx, stm, &cloudlet.Key, warnings)
	}
	return nil
}

func (s *ClusterInstApi) getCloudletResourceMetric(ctx context.Context, stm concurrency.STM, key *edgeproto.CloudletKey) ([]*edgeproto.Metric, error) {
	cloudlet := edgeproto.Cloudlet{}
	if !s.all.cloudletApi.store.STMGet(stm, key, &cloudlet) {
		return nil, fmt.Errorf("Cloudlet not found: %v", key)
	}
	cloudletInfo := edgeproto.CloudletInfo{}
	if !s.all.cloudletInfoApi.store.STMGet(stm, key, &cloudletInfo) {
		return nil, fmt.Errorf("CloudletInfo not found: %v", key)
	}
	cloudletRefs := edgeproto.CloudletRefs{}
	s.all.cloudletRefsApi.store.STMGet(stm, key, &cloudletRefs)
	features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
	if err != nil {
		return nil, err
	}
	pfType := cloudlet.PlatformType

	// get all cloudlet resources (platformVM, sharedRootLB, clusterVms, AppVMs, etc)
	allResources, err := s.all.clusterInstApi.getAllCloudletResources(ctx, stm, &cloudlet, &cloudletInfo, &cloudletRefs)
	if err != nil {
		return nil, err
	}

	ramUsed := uint64(0)
	vcpusUsed := uint64(0)
	gpusUsed := uint64(0)
	externalIPsUsed := uint64(0)
	flavorCount := make(map[string]uint64)
	for _, vmRes := range allResources {
		if vmRes.VmFlavor != nil {
			ramUsed += vmRes.VmFlavor.Ram
			vcpusUsed += vmRes.VmFlavor.Vcpus
			if s.all.resTagTableApi.UsesGpu(ctx, stm, *vmRes.VmFlavor, cloudlet) {
				gpusUsed += 1
			}
			if _, ok := flavorCount[vmRes.VmFlavor.Name]; ok {
				flavorCount[vmRes.VmFlavor.Name] += 1
			} else {
				flavorCount[vmRes.VmFlavor.Name] = 1
			}
		}
		if cloudcommon.IsLBNode(vmRes.Type) || cloudcommon.IsPlatformNode(vmRes.Type) {
			externalIPsUsed += 1
		}
	}

	resMetric := edgeproto.Metric{}
	ts, _ := types.TimestampProto(time.Now())
	resMetric.Timestamp = *ts
	resMetric.Name = cloudcommon.GetCloudletResourceUsageMeasurement(pfType)
	resMetric.AddTag("cloudletorg", key.Organization)
	resMetric.AddTag("cloudlet", key.Name)
	resMetric.AddIntVal(cloudcommon.ResourceMetricRamMB, ramUsed)
	resMetric.AddIntVal(cloudcommon.ResourceMetricVcpus, vcpusUsed)
	resMetric.AddIntVal(cloudcommon.ResourceMetricGpus, gpusUsed)
	resMetric.AddIntVal(cloudcommon.ResourceMetricExternalIPs, externalIPsUsed)

	// get additional infra specific metric
	reqCtx, cancel := context.WithTimeout(ctx, s.all.settingsApi.Get().CcrmApiTimeout.TimeDuration())
	defer cancel()
	conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewCloudletPlatformAPIClient(conn)
	req := edgeproto.ClusterResourceMetricReq{
		CloudletKey: &cloudlet.Key,
		ResMetric:   &resMetric,
		VmResources: allResources,
	}
	resMetricOut, err := api.GetClusterAdditionalResourceMetric(reqCtx, &req)
	if err != nil {
		return nil, cloudcommon.GRPCErrorUnwrap(err)
	}
	resMetric = *resMetricOut

	metrics := []*edgeproto.Metric{}
	metrics = append(metrics, &resMetric)

	for fName, fCount := range flavorCount {
		flavorMetric := edgeproto.Metric{}
		flavorMetric.Name = cloudcommon.CloudletFlavorUsageMeasurement
		flavorMetric.Timestamp = *ts
		flavorMetric.AddTag("cloudletorg", cloudlet.Key.Organization)
		flavorMetric.AddTag("cloudlet", cloudlet.Key.Name)
		flavorMetric.AddTag("flavor", fName)
		flavorMetric.AddIntVal("count", fCount)
		metrics = append(metrics, &flavorMetric)
	}
	return metrics, nil
}

// createClusterInstInternal is used to create dynamic cluster insts internally,
// bypassing static assignment. It is also used to create auto-cluster insts.
func (s *ClusterInstApi) createClusterInstInternal(cctx *CallContext, in *edgeproto.ClusterInst, inCb edgeproto.ClusterInstApi_CreateClusterInstServer) (reterr error) {
	cctx.SetOverride(&in.CrmOverride)
	if err := in.Key.ValidateKey(); err != nil {
		return err
	}

	ctx := inCb.Context()

	clusterKey := in.Key
	var err error
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, clusterKey.StreamKey(), inCb)

	if in.Key.Organization == "" {
		return fmt.Errorf("ClusterInst Organization cannot be empty")
	}
	if in.CloudletKey.Name == "" {
		// internal tools, or undo may specify the cloudlet key.
		// otherwise the zone must be specified.
		if in.ZoneKey.Name == "" {
			return fmt.Errorf("zone name must be specified")
		}
		if in.ZoneKey.Organization == "" {
			return fmt.Errorf("zone organization must be specified")
		}
	}
	if in.Key.Name == "" {
		return fmt.Errorf("Cluster name cannot be empty")
	}
	if in.Reservable && !edgeproto.IsEdgeCloudOrg(in.Key.Organization) {
		return fmt.Errorf("Only %s ClusterInsts may be reservable", edgeproto.OrganizationEdgeCloud)
	}
	if in.Reservable {
		in.ReservationEndedAt = dme.TimeToTimestamp(time.Now())
	}
	if in.MultiTenant && !edgeproto.IsEdgeCloudOrg(in.Key.Organization) {
		return fmt.Errorf("Only %s ClusterInsts may be multi-tenant", edgeproto.OrganizationEdgeCloud)
	}

	// validate deployment
	if in.Deployment == "" {
		// assume kubernetes, because that's what we've been doing
		in.Deployment = cloudcommon.DeploymentTypeKubernetes
	}
	if in.Deployment == cloudcommon.DeploymentTypeHelm {
		// helm runs on kubernetes
		in.Deployment = cloudcommon.DeploymentTypeKubernetes
	}
	if in.Deployment == cloudcommon.DeploymentTypeVM {
		// friendly error message if they try to specify VM
		return fmt.Errorf("ClusterInst is not needed for deployment type %s, just create an AppInst directly", cloudcommon.DeploymentTypeVM)
	}
	if in.MultiTenant && in.Deployment != cloudcommon.DeploymentTypeKubernetes {
		return fmt.Errorf("Multi-tenant clusters must be of deployment type Kubernetes")
	}

	// validate other parameters based on deployment type
	if in.Deployment == cloudcommon.DeploymentTypeKubernetes {
		// must have at least one master, but currently don't support
		// more than one.
		if in.NumMasters == 0 {
			// just set it to 1
			in.NumMasters = 1
		}
		if in.NumMasters > 1 {
			return fmt.Errorf("NumMasters cannot be greater than 1")
		}
	} else if in.Deployment == cloudcommon.DeploymentTypeDocker {
		if in.NumMasters != 0 || in.NumNodes != 0 {
			return fmt.Errorf("NumMasters and NumNodes not applicable for deployment type %s", cloudcommon.DeploymentTypeDocker)
		}
		if in.SharedVolumeSize != 0 {
			return fmt.Errorf("SharedVolumeSize not supported for deployment type %s", cloudcommon.DeploymentTypeDocker)

		}
	} else {
		return fmt.Errorf("Invalid deployment type %s for ClusterInst", in.Deployment)
	}

	// dedicatedOrShared(2) is removed
	if in.IpAccess == 2 {
		in.IpAccess = edgeproto.IpAccess_IP_ACCESS_UNKNOWN
	}
	in.CompatibilityVersion = cloudcommon.GetClusterInstCompatibilityVersion()

	// STM ends up modifying input data, but we need to reset those
	// changes if STM reruns, because it may end up choosing a different
	// cloudlet.
	inCopy := edgeproto.ClusterInst{}
	inCopy.DeepCopyIn(in)

	nodeType := ""
	crmOnEdge := false
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		// reset input data if STM was rerun
		in.DeepCopyIn(&inCopy)

		if s.all.clusterInstApi.store.STMGet(stm, &in.Key, in) {
			if !cctx.Undo && in.State != edgeproto.TrackedState_DELETE_ERROR && !ignoreTransient(cctx, in.State) {
				if in.State == edgeproto.TrackedState_CREATE_ERROR {
					cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Previous create failed, %v", in.Errors)})
					cb.Send(&edgeproto.Result{Message: "Use DeleteClusterInst to remove and try again"})
				}
				return in.Key.ExistsError()
			}
			in.Errors = nil
		} else {
			err := in.Validate(edgeproto.ClusterInstAllFieldsMap)
			if err != nil {
				return err
			}
		}
		if in.Liveness == edgeproto.Liveness_LIVENESS_UNKNOWN {
			in.Liveness = edgeproto.Liveness_LIVENESS_STATIC
		}
		if len(in.Key.Name) > cloudcommon.MaxClusterNameLength {
			return fmt.Errorf("Cluster name limited to %d characters", cloudcommon.MaxClusterNameLength)
		}
		potentialCloudlets, err := s.getPotentialCloudlets(ctx, cctx, in)
		if err != nil {
			return err
		}
		sort.Sort(PotentialInstCloudletsByResource(potentialCloudlets))
		// TODO: if creating on the first cloudlet fails, we could walk the
		// list and try subsequent cloudlets. For now we just try on the first one.
		pc := potentialCloudlets[0]
		in.CloudletKey = pc.cloudlet.Key
		features := pc.features
		log.SpanLog(ctx, log.DebugLevelApi, "chose cloudlet with most available resources", "cloudlet", pc.cloudlet.Key)

		cloudlet := edgeproto.Cloudlet{}
		if !s.all.cloudletApi.store.STMGet(stm, &in.CloudletKey, &cloudlet) {
			return in.CloudletKey.NotFoundError()
		}
		if cloudlet.DeletePrepare {
			return in.CloudletKey.BeingDeletedError()
		}
		// set zone in case caller did not specify
		in.ZoneKey = *cloudlet.GetZone()

		nodeType = features.NodeType
		crmOnEdge = cloudlet.CrmOnEdge
		if in.EnableIpv6 && in.Deployment == cloudcommon.DeploymentTypeKubernetes {
			// TODO: need new base image, IPv6 podCIDR must be specified during
			// kubeadm init. Apparently no way to convert after init.
			return fmt.Errorf("no support for IPv6 on Kubernetes yet")
		}
		if !in.EnableIpv6 && in.Deployment != cloudcommon.DeploymentTypeKubernetes {
			// enable by default if supported
			in.EnableIpv6 = features.SupportsIpv6
		}
		if err := s.validateClusterInstUpdates(ctx, stm, in); err != nil {
			return err
		}
		info := edgeproto.CloudletInfo{}
		if !s.all.cloudletInfoApi.store.STMGet(stm, &in.CloudletKey, &info) {
			return fmt.Errorf("No resource information found for Cloudlet %s", in.CloudletKey)
		}

		refs := edgeproto.CloudletRefs{}
		if !s.all.cloudletRefsApi.store.STMGet(stm, &in.CloudletKey, &refs) {
			initCloudletRefs(&refs, &in.CloudletKey)
		}

		if in.Flavor.Name == "" {
			return errors.New("No Flavor specified")
		}
		platformFlavor := edgeproto.Flavor{}
		if !s.all.flavorApi.store.STMGet(stm, &in.Flavor, &platformFlavor) {
			return fmt.Errorf("flavor %s not found", in.Flavor.Name)
		}
		if platformFlavor.DeletePrepare {
			return in.Flavor.BeingDeletedError()
		}
		log.SpanLog(ctx, log.DebugLevelApi, "platformFlavor found find match", "platformFlavor", platformFlavor)
		vmspec, err := s.all.resTagTableApi.GetVMSpec(ctx, stm, platformFlavor, in.NodeFlavor, cloudlet, info)
		if err != nil {
			return err
		}
		in.OptRes = s.all.resTagTableApi.AddGpuResourceHintIfNeeded(ctx, stm, vmspec, cloudlet)
		if in.OptRes == "gpu" {
			if cloudlet.GpuConfig.Driver.Name == "" {
				return fmt.Errorf("No GPU driver associated with cloudlet %s", cloudlet.Key)
			}
		}
		in.NodeFlavor = vmspec.FlavorName
		in.AvailabilityZone = vmspec.AvailabilityZone
		in.ExternalVolumeSize = vmspec.ExternalVolumeSize
		log.SpanLog(ctx, log.DebugLevelApi, "Selected Cloudlet Node Flavor", "vmspec", vmspec, "master flavor", in.MasterNodeFlavor)

		// check if MasterNodeFlavor required
		if in.Deployment == cloudcommon.DeploymentTypeKubernetes {
			if in.NumNodes == 0 {
				// if numnodes is 0, then developer will run its application on master node.
				// Hence master node flavor should match user given flavor i.e. node flavor
				in.MasterNodeFlavor = in.NodeFlavor
			} else {
				masterFlavor := edgeproto.Flavor{}
				masterFlavorKey := edgeproto.FlavorKey{}
				settings := s.all.settingsApi.Get()
				masterFlavorKey.Name = settings.MasterNodeFlavor

				if s.all.flavorApi.store.STMGet(stm, &masterFlavorKey, &masterFlavor) {
					log.SpanLog(ctx, log.DebugLevelApi, "MasterNodeFlavor found ", "MasterNodeFlavor", settings.MasterNodeFlavor)
					vmspec, err := s.all.resTagTableApi.GetVMSpec(ctx, stm, masterFlavor, in.MasterNodeFlavor, cloudlet, info)
					if err != nil {
						// Unlikely with reasonably modest settings.MasterNodeFlavor sized flavor
						log.SpanLog(ctx, log.DebugLevelApi, "Error K8s Master Node Flavor matches no eixsting OS flavor", "nodeFlavor", in.NodeFlavor)
						return err
					} else {
						in.MasterNodeFlavor = vmspec.FlavorName
						log.SpanLog(ctx, log.DebugLevelApi, "Selected Cloudlet Master Node Flavor", "vmspec", vmspec, "master flavor", in.MasterNodeFlavor)
					}
				} else {
					// should never be non empty and not found due to validation in update
					// revert to using NodeFlavor (pre EC-1767) and log warning
					in.MasterNodeFlavor = in.NodeFlavor
					log.SpanLog(ctx, log.DebugLevelApi, "Warning : Master Node Flavor does not exist using", "master flavor", in.MasterNodeFlavor)
				}
			}
		}

		in.IpAccess, err = validateAndDefaultIPAccess(ctx, in, cloudlet.PlatformType, features, cb)
		if err != nil {
			return err
		}
		for _, n := range in.Networks {
			network := edgeproto.Network{}
			networkKey := edgeproto.NetworkKey{
				Name:        n,
				CloudletKey: in.CloudletKey,
			}
			if !s.all.networkApi.store.STMGet(stm, &networkKey, &network) {
				return networkKey.NotFoundError()
			}
			if network.DeletePrepare {
				return networkKey.BeingDeletedError()
			}
			if in.IpAccess == edgeproto.IpAccess_IP_ACCESS_SHARED {
				if network.ConnectionType == edgeproto.NetworkConnectionType_CONNECT_TO_LOAD_BALANCER || network.ConnectionType == edgeproto.NetworkConnectionType_CONNECT_TO_ALL {
					return fmt.Errorf("Cannot specify an additional cluster network of ConnectionType ConnectToLoadBalancer or ConnectToAll with IpAccessShared")
				}
			}
		}
		err = s.validateResources(ctx, stm, in, nil, nil, &cloudlet, &info, &refs, GenResourceAlerts)
		if err != nil {
			return err
		}
		err = allocateIP(ctx, in, &cloudlet, cloudlet.PlatformType, features, &refs)
		if err != nil {
			return err
		}
		refs.ClusterInsts = append(refs.ClusterInsts, in.Key)
		s.all.cloudletRefsApi.store.STMPut(stm, &refs)

		if err := s.setDnsLabel(stm, in); err != nil {
			return err
		}
		in.Fqdn = getClusterInstFQDN(in, &cloudlet)
		in.StaticFqdn = in.Fqdn

		in.CreatedAt = dme.TimeToTimestamp(time.Now())
		in.ObjId = ulid.Make().String()

		if ignoreCRM(cctx) {
			in.State = edgeproto.TrackedState_READY
		} else {
			in.State = edgeproto.TrackedState_CREATE_REQUESTED
		}
		s.store.STMPut(stm, in)
		s.dnsLabelStore.STMPut(stm, &in.CloudletKey, in.DnsLabel)
		return nil
	})
	if err != nil {
		return err
	}

	sendObj, err := s.startClusterInstStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		return err
	}
	defer func() {
		cleanupStream := NoCleanupStream
		if reterr != nil {
			// Cleanup stream if object is not present in etcd (due to undo)
			if !s.store.Get(ctx, &in.Key, nil) {
				cleanupStream = CleanupStream
			}
		}
		s.stopClusterInstStream(ctx, cctx, &clusterKey, sendObj, reterr, cleanupStream)
		if reterr == nil {
			s.RecordClusterInstEvent(cb.Context(), in, cloudcommon.CREATED, cloudcommon.InstanceUp)
		}
	}()

	if ignoreCRM(cctx) {
		return nil
	}
	reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().CreateClusterInstTimeout.TimeDuration())
	defer reqCancel()

	conn, err := services.platformServiceConnCache.GetConn(ctx, nodeType)
	if err != nil {
		return err
	}
	successMsg := "Created ClusterInst successfully"
	if crmOnEdge {
		err = edgeproto.WaitForClusterInstInfo(reqCtx, &in.Key, s.store, edgeproto.TrackedState_READY, CreateClusterInstTransitions,
			edgeproto.TrackedState_CREATE_ERROR,
			successMsg, cb.Send,
			edgeproto.WithCrmMsgCh(sendObj.crmMsgCh))
	} else {
		api := edgeproto.NewClusterPlatformAPIClient(conn)
		var outStream edgeproto.ClusterPlatformAPI_ApplyClusterInstClient
		in.Fields = edgeproto.ClusterInstAllFields
		outStream, err = api.ApplyClusterInst(reqCtx, in)
		if err == nil {
			err = cloudcommon.StreamRecvWithStatus(ctx, outStream, cb.Send, func(info *edgeproto.ClusterInstInfo) error {
				s.all.clusterInstApi.UpdateFromInfo(ctx, info)
				return nil
			})
			if err == nil {
				cb.Send(&edgeproto.Result{
					Message: successMsg,
				})
			}
		}
		err = cloudcommon.GRPCErrorUnwrap(err)
	}
	if err != nil && cctx.Override == edgeproto.CRMOverride_IGNORE_CRM_ERRORS {
		cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Create ClusterInst ignoring CRM failure: %s", err.Error())})
		s.ReplaceErrorState(ctx, in, edgeproto.TrackedState_READY)
		cb.Send(&edgeproto.Result{Message: "Created ClusterInst successfully"})
		err = nil
	}
	if err != nil {
		// XXX should probably track mod revision ID and only undo
		// if no other changes were made to appInst in the meantime.
		// crm failed or some other err, undo
		cb.Send(&edgeproto.Result{Message: "DELETING ClusterInst due to failures"})
		undoErr := s.deleteClusterInstInternal(cctx.WithUndo(), in, cb)
		if undoErr != nil {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Failed to undo ClusterInst creation: %v", undoErr)})
			log.InfoLog("Undo create ClusterInst", "undoErr", undoErr)
		}
	}
	if err == nil {
		s.updateCloudletResourcesMetric(ctx, &in.CloudletKey)
	}
	return err
}

func (s *ClusterInstApi) DeleteClusterInst(in *edgeproto.ClusterInst, cb edgeproto.ClusterInstApi_DeleteClusterInstServer) error {
	return s.deleteClusterInstInternal(DefCallContext(), in, cb)
}

func (s *ClusterInstApi) UpdateClusterInst(in *edgeproto.ClusterInst, cb edgeproto.ClusterInstApi_UpdateClusterInstServer) error {
	return s.updateClusterInstInternal(DefCallContext(), in, cb)
}

func (s *ClusterInstApi) updateClusterInstInternal(cctx *CallContext, in *edgeproto.ClusterInst, inCb edgeproto.ClusterInstApi_DeleteClusterInstServer) (reterr error) {
	ctx := inCb.Context()
	log.SpanLog(ctx, log.DebugLevelApi, "updateClusterInstInternal")

	err := in.ValidateUpdateFields()
	if err != nil {
		return err
	}
	if err := in.Key.ValidateKey(); err != nil {
		return err
	}

	cctx.SetOverride(&in.CrmOverride)
	fmap := edgeproto.MakeFieldMap(in.Fields)

	if fmap.Has(edgeproto.ClusterInstFieldEnableIpv6) && !in.EnableIpv6 {
		err := s.checkDisableDisableIPV6(ctx, &in.Key)
		if err != nil {
			return err
		}
	}

	clusterKey := in.Key
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, clusterKey.StreamKey(), inCb)

	var inbuf edgeproto.ClusterInst
	var changeCount int
	retry := false
	nodeType := ""
	crmOnEdge := false
	var diffFields *edgeproto.FieldMap
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		changeCount = 0
		inbuf = edgeproto.ClusterInst{}
		if !s.store.STMGet(stm, &in.Key, &inbuf) {
			return in.Key.NotFoundError()
		}
		old := edgeproto.ClusterInst{}
		old.DeepCopyIn(&inbuf)
		if inbuf.Deployment != cloudcommon.DeploymentTypeKubernetes {
			if inbuf.AutoScalePolicy == "" && in.AutoScalePolicy != "" {
				return fmt.Errorf("Cannot add auto scale policy to non-kubernetes ClusterInst")
			}
			if fmap.Has(edgeproto.ClusterInstFieldNumMasters) && in.NumMasters != 0 {
				return fmt.Errorf("Cannot update number of master nodes in non-kubernetes cluster")
			}
			if fmap.Has(edgeproto.ClusterInstFieldNumNodes) && in.NumNodes != 0 {
				return fmt.Errorf("Cannot update number of nodes in non-kubernetes cluster")
			}
		}

		if err := s.all.cloudletInfoApi.checkCloudletReadySTM(cctx, stm, &inbuf.CloudletKey, cloudcommon.Update); err != nil {
			return err
		}

		if !cctx.Undo && inbuf.State != edgeproto.TrackedState_READY && !ignoreTransient(cctx, inbuf.State) {
			if inbuf.State == edgeproto.TrackedState_UPDATE_ERROR {
				cb.Send(&edgeproto.Result{Message: fmt.Sprintf("previous update failed, %v, trying again", inbuf.Errors)})
				retry = true
			} else {
				return errors.New("ClusterInst busy, cannot update")
			}
		}

		cloudlet := edgeproto.Cloudlet{}
		if !s.all.cloudletApi.store.STMGet(stm, &inbuf.CloudletKey, &cloudlet) {
			return inbuf.CloudletKey.NotFoundError()
		}
		features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
		if err != nil {
			return fmt.Errorf("Failed to get features for platform: %s", err)
		}
		crmOnEdge = cloudlet.CrmOnEdge
		nodeType = features.NodeType
		if fmap.Has(edgeproto.ClusterInstFieldEnableIpv6) {
			if in.EnableIpv6 && !features.SupportsIpv6 {
				return fmt.Errorf("cloudlet platform does not support IPv6")
			}
			if in.EnableIpv6 != inbuf.EnableIpv6 {
				if inbuf.Deployment == cloudcommon.DeploymentTypeKubernetes {
					return fmt.Errorf("cannot change IPv6 setting on Kubernetes clusters")
				}
			}
		}

		// Get diff of nodes to validate and track cloudlet resources
		resChanged := false
		resClusterInst := &edgeproto.ClusterInst{}
		resClusterInst.DeepCopyIn(&inbuf)
		if in.NumNodes > resClusterInst.NumNodes {
			// update diff
			resClusterInst.NumNodes = in.NumNodes - resClusterInst.NumNodes
			resChanged = true
		} else {
			resClusterInst.NumNodes = 0
		}
		if in.NumMasters > resClusterInst.NumMasters {
			// update diff
			resClusterInst.NumMasters = in.NumMasters - resClusterInst.NumMasters
			resChanged = true
		} else {
			resClusterInst.NumMasters = 0
		}
		if resChanged {
			info := edgeproto.CloudletInfo{}
			if !s.all.cloudletInfoApi.store.STMGet(stm, &inbuf.CloudletKey, &info) {
				return fmt.Errorf("No resource information found for Cloudlet %s", inbuf.CloudletKey)
			}
			cloudletRefs := edgeproto.CloudletRefs{}
			s.all.cloudletRefsApi.store.STMGet(stm, &inbuf.CloudletKey, &cloudletRefs)
			// set ipaccess to unknown so that rootlb resource is not calculated as part of diff resource calculation
			resClusterInst.IpAccess = edgeproto.IpAccess_IP_ACCESS_UNKNOWN
			err = s.validateResources(ctx, stm, resClusterInst, nil, nil, &cloudlet, &info, &cloudletRefs, GenResourceAlerts)
			if err != nil {
				return err
			}
		}
		// invalidate resClusterInst obj so that it is not used anymore,
		// as it was just made for above diff resource calculation
		resClusterInst = nil

		changeCount = inbuf.CopyInFields(in)
		if changeCount == 0 && !retry {
			// nothing changed
			return nil
		}

		if err := s.validateClusterInstUpdates(ctx, stm, &inbuf); err != nil {
			return err
		}

		if !ignoreCRM(cctx) {
			inbuf.State = edgeproto.TrackedState_UPDATE_REQUESTED
		}
		inbuf.UpdatedAt = dme.TimeToTimestamp(time.Now())
		s.store.STMPut(stm, &inbuf)
		diffFields = old.GetDiffFields(&inbuf)
		return nil
	})
	if err != nil {
		return err
	}
	if changeCount == 0 && !retry {
		return nil
	}

	sendObj, err := s.startClusterInstStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		return err
	}
	defer func() {
		s.stopClusterInstStream(ctx, cctx, &clusterKey, sendObj, reterr, NoCleanupStream)
	}()

	s.RecordClusterInstEvent(ctx, &inbuf, cloudcommon.UPDATE_START, cloudcommon.InstanceDown)
	defer func() {
		if reterr == nil {
			s.RecordClusterInstEvent(ctx, &inbuf, cloudcommon.UPDATE_COMPLETE, cloudcommon.InstanceUp)
		} else {
			s.RecordClusterInstEvent(ctx, &inbuf, cloudcommon.UPDATE_ERROR, cloudcommon.InstanceDown)
		}
	}()

	if ignoreCRM(cctx) {
		return nil
	}
	reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().UpdateClusterInstTimeout.TimeDuration())
	defer reqCancel()

	successMsg := "Updated ClusterInst successfully"
	if crmOnEdge {
		err = edgeproto.WaitForClusterInstInfo(reqCtx, &in.Key, s.store, edgeproto.TrackedState_READY,
			UpdateClusterInstTransitions, edgeproto.TrackedState_UPDATE_ERROR,
			successMsg, cb.Send,
			edgeproto.WithCrmMsgCh(sendObj.crmMsgCh),
		)
	} else {
		conn, err := services.platformServiceConnCache.GetConn(ctx, nodeType)
		if err != nil {
			return err
		}
		api := edgeproto.NewClusterPlatformAPIClient(conn)
		inbuf.Fields = diffFields.Fields()
		outStream, err := api.ApplyClusterInst(reqCtx, &inbuf)
		if err != nil {
			return cloudcommon.GRPCErrorUnwrap(err)
		}
		err = cloudcommon.StreamRecvWithStatus(ctx, outStream, cb.Send, func(info *edgeproto.ClusterInstInfo) error {
			s.all.clusterInstApi.UpdateFromInfo(ctx, info)
			return nil
		})
		if err == nil {
			cb.Send(&edgeproto.Result{
				Message: successMsg,
			})
		}
		if err != nil {
			return err
		}
	}
	return err
}

func (s *ClusterInstApi) updateCloudletResourcesMetric(ctx context.Context, key *edgeproto.CloudletKey) {
	var err error
	metrics := []*edgeproto.Metric{}
	resErr := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		metrics, err = s.getCloudletResourceMetric(ctx, stm, key)
		return err
	})
	if resErr == nil {
		services.cloudletResourcesInfluxQ.AddMetric(metrics...)
	} else {
		log.SpanLog(ctx, log.DebugLevelApi, "Failed to generate cloudlet resource usage metric", "cloudletkey", key, "err", resErr)
	}
}

// update AppInst enable ipv6 setting to match clusterInst's setting
func (s *ClusterInstApi) checkDisableDisableIPV6(ctx context.Context, key *edgeproto.ClusterKey) error {
	refs := edgeproto.ClusterRefs{}
	if !s.all.clusterRefsApi.cache.Get(key, &refs) {
		return nil
	}
	enabledAppInsts := []string{}

	for _, aiKey := range refs.Apps {
		appInst := edgeproto.AppInst{}
		if s.all.appInstApi.cache.Get(&aiKey, &appInst) {
			app := edgeproto.App{}
			if s.all.appApi.cache.Get(&appInst.AppKey, &app) {
				if len(appInst.MappedPorts) == 0 || app.InternalPorts {
					// doesn't depend on IPv6 interface
					continue
				}
				if appInst.EnableIpv6 {
					enabledAppInsts = append(enabledAppInsts, appInst.Key.GetKeyString())
				}
			}
		}
	}
	if len(enabledAppInsts) > 0 {
		return fmt.Errorf("cannot disable IPv6 on cluster when AppInsts on cluster have it enabled: %s", strings.Join(enabledAppInsts, ", "))
	}
	return nil
}

func (s *ClusterInstApi) validateClusterInstUpdates(ctx context.Context, stm concurrency.STM, in *edgeproto.ClusterInst) error {
	cloudlet := edgeproto.Cloudlet{}
	if !s.all.cloudletApi.store.STMGet(stm, &in.CloudletKey, &cloudlet) {
		return in.CloudletKey.NotFoundError()
	}
	if in.AutoScalePolicy != "" {
		policy := edgeproto.AutoScalePolicy{}
		policy.Key.Name = in.AutoScalePolicy
		policy.Key.Organization = in.Key.Organization
		if !s.all.autoScalePolicyApi.store.STMGet(stm, &policy.Key, &policy) {
			return policy.Key.NotFoundError()
		}
		if policy.DeletePrepare {
			return policy.Key.BeingDeletedError()
		}
		if in.NumNodes < policy.MinNodes {
			in.NumNodes = policy.MinNodes
		}
		if in.NumNodes > policy.MaxNodes {
			in.NumNodes = policy.MaxNodes
		}
	}
	return nil
}

func validateDeleteState(cctx *CallContext, objName string, state edgeproto.TrackedState, prevErrs []string, send func(*edgeproto.Result) error) error {
	if cctx.Undo {
		// ignore any validation if deletion is done as part of undo
		return nil
	}
	if cctx.Override != edgeproto.CRMOverride_IGNORE_TRANSIENT_STATE &&
		cctx.Override != edgeproto.CRMOverride_IGNORE_CRM_AND_TRANSIENT_STATE {
		if edgeproto.IsDeleteState(state) {
			return fmt.Errorf("%s %s", objName, cloudcommon.AlreadyUnderDeletionMsg)
		}
		if edgeproto.IsTransientState(state) {
			return fmt.Errorf("%s %s", objName, ObjBusyDeletionMsg)
		}
	}
	return nil
}

func (s *ClusterInstApi) deleteClusterInstInternal(cctx *CallContext, in *edgeproto.ClusterInst, inCb edgeproto.ClusterInstApi_DeleteClusterInstServer) (reterr error) {
	log.SpanLog(inCb.Context(), log.DebugLevelApi, "delete ClusterInst internal", "key", in.Key)
	if err := in.Key.ValidateKey(); err != nil {
		return err
	}
	cctx.SetOverride(&in.CrmOverride)
	ctx := inCb.Context()

	clusterKey := in.Key
	var err error
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, clusterKey.StreamKey(), inCb)

	dynInsts := make(map[edgeproto.AppInstKey]struct{})
	var prevState edgeproto.TrackedState
	// Set state to prevent other apps from being created on ClusterInst
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, in) {
			return in.Key.NotFoundError()
		}
		if !ignoreCRMTransient(cctx) && in.DeletePrepare {
			return in.Key.BeingDeletedError()
		}
		if err := s.all.cloudletInfoApi.checkCloudletReadySTM(cctx, stm, &in.CloudletKey, cloudcommon.Delete); err != nil {
			return err
		}
		if err := validateDeleteState(cctx, "ClusterInst", in.State, in.Errors, cb.Send); err != nil {
			return err
		}
		// If it is autoClusterInst and creation had failed,
		// then deletion should proceed even though clusterinst
		// is in use by Application Instance
		refs := edgeproto.ClusterRefs{}
		if !(cctx.Undo && cctx.AutoCluster) && s.all.clusterRefsApi.store.STMGet(stm, &in.Key, &refs) {
			aiKeys := []edgeproto.AppInstKey{}
			for _, aiKey := range refs.Apps {
				aiKeys = append(aiKeys, aiKey)
			}
			err := s.all.appInstApi.cascadeDeleteOk(stm, in.CloudletKey.Organization, "ClusterInst", aiKeys, dynInsts)
			if err != nil {
				return err
			}
		}

		prevState = in.State
		in.DeletePrepare = true
		// TODO: remove redundant DELETE_PREPARE state, unforunately
		// a lot of other code does checks against state READY that
		// would need to be modified.
		in.State = edgeproto.TrackedState_DELETE_PREPARE
		s.store.STMPut(stm, in)
		return nil
	})
	if err != nil {
		return err
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			cur := edgeproto.ClusterInst{}
			if !s.store.STMGet(stm, &in.Key, &cur) {
				return in.Key.NotFoundError()
			}
			changed := true
			if cur.State == edgeproto.TrackedState_DELETE_PREPARE {
				// restore previous state since we failed pre-delete actions
				cur.State = prevState
				changed = true
			}
			if cur.DeletePrepare {
				cur.DeletePrepare = false
				changed = true
			}
			if changed {
				s.store.STMPut(stm, &cur)
			}
			return nil
		})
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to undo delete prepare", "key", in.Key, "err", undoErr)
		}
	}()

	sendObj, err := s.startClusterInstStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		return err
	}
	defer func() {
		cleanupStream := NoCleanupStream
		if reterr == nil {
			// deletion is successful, cleanup stream
			cleanupStream = CleanupStream
		}
		s.stopClusterInstStream(ctx, cctx, &clusterKey, sendObj, reterr, cleanupStream)
		if reterr == nil {
			s.RecordClusterInstEvent(ctx, in, cloudcommon.DELETED, cloudcommon.InstanceDown)
		}
	}()

	// Delete appInsts that are set for autodelete
	if err := s.all.appInstApi.AutoDeleteAppInsts(ctx, dynInsts, cctx.Override, cb); err != nil {
		return err
	}

	crmOnEdge := false
	platformType := ""
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, in) {
			return in.Key.NotFoundError()
		}
		if !in.DeletePrepare {
			return errors.New("ClusterInst expected delete prepare")
		}

		nodeFlavor := edgeproto.Flavor{}
		if !s.all.flavorApi.store.STMGet(stm, &in.Flavor, &nodeFlavor) {
			log.WarnLog("Delete ClusterInst: flavor not found",
				"flavor", in.Flavor.Name)
		}
		cloudlet := edgeproto.Cloudlet{}
		if !s.all.cloudletApi.store.STMGet(stm, &in.CloudletKey, &cloudlet) {
			log.WarnLog("Delete ClusterInst: cloudlet not found",
				"cloudlet", in.CloudletKey)
		}
		crmOnEdge = cloudlet.CrmOnEdge
		platformType = cloudlet.PlatformType
		refs := edgeproto.CloudletRefs{}
		if s.all.cloudletRefsApi.store.STMGet(stm, &in.CloudletKey, &refs) {
			ii := 0
			for ; ii < len(refs.ClusterInsts); ii++ {
				cKey := refs.ClusterInsts[ii]
				if cKey.Matches(&in.Key) {
					break
				}
			}
			if ii < len(refs.ClusterInsts) {
				// explicity zero out deleted item to
				// prevent memory leak
				a := refs.ClusterInsts
				copy(a[ii:], a[ii+1:])
				a[len(a)-1] = edgeproto.ClusterKey{}
				refs.ClusterInsts = a[:len(a)-1]
			}
			freeIP(in, &cloudlet, &refs)

			if in.Reservable && in.Auto && strings.HasPrefix(in.Key.Name, cloudcommon.ReservableClusterPrefix) {
				id, _, err := cloudcommon.ParseReservableClusterName(in.Key.Name)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelApi, "Failed to convert reservable auto-cluster id in name", "name", in.Key.Name, "err", err)
				} else {
					// clear bit
					mask := uint64(1) << id
					refs.ReservedAutoClusterIds &^= mask
				}
			}
			s.all.cloudletRefsApi.store.STMPut(stm, &refs)
		}
		if ignoreCRM(cctx) {
			// CRM state should be the same as before the
			// operation failed, so just need to clean up
			// controller state.
			s.store.STMDel(stm, &in.Key)
			s.dnsLabelStore.STMDel(stm, &in.CloudletKey, in.DnsLabel)
			s.all.clusterRefsApi.deleteRef(stm, &in.Key)
		} else {
			in.State = edgeproto.TrackedState_DELETE_REQUESTED
			s.store.STMPut(stm, in)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if ignoreCRM(cctx) {
		s.all.alertApi.CleanupClusterInstAlerts(ctx, &clusterKey, &in.CloudletKey)
		return nil
	}
	reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().DeleteClusterInstTimeout.TimeDuration())
	defer reqCancel()

	crmAction := func() error {
		successMsg := "Deleted ClusterInst successfully"
		if crmOnEdge {
			return edgeproto.WaitForClusterInstInfo(reqCtx, &in.Key, s.store, edgeproto.TrackedState_NOT_PRESENT,
				DeleteClusterInstTransitions, edgeproto.TrackedState_DELETE_ERROR,
				successMsg, cb.Send,
				edgeproto.WithCrmMsgCh(sendObj.crmMsgCh),
			)
		} else {
			features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, platformType)
			if err != nil {
				return err
			}
			conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
			if err != nil {
				return err
			}
			api := edgeproto.NewClusterPlatformAPIClient(conn)
			in.Fields = []string{edgeproto.ClusterInstFieldState}
			outStream, err := api.ApplyClusterInst(reqCtx, in)
			if err != nil {
				return cloudcommon.GRPCErrorUnwrap(err)
			}
			err = cloudcommon.StreamRecvWithStatus(ctx, outStream, cb.Send, func(info *edgeproto.ClusterInstInfo) error {
				s.UpdateFromInfo(ctx, info)
				return nil
			})
			if err == nil {
				cb.Send(&edgeproto.Result{
					Message: successMsg,
				})
			}
			return err
		}
	}
	err = crmAction()
	if err != nil && cctx.Override == edgeproto.CRMOverride_IGNORE_CRM_ERRORS {
		cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Delete ClusterInst ignoring CRM failure: %s", err.Error())})
		s.ReplaceErrorState(ctx, in, edgeproto.TrackedState_NOT_PRESENT)
		cb.Send(&edgeproto.Result{Message: "Deleted ClusterInst successfully"})
		err = nil
	}
	if err != nil {
		// crm failed or some other err, undo
		cb.Send(&edgeproto.Result{Message: "Recreating ClusterInst due to failure"})
		undoErr := s.createClusterInstInternal(cctx.WithUndo(), in, cb)
		if undoErr != nil {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Failed to undo ClusterInst deletion: %v", undoErr)})
			log.SpanLog(ctx, log.DebugLevelApi, "Undo delete ClusterInst", "name", in.Key, "undoErr", undoErr)
			s.RecordClusterInstEvent(ctx, in, cloudcommon.DELETE_ERROR, cloudcommon.InstanceDown)
		}
	}
	if err == nil {
		s.updateCloudletResourcesMetric(ctx, &in.CloudletKey)
	}
	s.all.alertApi.CleanupClusterInstAlerts(ctx, &clusterKey, &in.CloudletKey)
	return err
}

func (s *ClusterInstApi) ShowClusterInst(in *edgeproto.ClusterInst, cb edgeproto.ClusterInstApi_ShowClusterInstServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.ClusterInst) error {
		err := cb.Send(obj)
		return err
	})
	return err
}

// crmTransitionOk checks that the next state received from the CRM is a
// valid transition from the current state.
// See state_transitions.md
func crmTransitionOk(cur edgeproto.TrackedState, next edgeproto.TrackedState) bool {
	switch cur {
	case edgeproto.TrackedState_CREATE_REQUESTED:
		if next == edgeproto.TrackedState_CREATING || next == edgeproto.TrackedState_READY || next == edgeproto.TrackedState_CREATE_ERROR {
			return true
		}
	case edgeproto.TrackedState_CREATING:
		if next == edgeproto.TrackedState_READY || next == edgeproto.TrackedState_CREATE_ERROR {
			return true
		}
	case edgeproto.TrackedState_UPDATE_REQUESTED:
		if next == edgeproto.TrackedState_UPDATING || next == edgeproto.TrackedState_READY || next == edgeproto.TrackedState_UPDATE_ERROR {
			return true
		}
	case edgeproto.TrackedState_UPDATING:
		if next == edgeproto.TrackedState_READY || next == edgeproto.TrackedState_UPDATE_ERROR {
			return true
		}
	case edgeproto.TrackedState_DELETE_REQUESTED:
		if next == edgeproto.TrackedState_DELETING || next == edgeproto.TrackedState_NOT_PRESENT || next == edgeproto.TrackedState_DELETE_ERROR || next == edgeproto.TrackedState_DELETE_DONE {
			return true
		}
	case edgeproto.TrackedState_DELETING:
		if next == edgeproto.TrackedState_NOT_PRESENT || next == edgeproto.TrackedState_DELETE_ERROR || next == edgeproto.TrackedState_DELETE_DONE {
			return true
		}
	}
	return false
}

func ignoreTransient(cctx *CallContext, state edgeproto.TrackedState) bool {
	if cctx.Override == edgeproto.CRMOverride_IGNORE_TRANSIENT_STATE ||
		cctx.Override == edgeproto.CRMOverride_IGNORE_CRM_AND_TRANSIENT_STATE {
		return edgeproto.IsTransientState(state)
	}
	return false
}

func ignoreCRM(cctx *CallContext) bool {
	if (cctx.Undo && !cctx.CRMUndo) || cctx.Override == edgeproto.CRMOverride_IGNORE_CRM ||
		cctx.Override == edgeproto.CRMOverride_IGNORE_CRM_AND_TRANSIENT_STATE {
		return true
	}
	return false
}

func ignoreCRMTransient(cctx *CallContext) bool {
	if cctx.Override == edgeproto.CRMOverride_IGNORE_TRANSIENT_STATE ||
		cctx.Override == edgeproto.CRMOverride_IGNORE_CRM_AND_TRANSIENT_STATE {
		return true
	}
	return false
}

func (s *ClusterInstApi) UpdateFromInfo(ctx context.Context, in *edgeproto.ClusterInstInfo) {
	log.SpanLog(ctx, log.DebugLevelApi, "update ClusterInst", "key", in.Key, "state", in.State, "status", in.Status, "resources", in.Resources)

	fmap := edgeproto.MakeFieldMap(in.Fields)

	s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		saveInst := false
		inst := edgeproto.ClusterInst{}
		if !s.store.STMGet(stm, &in.Key, &inst) {
			// got deleted in the meantime
			return nil
		}
		if fmap.HasOrHasChild(edgeproto.ClusterInstInfoFieldResources) {
			if inst.Resources.UpdateResources(&in.Resources) {
				inst.Resources = in.Resources
				saveInst = true
			}
		}
		if fmap.HasOrHasChild(edgeproto.ClusterInstInfoFieldState) {
			if inst.State != in.State {
				saveInst = true
				// please see state_transitions.md
				if !crmTransitionOk(inst.State, in.State) {
					log.SpanLog(ctx, log.DebugLevelApi, "invalid state transition", "cur", inst.State, "next", in.State)
					return nil
				}
			}
			inst.State = in.State
			if in.State == edgeproto.TrackedState_CREATE_ERROR || in.State == edgeproto.TrackedState_DELETE_ERROR || in.State == edgeproto.TrackedState_UPDATE_ERROR {
				inst.Errors = in.Errors
			} else {
				inst.Errors = nil
			}
		}
		if saveInst {
			s.store.STMPut(stm, &inst)
		}
		return nil
	})
	// publish the received info object on redis
	// (must happen after updating etcd, see AppInst UpdateFromInfo comment)
	s.all.streamObjApi.UpdateStatus(ctx, in, &in.State, nil, in.Key.StreamKey())

	if in.State == edgeproto.TrackedState_DELETE_DONE {
		s.DeleteFromInfo(ctx, in)
		// update stream message about deletion of main object
		in.State = edgeproto.TrackedState_NOT_PRESENT
		s.all.streamObjApi.UpdateStatus(ctx, in, &in.State, nil, in.Key.StreamKey())
	}
}

func (s *ClusterInstApi) DeleteFromInfo(ctx context.Context, in *edgeproto.ClusterInstInfo) {
	log.SpanLog(ctx, log.DebugLevelApi, "delete ClusterInst from info", "key", in.Key, "state", in.State)
	s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		inst := edgeproto.ClusterInst{}
		if !s.store.STMGet(stm, &in.Key, &inst) {
			// got deleted in the meantime
			return nil
		}
		// please see state_transitions.md
		if inst.State != edgeproto.TrackedState_DELETING && inst.State != edgeproto.TrackedState_DELETE_REQUESTED && inst.State != edgeproto.TrackedState_DELETE_DONE {
			log.SpanLog(ctx, log.DebugLevelApi, "invalid state transition", "cur", inst.State, "next", edgeproto.TrackedState_DELETE_DONE)
			return nil
		}
		s.store.STMDel(stm, &in.Key)
		s.dnsLabelStore.STMDel(stm, &inst.CloudletKey, inst.DnsLabel)
		s.all.clusterRefsApi.deleteRef(stm, &in.Key)

		return nil
	})
}

func (s *ClusterInstApi) ReplaceErrorState(ctx context.Context, in *edgeproto.ClusterInst, newState edgeproto.TrackedState) {
	s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		inst := edgeproto.ClusterInst{}
		if !s.store.STMGet(stm, &in.Key, &inst) {
			// got deleted in the meantime
			return nil
		}

		if inst.State != edgeproto.TrackedState_CREATE_ERROR &&
			inst.State != edgeproto.TrackedState_DELETE_ERROR &&
			inst.State != edgeproto.TrackedState_UPDATE_ERROR {
			return nil
		}
		if newState == edgeproto.TrackedState_NOT_PRESENT {
			s.store.STMDel(stm, &in.Key)
			s.dnsLabelStore.STMDel(stm, &in.CloudletKey, inst.DnsLabel)
			s.all.clusterRefsApi.deleteRef(stm, &in.Key)
		} else {
			inst.State = newState
			inst.Errors = nil
			s.store.STMPut(stm, &inst)
		}
		return nil
	})
}

func (s *ClusterInstApi) RecordClusterInstEvent(ctx context.Context, cluster *edgeproto.ClusterInst, event cloudcommon.InstanceEvent, serverStatus string) {
	metric := edgeproto.Metric{}
	metric.Name = cloudcommon.ClusterInstEvent
	now := time.Now()
	ts, _ := types.TimestampProto(now)
	metric.Timestamp = *ts
	// influx requires that at least one field must be specified when querying so these cant be all tags
	metric.AddStringVal(edgeproto.CloudletKeyTagOrganization, cluster.CloudletKey.Organization)
	metric.AddTag(edgeproto.CloudletKeyTagName, cluster.CloudletKey.Name)
	metric.AddTag(edgeproto.ClusterKeyTagName, cluster.Key.Name)
	metric.AddTag(edgeproto.ClusterKeyTagOrganization, cluster.Key.Organization)
	cluster.ZoneKey.AddTagsByFunc(metric.AddTag)
	metric.AddStringVal(cloudcommon.MetricTagEvent, string(event))
	metric.AddStringVal(cloudcommon.MetricTagStatus, serverStatus)

	// if this is a clusterinst use the org its reserved for instead of MobiledgeX
	metric.AddTag("reservedBy", cluster.ReservedBy)
	// org field so that influx queries are a lot simpler to retrieve reserved clusters
	if cluster.ReservedBy != "" {
		metric.AddTag(cloudcommon.MetricTagOrg, cluster.ReservedBy)
	} else {
		metric.AddTag(cloudcommon.MetricTagOrg, cluster.Key.Organization)
	}
	// errors should never happen here since to get to this point the flavor should have already been checked previously, but just in case
	nodeFlavor := edgeproto.Flavor{}
	if !s.all.flavorApi.cache.Get(&cluster.Flavor, &nodeFlavor) {
		log.SpanLog(ctx, log.DebugLevelMetrics, "flavor not found for recording clusterInst lifecycle", "flavor name", cluster.Flavor.Name)
	} else {
		metric.AddStringVal(cloudcommon.MetricTagFlavor, cluster.Flavor.Name)
		metric.AddIntVal(cloudcommon.MetricTagRAM, nodeFlavor.Ram)
		metric.AddIntVal(cloudcommon.MetricTagVCPU, nodeFlavor.Vcpus)
		metric.AddIntVal(cloudcommon.MetricTagDisk, nodeFlavor.Disk)
		metric.AddIntVal(cloudcommon.MetricTagNodeCount, uint64(cluster.NumMasters+cluster.NumNodes))
		metric.AddStringVal(cloudcommon.MetricTagOther, fmt.Sprintf("%v", nodeFlavor.OptResMap))
	}
	metric.AddStringVal(cloudcommon.MetricTagIpAccess, cluster.IpAccess.String())

	services.events.AddMetric(&metric)
}

func (s *ClusterInstApi) cleanupIdleReservableAutoClusters(ctx context.Context, idletime time.Duration) {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for _, data := range s.cache.Objs {
		cinst := data.Obj
		if cinst.Auto && cinst.Reservable && cinst.ReservedBy == "" && time.Since(dme.TimestampToTime(cinst.ReservationEndedAt)) > idletime {
			// spawn worker for cleanupClusterInst
			s.cleanupWorkers.NeedsWork(ctx, cinst.Key)
		}
	}
}

func (s *ClusterInstApi) cleanupClusterInst(ctx context.Context, k interface{}) {
	key, ok := k.(edgeproto.ClusterKey)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelApi, "Unexpected failure, key not ClusterKey", "key", k)
		return
	}
	log.SetContextTags(ctx, key.GetTags())
	clusterInst := edgeproto.ClusterInst{
		Key: key,
	}
	startTime := time.Now()
	cb := &DummyStreamout{ctx: ctx}
	err := s.DeleteClusterInst(&clusterInst, cb)
	log.SpanLog(ctx, log.DebugLevelApi, "ClusterInst cleanup", "ClusterInst", key, "err", err)
	if err != nil && err.Error() == key.NotFoundError().Error() {
		// don't log event if it was already deleted
		return
	}
	nodeMgr.TimedEvent(ctx, "ClusterInst cleanup", key.Organization, node.EventType, key.GetTags(), err, startTime, time.Now())
}

type DummyStreamout struct {
	grpc.ServerStream
	ctx context.Context
}

func (d *DummyStreamout) Context() context.Context {
	return d.ctx
}

func (d *DummyStreamout) Send(res *edgeproto.Result) error {
	return nil
}

type PeriodicReservableClusterInstCleanup struct {
	clusterInstApi *ClusterInstApi
}

func (s *PeriodicReservableClusterInstCleanup) GetInterval() time.Duration {
	idletime := s.clusterInstApi.all.settingsApi.Get().CleanupReservableAutoClusterIdletime.TimeDuration()
	return idletime / 5
}

func (s *PeriodicReservableClusterInstCleanup) StartSpan() opentracing.Span {
	return log.StartSpan(log.DebugLevelApi, "reservable ClusterInst periodic cleanup thread")
}

func (s *PeriodicReservableClusterInstCleanup) Run(ctx context.Context) {
	idletime := s.clusterInstApi.all.settingsApi.Get().CleanupReservableAutoClusterIdletime.TimeDuration()
	s.clusterInstApi.cleanupIdleReservableAutoClusters(ctx, idletime)
}

func (s *ClusterInstApi) DeleteIdleReservableClusterInsts(ctx context.Context, in *edgeproto.IdleReservableClusterInsts) (*edgeproto.Result, error) {
	s.cleanupIdleReservableAutoClusters(ctx, in.IdleTime.TimeDuration())
	s.cleanupWorkers.WaitIdle()
	return &edgeproto.Result{Message: "Delete done"}, nil
}

type StreamoutCb struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *StreamoutCb) Send(res *edgeproto.Result) error {
	log.SpanLog(s.ctx, log.DebugLevelApi, res.Message)
	return nil
}

func (s *StreamoutCb) Context() context.Context {
	return s.ctx
}

func (s *ClusterInstApi) createDefaultMultiTenantCluster(ctx context.Context, cloudletKey edgeproto.CloudletKey, features *edgeproto.PlatformFeatures) {
	log.SpanLog(ctx, log.DebugLevelApi, "Create default multi-tenant cluster", "cloudlet", cloudletKey)

	// find largest flavor
	largest := edgeproto.Flavor{}
	s.all.flavorApi.cache.Mux.Lock()
	for _, data := range s.all.flavorApi.cache.Objs {
		flavor := data.Obj
		if strings.Contains(flavor.Key.Name, "gpu") {
			// for now avoid gpu flavors
			continue
		}
		if flavor.OptResMap != nil {
			if _, found := flavor.OptResMap["gpu"]; found {
				// avoid gpu flavors
				continue
			}
		}
		if flavor.Vcpus != largest.Vcpus {
			if flavor.Vcpus > largest.Vcpus {
				largest = *flavor
			}
			continue
		}
		if flavor.Ram != largest.Ram {
			if flavor.Ram > largest.Ram {
				largest = *flavor
			}
			continue
		}
		if flavor.Disk > largest.Disk {
			largest = *flavor
		}
	}
	s.all.flavorApi.cache.Mux.Unlock()

	autoScalePolicy := ""
	clusterKey := cloudcommon.GetDefaultMTClustKey(cloudletKey)
	if !features.NoKubernetesClusterAutoScale {
		// default autoscale policy
		// TODO: make these settings configurable
		policy := edgeproto.AutoScalePolicy{}
		policy.Key.Organization = edgeproto.OrganizationEdgeCloud
		policy.Key.Name = clusterKey.Name
		policy.TargetCpu = 70
		policy.TargetMem = 80
		policy.StabilizationWindowSec = 300
		policy.MinNodes = 1
		policy.MaxNodes = 4
		_, err := s.all.autoScalePolicyApi.CreateAutoScalePolicy(ctx, &policy)
		log.SpanLog(ctx, log.DebugLevelApi, "create default multi-tenant ClusterInst autoscale policy", "policy", policy, "err", err)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return
		}
		autoScalePolicy = policy.Key.Name
	}
	clusterInst := edgeproto.ClusterInst{}
	clusterInst.Key = *clusterKey
	clusterInst.CloudletKey = cloudletKey
	clusterInst.Deployment = cloudcommon.DeploymentTypeKubernetes
	clusterInst.MultiTenant = true
	clusterInst.Flavor = largest.Key
	// TODO: custom settings or per-cloudlet config for the below fields?
	clusterInst.NumMasters = 1
	clusterInst.NumNodes = 3
	clusterInst.AutoScalePolicy = autoScalePolicy
	cb := StreamoutCb{
		ctx: ctx,
	}
	start := time.Now()

	err := s.all.clusterInstApi.createClusterInstInternal(DefCallContext(), &clusterInst, &cb)
	log.SpanLog(ctx, log.DebugLevelApi, "create default multi-tenant ClusterInst", "cluster", clusterInst, "err", err)

	if err != nil && err.Error() == clusterInst.Key.ExistsError().Error() {
		return
	}
	nodeMgr.TimedEvent(ctx, "default multi-tenant cluster created", clusterInst.Key.Organization, node.EventType, clusterInst.Key.GetTags(), err, start, time.Now())
}

func (s *ClusterInstApi) deleteDefaultMultiTenantCluster(ctx context.Context, cloudletKey edgeproto.CloudletKey) {
	clusterInst := edgeproto.ClusterInst{}
	clusterInst.Key = *cloudcommon.GetDefaultMTClustKey(cloudletKey)
	cb := StreamoutCb{
		ctx: ctx,
	}
	start := time.Now()

	err := s.deleteClusterInstInternal(DefCallContext(), &clusterInst, &cb)
	log.SpanLog(ctx, log.DebugLevelApi, "delete default multi-tenant ClusterInst", "cluster", clusterInst, "err", err)

	if err != nil && err.Error() == clusterInst.Key.NotFoundError().Error() {
		return
	}
	nodeMgr.TimedEvent(ctx, "default multi-tenant cluster deleted", clusterInst.Key.Organization, node.EventType, clusterInst.Key.GetTags(), err, start, time.Now())
}

// The cloudlet singular cluster is a software-only cluster that represents
// the singular infra k8s cluster that already exists and is the entire cloudlet.
func (s *ClusterInstApi) createCloudletSingularCluster(stm concurrency.STM, cloudlet *edgeproto.Cloudlet, ownerOrg string) error {
	clusterInst := edgeproto.ClusterInst{}
	multiTenant := false
	if ownerOrg == "" {
		multiTenant = true
	}
	clusterInst.Key = *cloudcommon.GetDefaultClustKey(cloudlet.Key, ownerOrg)
	clusterInst.Deployment = cloudcommon.DeploymentTypeKubernetes
	clusterInst.MultiTenant = multiTenant
	clusterInst.State = edgeproto.TrackedState_READY
	clusterInst.IpAccess = edgeproto.IpAccess_IP_ACCESS_SHARED
	clusterInst.CloudletKey = cloudlet.Key
	if err := s.setDnsLabel(stm, &clusterInst); err != nil {
		return err
	}
	clusterInst.Fqdn = getClusterInstFQDN(&clusterInst, cloudlet)
	clusterInst.StaticFqdn = clusterInst.Fqdn
	s.store.STMPut(stm, &clusterInst)
	s.dnsLabelStore.STMPut(stm, &cloudlet.Key, clusterInst.DnsLabel)
	return nil
}

func (s *ClusterInstApi) deleteCloudletSingularCluster(stm concurrency.STM, key *edgeproto.CloudletKey, ownerOrg string) {
	clusterKey := cloudcommon.GetDefaultClustKey(*key, ownerOrg)
	clusterInst := edgeproto.ClusterInst{}
	if !s.store.STMGet(stm, clusterKey, &clusterInst) {
		return
	}
	s.store.STMDel(stm, clusterKey)
	s.dnsLabelStore.STMDel(stm, key, clusterInst.DnsLabel)
	s.all.clusterRefsApi.deleteRef(stm, clusterKey)
}

func (s *ClusterInstApi) updateRootLbFQDN(key *edgeproto.ClusterKey, cloudlet *edgeproto.Cloudlet, inCb edgeproto.ClusterInstApi_UpdateClusterInstServer) (reterr error) {
	ctx := inCb.Context()
	cctx := DefCallContext()

	log.SpanLog(ctx, log.DebugLevelApi, "updateRootLbFQDN", "cluster", key, "cloudlet", cloudlet)

	clusterKey := key
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, clusterKey.StreamKey(), inCb)

	needUpdate := false
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		clusterInst := edgeproto.ClusterInst{}
		if !s.store.STMGet(stm, key, &clusterInst) {
			log.SpanLog(ctx, log.DebugLevelApi, "Cluster deleted before DNS update", "cluster", key)
			return nil
		}
		if clusterInst.Fqdn == getClusterInstFQDN(&clusterInst, cloudlet) {
			log.SpanLog(ctx, log.DebugLevelApi, "Cluster fqnd is up to date.")
			return nil
		}
		if clusterInst.DeletePrepare {
			log.SpanLog(ctx, log.DebugLevelApi, "Cluster is currently being deleted", "cluster", key)
			return nil
		}

		// Could be in an update error after an unsuccessful dns update
		if clusterInst.State != edgeproto.TrackedState_READY && clusterInst.State != edgeproto.TrackedState_UPDATE_ERROR {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Cluster %s is not ready - skipping", clusterInst.Key.Name)})
			log.SpanLog(ctx, log.DebugLevelApi, "Cluster is not ready - skipping", "clusterinst", clusterInst)
			return nil
		}

		// save old dns fqdn, so it can be updated in CCRM
		log.SpanLog(ctx, log.DebugLevelApi, "Updating DNS for cluster", "old FQDN", clusterInst.Fqdn, "new", getClusterInstFQDN(&clusterInst, cloudlet))
		clusterInst.AddAnnotation(cloudcommon.AnnotationPreviousDNSName, clusterInst.Fqdn)
		clusterInst.Fqdn = getClusterInstFQDN(&clusterInst, cloudlet)
		clusterInst.UpdatedAt = dme.TimeToTimestamp(time.Now())
		clusterInst.State = edgeproto.TrackedState_UPDATE_REQUESTED
		s.store.STMPut(stm, &clusterInst)
		needUpdate = true
		return nil
	})
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Failed to update clusterinst in etcd", "err", err)
		return err
	}

	// Revert cluster to old state if update failed
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			clusterInst := edgeproto.ClusterInst{}
			if !s.store.STMGet(stm, key, &clusterInst) {
				log.SpanLog(ctx, log.DebugLevelApi, "Cluster deleted before DNS update", "cluster", key)
				return nil
			}
			if clusterInst.DeletePrepare {
				log.SpanLog(ctx, log.DebugLevelApi, "Cluster is currently being deleted", "cluster", key)
				return nil
			}
			oldFqdn, ok := clusterInst.Annotations[cloudcommon.AnnotationPreviousDNSName]
			if !ok {
				log.SpanLog(ctx, log.DebugLevelApi, "no previous fqdn is set")
				return fmt.Errorf("no previous fqdn set for %s", clusterInst.Key.Name)
			}
			delete(clusterInst.Annotations, cloudcommon.AnnotationPreviousDNSName)
			clusterInst.Fqdn = oldFqdn
			clusterInst.UpdatedAt = dme.TimeToTimestamp(time.Now())
			s.store.STMPut(stm, &clusterInst)
			return nil
		})
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to undo dns update", "key", key, "err", undoErr)
		}
	}()

	// Nothing changed
	if !needUpdate {
		return nil
	}
	sendObj, err := s.startClusterInstStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		return err
	}
	defer func() {
		s.stopClusterInstStream(ctx, cctx, key, sendObj, reterr, NoCleanupStream)
	}()

	reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().UpdateClusterInstTimeout.TimeDuration())
	defer reqCancel()

	successMsg := fmt.Sprintf("Cluster %s updated successfully", key.Name)
	return edgeproto.WaitForClusterInstInfo(reqCtx, key, s.store, edgeproto.TrackedState_READY,
		UpdateClusterInstTransitions, edgeproto.TrackedState_UPDATE_ERROR,
		successMsg, cb.Send,
		edgeproto.WithCrmMsgCh(sendObj.crmMsgCh),
	)
}
