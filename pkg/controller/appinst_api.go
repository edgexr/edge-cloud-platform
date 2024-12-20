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
	"strconv"
	"strings"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/gogo/protobuf/types"
	"github.com/oklog/ulid/v2"
	"go.etcd.io/etcd/client/v3/concurrency"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type AppInstApi struct {
	all                     *AllApis
	sync                    *regiondata.Sync
	store                   edgeproto.AppInstStore
	cache                   edgeproto.AppInstCache
	idStore                 edgeproto.AppInstIdStore
	fedStore                edgeproto.FedAppInstStore
	dnsLabelStore           *edgeproto.CloudletObjectDnsLabelStore
	fedAppInstEventSendMany *notify.FedAppInstEventSendMany
}

const RootLBSharedPortBegin int32 = 10000

var RequireAppInstPortConsistency = false

// Transition states indicate states in which the CRM is still busy.
var CreateAppInstTransitions = map[edgeproto.TrackedState]struct{}{
	edgeproto.TrackedState_CREATING: struct{}{},
}
var UpdateAppInstTransitions = map[edgeproto.TrackedState]struct{}{
	edgeproto.TrackedState_UPDATING: struct{}{},
}
var DeleteAppInstTransitions = map[edgeproto.TrackedState]struct{}{
	edgeproto.TrackedState_DELETING: struct{}{},
}

func NewAppInstApi(sync *regiondata.Sync, all *AllApis) *AppInstApi {
	appInstApi := AppInstApi{}
	appInstApi.all = all
	appInstApi.sync = sync
	appInstApi.store = edgeproto.NewAppInstStore(sync.GetKVStore())
	appInstApi.idStore.Init(sync.GetKVStore())
	appInstApi.fedStore = edgeproto.NewFedAppInstStore(sync.GetKVStore())
	appInstApi.dnsLabelStore = &all.cloudletApi.objectDnsLabelStore
	appInstApi.fedAppInstEventSendMany = notify.NewFedAppInstEventSendMany()
	edgeproto.InitAppInstCacheWithStore(&appInstApi.cache, appInstApi.store)
	sync.RegisterCache(&appInstApi.cache)
	return &appInstApi
}

func (s *AppInstApi) Get(key *edgeproto.AppInstKey, val *edgeproto.AppInst) bool {
	return s.cache.Get(key, val)
}

func (s *AppInstApi) HasKey(key *edgeproto.AppInstKey) bool {
	return s.cache.HasKey(key)
}

func isAutoDeleteAppInstOk(callerOrg string, appInst *edgeproto.AppInst, app *edgeproto.App) bool {
	if appInst.Liveness == edgeproto.Liveness_LIVENESS_DYNAMIC || app.DelOpt == edgeproto.DeleteType_AUTO_DELETE {
		return true
	}
	if callerOrg == app.Key.Organization && appInst.Liveness == edgeproto.Liveness_LIVENESS_AUTOPROV {
		// Caller owns the App and AppInst. Allow them to automatically
		// delete auto-provisioned instances. Otherwise, this is
		// probably an operator trying to delete a cloudlet or common
		// ClusterInst, and should not be able to automatically delete
		// developer's instances.
		return true
	}
	return false
}

func (s *AppInstApi) deleteCloudletOk(stm concurrency.STM, refs *edgeproto.CloudletRefs, defaultClustKey *edgeproto.ClusterKey, dynInsts map[edgeproto.AppInstKey]struct{}) error {
	// Only need to check VM apps, as other AppInsts require ClusterInsts,
	// so ClusterInst check will apply.
	aiKeys := refs.VmAppInsts
	// check any AppInsts on default cluster
	clustRefs := edgeproto.ClusterRefs{}
	if defaultClustKey != nil && s.all.clusterRefsApi.store.STMGet(stm, defaultClustKey, &clustRefs) {
		aiKeys = append(aiKeys, clustRefs.Apps...)
	}
	return s.cascadeDeleteOk(stm, refs.Key.Organization, "Cloudlet", aiKeys, dynInsts)
}

func (s *AppInstApi) cascadeDeleteOk(stm concurrency.STM, callerOrg, deleteTarget string, aiKeys []edgeproto.AppInstKey, dynInsts map[edgeproto.AppInstKey]struct{}) error {
	for _, aiKey := range aiKeys {
		ai := edgeproto.AppInst{}
		if !s.store.STMGet(stm, &aiKey, &ai) {
			continue
		}
		app := edgeproto.App{}
		if !s.all.appApi.store.STMGet(stm, &ai.AppKey, &app) {
			continue
		}
		if isAutoDeleteAppInstOk(callerOrg, &ai, &app) {
			dynInsts[ai.Key] = struct{}{}
			continue
		}
		return fmt.Errorf("%s in use by AppInst %s", deleteTarget, ai.Key.GetKeyString())
	}
	return nil
}

func (s *AppInstApi) CheckCloudletAppinstsCompatibleWithTrustPolicy(ctx context.Context, ckey *edgeproto.CloudletKey, TrustPolicy *edgeproto.TrustPolicy) error {
	apps := make(map[edgeproto.AppKey]*edgeproto.App)
	s.all.appApi.GetAllApps(apps)
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for _, data := range s.cache.Objs {
		if !data.Obj.CloudletKey.Matches(ckey) {
			continue
		}
		val := data.Obj
		app, found := apps[val.AppKey]
		if !found {
			return val.AppKey.NotFoundError()
		}
		err := s.all.appApi.CheckAppCompatibleWithTrustPolicy(ctx, ckey, app, TrustPolicy)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *AppInstApi) updateAppInstRevision(ctx context.Context, key *edgeproto.AppInstKey, revision string) error {
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		inst := edgeproto.AppInst{}
		if !s.store.STMGet(stm, key, &inst) {
			// got deleted in the meantime
			return nil
		}
		inst.Revision = revision
		log.SpanLog(ctx, log.DebugLevelApi, "AppInst revision updated", "key", key, "revision", revision)

		s.store.STMPut(stm, &inst)
		return nil
	})

	return err
}

func (s *AppInstApi) UsesClusterInst(callerOrg string, in *edgeproto.ClusterKey) bool {
	var app edgeproto.App
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for _, data := range s.cache.Objs {
		val := data.Obj
		if val.GetClusterKey().Matches(in) && s.all.appApi.Get(&val.AppKey, &app) {
			if !isAutoDeleteAppInstOk(callerOrg, val, &app) {
				return true
			}
		}
	}
	return false
}

func (s *AppInstApi) AutoDeleteAppInsts(ctx context.Context, dynInsts map[edgeproto.AppInstKey]struct{}, crmoverride edgeproto.CRMOverride, cb edgeproto.ClusterInstApi_DeleteClusterInstServer) error {
	var err error
	log.SpanLog(ctx, log.DebugLevelApi, "Auto-deleting AppInsts")

	keys := []edgeproto.AppInstKey{}
	for key := range dynInsts {
		keys = append(keys, key)
	}
	// sort keys for stable iteration order, needed for testing
	sort.Slice(keys[:], func(i, j int) bool {
		return keys[i].GetKeyString() < keys[j].GetKeyString()
	})

	//Spin in case cluster was just created and apps are still in the creation process and cannot be deleted
	var spinTime time.Duration
	start := time.Now()
	for _, key := range keys {
		val := &edgeproto.AppInst{}
		if !s.cache.Get(&key, val) {
			continue
		}
		log.SpanLog(ctx, log.DebugLevelApi, "Auto-deleting AppInst", "appinst", val.Key.Name)
		cb.Send(&edgeproto.Result{Message: "Autodeleting AppInst " + val.Key.Name})
		for {
			// ignore CRM errors when deleting dynamic apps as we will be deleting the cluster anyway
			cctx := DefCallContext()
			if crmoverride != edgeproto.CRMOverride_NO_OVERRIDE {
				cctx.SetOverride(&crmoverride)
			} else {
				crmo := edgeproto.CRMOverride_IGNORE_CRM_ERRORS
				cctx.SetOverride(&crmo)
			}
			// cloudlet ready check should already have been done
			cctx.SkipCloudletReadyCheck = true
			err = s.deleteAppInstInternal(cctx, val, cb)
			if err != nil && err.Error() == val.Key.NotFoundError().Error() {
				err = nil
				break
			}
			if err != nil && (strings.Contains(err.Error(), ObjBusyDeletionMsg) ||
				strings.Contains(err.Error(), ActionInProgressMsg)) {
				spinTime = time.Since(start)
				if spinTime > s.all.settingsApi.Get().DeleteAppInstTimeout.TimeDuration() {
					log.SpanLog(ctx, log.DebugLevelApi, "Timeout while waiting for AppInst", "appInstName", val.Key.Name)
					return err
				}
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst busy, retrying in 0.5s...", "AppInst Name", val.Key.Name)
				time.Sleep(500 * time.Millisecond)
			} else { //if its anything other than an appinst busy error, break out of the spin
				break
			}
		}

		if err != nil {
			return err
		}
	}
	return nil
}

func (s *AppInstApi) AutoDelete(ctx context.Context, appinsts []*edgeproto.AppInst) error {
	if len(appinsts) == 0 {
		return nil
	}
	// sort so order is deterministic for testing
	sort.Slice(appinsts, func(i, j int) bool {
		return appinsts[i].Key.GetKeyString() < appinsts[j].Key.GetKeyString()
	})

	failed := 0
	deleted := 0
	for _, val := range appinsts {
		log.SpanLog(ctx, log.DebugLevelApi, "Auto-delete AppInst for App", "AppInst", val.Key)
		stream := streamoutAppInst{}
		stream.ctx = ctx
		stream.debugLvl = log.DebugLevelApi
		err := s.DeleteAppInst(val, &stream)
		if err != nil && err.Error() != val.Key.NotFoundError().Error() {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to auto-delete AppInst", "AppInst", val.Key, "err", err)
			failed++
		} else {
			deleted++
		}
	}
	if failed > 0 {
		return fmt.Errorf("Auto-deleted %d AppInsts but failed to delete %d AppInsts for App", deleted, failed)
	}
	return nil
}

func (s *AppInstApi) UsesFlavor(key *edgeproto.FlavorKey) *edgeproto.AppInstKey {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for k, data := range s.cache.Objs {
		app := data.Obj
		if app.Flavor.Matches(key) {
			return &k
		}
	}
	return nil
}

func (s *AppInstApi) CreateAppInst(in *edgeproto.AppInst, cb edgeproto.AppInstApi_CreateAppInstServer) error {
	return s.createAppInstInternal(DefCallContext(), in, cb)
}

func getProtocolBitMap(proto dme.LProto) (int32, error) {
	var bitmap int32
	switch proto {
	case dme.LProto_L_PROTO_HTTP:
		fallthrough // HTTP ports are treated as TCP for conflicts
	case dme.LProto_L_PROTO_TCP:
		bitmap = 1 //01
	//put all "UDP" protocols below here
	case dme.LProto_L_PROTO_UDP:
		bitmap = 2 //10
	default:
		return 0, errors.New("Unknown protocol in use for this app")
	}
	return bitmap, nil
}

func protocolInUse(protocolsToCheck int32, usedProtocols int32) bool {
	return (protocolsToCheck & usedProtocols) != 0
}

func addProtocol(protos int32, protocolToAdd int32) int32 {
	return protos | protocolToAdd
}

func removeProtocol(protos int32, protocolToRemove int32) int32 {
	return protos & (^protocolToRemove)
}

func (s *AppInstApi) startAppInstStream(ctx context.Context, cctx *CallContext, streamCb *CbWrapper, modRev int64) (*streamSend, error) {
	streamSendObj, err := s.all.streamObjApi.startStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to start appinst stream", "err", err)
		return nil, err
	}
	return streamSendObj, err
}

func (s *AppInstApi) stopAppInstStream(ctx context.Context, cctx *CallContext, key *edgeproto.AppInstKey, streamSendObj *streamSend, objErr error, cleanupStream CleanupStreamAction) {
	if err := s.all.streamObjApi.stopStream(ctx, cctx, key.StreamKey(), streamSendObj, objErr, cleanupStream); err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to stop appinst stream", "err", err)
	}
}

func (s *StreamObjApi) StreamAppInst(key *edgeproto.AppInstKey, cb edgeproto.StreamObjApi_StreamAppInstServer) error {
	// populate the clusterinst developer from the app developer if not already present
	return s.StreamMsgs(cb.Context(), key.StreamKey(), cb)
}

type AutoClusterType int

const (
	NoAutoCluster AutoClusterType = iota
	ChooseAutoCluster
	ReservableAutoCluster
	MultiTenantAutoCluster
)

func (s *AppInstApi) checkPortOverlapDedicatedLB(stm concurrency.STM, appPorts []edgeproto.InstPort, appInstKey *edgeproto.AppInstKey, clusterKey *edgeproto.ClusterKey, skipHTTP bool) error {
	clustRefs := edgeproto.ClusterRefs{}
	if !s.all.clusterRefsApi.store.STMGet(stm, clusterKey, &clustRefs) {
		return nil
	}
	for ii := range clustRefs.Apps {
		aiKey := clustRefs.Apps[ii]
		if aiKey == *appInstKey {
			// it's me, happens on delete recovery, ignore
			continue
		}
		obj := edgeproto.AppInst{}
		if !s.all.appInstApi.store.STMGet(stm, &aiKey, &obj) {
			continue
		}
		if obj.State == edgeproto.TrackedState_DELETE_ERROR || edgeproto.IsDeleteState(obj.State) {
			// ignore apps that are being deleted, as several
			// apps may be being created concurrently and their
			// ports may conflict.
			continue
		}
		if obj.DedicatedIp {
			continue
		}
		for ii := range appPorts {
			for jj := range obj.MappedPorts {
				if edgeproto.DoPortsOverlap(appPorts[ii], obj.MappedPorts[jj], skipHTTP) {
					if appPorts[ii].EndPort != appPorts[ii].InternalPort && appPorts[ii].EndPort != 0 {
						return fmt.Errorf("port range %d-%d overlaps with ports in use on the cluster", appPorts[ii].InternalPort, appPorts[ii].EndPort)
					}
					return fmt.Errorf("port %d is already in use on the cluster by AppInst %s", appPorts[ii].InternalPort, obj.Key.Name)
				}
			}
		}
	}
	return nil
}

func removeAppInstFromRefs(appInstKey *edgeproto.AppInstKey, appInstRefs *[]edgeproto.AppInstKey) bool {
	ii := 0
	refsChanged := false
	for ; ii < len(*appInstRefs); ii++ {
		aiKey := (*appInstRefs)[ii]
		if aiKey.Matches(appInstKey) {
			break
		}
	}
	if ii < len(*appInstRefs) {
		// explicity zero out deleted item to
		// pr*event memory leak
		a := *appInstRefs
		copy(a[ii:], a[ii+1:])
		a[len(a)-1] = edgeproto.AppInstKey{}
		*appInstRefs = a[:len(a)-1]
		refsChanged = true
	}
	return refsChanged
}

// getAppInstURI get the Uri for the application instance.
// Takes into account how the app is deployed and features of a given cloudlet
func getAppInstURI(ctx context.Context, appInst *edgeproto.AppInst, app *edgeproto.App, clusterInst *edgeproto.ClusterInst, cloudlet *edgeproto.Cloudlet, cloudletFeatures *edgeproto.PlatformFeatures) string {
	// Internal apps, or apps that don't have ports exposed don't need uri
	ports, _ := edgeproto.ParseAppPorts(app.AccessPorts)
	if app.InternalPorts || len(ports) == 0 {
		return ""
	}

	// uri is specific to appinst if it has dedicated IP, or no cluster
	// also, if an AppInst has HTTP ports and uses ingress, it
	// needs its own URI for host-based routing.
	if !cloudcommon.IsClusterInstReqd(app) || appInst.DedicatedIp || appInst.UsesHTTP() {
		return getAppInstFQDN(appInst, cloudlet)
	}

	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_SHARED {
		// uri points to cloudlet shared root LB
		return cloudlet.RootLbFqdn
	}
	if !isIPAllocatedPerService(ctx, cloudlet.PlatformType, cloudletFeatures, appInst.CloudletKey.Organization) {
		// dedicated access in which IP is that of the LB
		return clusterInst.Fqdn
	}

	// Default to dedicated IP
	return getAppInstFQDN(appInst, cloudlet)
}

func (s *AppInstApi) resolveResourcesSpec(ctx context.Context, stm concurrency.STM, app *edgeproto.App, in *edgeproto.AppInst) error {
	appResources := AppResourcesSpec{
		FlavorKey:           in.Flavor,
		KubernetesResources: in.KubernetesResources,
		NodeResources:       in.NodeResources,
	}
	err := s.all.appApi.resolveAppResourcesSpec(stm, app.Deployment, &appResources)
	if err != nil {
		return err
	}
	in.KubernetesResources = appResources.KubernetesResources
	in.NodeResources = appResources.NodeResources
	return nil
}

// createAppInstInternal is used to create dynamic app insts internally,
// bypassing static assignment.
func (s *AppInstApi) createAppInstInternal(cctx *CallContext, in *edgeproto.AppInst, inCb edgeproto.AppInstApi_CreateAppInstServer) (reterr error) {
	var clusterInst edgeproto.ClusterInst
	var err error
	ctx := inCb.Context()
	cctx.SetOverride(&in.CrmOverride)

	// If the ClusterKey is left blank and a cluster is required,
	// then a cluster will automatically be chosen or created.
	// If a ClusterKey is specified, then the cluster must exist and
	// be allowed to host the AppInst.
	clusterSpecified := false
	if in.ClusterKey.Name != "" || in.ClusterKey.Organization != "" {
		if in.ClusterKey.Organization == "" {
			return fmt.Errorf("cluster organization must also be specified with cluster name")
		}
		if in.ClusterKey.Name == "" {
			return fmt.Errorf("cluster name must also be specified with cluster organization")
		}
		clusterSpecified = true
	}

	appInstKey := in.Key
	// create stream once AppInstKey is formed correctly
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, appInstKey.StreamKey(), inCb)

	if err := in.Key.ValidateKey(); err != nil {
		return err
	}
	if err := in.AppKey.ValidateKey(); err != nil {
		return err
	}

	if in.Liveness == edgeproto.Liveness_LIVENESS_UNKNOWN {
		in.Liveness = edgeproto.Liveness_LIVENESS_STATIC
	}

	createCluster := false
	autoClusterType := NoAutoCluster
	sidecarApp := false
	reservedAutoClusterId := -1
	var reservedCluster *edgeproto.ClusterInst
	var cloudletFeatures *edgeproto.PlatformFeatures
	var cloudletPlatformType string
	var cloudletLoc dme.Loc
	var platformSupportsIPV6 bool
	crmOnEdge := false
	var scaleSpec *resspec.KubeResScaleSpec

	in.CompatibilityVersion = cloudcommon.GetAppInstCompatibilityVersion()

	defer func() {
		if reterr != nil {
			return
		}
		s.RecordAppInstEvent(ctx, in, cloudcommon.CREATED, cloudcommon.InstanceUp)
		if reservedCluster != nil {
			s.all.clusterInstApi.RecordClusterInstEvent(ctx, reservedCluster, cloudcommon.RESERVED, cloudcommon.InstanceUp)
		}
	}()

	// STM ends up modifying input data, but we need to reset those
	// changes if STM reruns, because it may end up choosing a different
	// cloudlet.
	inCopy := edgeproto.AppInst{}
	inCopy.DeepCopyIn(in)
	var app edgeproto.App

	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		// reset modified state in case STM hits conflict and runs again
		createCluster = false
		autoClusterType = NoAutoCluster
		sidecarApp = false
		reservedAutoClusterId = -1
		reservedCluster = nil
		platformSupportsIPV6 = false
		in.DeepCopyIn(&inCopy)
		app = edgeproto.App{}
		scaleSpec = nil

		// lookup App so we can get flavor for reservable ClusterInst
		if !s.all.appApi.store.STMGet(stm, &in.AppKey, &app) {
			return in.AppKey.NotFoundError()
		}
		if app.DeletePrepare {
			return in.AppKey.BeingDeletedError()
		}
		if !cloudcommon.IsClusterInstReqd(&app) {
			if in.ClusterKey.Name != "" {
				return fmt.Errorf("Cluster name must be blank for App deployment type %s", app.Deployment)
			}
			if in.ClusterKey.Organization != "" {
				return fmt.Errorf("Cluster organization must be blank for App deployment type %s", app.Deployment)
			}
		}
		if clusterSpecified {
			autoClusterType = NoAutoCluster
			if in.ClusterKey.Organization == "" {
				return fmt.Errorf("Must specify cluster organization if cluster name is specified")
			}
		}
		if !clusterSpecified && cloudcommon.IsClusterInstReqd(&app) {
			// we'll look for the best fit autocluster
			autoClusterType = ChooseAutoCluster
			if err := validateAutoDeployApp(stm, &app); err != nil {
				return err
			}
		}
		if app.IsStandalone {
			in.IsStandalone = true
		}

		// if no resources specified, inherit from app
		if in.Flavor.Name == "" && in.KubernetesResources == nil && in.NodeResources == nil {
			if app.KubernetesResources != nil {
				in.KubernetesResources = app.KubernetesResources.Clone()
			}
			if app.NodeResources != nil {
				in.NodeResources = app.NodeResources.Clone()
			}
			in.Flavor = app.DefaultFlavor
		}
		// if no kubernetes version specified, inherit from app
		if in.KubernetesResources != nil && app.KubernetesResources != nil {
			if in.KubernetesResources.MinKubernetesVersion == "" {
				in.KubernetesResources.MinKubernetesVersion = app.KubernetesResources.MinKubernetesVersion
			}
		}
		sidecarApp = cloudcommon.IsSideCarApp(&app)
		if sidecarApp && (in.ClusterKey.Name == "" || in.ClusterKey.Organization == "") {
			return fmt.Errorf("Sidecar AppInst (AutoDelete App) must specify the Cluster name and organization to deploy to")
		}
		if err := s.all.autoProvPolicyApi.appInstCheck(ctx, stm, cloudcommon.Create, &app, in); err != nil {
			return err
		}
		if s.store.STMGet(stm, &in.Key, in) {
			if !cctx.Undo && in.State != edgeproto.TrackedState_DELETE_ERROR && !ignoreTransient(cctx, in.State) {
				if in.State == edgeproto.TrackedState_CREATE_ERROR {
					cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Previous create failed, %v", in.Errors)})
					cb.Send(&edgeproto.Result{Message: "Use DeleteAppInst to remove and try again"})
				}
				return in.Key.ExistsError()
			}
			in.Errors = nil
			// must reset Uri
			in.Uri = ""
		} else {
			err := in.Validate(edgeproto.AppInstAllFieldsMap)
			if err != nil {
				return err
			}
		}

		err := s.resolveResourcesSpec(ctx, stm, &app, in)
		if err != nil {
			return err
		}
		// Since autoclusteripaccess is deprecated, set it to unknown
		in.AutoClusterIpAccess = edgeproto.IpAccess_IP_ACCESS_UNKNOWN
		if app.DeploymentManifest != "" {
			err = cloudcommon.IsValidDeploymentManifestForResources(app.Deployment, app.DeploymentManifest, in.KubernetesResources)
			if err != nil {
				return fmt.Errorf("Invalid deployment manifest, %v", err)
			}
		}

		// We need to determine which cloudlet in the target zone will
		// host the instance.
		potentialCloudlets, err := s.getPotentialCloudlets(ctx, cctx, in, &app)
		if err != nil {
			return err
		}
		if cloudcommon.IsClusterInstReqd(&app) {
			// Check if we will use a pre-existing cluster.
			// This may be a cluster specified by the caller, or it may
			// be a system-provided reservable/multi-tenant cluster.
			autoClusterType = ChooseAutoCluster
			potentialClusters, err := s.getPotentialClusters(ctx, cctx, in, &app, potentialCloudlets)
			if err != nil {
				return err
			}
			for _, pc := range potentialClusters {
				clusterInst, err := s.usePotentialCluster(ctx, stm, in, &app, sidecarApp, pc)
				if err != nil && pc.userSpecified {
					// user specified this cluster, so this is a hard failure
					return err
				}
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelApi, "failed to use potential cluster, will try another", "cluster", pc.existingCluster, "cloudlet", pc.cloudletKey, "err", err)
					continue
				}
				if pc.scaleSpec != nil {
					// resources are not available right now, so
					// we defer the resource check until after the
					// cluster has been scaled
					log.SpanLog(ctx, log.DebugLevelApi, "target cluster requires scaling", "pc-cluster", pc.existingCluster, "scaleSpec", pc.scaleSpec)
					scaleSpec = pc.scaleSpec
				} else {
					err := s.potentialClusterResourceCheck(ctx, stm, in, &app, clusterInst, pc.parentPC.flavorLookup)
					if err != nil && pc.userSpecified {
						// user specified this cluster, so this is a hard failure
						return err
					}
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelApi, "failed to confirm potential cluster resources, will try another", "cluster", pc.existingCluster, "cloudlet", pc.cloudletKey, "err", err)
						continue
					}
				}
				// ok to use
				if clusterInst.MultiTenant {
					cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Chose multi-tenant ClusterInst %s to deploy AppInst", clusterInst.Key.Name)})
					autoClusterType = MultiTenantAutoCluster
				} else if clusterInst.Reservable {
					autoClusterType = ReservableAutoCluster
					reservedCluster = clusterInst
					cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Chose reservable ClusterInst %s to deploy AppInst", clusterInst.Key.Name)})
				} else {
					autoClusterType = NoAutoCluster
				}
				in.ClusterKey = pc.existingCluster
				in.CloudletKey = pc.cloudletKey
				in.EnableIpv6 = clusterInst.EnableIpv6
				log.SpanLog(ctx, log.DebugLevelApi, "chose existing cluster", "appinst", in.Key, "cluster", pc.existingCluster, "cloudlet", pc.cloudletKey, "scaleSpec", pc.scaleSpec)
				break
			}
		}
		if in.CloudletKey.Name == "" {
			// No cloudlet chosen, we will choose one based on available resources.
			// Sort potential cloudlets by available resources.
			// TODO: filter this list based on the actual resource requirements
			// for the instance.
			// TODO: Currently we choose the cloudlet with the best free
			// resource score. However that score is calculated on cached
			// data, not part of a transaction. So, we could still fail with
			// out of resources if another thread happens to use that cloudlet
			// before us. Instead, we need to loop over all cloudlets in the
			// list and attempt to use it in a transaction. This is what the
			// createClusterInst code already does. Probably the best solution
			// is to leverage the code in createCluster to figure out which
			// cloudlet to use, but that requires refactoring a bunch of the
			// logic in the this STM which depends on the target cloudlet,
			// and moving it into the createClusterInst code.
			sort.Sort(PotentialInstCloudletsByResource(potentialCloudlets))
			found := false
			log.SpanLog(ctx, log.DebugLevelApi, "no existing clusterinst found, search potential cloudlets")
			for _, pc := range potentialCloudlets {
				ciKey := edgeproto.ClusterKey{
					Name: "potentialClusterInst",
				}
				if pc.features.IsSingleKubernetesCluster {
					// can't create new clusters
					log.SpanLog(ctx, log.DebugLevelApi, "skip potential cloudlet for reservable clusterinst, single kubernetes clusters cannot create new clusters", "cloudlet", pc.cloudlet.Key, "err", err)
					continue
				}
				autoCi, err := s.buildAutocluster(ctx, ciKey, pc.cloudlet.Key, pc.features, &app, in)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelApi, "failed to build auto cluster for potential cloudlet check, skipping", "err", err)
					continue
				}
				_, err = pc.resCalc.CloudletFitsCluster(ctx, autoCi, nil)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelApi, "skip potential cloudlet for reservable clusterinst", "cloudlet", pc.cloudlet.Key, "err", err)
					continue
				}
				found = true
				in.CloudletKey = pc.cloudlet.Key
				log.SpanLog(ctx, log.DebugLevelApi, "chose cloudlet for autocluster", "appinst", in.Key, "cloudlet", in.CloudletKey)
				break
			}
			if !found {
				return fmt.Errorf("no available cloudlet sites to create a new cluster")
			}
		}

		// validate chosen cloudlet
		cloudlet := edgeproto.Cloudlet{}
		if !s.all.cloudletApi.store.STMGet(stm, &in.CloudletKey, &cloudlet) {
			return in.CloudletKey.NotFoundError()
		}
		if cloudlet.DeletePrepare {
			return cloudlet.Key.BeingDeletedError()
		}
		cloudletFeatures, err = s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
		if err != nil {
			return fmt.Errorf("failed to get features for platform, %s", err)
		}
		if err := cloudcommon.ValidateProps(cloudlet.EnvVar); err != nil {
			return err
		}
		// set zone in case caller did not specify
		in.ZoneKey = *cloudlet.GetZone()

		crmOnEdge = cloudlet.CrmOnEdge
		cloudletPlatformType = cloudlet.PlatformType
		cloudletLoc = cloudlet.Location
		info := edgeproto.CloudletInfo{}
		if !s.all.cloudletInfoApi.store.STMGet(stm, &in.CloudletKey, &info) {
			return fmt.Errorf("No resource information found for Cloudlet %s", in.CloudletKey)
		}
		if !cloudcommon.IsClusterInstReqd(&app) && !in.EnableIpv6 {
			// VM Apps default to the platform setting
			in.EnableIpv6 = cloudletFeatures.SupportsIpv6
		}

		// if cluster still needed, set up to create new reservable autocluster
		if cloudcommon.IsClusterInstReqd(&app) && autoClusterType == ChooseAutoCluster {
			refs := edgeproto.CloudletRefs{}
			if !s.all.cloudletRefsApi.store.STMGet(stm, &in.CloudletKey, &refs) {
				initCloudletRefs(&refs, &in.CloudletKey)
			}
			// find and reserve a free id
			id := 0
			for ; id < 64; id++ {
				mask := uint64(1) << id
				if refs.ReservedAutoClusterIds&mask != 0 {
					continue
				}
				refs.ReservedAutoClusterIds |= mask
				break
			}
			if id == 64 {
				return fmt.Errorf("Requested new reservable autocluster but maximum number reached")
			}
			s.all.cloudletRefsApi.store.STMPut(stm, &refs)
			reservedAutoClusterId = id
			createCluster = true
			autoClusterType = ReservableAutoCluster
			in.ClusterKey.Name = cloudcommon.BuildReservableClusterName(id, &in.CloudletKey)
			in.ClusterKey.Organization = edgeproto.OrganizationEdgeCloud
			in.EnableIpv6 = platformSupportsIPV6
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Creating new auto-cluster named %s to deploy AppInst", in.ClusterKey.Name)})
			log.SpanLog(ctx, log.DebugLevelApi, "Creating new auto-cluster", "key", in.GetClusterKey())
		}

		if !cloudcommon.IsClusterInstReqd(&app) {
			// select infra flavor for VM AppInst
			ostm := edgeproto.NewOptionalSTM(stm)
			az, optRes, err := s.all.clusterInstApi.setInfraFlavor(ctx, ostm, &cloudlet, &info, in.NodeResources)
			if err != nil {
				return err
			}
			log.SpanLog(ctx, log.DebugLevelApi, "selected VM AppInst infra node flavor", "flavor", in.NodeResources.InfraNodeFlavor, "availabilityzone", az)
			in.AvailabilityZone = az
			in.OptRes = optRes
		}

		in.Revision = app.Revision
		// there may be direct access apps still defined, disallow them from being instantiated.
		if app.AccessType == edgeproto.AccessType_ACCESS_TYPE_DIRECT {
			return fmt.Errorf("Direct Access Apps are no longer supported, please re-create App as ACCESS_TYPE_LOAD_BALANCER")
		}

		refs := edgeproto.CloudletRefs{}
		if !s.all.cloudletRefsApi.store.STMGet(stm, &in.CloudletKey, &refs) {
			initCloudletRefs(&refs, &in.CloudletKey)
		}
		refsChanged := false
		if app.Deployment == cloudcommon.DeploymentTypeVM {
			// no cluster for vms
			in.ClusterKey = edgeproto.ClusterKey{}
			// check resources
			ostm := edgeproto.NewOptionalSTM(stm)
			resCalc := NewCloudletResCalc(s.all, ostm, &in.CloudletKey)
			warnings, err := resCalc.CloudletFitsVMApp(ctx, &app, in)
			if err != nil {
				return err
			}
			s.all.clusterInstApi.handleResourceUsageAlerts(ctx, stm, &cloudlet.Key, warnings)
			refs.VmAppInsts = append(refs.VmAppInsts, in.Key)
			refsChanged = true
		}
		if refsChanged {
			s.all.cloudletRefsApi.store.STMPut(stm, &refs)
		}
		// Iterate to get a unique id. The number of iterations must
		// be fairly low because the STM has a limit on the number of
		// keys it can manage.
		in.UniqueId = ""
		sanitizer := NewAppInstIDSanitizer(ctx, s, &cloudlet)
		for ii := 0; ii < 10; ii++ {
			salt := ""
			if ii != 0 {
				salt = strconv.Itoa(ii)
			}
			id, err := GetAppInstID(ctx, in, &app, salt, sanitizer)
			if err != nil {
				return err
			}
			if s.idStore.STMHas(stm, id) {
				continue
			}
			in.UniqueId = id
			break
		}
		if in.UniqueId == "" {
			return fmt.Errorf("Unable to compute unique AppInstId, please change AppInst key values")
		}
		in.ObjId = ulid.Make().String()
		if err := s.setDnsLabel(stm, in); err != nil {
			return err
		}
		if !clusterInst.MultiTenant {
			clustRefs := edgeproto.ClusterRefs{}
			if s.all.clusterRefsApi.store.STMGet(stm, in.GetClusterKey(), &clustRefs) {
				for ii := range clustRefs.Apps {
					aiKey := clustRefs.Apps[ii]
					if aiKey == in.Key {
						// it's me, happens on delete recovery, ignore
						continue
					}
					ai := edgeproto.AppInst{}
					if s.all.appInstApi.store.STMGet(stm, &aiKey, &ai) {
						if ai.AppKey == in.AppKey {
							return fmt.Errorf("cannot deploy another instance of App %s to the target cluster", ai.AppKey.GetKeyString())
						}
					}
				}
			}
		}
		// Set new state to show autocluster clusterinst progress as part of
		// appinst progress
		in.State = edgeproto.TrackedState_CREATING_DEPENDENCIES
		s.store.STMPut(stm, in)
		s.idStore.STMPut(stm, in.UniqueId, &in.Key)
		s.dnsLabelStore.STMPut(stm, &in.CloudletKey, in.DnsLabel)
		s.all.appInstRefsApi.addRef(stm, &in.AppKey, &in.Key)
		if cloudcommon.IsClusterInstReqd(&app) {
			s.all.clusterRefsApi.addRef(stm, in)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if reservedCluster != nil {
		clusterInstReservationEvent(ctx, cloudcommon.ReserveClusterEvent, in)
	}

	defer func() {
		if reterr == nil {
			return
		}
		// undo changes on error
		s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			var app edgeproto.App
			if !s.all.appApi.store.STMGet(stm, &in.AppKey, &app) {
				return in.AppKey.NotFoundError()
			}
			refs := edgeproto.CloudletRefs{}
			refsFound := s.all.cloudletRefsApi.store.STMGet(stm, &in.CloudletKey, &refs)
			refsChanged := false
			var curr edgeproto.AppInst
			if s.store.STMGet(stm, &in.Key, &curr) {
				// In case there is an error after CREATING_DEPENDENCIES state
				// is set, then delete AppInst obj directly as there is
				// no change done on CRM side
				if curr.State == edgeproto.TrackedState_CREATING_DEPENDENCIES {
					s.store.STMDel(stm, &in.Key)
					s.idStore.STMDel(stm, in.UniqueId)
					if in.FedKey.FederationName != "" {
						s.fedStore.STMDel(stm, &in.FedKey)
					}
					s.dnsLabelStore.STMDel(stm, &in.CloudletKey, in.DnsLabel)
					s.all.appInstRefsApi.removeRef(stm, &in.AppKey, &in.Key)
					if cloudcommon.IsClusterInstReqd(&app) {
						s.all.clusterRefsApi.removeRef(stm, in)
					}
					if refsFound {
						if app.Deployment == cloudcommon.DeploymentTypeVM {
							refsChanged = removeAppInstFromRefs(&in.Key, &refs.VmAppInsts)
						}
					}
				}
			}
			// Cleanup reserved id on failure. Note that if we fail
			// after creating the auto-cluster, then deleting the
			// ClusterInst will cleanup the reserved id instead.
			if reservedAutoClusterId != -1 {
				if refsFound {
					mask := uint64(1) << reservedAutoClusterId
					refs.ReservedAutoClusterIds &^= mask
					refsChanged = true
				}
			}
			if refsFound && refsChanged {
				s.all.cloudletRefsApi.store.STMPut(stm, &refs)
			}
			// Remove reservation (if done) on failure.
			if reservedCluster != nil {
				cinst := edgeproto.ClusterInst{}
				if s.all.clusterInstApi.store.STMGet(stm, &reservedCluster.Key, &cinst) {
					cinst.ReservedBy = ""
					s.all.clusterInstApi.store.STMPut(stm, &cinst)
				}
			}
			return nil
		})
		if reservedCluster != nil {
			clusterInstReservationEvent(ctx, cloudcommon.FreeClusterEvent, in)
		}
	}()

	sendObj, err := s.startAppInstStream(ctx, cctx, streamCb, modRev)
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
		s.stopAppInstStream(ctx, cctx, &appInstKey, sendObj, reterr, cleanupStream)
	}()

	clusterKey := *in.GetClusterKey()

	if createCluster {
		// auto-create cluster inst
		log.SpanLog(ctx, log.DebugLevelApi, "Create auto-ClusterInst", "key", clusterInst.Key, "AppInst", in)
		ci, err := s.buildAutocluster(ctx, clusterKey, in.CloudletKey, cloudletFeatures, &app, in)
		if err != nil {
			return err
		}
		clusterInst = *ci

		createStart := time.Now()
		cctxauto := cctx.WithAutoCluster()
		err = s.all.clusterInstApi.createClusterInstInternal(cctxauto, &clusterInst, cb)
		nodeMgr.TimedEvent(ctx, "AutoCluster create", in.Key.Organization, node.EventType, in.GetTags(), err, createStart, time.Now())
		clusterInstReservationEvent(ctx, cloudcommon.ReserveClusterEvent, in)
		if err != nil {
			return err
		}
		// disable the previous defer func for cleaning up the reserved id,
		// as the following defer func to cleanup the ClusterInst will
		// free it instead.
		reservedAutoClusterId = -1

		defer func() {
			if reterr != nil && !cctx.Undo {
				cb.Send(&edgeproto.Result{Message: "Deleting auto-ClusterInst due to failure"})
				undoErr := s.all.clusterInstApi.deleteClusterInstInternal(cctxauto.WithUndo().WithCRMUndo().WithStream(sendObj), &clusterInst, cb)
				if undoErr != nil {
					log.SpanLog(ctx, log.DebugLevelApi,
						"Undo create auto-ClusterInst failed",
						"key", clusterInst.Key,
						"undoErr", undoErr)
				}
			}
		}()
	} else if scaleSpec != nil {
		cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Scaling existing cluster %s to deploy AppInst", clusterKey.Name)})
		log.SpanLog(ctx, log.DebugLevelApi, "scale existing cluster", "cluster", clusterKey, "AppInst", in.Key, "scaleSpec", scaleSpec)
		clusterInst.Key = clusterKey
		clusterInst.CloudletKey = in.CloudletKey
		clusterInst.Fields = []string{
			// bypass empty fields check
			edgeproto.ClusterInstFieldKey,
		}
		updateStart := time.Now()
		err := s.all.clusterInstApi.updateClusterInstInternal(cctx, &clusterInst, scaleSpec, cb)
		nodeMgr.TimedEvent(ctx, "AppInst Cluster Scale", in.Key.Organization, node.EventType, in.GetTags(), err, updateStart, time.Now())
		if err != nil {
			return err
		}
		// TODO: we need some mechanism to scale back down a
		// scalable node pool if it hasn't been in use for some time
	}

	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		// lookup already done, don't overwrite changes
		if s.store.STMGet(stm, &in.Key, in) {
			if in.State != edgeproto.TrackedState_CREATING_DEPENDENCIES {
				return in.Key.ExistsError()
			}
		} else {
			return fmt.Errorf("Unexpected error: AppInst %s was deleted", in.Key.GetKeyString())
		}

		// cache location of cloudlet in app inst
		in.CloudletLoc = cloudletLoc

		var app edgeproto.App
		if !s.all.appApi.store.STMGet(stm, &in.AppKey, &app) {
			return in.AppKey.NotFoundError()
		}

		cloudlet := edgeproto.Cloudlet{}
		if !s.all.cloudletApi.store.STMGet(stm, &in.CloudletKey, &cloudlet) {
			return in.CloudletKey.NotFoundError()
		}
		info := edgeproto.CloudletInfo{}
		if !s.all.cloudletInfoApi.store.STMGet(stm, &in.CloudletKey, &info) {
			return fmt.Errorf("no resource information found for Cloudlet %s", in.CloudletKey)
		}
		clusterInst := edgeproto.ClusterInst{}
		ipaccess := edgeproto.IpAccess_IP_ACCESS_SHARED
		if cloudcommon.IsClusterInstReqd(&app) {
			if !s.all.clusterInstApi.store.STMGet(stm, in.GetClusterKey(), &clusterInst) {
				return errors.New("ClusterInst does not exist for App")
			}
			if clusterInst.State != edgeproto.TrackedState_READY {
				return fmt.Errorf("ClusterInst %s not ready, it is %s", clusterInst.Key.GetKeyString(), clusterInst.State.String())
			}
			if !sidecarApp && clusterInst.Reservable && clusterInst.ReservedBy != in.Key.Organization {
				return fmt.Errorf("ClusterInst reservation changed unexpectedly, expected %s but was %s", in.Key.Organization, clusterInst.ReservedBy)
			}
			needDeployment := app.Deployment
			if app.Deployment == cloudcommon.DeploymentTypeHelm {
				needDeployment = cloudcommon.DeploymentTypeKubernetes
			}
			if clusterInst.Deployment != needDeployment {
				return fmt.Errorf("Cannot deploy %s App into %s ClusterInst", app.Deployment, clusterInst.Deployment)
			}
			ipaccess = clusterInst.IpAccess
			if scaleSpec != nil {
				// we deferred the STM resource check until after
				// the cluster was scaled, so do it now.
				err := s.potentialClusterResourceCheck(ctx, stm, in, &app, &clusterInst, info.GetFlavorLookup())
				if err != nil {
					return err
				}
			}
		}

		cloudletRefs := edgeproto.CloudletRefs{}
		cloudletRefsChanged := false
		if !s.all.cloudletRefsApi.store.STMGet(stm, &in.CloudletKey, &cloudletRefs) {
			initCloudletRefs(&cloudletRefs, &in.CloudletKey)
		}

		ports, _ := edgeproto.ParseAppPorts(app.AccessPorts)
		for ii := range ports {
			// HTTP port special handling
			if ports[ii].IsHTTP() {
				if !cloudletFeatures.UsesIngress {
					// If the cloudlet does not support ingress, then
					// we convert HTTP ports to TCP, and from this point
					// on throughout all the rest of the platform code,
					// these ports are treated as TCP ports.
					ports[ii].Proto = dme.LProto_L_PROTO_TCP
				} else {
					// port will be fronted by ingress, set the
					// public port for all LB cases
					var publicPort int32
					if ports[ii].Tls {
						val, err := cloudcommon.GetIngressHTTPSPort(cloudlet.EnvVar)
						if err != nil {
							return err
						}
						publicPort = val
					} else {
						val, err := cloudcommon.GetIngressHTTPPort(cloudlet.EnvVar)
						if err != nil {
							return err
						}
						publicPort = val
					}
					ports[ii].PublicPort = publicPort
				}
			}
		}
		if !cloudcommon.IsClusterInstReqd(&app) {
			for ii := range ports {
				ports[ii].PublicPort = ports[ii].InternalPort
			}
		} else if in.DedicatedIp {
			// Per AppInst dedicated IP
			for ii := range ports {
				if ports[ii].IsHTTP() {
					continue
				}
				ports[ii].PublicPort = ports[ii].InternalPort
			}
		} else if ipaccess == edgeproto.IpAccess_IP_ACCESS_SHARED && !app.InternalPorts {
			if cloudletRefs.RootLbPorts == nil {
				cloudletRefs.RootLbPorts = make(map[int32]int32)
			}

			for ii, port := range ports {
				if port.EndPort != 0 {
					return fmt.Errorf("Shared IP access with port range not allowed")
				}
				if port.IsHTTP() {
					continue
				}
				// platos enabling layer ignores port mapping.
				// Attempt to use the internal port as the
				// external port so port remap is not required.
				protocolBits, err := getProtocolBitMap(ports[ii].Proto)
				if err != nil {
					return err
				}
				iport := ports[ii].InternalPort
				eport := int32(-1)
				if usedProtocols, found := cloudletRefs.RootLbPorts[iport]; !found || !protocolInUse(protocolBits, usedProtocols) {

					// rootLB has its own ports it uses
					// before any apps are even present.
					iport := ports[ii].InternalPort
					if iport != 22 && iport != cloudcommon.ProxyMetricsPort {
						eport = iport
					}
				}
				for p := RootLBSharedPortBegin; p < 65000 && eport == int32(-1); p++ {
					// each kubernetes service gets its own
					// nginx proxy that runs in the rootLB,
					// and http ports are also mapped to it,
					// so there is no shared L7 port + path.
					if usedProtocols, found := cloudletRefs.RootLbPorts[p]; found && protocolInUse(protocolBits, usedProtocols) {

						continue
					}
					eport = p
				}
				if eport == int32(-1) {
					return errors.New("no free external ports")
				}
				ports[ii].PublicPort = eport
				existingProtoBits := cloudletRefs.RootLbPorts[eport]
				cloudletRefs.RootLbPorts[eport] = addProtocol(protocolBits, existingProtoBits)

				cloudletRefsChanged = true
			}
		} else {
			if isIPAllocatedPerService(ctx, cloudletPlatformType, cloudletFeatures, in.CloudletKey.Organization) {
				// dedicated access in which each service gets a different ip
				for ii := range ports {
					if ports[ii].IsHTTP() {
						continue
					}
					ports[ii].PublicPort = ports[ii].InternalPort
				}
			} else {
				// we need to prevent overlapping ports on the dedicated rootLB
				skipHTTP := cloudcommon.AppDeploysToKubernetes(app.Deployment) && cloudletFeatures.UsesIngress
				if err = s.checkPortOverlapDedicatedLB(stm, ports, &in.Key, &clusterKey, skipHTTP); !cctx.Undo && err != nil {
					return err
				}
				for ii := range ports {
					ports[ii].PublicPort = ports[ii].InternalPort
				}
			}
		}
		if len(ports) > 0 {
			in.MappedPorts = ports
			if isIPAllocatedPerService(ctx, cloudletPlatformType, cloudletFeatures, in.CloudletKey.Organization) {
				setPortFQDNPrefixes(in, &app)
			}
		}

		// TODO: Make sure resources are available
		if cloudletRefsChanged {
			s.all.cloudletRefsApi.store.STMPut(stm, &cloudletRefs)
		}
		in.CreatedAt = dme.TimeToTimestamp(time.Now())

		if ignoreCRM(cctx) {
			in.State = edgeproto.TrackedState_READY
		} else {
			in.State = edgeproto.TrackedState_CREATE_REQUESTED
		}
		in.Uri = getAppInstURI(ctx, in, &app, &clusterInst, &cloudlet, cloudletFeatures)
		if err := cloudcommon.CheckFQDNLengths("", in.Uri); err != nil {
			return err
		}
		in.StaticUri = in.Uri
		s.store.STMPut(stm, in)
		return nil
	})
	if err != nil {
		return err
	}
	if ignoreCRM(cctx) {
		cb.Send(&edgeproto.Result{Message: "Created AppInst successfully"})
		return nil
	}
	reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().CreateAppInstTimeout.TimeDuration())
	defer reqCancel()

	crmAction := func() error {
		successMsg := "Created AppInst successfully"
		if crmOnEdge {
			return edgeproto.WaitForAppInstInfo(reqCtx, &in.Key, s.store,
				edgeproto.TrackedState_READY,
				CreateAppInstTransitions, edgeproto.TrackedState_CREATE_ERROR,
				successMsg, cb.Send, sendObj.crmMsgCh,
			)
		} else {
			conn, err := services.platformServiceConnCache.GetConn(ctx, cloudletFeatures.NodeType)
			if err != nil {
				return err
			}
			api := edgeproto.NewAppInstPlatformAPIClient(conn)
			in.Fields = edgeproto.AppInstAllFields
			outStream, err := api.ApplyAppInst(reqCtx, in)
			if err != nil {
				return cloudcommon.GRPCErrorUnwrap(err)
			}
			err = cloudcommon.StreamRecvWithStatus(ctx, outStream, cb.Send, func(info *edgeproto.AppInstInfo) error {
				s.all.appInstApi.UpdateFromInfo(ctx, info)
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
		cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Create AppInst ignoring CRM failure: %s", err.Error())})
		s.ReplaceErrorState(ctx, in, edgeproto.TrackedState_READY)
		cb.Send(&edgeproto.Result{Message: "Created AppInst successfully"})
		err = nil
	}
	if err != nil {
		// XXX should probably track mod revision ID and only undo
		// if no other changes were made to appInst in the meantime.
		// crm failed or some other err, undo
		cb.Send(&edgeproto.Result{Message: "Deleting AppInst due to failure"})
		undoErr := s.deleteAppInstInternal(cctx.WithUndo().WithStream(sendObj), in, cb)
		if undoErr != nil {
			log.InfoLog("Undo create AppInst", "undoErr", undoErr)
		}
	}
	if err == nil {
		s.updateCloudletResourcesMetric(ctx, in)
	}
	return err
}

func (s *AppInstApi) buildAutocluster(ctx context.Context, clusterKey edgeproto.ClusterKey, cloudletKey edgeproto.CloudletKey, features *edgeproto.PlatformFeatures, app *edgeproto.App, in *edgeproto.AppInst) (*edgeproto.ClusterInst, error) {
	clusterInst := edgeproto.ClusterInst{}
	clusterInst.Key = clusterKey
	clusterInst.CloudletKey = cloudletKey
	clusterInst.Auto = true
	clusterInst.Reservable = true
	clusterInst.ReservedBy = in.Key.Organization

	// To reduce the proliferation of different reservable ClusterInst
	// configurations, we restrict reservable ClusterInst configs.
	if err := setClusterResourcesForReqs(ctx, &clusterInst, app, in); err != nil {
		return nil, err
	}
	// Prefer IP access shared, but some platforms (gcp, etc) only
	// support dedicated.
	clusterInst.IpAccess = edgeproto.IpAccess_IP_ACCESS_UNKNOWN
	clusterInst.Deployment = app.Deployment
	clusterInst.EnableIpv6 = features.SupportsIpv6
	if cloudcommon.AppDeploysToKubernetes(app.Deployment) {
		clusterInst.Deployment = cloudcommon.DeploymentTypeKubernetes
		clusterInst.NumMasters = 1
		clusterInst.EnableIpv6 = false
	}
	clusterInst.Liveness = edgeproto.Liveness_LIVENESS_DYNAMIC
	return &clusterInst, nil
}

func (s *AppInstApi) useReservableClusterInst(stm concurrency.STM, ctx context.Context, in *edgeproto.AppInst, app *edgeproto.App, sidecarApp bool, cibuf *edgeproto.ClusterInst) error {
	if !cibuf.Reservable {
		return fmt.Errorf("ClusterInst not reservable")
	}
	if sidecarApp {
		// no restrictions, no reservation
		return nil
	}
	if cibuf.ReservedBy != "" && cibuf.ReservedBy != in.Key.Organization {
		return fmt.Errorf("ClusterInst already reserved")
	}
	targetDeployment := app.Deployment
	if app.Deployment == cloudcommon.DeploymentTypeHelm {
		targetDeployment = cloudcommon.DeploymentTypeKubernetes
	}
	if targetDeployment != cibuf.Deployment {
		return fmt.Errorf("deployment type mismatch between App and reservable ClusterInst")
	}
	if in.EnableIpv6 && !cibuf.EnableIpv6 {
		return fmt.Errorf("AppInst requests for IPv6 but cluster does not have it enabled")
	}
	// reserve it
	log.SpanLog(ctx, log.DebugLevelApi, "reserving ClusterInst", "cluster", cibuf.Key.Name, "AppInst", in.Key)
	cibuf.ReservedBy = in.Key.Organization
	s.all.clusterInstApi.store.STMPut(stm, cibuf)
	return nil
}

func useMultiTenantClusterInst(stm concurrency.STM, ctx context.Context, in *edgeproto.AppInst, app *edgeproto.App, sidecarApp bool, cibuf *edgeproto.ClusterInst) error {
	if !cibuf.MultiTenant {
		return fmt.Errorf("ClusterInst not multi-tenant")
	}
	if sidecarApp {
		// no restrictions, no resource check
	}
	if !app.AllowServerless {
		return fmt.Errorf("App must allow serverless deployment to deploy to multi-tenant cluster %s", cibuf.Key.Name)
	}
	if app.Deployment != cloudcommon.DeploymentTypeKubernetes {
		// helm not supported
		return fmt.Errorf("Deployment type must be kubernetes for multi-tenant ClusterInst")
	}
	if in.EnableIpv6 && !cibuf.EnableIpv6 {
		return fmt.Errorf("AppInst requests for IPv6 but cluster does not have it enabled")
	}
	return nil
}

func (s *AppInstApi) updateCloudletResourcesMetric(ctx context.Context, in *edgeproto.AppInst) {
	var err error
	metrics := []*edgeproto.Metric{}
	skipMetric := true
	resErr := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		var cloudlet edgeproto.Cloudlet
		if !s.all.cloudletApi.store.STMGet(stm, &in.CloudletKey, &cloudlet) {
			return in.CloudletKey.NotFoundError()
		}
		var app edgeproto.App
		if !s.all.appApi.store.STMGet(stm, &in.AppKey, &app) {
			return in.AppKey.NotFoundError()
		}
		skipMetric = true
		if app.Deployment == cloudcommon.DeploymentTypeVM {
			metrics, err = s.all.clusterInstApi.getCloudletResourceMetric(ctx, stm, &in.CloudletKey)
			skipMetric = false
			return err
		}
		cloudletFeatures, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
		if err != nil {
			return fmt.Errorf("Failed to get features for platform: %s", err)
		}
		if platform.TrackK8sAppInst(ctx, &app, cloudletFeatures) {
			metrics, err = s.all.clusterInstApi.getCloudletResourceMetric(ctx, stm, &in.CloudletKey)
			skipMetric = false
			return err
		}
		return nil
	})
	if !skipMetric {
		if resErr == nil {
			services.cloudletResourcesInfluxQ.AddMetric(metrics...)
		} else {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to generate cloudlet resource usage metric", "clusterKey", in.Key, "err", resErr)
		}
	}
}

func (s *AppInstApi) updateAppInstStore(ctx context.Context, in *edgeproto.AppInst) error {
	_, err := s.store.Update(ctx, in, s.sync.SyncWait)
	return err
}

// refreshAppInstInternal returns true if the appinst updated, false otherwise.  False value with no error means no update was needed
func (s *AppInstApi) refreshAppInstInternal(cctx *CallContext, key edgeproto.AppInstKey, appKey edgeproto.AppKey, inCb edgeproto.AppInstApi_RefreshAppInstServer, forceUpdate, vmAppIpv6Enabled bool, updateDiffFields *edgeproto.FieldMap) (retbool bool, reterr error) {
	ctx := inCb.Context()
	log.SpanLog(ctx, log.DebugLevelApi, "refreshAppInstInternal", "key", key)

	updatedRevision := false
	crmUpdateRequired := false

	err := key.ValidateKey()
	if err != nil {
		return false, err
	}

	// create stream once AppInstKey is formed correctly
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, key.StreamKey(), inCb)

	var app edgeproto.App
	var curr edgeproto.AppInst

	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		if !s.all.appApi.store.STMGet(stm, &appKey, &app) {
			return appKey.NotFoundError()
		}
		if s.store.STMGet(stm, &key, &curr) {
			// allow UPDATE_ERROR state so updates can be retried
			if curr.State != edgeproto.TrackedState_READY && curr.State != edgeproto.TrackedState_UPDATE_ERROR {
				log.InfoLog("AppInst is not ready or update_error state for update", "state", curr.State)
				return fmt.Errorf("AppInst is not ready or update_error")
			}
			if curr.Revision != app.Revision || forceUpdate {
				crmUpdateRequired = true
				updatedRevision = true
			} else {
				return nil
			}
		} else {
			return key.NotFoundError()
		}
		if ignoreCRM(cctx) {
			crmUpdateRequired = false
		} else {
			// check cloudlet state before updating
			cloudletErr := s.all.cloudletInfoApi.checkCloudletReadySTM(cctx, stm, &curr.CloudletKey, cloudcommon.Update)
			if crmUpdateRequired && cloudletErr != nil {
				return cloudletErr
			}
			curr.State = edgeproto.TrackedState_UPDATE_REQUESTED
		}
		s.store.STMPut(stm, &curr)
		return nil
	})

	if err != nil {
		return false, err
	}

	sendObj, err := s.startAppInstStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		return false, err
	}
	defer func() {
		s.stopAppInstStream(ctx, cctx, &key, sendObj, reterr, NoCleanupStream)
	}()

	if crmUpdateRequired {
		s.RecordAppInstEvent(ctx, &curr, cloudcommon.UPDATE_START, cloudcommon.InstanceDown)

		defer func() {
			if reterr == nil {
				s.RecordAppInstEvent(ctx, &curr, cloudcommon.UPDATE_COMPLETE, cloudcommon.InstanceUp)
			} else {
				s.RecordAppInstEvent(ctx, &curr, cloudcommon.UPDATE_ERROR, cloudcommon.InstanceDown)
			}
		}()
		reqCtx, reqCancel := context.WithTimeout(cb.Context(), s.all.settingsApi.Get().UpdateAppInstTimeout.TimeDuration())
		defer reqCancel()

		cloudlet := edgeproto.Cloudlet{}
		if !s.all.cloudletApi.cache.Get(&curr.CloudletKey, &cloudlet) {
			return false, curr.CloudletKey.NotFoundError()
		}
		if cloudlet.CrmOnEdge {
			err = edgeproto.WaitForAppInstInfo(reqCtx, &key, s.store, edgeproto.TrackedState_READY,
				UpdateAppInstTransitions, edgeproto.TrackedState_UPDATE_ERROR,
				"", cb.Send, sendObj.crmMsgCh,
			)
		} else {
			features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
			if err != nil {
				return false, err
			}
			conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
			if err != nil {
				return false, err
			}
			api := edgeproto.NewAppInstPlatformAPIClient(conn)
			curr.Fields = []string{edgeproto.AppInstFieldState}
			if updateDiffFields != nil {
				for _, k := range updateDiffFields.Fields() {
					curr.Fields = append(curr.Fields, k)
				}
			}
			outStream, err := api.ApplyAppInst(reqCtx, &curr)
			if err != nil {
				return false, cloudcommon.GRPCErrorUnwrap(err)
			}
			err = cloudcommon.StreamRecvWithStatus(ctx, outStream, cb.Send, func(info *edgeproto.AppInstInfo) error {
				s.all.appInstApi.UpdateFromInfo(ctx, info)
				return nil
			})
			if err != nil {
				return false, err
			}
		}
		if err != nil {
			return false, err
		}
		if vmAppIpv6Enabled {
			cb.Send(&edgeproto.Result{Message: "IPv6 enabled, you may need to manually update the network configuration on your VM"})
		}
	}
	return updatedRevision, s.updateAppInstRevision(ctx, &key, app.Revision)
}

func (s *AppInstApi) RefreshAppInst(in *edgeproto.AppInst, cb edgeproto.AppInstApi_RefreshAppInstServer) error {
	ctx := cb.Context()

	type updateResult struct {
		errString       string
		revisionUpdated bool
	}
	instanceUpdateResults := make(map[edgeproto.AppInstKey]chan updateResult)
	instances := make(map[edgeproto.AppInstKey]struct{})
	singleAppInst := false

	if in.UpdateMultiple {
		// if UpdateMultiple flag is specified, then only the appkey must be present
		if err := in.AppKey.ValidateKey(); err != nil {
			return err
		}
		s.cache.Mux.Lock()
		for k, data := range s.cache.Objs {
			val := data.Obj
			// ignore forceupdate, Crmoverride updatemultiple for match
			val.ForceUpdate = in.ForceUpdate
			val.UpdateMultiple = in.UpdateMultiple
			val.CrmOverride = in.CrmOverride
			if !val.Matches(in, edgeproto.MatchFilter()) {
				continue
			}
			instances[k] = struct{}{}
			instanceUpdateResults[k] = make(chan updateResult)

		}
		s.cache.Mux.Unlock()
	} else {
		// the whole key must be present
		if err := in.Key.ValidateKey(); err != nil {
			return fmt.Errorf("cluster key needed without updatemultiple option: %v", err)
		}
		if !s.store.Get(ctx, &in.Key, in) {
			return in.Key.NotFoundError()
		}
		instances[in.Key] = struct{}{}
		instanceUpdateResults[in.Key] = make(chan updateResult)
		singleAppInst = true
	}
	appKey := in.AppKey

	if len(instances) == 0 {
		log.SpanLog(ctx, log.DebugLevelApi, "no AppInsts matched", "key", in.Key)
		return in.Key.NotFoundError()
	}

	if !singleAppInst {
		cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Updating: %d AppInsts", len(instances))})
	}

	vmAppIpv6Enabled := false
	for instkey := range instances {
		go func(k edgeproto.AppInstKey) {
			log.SpanLog(ctx, log.DebugLevelApi, "updating AppInst", "key", k)
			updated, err := s.refreshAppInstInternal(DefCallContext(), k, appKey, cb, in.ForceUpdate, vmAppIpv6Enabled, nil)
			if err == nil {
				instanceUpdateResults[k] <- updateResult{errString: "", revisionUpdated: updated}
			} else {
				instanceUpdateResults[k] <- updateResult{errString: err.Error(), revisionUpdated: updated}
			}
		}(instkey)
	}

	numUpdated := 0
	numFailed := 0
	numSkipped := 0
	numTotal := 0
	for k, r := range instanceUpdateResults {
		numTotal++
		result := <-r
		log.SpanLog(ctx, log.DebugLevelApi, "instanceUpdateResult ", "key", k, "updated", result.revisionUpdated, "error", result.errString)
		if result.errString == "" {
			if result.revisionUpdated {
				numUpdated++
				if singleAppInst {
					cb.Send(&edgeproto.Result{Message: "Successfully updated AppInst"})
				}
			} else {
				numSkipped++
				if singleAppInst {
					cb.Send(&edgeproto.Result{Message: "Skipped updating AppInst"})
				}
			}
		} else {
			numFailed++
			if singleAppInst {
				return fmt.Errorf("%s", result.errString)
			} else {
				cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Failed for AppInst %s[%s]: %s", k.Name, k.Organization, result.errString)})
			}
		}
		// give some intermediate status
		if (numTotal%10 == 0) && numTotal != len(instances) {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Processing: %d of %d AppInsts.  Updated: %d Skipped: %d Failed: %d", numTotal, len(instances), numUpdated, numSkipped, numFailed)})
		}
	}
	if !singleAppInst {
		cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Completed: %d of %d AppInsts.  Updated: %d Skipped: %d Failed: %d", numTotal, len(instances), numUpdated, numSkipped, numFailed)})
	}
	return nil
}

func (s *AppInstApi) UpdateAppInst(in *edgeproto.AppInst, cb edgeproto.AppInstApi_UpdateAppInstServer) error {
	ctx := cb.Context()
	err := in.ValidateUpdateFields()
	if err != nil {
		return err
	}
	fmap := edgeproto.MakeFieldMap(in.Fields)
	err = in.Validate(fmap)
	if err != nil {
		return err
	}
	powerState := edgeproto.PowerState_POWER_STATE_UNKNOWN
	if fmap.Has(edgeproto.AppInstFieldPowerState) {
		for _, field := range in.Fields {
			if field == edgeproto.AppInstFieldCrmOverride ||
				field == edgeproto.AppInstFieldKey ||
				field == edgeproto.AppInstFieldPowerState ||
				in.IsKeyField(field) {
				continue
			} else if edgeproto.UpdateAppInstFieldsMap.Has(field) {
				return fmt.Errorf("If powerstate is to be updated, then no other fields can be modified")
			}
		}
		// Get the request state as user has specified action and not state
		powerState = edgeproto.GetNextPowerState(in.PowerState, edgeproto.RequestState)
		if powerState == edgeproto.PowerState_POWER_STATE_UNKNOWN {
			return fmt.Errorf("Invalid power state specified")
		}
	}

	resChange := false
	if fmap.HasOrHasChild(edgeproto.AppInstFieldFlavor) || fmap.HasOrHasChild(edgeproto.AppInstFieldKubernetesResources) || fmap.HasOrHasChild(edgeproto.AppFieldKubernetesResources) {
		resChange = true
	}

	cctx := DefCallContext()
	cctx.SetOverride(&in.CrmOverride)

	cur := edgeproto.AppInst{}
	changeCount := 0
	vmAppIpv6Enabled := false
	var diffFields *edgeproto.FieldMap
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		var app edgeproto.App
		if !s.all.appApi.store.STMGet(stm, &cur.AppKey, &app) {
			return in.AppKey.NotFoundError()
		}
		if fmap.Has(edgeproto.AppInstFieldEnableIpv6) {
			if cloudcommon.IsClusterInstReqd(&app) {
				// ipv6 setting is based on clusterInst setting
				clusterInst := edgeproto.ClusterInst{}
				if !s.all.clusterInstApi.store.STMGet(stm, cur.GetClusterKey(), &clusterInst) {
					return cur.GetClusterKey().NotFoundError()
				}
				if in.EnableIpv6 && !clusterInst.EnableIpv6 {
					return fmt.Errorf("cannot enable IPv6 when cluster does not have it enabled, please enable on cluster first")
				}
			} else {
				// VM app, can only enable if platform supports it
				cloudlet := edgeproto.Cloudlet{}
				if !s.all.cloudletApi.store.STMGet(stm, &in.CloudletKey, &cloudlet) {
					return in.CloudletKey.NotFoundError()
				}
				features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
				if err != nil {
					return fmt.Errorf("Failed to get features for platform: %s", err)
				}
				if in.EnableIpv6 && !features.SupportsIpv6 {
					return fmt.Errorf("cloudlet platform does not support IPv6")
				}
				if in.EnableIpv6 && !cur.EnableIpv6 {
					vmAppIpv6Enabled = true
				}
			}
		}
		old := edgeproto.AppInst{}
		old.DeepCopyIn(&cur)
		changeCount = cur.CopyInFields(in)
		if changeCount == 0 {
			// nothing changed
			return nil
		}
		if resChange {
			if !cloudcommon.IsClusterInstReqd(&app) {
				return errors.New("cannot modify resources allocated to VM deployments")
			}
			// In clusters, resource specs can be changed because
			// they specify the resources to be reserved, and do not
			// correspond to any change in the deployment.
			err := s.resolveResourcesSpec(ctx, stm, &app, &cur)
			if err != nil {
				return err
			}
			clusterInst := edgeproto.ClusterInst{}
			if !s.all.clusterInstApi.store.STMGet(stm, &cur.ClusterKey, &clusterInst) {
				return cur.ClusterKey.NotFoundError()
			}
			cloudletInfo := edgeproto.CloudletInfo{}
			s.all.cloudletInfoApi.store.STMGet(stm, &cur.CloudletKey, &cloudletInfo)
			refs := edgeproto.ClusterRefs{}
			if !s.all.clusterRefsApi.store.STMGet(stm, &cur.ClusterKey, &refs) {
				refs.Key = cur.ClusterKey
			}
			// ensure that cluster can fit new specified resources
			_, _, err = s.all.clusterInstApi.fitsAppResources(ctx, &clusterInst, &refs, &app, &cur, cloudletInfo.GetFlavorLookup())
			if err != nil {
				return err
			}
		}
		diffFields = old.GetDiffFields(&cur)
		if !ignoreCRM(cctx) && powerState != edgeproto.PowerState_POWER_STATE_UNKNOWN {
			if app.Deployment != cloudcommon.DeploymentTypeVM {
				return fmt.Errorf("Updating powerstate is only supported for VM deployment")
			}
			cur.PowerState = powerState
		}
		cur.UpdatedAt = dme.TimeToTimestamp(time.Now())
		s.store.STMPut(stm, &cur)
		return nil
	})
	if err != nil {
		return err
	}
	if changeCount == 0 {
		return nil
	}
	if ignoreCRM(cctx) {
		return nil
	}
	forceUpdate := true
	_, err = s.refreshAppInstInternal(cctx, in.Key, cur.AppKey, cb, forceUpdate, vmAppIpv6Enabled, diffFields)
	return err
}

func (s *AppInstApi) DeleteAppInst(in *edgeproto.AppInst, cb edgeproto.AppInstApi_DeleteAppInstServer) error {
	return s.deleteAppInstInternal(DefCallContext(), in, cb)
}

func (s *AppInstApi) deleteAppInstInternal(cctx *CallContext, in *edgeproto.AppInst, inCb edgeproto.AppInstApi_DeleteAppInstServer) (reterr error) {
	cctx.SetOverride(&in.CrmOverride)
	ctx := inCb.Context()

	var app edgeproto.App
	var reservationFreed bool
	var clusterInstReqd bool
	clusterInst := edgeproto.ClusterInst{}

	err := in.Key.ValidateKey()
	if err != nil {
		return err
	}

	appInstKey := in.Key
	// create stream once AppInstKey is formed correctly
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, appInstKey.StreamKey(), inCb)

	// get appinst info for flavor
	appInstInfo := edgeproto.AppInst{}
	if !s.cache.Get(&in.Key, &appInstInfo) {
		return in.Key.NotFoundError()
	}
	defer func() {
		if reterr != nil {
			return
		}
		s.RecordAppInstEvent(ctx, in, cloudcommon.DELETED, cloudcommon.InstanceDown)
		if reservationFreed {
			s.all.clusterInstApi.RecordClusterInstEvent(ctx, &clusterInst, cloudcommon.UNRESERVED, cloudcommon.InstanceDown)
		}
	}()

	crmOnEdge := false
	nodeType := ""
	log.SpanLog(ctx, log.DebugLevelApi, "deleteAppInstInternal", "AppInst", in)
	// populate the clusterinst developer from the app developer if not already present
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		// clear change tracking vars in case STM is rerun due to conflict.
		reservationFreed = false

		if !s.store.STMGet(stm, &in.Key, in) {
			// already deleted
			return in.Key.NotFoundError()
		}
		if err := validateDeleteState(cctx, "AppInst", in.State, in.Errors, cb.Send); err != nil {
			return err
		}
		if err := s.all.cloudletInfoApi.checkCloudletReadySTM(cctx, stm, &in.CloudletKey, cloudcommon.Delete); err != nil {
			return err
		}

		var cloudlet edgeproto.Cloudlet
		if !s.all.cloudletApi.store.STMGet(stm, &in.CloudletKey, &cloudlet) {
			return fmt.Errorf("For AppInst, %v", in.CloudletKey.NotFoundError())
		}
		cloudletFeatures, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
		if err != nil {
			return fmt.Errorf("failed to get features for platform, %s", err)
		}

		crmOnEdge = cloudlet.CrmOnEdge
		app = edgeproto.App{}
		if !s.all.appApi.store.STMGet(stm, &in.AppKey, &app) {
			return fmt.Errorf("For AppInst, %v", in.AppKey.NotFoundError())
		}
		clusterInstReqd = cloudcommon.IsClusterInstReqd(&app)
		clusterInst = edgeproto.ClusterInst{}
		clusterKey := &in.ClusterKey
		if clusterInstReqd && !s.all.clusterInstApi.store.STMGet(stm, clusterKey, &clusterInst) {
			return fmt.Errorf("For AppInst, %v", clusterKey.NotFoundError())
		}
		if err := s.all.autoProvPolicyApi.appInstCheck(ctx, stm, cloudcommon.Delete, &app, in); err != nil {
			return err
		}

		cloudletRefs := edgeproto.CloudletRefs{}
		cloudletRefsChanged := false
		hasRefs := s.all.cloudletRefsApi.store.STMGet(stm, &in.CloudletKey, &cloudletRefs)
		if hasRefs && clusterInstReqd && clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_SHARED && !app.InternalPorts && !in.DedicatedIp {
			// shared root load balancer
			log.SpanLog(ctx, log.DebugLevelApi, "refs", "AppInst", in)
			for ii := range in.MappedPorts {
				if in.MappedPorts[ii].IsHTTP() {
					// port routed via ingress, no need to track
					// for conflicts
					continue
				}
				p := in.MappedPorts[ii].PublicPort
				protocol, err := getProtocolBitMap(in.MappedPorts[ii].Proto)

				if err != nil {
					return err
				}
				protos, found := cloudletRefs.RootLbPorts[p]
				if RequireAppInstPortConsistency && !found {
					return fmt.Errorf("Port %d not found in cloudlet refs %v", p, cloudletRefs.RootLbPorts)
				}
				if cloudletRefs.RootLbPorts != nil {
					if RequireAppInstPortConsistency && !protocolInUse(protos, protocol) {
						return fmt.Errorf("Port %d proto %x not found in cloudlet refs %v", p, protocol, cloudletRefs.RootLbPorts)

					}
					cloudletRefs.RootLbPorts[p] = removeProtocol(protos, protocol)
					if cloudletRefs.RootLbPorts[p] == 0 {
						delete(cloudletRefs.RootLbPorts, p)
					}
				}
				cloudletRefsChanged = true
			}
		}
		if app.Deployment == cloudcommon.DeploymentTypeVM {
			ii := 0
			for ; ii < len(cloudletRefs.VmAppInsts); ii++ {
				aiKey := cloudletRefs.VmAppInsts[ii]
				if aiKey.Matches(&in.Key) {
					break
				}
			}
			if ii < len(cloudletRefs.VmAppInsts) {
				// explicity zero out deleted item to
				// prevent memory leak
				a := cloudletRefs.VmAppInsts
				copy(a[ii:], a[ii+1:])
				a[len(a)-1] = edgeproto.AppInstKey{}
				cloudletRefs.VmAppInsts = a[:len(a)-1]
				cloudletRefsChanged = true
			}
		}
		nodeType = cloudletFeatures.NodeType
		if cloudletRefsChanged {
			s.all.cloudletRefsApi.store.STMPut(stm, &cloudletRefs)
		}
		if clusterInstReqd && clusterInst.ReservedBy != "" && clusterInst.ReservedBy == in.Key.Organization && s.all.clusterRefsApi.canReleaseReservation(stm, in) {
			clusterInst.ReservedBy = ""
			clusterInst.ReservationEndedAt = dme.TimeToTimestamp(time.Now())
			s.all.clusterInstApi.store.STMPut(stm, &clusterInst)
			reservationFreed = true
		}

		// delete app inst
		if ignoreCRM(cctx) {
			// CRM state should be the same as before the
			// operation failed, so just need to clean up
			// controller state.
			s.store.STMDel(stm, &in.Key)
			s.idStore.STMDel(stm, in.UniqueId)
			if in.FedKey.FederationName != "" {
				s.fedStore.STMDel(stm, &in.FedKey)
			}
			s.dnsLabelStore.STMDel(stm, &in.CloudletKey, in.DnsLabel)
			s.all.appInstRefsApi.removeRef(stm, &in.AppKey, &in.Key)
			if cloudcommon.IsClusterInstReqd(&app) {
				s.all.clusterRefsApi.removeRef(stm, in)
			}
		} else {
			in.State = edgeproto.TrackedState_DELETE_REQUESTED
			s.store.STMPut(stm, in)
			s.all.appInstRefsApi.addDeleteRequestedRef(stm, &in.AppKey, &in.Key)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if reservationFreed {
		clusterInstReservationEvent(ctx, cloudcommon.FreeClusterEvent, in)
	}

	sendObj, err := s.startAppInstStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		return err
	}
	defer func() {
		cleanupStream := NoCleanupStream
		if reterr == nil {
			// deletion is successful, cleanup stream
			cleanupStream = CleanupStream
		}
		s.stopAppInstStream(ctx, cctx, &appInstKey, sendObj, reterr, cleanupStream)
	}()

	// clear all alerts for this appInst
	s.all.alertApi.CleanupAppInstAlerts(ctx, &appInstKey)
	if ignoreCRM(cctx) {
		cb.Send(&edgeproto.Result{Message: "Deleted AppInst successfully"})
	} else {
		reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().DeleteAppInstTimeout.TimeDuration())
		defer reqCancel()

		crmAction := func() error {
			successMsg := "Deleted AppInst successfully"
			if crmOnEdge {
				return edgeproto.WaitForAppInstInfo(reqCtx, &in.Key, s.store, edgeproto.TrackedState_NOT_PRESENT,
					DeleteAppInstTransitions, edgeproto.TrackedState_DELETE_ERROR,
					successMsg, cb.Send, sendObj.crmMsgCh,
				)
			} else {
				conn, err := services.platformServiceConnCache.GetConn(ctx, nodeType)
				if err != nil {
					return err
				}
				api := edgeproto.NewAppInstPlatformAPIClient(conn)
				in.Fields = []string{edgeproto.AppInstFieldState}
				outStream, err := api.ApplyAppInst(reqCtx, in)
				if err != nil {
					return cloudcommon.GRPCErrorUnwrap(err)
				}
				err = cloudcommon.StreamRecvWithStatus(ctx, outStream, cb.Send, func(info *edgeproto.AppInstInfo) error {
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
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Delete AppInst ignoring CRM failure: %s", err.Error())})
			s.ReplaceErrorState(ctx, in, edgeproto.TrackedState_DELETE_DONE)
			cb.Send(&edgeproto.Result{Message: "Deleted AppInst successfully"})
			err = nil
		}
		if err != nil {
			// crm failed or some other err, undo
			cb.Send(&edgeproto.Result{Message: "Recreating AppInst due to failure"})
			// Note that we use CRMUndo here, because the CRM
			// delete will continue on failure and delete evrything
			// without restoring on failure. So we need to ensure
			// the create will call the CRM functions to recreate
			// everything.
			undoErr := s.createAppInstInternal(cctx.WithUndo().WithCRMUndo().WithStream(sendObj), in, cb)
			if undoErr != nil {
				log.InfoLog("Undo delete AppInst", "undoErr", undoErr)
			}
			return err
		}
		s.updateCloudletResourcesMetric(ctx, in)

	}
	// delete clusterinst afterwards if it was auto-created and nobody is left using it
	// this is retained for old autoclusters that are not reservable,
	// and can be removed once no old autoclusters exist anymore.
	if clusterInstReqd && clusterInst.Auto && !s.UsesClusterInst(in.Key.Organization, &clusterInst.Key) && !clusterInst.Reservable {
		cb.Send(&edgeproto.Result{Message: "Deleting auto-ClusterInst"})
		cctxauto := cctx.WithAutoCluster()
		autoerr := s.all.clusterInstApi.deleteClusterInstInternal(cctxauto, &clusterInst, cb)
		if autoerr != nil {
			log.InfoLog("Failed to delete auto-ClusterInst",
				"clusterInst", clusterInst, "err", autoerr)
		}
	}
	return err
}

func (s *AppInstApi) ShowAppInst(in *edgeproto.AppInst, cb edgeproto.AppInstApi_ShowAppInstServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.AppInst) error {
		err := cb.Send(obj)
		return err
	})
	return err
}

func (s *AppInstApi) HealthCheckUpdate(ctx context.Context, key *edgeproto.AppInstKey, state dme.HealthCheck) {
	log.SpanLog(ctx, log.DebugLevelApi, "Update AppInst Health Check", "key", key, "state", state)
	s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		inst := edgeproto.AppInst{}
		if !s.store.STMGet(stm, key, &inst) {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst not found updating health check", "appinst", key)
			// got deleted in the meantime
			return nil
		}
		if inst.HealthCheck == state {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst state is already set", "appinst", inst, "state", state)
			// nothing to do
			return nil
		}
		if inst.HealthCheck == dme.HealthCheck_HEALTH_CHECK_OK && state != dme.HealthCheck_HEALTH_CHECK_OK {
			// healthy -> not healthy
			s.RecordAppInstEvent(ctx, &inst, cloudcommon.HEALTH_CHECK_FAIL, cloudcommon.InstanceDown)
			nodeMgr.Event(ctx, "AppInst offline", key.Organization, inst.GetTags(), nil, "state", state.String())
		} else if inst.HealthCheck != dme.HealthCheck_HEALTH_CHECK_OK && state == dme.HealthCheck_HEALTH_CHECK_OK {
			// not healthy -> healthy
			s.RecordAppInstEvent(ctx, &inst, cloudcommon.HEALTH_CHECK_OK, cloudcommon.InstanceUp)
			nodeMgr.Event(ctx, "AppInst online", key.Organization, inst.GetTags(), nil, "state", state.String())
		}
		inst.HealthCheck = state
		s.store.STMPut(stm, &inst)
		return nil
	})
}

func (s *AppInstApi) UpdateFromInfo(ctx context.Context, in *edgeproto.AppInstInfo) {
	log.SpanLog(ctx, log.DebugLevelApi, "Update AppInst from info", "key", in.Key, "state", in.State, "status", in.Status, "powerstate", in.PowerState, "uri", in.Uri)
	fmap := edgeproto.MakeFieldMap(in.Fields)

	readyChanged := false
	inst := edgeproto.AppInst{}
	s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		applyUpdate := false
		if !s.store.STMGet(stm, &in.Key, &inst) {
			// got deleted in the meantime
			return nil
		}
		if fmap.Has(edgeproto.AppInstInfoFieldPowerState) {
			if in.PowerState != edgeproto.PowerState_POWER_STATE_UNKNOWN &&
				inst.PowerState != in.PowerState {
				inst.PowerState = in.PowerState
				applyUpdate = true
			}
		}
		if fmap.Has(edgeproto.AppInstInfoFieldState) {
			// If AppInst is ready and state has not been set yet by HealthCheckUpdate, default to Ok.
			if in.State == edgeproto.TrackedState_READY &&
				inst.HealthCheck == dme.HealthCheck_HEALTH_CHECK_UNKNOWN {
				inst.HealthCheck = dme.HealthCheck_HEALTH_CHECK_OK
				applyUpdate = true
			}
		}
		if fmap.Has(edgeproto.AppInstInfoFieldUri) {
			if in.Uri != "" && inst.Uri != in.Uri {
				inst.Uri = in.Uri
				applyUpdate = true
			}
		}
		if fmap.HasOrHasChild(edgeproto.AppInstInfoFieldFedKey) {
			if in.FedKey.AppInstId != "" && inst.FedKey.AppInstId == "" {
				inst.FedKey = in.FedKey
				fedAppInst := edgeproto.FedAppInst{
					Key:        in.FedKey,
					AppInstKey: in.Key,
				}
				s.fedStore.STMPut(stm, &fedAppInst)
				applyUpdate = true
			}
		}
		if fmap.HasOrHasChild(edgeproto.AppInstInfoFieldFedPorts) {
			if len(in.FedPorts) > 0 {
				log.SpanLog(ctx, log.DebugLevelApi, "Updating ports on federated appinst", "key", in.Key, "ports", in.FedPorts)
				fedPortLookup := map[string]*edgeproto.InstPort{}
				for ii := range in.FedPorts {
					key := edgeproto.AppPortLookupKey(&in.FedPorts[ii])
					fedPortLookup[key] = &in.FedPorts[ii]
				}
				for ii, port := range inst.MappedPorts {
					key := edgeproto.AppPortLookupKey(&port)
					fedPort, ok := fedPortLookup[key]
					if !ok {
						continue
					}
					if inst.MappedPorts[ii].FqdnPrefix == fedPort.FqdnPrefix && inst.MappedPorts[ii].PublicPort == fedPort.PublicPort {
						continue
					}
					inst.MappedPorts[ii].FqdnPrefix = fedPort.FqdnPrefix
					inst.MappedPorts[ii].PublicPort = fedPort.PublicPort
					applyUpdate = true
				}
				// clear URI, as full path to port is in FqdnPrefix
				if inst.Uri != "" {
					inst.Uri = ""
					applyUpdate = true
				}
			}
		}

		if fmap.Has(edgeproto.AppInstInfoFieldState) {
			if inst.State == in.State {
				// already in that state
				if in.State == edgeproto.TrackedState_READY {
					// update runtime info
					if len(in.RuntimeInfo.ContainerIds) > 0 {
						inst.RuntimeInfo = in.RuntimeInfo
						applyUpdate = true
					}
				}
			} else {
				if inst.State == edgeproto.TrackedState_READY || in.State == edgeproto.TrackedState_READY {
					readyChanged = true
				}
				// please see state_transitions.md
				if !crmTransitionOk(inst.State, in.State) {
					log.SpanLog(ctx, log.DebugLevelApi, "Invalid state transition",
						"key", &in.Key, "cur", inst.State, "next", in.State)
					return nil
				}
				if inst.State == edgeproto.TrackedState_DELETE_REQUESTED && in.State != edgeproto.TrackedState_DELETE_REQUESTED {
					s.all.appInstRefsApi.removeDeleteRequestedRef(stm, &inst.AppKey, &in.Key)
				}
				inst.State = in.State
				applyUpdate = true
			}
			if in.State == edgeproto.TrackedState_CREATE_ERROR || in.State == edgeproto.TrackedState_DELETE_ERROR || in.State == edgeproto.TrackedState_UPDATE_ERROR {
				inst.Errors = in.Errors
			} else {
				inst.Errors = nil
			}
		}

		if fmap.HasOrHasChild(edgeproto.AppInstInfoFieldRuntimeInfo) {
			if len(in.RuntimeInfo.ContainerIds) > 0 {
				inst.RuntimeInfo = in.RuntimeInfo
				applyUpdate = true
			}
		}
		if applyUpdate {
			s.store.STMPut(stm, &inst)
		}
		return nil
	})
	// publish the received info object on redis
	// currently this must happen after updating etcd becauses unit tests
	// check the etcd state after create/delete, but the create API call
	// waits until the redis change is done, not the etcd change. We have
	// some duplication of state (i.e. the AppInst.State) in both etcd and redis,
	// which is the source of this confusion.
	s.all.streamObjApi.UpdateStatus(ctx, in, &in.State, nil, in.Key.StreamKey())

	if in.State == edgeproto.TrackedState_DELETE_DONE {
		s.DeleteFromInfo(ctx, in)
		// update stream message about deletion of main object
		in.State = edgeproto.TrackedState_NOT_PRESENT
		s.all.streamObjApi.UpdateStatus(ctx, in, &in.State, nil, in.Key.StreamKey())
	}
	if readyChanged {
		s.all.trustPolicyExceptionApi.applyAllTPEsForAppInst(ctx, &inst)
	}
}

func (s *AppInstApi) DeleteFromInfo(ctx context.Context, in *edgeproto.AppInstInfo) {
	log.SpanLog(ctx, log.DebugLevelApi, "Delete AppInst from info", "key", in.Key, "state", in.State)
	s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		inst := edgeproto.AppInst{}
		if !s.store.STMGet(stm, &in.Key, &inst) {
			// got deleted in the meantime
			return nil
		}
		// please see state_transitions.md
		if inst.State != edgeproto.TrackedState_DELETING && inst.State != edgeproto.TrackedState_DELETE_REQUESTED &&
			inst.State != edgeproto.TrackedState_DELETE_DONE {
			log.SpanLog(ctx, log.DebugLevelApi, "Invalid state transition",
				"key", &in.Key, "cur", inst.State,
				"next", edgeproto.TrackedState_DELETE_DONE)
			return nil
		}
		s.store.STMDel(stm, &in.Key)
		s.idStore.STMDel(stm, inst.UniqueId)
		if inst.FedKey.FederationName != "" {
			s.fedStore.STMDel(stm, &inst.FedKey)
		}
		s.dnsLabelStore.STMDel(stm, &inst.CloudletKey, inst.DnsLabel)
		s.all.appInstRefsApi.removeRef(stm, &inst.AppKey, &in.Key)
		s.all.clusterRefsApi.removeRef(stm, &inst)
		return nil
	})
}

// Handle AppInst status callbacks from Federation Partner
func (s *AppInstApi) HandleFedAppInstEvent(ctx context.Context, in *edgeproto.FedAppInstEvent) (*edgeproto.Result, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "handle FedAppInstEvent", "event", in)

	// The FRM may be waiting for the callbacks. It needs to do this because
	// the FRM performs some more work (GetAppInst runtime, etc) in the
	// common controller-data code once the AppInst has been created.
	// So, we need to forward the event to the FRM.
	// For intermediate events (i.e. task message updates), the
	// FRM would just end up sending the event back to the controller,
	// which is roundabout and pointless. Unfortunately, the way the
	// streaming messages and callbacks work, they need to build the full
	// list of messages, which requires appending the current message to
	// AppInstInfo in the cache. And only the FRM keeps that cached.
	// So we still need to send it to the FRM.
	log.SpanLog(ctx, log.DebugLevelApi, "Forwarding FedAppInstEvent via notify")
	s.fedAppInstEventSendMany.Update(ctx, in)
	return &edgeproto.Result{}, nil
}

func (s *AppInstApi) ReplaceErrorState(ctx context.Context, in *edgeproto.AppInst, newState edgeproto.TrackedState) {
	s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		inst := edgeproto.AppInst{}
		if !s.store.STMGet(stm, &in.Key, &inst) {
			// got deleted in the meantime
			return nil
		}
		if inst.State != edgeproto.TrackedState_CREATE_ERROR &&
			inst.State != edgeproto.TrackedState_DELETE_ERROR &&
			inst.State != edgeproto.TrackedState_UPDATE_ERROR {
			return nil
		}
		if newState == edgeproto.TrackedState_DELETE_DONE {
			s.store.STMDel(stm, &in.Key)
			s.idStore.STMDel(stm, inst.UniqueId)
			if inst.FedKey.FederationName != "" {
				s.fedStore.STMDel(stm, &inst.FedKey)
			}
			s.dnsLabelStore.STMDel(stm, &inst.CloudletKey, inst.DnsLabel)
			s.all.appInstRefsApi.removeRef(stm, &inst.AppKey, &in.Key)
			s.all.clusterRefsApi.removeRef(stm, &inst)
		} else {
			inst.State = newState
			inst.Errors = nil
			s.store.STMPut(stm, &inst)
		}
		return nil
	})
}

// public cloud k8s cluster allocates a separate IP per service.  This is a type of dedicated access
func isIPAllocatedPerService(ctx context.Context, platformType string, features *edgeproto.PlatformFeatures, operator string) bool {
	log.SpanLog(ctx, log.DebugLevelApi, "isIPAllocatedPerService", "platformType", platformType, "operator", operator)

	if features.IsFake {
		// for a fake cloudlet used in testing, decide based on operator name
		return operator == cloudcommon.OperatorGCP || operator == cloudcommon.OperatorAzure || operator == cloudcommon.OperatorAWS
	}
	return features.IpAllocatedPerService
}

func validateImageTypeForPlatform(ctx context.Context, imageType edgeproto.ImageType, platformType string, features *edgeproto.PlatformFeatures) error {
	log.SpanLog(ctx, log.DebugLevelApi, "validateImageTypeForPlatform", "imageType", imageType, "platformType", platformType)
	supported := true
	if imageType == edgeproto.ImageType_IMAGE_TYPE_OVF && !features.SupportsImageTypeOvf {
		supported = false
	}
	if imageType == edgeproto.ImageType_IMAGE_TYPE_OVA && !features.SupportsImageTypeOva {
		supported = false
	}
	if !supported {
		return fmt.Errorf("image type %s is not valid for platform type: %s", imageType.String(), platformType)
	}
	return nil
}

func allocateIP(ctx context.Context, inst *edgeproto.ClusterInst, cloudlet *edgeproto.Cloudlet, platformType string, features *edgeproto.PlatformFeatures, refs *edgeproto.CloudletRefs) error {

	if isIPAllocatedPerService(ctx, platformType, features, cloudlet.Key.Organization) {
		// we don't track IPs in managed k8s clouds
		return nil
	}
	if inst.IpAccess == edgeproto.IpAccess_IP_ACCESS_SHARED {
		// shared, so no allocation needed
		return nil
	}
	if inst.IpAccess == edgeproto.IpAccess_IP_ACCESS_UNKNOWN {
		// This should have been modified already before coming here, this is a bug if this is hit
		return fmt.Errorf("Unexpected IP_ACCESS_UNKNOWN ")
	}
	// Allocate a dedicated IP
	if cloudlet.IpSupport == edgeproto.IpSupport_IP_SUPPORT_STATIC {
		// TODO:
		// parse cloudlet.StaticIps and refs.UsedStaticIps.
		// pick a free one, put it in refs.UsedStaticIps, and
		// set inst.AllocatedIp to the Ip.
		return errors.New("Static IPs not supported yet")
	} else if cloudlet.IpSupport == edgeproto.IpSupport_IP_SUPPORT_DYNAMIC {
		// Note one dynamic IP is reserved for Global Reverse Proxy LB.
		if refs.UsedDynamicIps+1 >= cloudlet.NumDynamicIps {
			return errors.New("No more dynamic IPs left")
		}
		refs.UsedDynamicIps++
		inst.AllocatedIp = cloudcommon.AllocatedIpDynamic
		return nil
	}
	return errors.New("Invalid IpSupport type")
}

func freeIP(inst *edgeproto.ClusterInst, cloudlet *edgeproto.Cloudlet, refs *edgeproto.CloudletRefs) {
	if inst.IpAccess == edgeproto.IpAccess_IP_ACCESS_SHARED {
		return
	}
	if cloudlet.IpSupport == edgeproto.IpSupport_IP_SUPPORT_STATIC {
		// TODO: free static ip in inst.AllocatedIp from refs.
	} else if cloudlet.IpSupport == edgeproto.IpSupport_IP_SUPPORT_DYNAMIC {
		refs.UsedDynamicIps--
		inst.AllocatedIp = ""
	}
}

func setPortFQDNPrefixes(in *edgeproto.AppInst, app *edgeproto.App) error {
	// For Kubernetes deployments, the CRM sets the
	// Fqdn based on the service (load balancer) name
	// in the kubernetes deployment manifest.
	// The Controller needs to set a matching
	// FqdnPrefix on the ports so the DME can tell the
	// App Client the correct Fqdn for a given port.
	if app.Deployment == cloudcommon.DeploymentTypeKubernetes {
		objs, _, err := cloudcommon.DecodeK8SYaml(app.DeploymentManifest)
		if err != nil {
			return fmt.Errorf("invalid kubernetes deployment yaml, %s", err.Error())
		}
		for ii := range in.MappedPorts {
			setPortFQDNPrefix(&in.MappedPorts[ii], objs)
			if err := cloudcommon.CheckFQDNLengths(in.MappedPorts[ii].FqdnPrefix, in.Uri); err != nil {
				return err
			}
		}
	}
	return nil
}

func setPortFQDNPrefix(port *edgeproto.InstPort, objs []runtime.Object) {
	for _, obj := range objs {
		ksvc, ok := obj.(*v1.Service)
		if !ok {
			continue
		}
		for _, kp := range ksvc.Spec.Ports {
			lproto, err := edgeproto.LProtoStr(port.Proto)
			if err != nil {
				return
			}
			// in case of HTTP ports, it will never match
			// any the kubernetes service ports which are only
			// TCP/UDP, which is what we want because http ports
			// are routed via ingress and use the App's URI, and
			// do not need fqdn prefixes which are used to route
			// to LBs.
			if lproto != strings.ToLower(string(kp.Protocol)) {
				continue
			}
			if kp.TargetPort.IntValue() == int(port.InternalPort) {
				port.FqdnPrefix = cloudcommon.FqdnPrefix(ksvc.Name)
				return
			}
		}
	}
}

func (s *AppInstApi) sumRequestedAppInstResources(appInst *edgeproto.AppInst) resspec.ResValMap {
	// Note this calculates the resource values as requested
	// by the user, not the actual resources deployed in the
	// infrastructure due to flavor quantization or additional
	// platform specific requirements like load balancers.
	resVals := resspec.ResValMap{}
	if appInst.KubernetesResources != nil {
		for _, pool := range []*edgeproto.NodePoolResources{
			appInst.KubernetesResources.CpuPool,
			appInst.KubernetesResources.GpuPool,
		} {
			resVals.AddNodePoolResources(pool)
		}
	}
	if appInst.NodeResources != nil {
		resVals.AddNodeResources(appInst.NodeResources, 1)
	}
	return resVals
}

func (s *AppInstApi) RecordAppInstEvent(ctx context.Context, appInst *edgeproto.AppInst, event cloudcommon.InstanceEvent, serverStatus string) {
	metric := edgeproto.Metric{}
	metric.Name = cloudcommon.AppInstEvent
	now := time.Now()
	ts, _ := types.TimestampProto(now)
	metric.Timestamp = *ts
	metric.AddStringVal(edgeproto.CloudletKeyTagOrganization, appInst.CloudletKey.Organization)
	metric.AddTag(edgeproto.CloudletKeyTagName, appInst.CloudletKey.Name)
	metric.AddTag(edgeproto.CloudletKeyTagFederatedOrganization, appInst.CloudletKey.FederatedOrganization)
	metric.AddTag(edgeproto.ClusterKeyTagName, appInst.ClusterKey.Name)
	metric.AddTag(edgeproto.ClusterKeyTagOrganization, appInst.ClusterKey.Organization)
	metric.AddTag(edgeproto.AppKeyTagOrganization, appInst.AppKey.Organization)
	metric.AddTag(edgeproto.AppKeyTagName, appInst.AppKey.Name)
	metric.AddTag(edgeproto.AppKeyTagVersion, appInst.AppKey.Version)
	metric.AddTag(edgeproto.AppInstKeyTagName, appInst.Key.Name)
	metric.AddTag(edgeproto.AppInstKeyTagOrganization, appInst.Key.Organization)
	metric.AddTag(cloudcommon.MetricTagOrg, appInst.Key.Organization)
	appInst.ZoneKey.AddTagsByFunc(metric.AddTag)
	metric.AddStringVal(cloudcommon.MetricTagEvent, string(event))
	metric.AddStringVal(cloudcommon.MetricTagStatus, serverStatus)

	app := edgeproto.App{}
	if !s.all.appApi.cache.Get(&appInst.AppKey, &app) {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Cannot find appdata for app", "app", appInst.AppKey)
		return
	}
	metric.AddStringVal(cloudcommon.MetricTagDeployment, app.Deployment)

	resVals := s.sumRequestedAppInstResources(appInst)
	metric.AddIntVal(cloudcommon.MetricTagRAM, resVals.GetInt(cloudcommon.ResourceRamMb))
	metric.AddIntVal(cloudcommon.MetricTagVCPU, resVals.GetInt(cloudcommon.ResourceVcpus))
	services.events.AddMetric(&metric)
}

func (s *AppInstApi) updateURI(key *edgeproto.AppInstKey, cloudlet *edgeproto.Cloudlet, inCb edgeproto.AppInstApi_UpdateAppInstServer) (reterr error) {
	ctx := inCb.Context()
	cctx := DefCallContext()

	log.SpanLog(ctx, log.DebugLevelApi, "updateURI", "appinst", key, "cloudlet", cloudlet)
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, key.StreamKey(), inCb)

	needUpdate := false
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		appInst := edgeproto.AppInst{}
		if !s.store.STMGet(stm, key, &appInst) {
			// deleted in the meantime
			log.SpanLog(ctx, log.DebugLevelApi, "Appinst deleted before DNS update", "appinst", key)
			return nil
		}
		if appInst.Uri == "" {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst is internal.")
			return nil
		}
		app := edgeproto.App{}
		if !s.all.appApi.store.STMGet(stm, &appInst.AppKey, &app) {
			return appInst.AppKey.NotFoundError()
		}
		clusterInst := edgeproto.ClusterInst{}
		if cloudcommon.IsClusterInstReqd(&app) {
			if !s.all.clusterInstApi.store.STMGet(stm, appInst.GetClusterKey(), &clusterInst) {
				return errors.New("ClusterInst does not exist for App")
			}
		}
		cloudletFeatures, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
		if err != nil {
			return fmt.Errorf("Failed to get features for platform: %s", err)
		}
		newURI := getAppInstURI(ctx, &appInst, &app, &clusterInst, cloudlet, cloudletFeatures)
		if err := cloudcommon.CheckFQDNLengths("", appInst.Uri); err != nil {
			return err
		}
		if appInst.Uri == newURI {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst URI is up to date.")
			return nil
		}

		// Could be in an update error after an unsuccessful dns update
		if appInst.State != edgeproto.TrackedState_READY && appInst.State != edgeproto.TrackedState_UPDATE_ERROR {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("AppInst %s is not ready - skipping", appInst.Key.Name)})
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst is not ready - skipping", "appinst", appInst)
			return nil
		}

		// Store previous URI, so we can update this with CCRM
		log.SpanLog(ctx, log.DebugLevelApi, "Updating AppInst URI", "old FQDN", appInst.Uri, "new", getAppInstFQDN(&appInst, cloudlet))
		appInst.AddAnnotation(cloudcommon.AnnotationPreviousDNSName, appInst.Uri)
		appInst.Uri = newURI
		appInst.UpdatedAt = dme.TimeToTimestamp(time.Now())
		appInst.State = edgeproto.TrackedState_UPDATE_REQUESTED
		s.store.STMPut(stm, &appInst)
		needUpdate = true
		return nil
	})
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Failed to update appinst in etcd", "err", err)
		return err
	}
	// Revert cluster to old state if update failed
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			appInst := edgeproto.AppInst{}
			if !s.store.STMGet(stm, key, &appInst) {
				// deleted in the meantime
				log.SpanLog(ctx, log.DebugLevelApi, "Appinst deleted before DNS update", "appinst", key)
				return nil
			}
			oldURI, ok := appInst.Annotations[cloudcommon.AnnotationPreviousDNSName]
			if !ok {
				log.SpanLog(ctx, log.DebugLevelApi, "no previous uri is set")
				return fmt.Errorf("no previous uri set for %s", appInst.Key.Name)
			}
			delete(appInst.Annotations, cloudcommon.AnnotationPreviousDNSName)
			appInst.Uri = oldURI
			appInst.UpdatedAt = dme.TimeToTimestamp(time.Now())
			s.store.STMPut(stm, &appInst)
			return nil
		})
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to undo dns update", "key", key, "err", undoErr)
		}
	}()

	// No need to dispatch to CRM
	if !needUpdate {
		return nil
	}
	sendObj, err := s.startAppInstStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		return err
	}
	defer func() {
		s.stopAppInstStream(ctx, cctx, key, sendObj, reterr, NoCleanupStream)
	}()
	reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().UpdateAppInstTimeout.TimeDuration())
	defer reqCancel()

	successMsg := fmt.Sprintf("AppInst %s updated successfully", key.Name)
	return edgeproto.WaitForAppInstInfo(reqCtx, key, s.store, edgeproto.TrackedState_READY,
		UpdateAppInstTransitions, edgeproto.TrackedState_UPDATE_ERROR,
		successMsg, cb.Send, sendObj.crmMsgCh)

}

func clusterInstReservationEvent(ctx context.Context, eventName string, appInst *edgeproto.AppInst) {
	nodeMgr.Event(ctx, eventName, appInst.Key.Organization, appInst.GetTags(), nil, edgeproto.ClusterKeyTagName, appInst.ClusterKey.Name, edgeproto.ClusterKeyTagOrganization, appInst.ClusterKey.Organization)
}

// GetAppInstID returns a string for this AppInst that is likely to be
// unique within the region. It does not guarantee uniqueness.
// The delimiter '.' is removed from the AppInstId so that it can be used
// to append further strings to this ID to build derived unique names.
// Salt can be used by the caller to add an extra field if needed
// to ensure uniqueness. In all cases, any requirements for uniqueness
// must be guaranteed by the caller. Name sanitization for the platform is performed
func GetAppInstID(ctx context.Context, appInst *edgeproto.AppInst, app *edgeproto.App, salt string, sanitizer NameSanitizer) (string, error) {
	fields := []string{}

	name := util.DNSSanitize(appInst.Key.Name)
	dev := util.DNSSanitize(appInst.Key.Organization)
	fields = append(fields, dev, name)

	loc := util.DNSSanitize(appInst.CloudletKey.Name)
	fields = append(fields, loc)

	oper := util.DNSSanitize(appInst.CloudletKey.Organization)
	fields = append(fields, oper)

	if salt != "" {
		salt = util.DNSSanitize(salt)
		fields = append(fields, salt)
	}
	appInstID := strings.Join(fields, "-")
	return sanitizer.NameSanitize(appInstID)
}

// NameSanitizer is broken out as an interface for unit tests
type NameSanitizer interface {
	NameSanitize(name string) (string, error)
}

type AppInstIDSanitizer struct {
	ctx        context.Context
	appInstApi *AppInstApi
	cloudlet   *edgeproto.Cloudlet
}

func NewAppInstIDSanitizer(ctx context.Context, appInstApi *AppInstApi, cloudlet *edgeproto.Cloudlet) *AppInstIDSanitizer {
	return &AppInstIDSanitizer{
		ctx:        ctx,
		appInstApi: appInstApi,
		cloudlet:   cloudlet,
	}
}

func (s *AppInstIDSanitizer) NameSanitize(name string) (string, error) {
	features, err := s.appInstApi.all.platformFeaturesApi.GetCloudletFeatures(s.ctx, s.cloudlet.PlatformType)
	if err != nil {
		return "", err
	}

	reqCtx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()

	conn, err := services.platformServiceConnCache.GetConn(s.ctx, features.NodeType)
	if err != nil {
		return "", err
	}
	api := edgeproto.NewCloudletPlatformAPIClient(conn)
	req := edgeproto.NameSanitizeReq{
		CloudletKey: &s.cloudlet.Key,
		Message:     name,
	}
	res, err := api.NameSanitize(reqCtx, &req)
	if err != nil {
		return "", cloudcommon.GRPCErrorUnwrap(err)
	}
	return res.Message, nil
}

// getAppInstByID finds AppInst by ID. If appInst not found returns nil AppInst
// instead of an error.
func (s *AppInstApi) getAppInstByID(ctx context.Context, id string) (*edgeproto.AppInst, error) {
	filter := &edgeproto.AppInst{
		ObjId: id,
	}
	var appInst *edgeproto.AppInst
	err := s.cache.Show(filter, func(obj *edgeproto.AppInst) error {
		appInst = obj
		return nil
	})
	if err != nil {
		return nil, err
	}
	return appInst, nil
}
