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

package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	pfutils "github.com/edgexr/edge-cloud-platform/pkg/platform/utils"
	"github.com/gogo/protobuf/types"
	"go.etcd.io/etcd/client/v3/concurrency"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type AppInstApi struct {
	all                     *AllApis
	sync                    *Sync
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

func NewAppInstApi(sync *Sync, all *AllApis) *AppInstApi {
	appInstApi := AppInstApi{}
	appInstApi.all = all
	appInstApi.sync = sync
	appInstApi.store = edgeproto.NewAppInstStore(sync.store)
	appInstApi.idStore.Init(sync.store)
	appInstApi.fedStore = edgeproto.NewFedAppInstStore(sync.store)
	appInstApi.dnsLabelStore = &all.cloudletApi.objectDnsLabelStore
	appInstApi.fedAppInstEventSendMany = notify.NewFedAppInstEventSendMany()
	edgeproto.InitAppInstCache(&appInstApi.cache)
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

func (s *AppInstApi) deleteCloudletOk(stm concurrency.STM, refs *edgeproto.CloudletRefs, defaultClustKey *edgeproto.ClusterInstKey, dynInsts map[edgeproto.AppInstKey]struct{}) error {
	aiKeys := []*edgeproto.AppInstKey{}
	// Only need to check VM apps, as other AppInsts require ClusterInsts,
	// so ClusterInst check will apply.
	for _, aiRefKey := range refs.VmAppInsts {
		aiKey := edgeproto.AppInstKey{}
		aiKey.FromAppInstRefKey(&aiRefKey, &refs.Key)
		aiKeys = append(aiKeys, &aiKey)
	}
	// check any AppInsts on default cluster
	clustRefs := edgeproto.ClusterRefs{}
	if defaultClustKey != nil && s.all.clusterRefsApi.store.STMGet(stm, defaultClustKey, &clustRefs) {
		for _, aiRefKey := range clustRefs.Apps {
			aiKey := edgeproto.AppInstKey{}
			aiKey.FromAppInstRefKey(&aiRefKey, &defaultClustKey.CloudletKey)
			aiKeys = append(aiKeys, &aiKey)
		}
	}
	return s.cascadeDeleteOk(stm, refs.Key.Organization, "Cloudlet", aiKeys, dynInsts)
}

func (s *AppInstApi) cascadeDeleteOk(stm concurrency.STM, callerOrg, deleteTarget string, aiKeys []*edgeproto.AppInstKey, dynInsts map[edgeproto.AppInstKey]struct{}) error {
	for _, aiKey := range aiKeys {
		ai := edgeproto.AppInst{}
		if !s.store.STMGet(stm, aiKey, &ai) {
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
	for key, data := range s.cache.Objs {
		if !key.CloudletKey.Matches(ckey) {
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

func (s *AppInstApi) UsesClusterInst(callerOrg string, in *edgeproto.ClusterInstKey) bool {
	var app edgeproto.App
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for _, data := range s.cache.Objs {
		val := data.Obj
		if val.ClusterInstKey().Matches(in) && s.all.appApi.Get(&val.AppKey, &app) {
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
	case dme.LProto_L_PROTO_TCP:
		bitmap = 1 //01
		break
	//put all "UDP" protocols below here
	case dme.LProto_L_PROTO_UDP:
		bitmap = 2 //10
		break
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

func (s *AppInstApi) startAppInstStream(ctx context.Context, cctx *CallContext, key *edgeproto.AppInstKey, inCb edgeproto.AppInstApi_CreateAppInstServer) (*streamSend, edgeproto.AppInstApi_CreateAppInstServer, error) {
	streamSendObj, outCb, err := s.all.streamObjApi.startStream(ctx, cctx, key.StreamKey(), inCb)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to start appinst stream", "err", err)
		return nil, inCb, err
	}
	return streamSendObj, outCb, err
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

func (s *AppInstApi) checkPortOverlapDedicatedLB(appPorts []dme.AppPort, clusterInstKey *edgeproto.ClusterInstKey) error {
	lookupKey := edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			CloudletKey: clusterInstKey.CloudletKey,
		},
		ClusterKey: clusterInstKey.ClusterKey,
	}
	err := s.cache.Show(&lookupKey, func(obj *edgeproto.AppInst) error {
		if obj.State == edgeproto.TrackedState_DELETE_ERROR || edgeproto.IsTransientState(obj.State) {
			// ignore apps that are in failed, or transient state
			return nil
		}
		if obj.DedicatedIp {
			return nil
		}
		for ii := range appPorts {
			for jj := range obj.MappedPorts {
				if edgeproto.DoPortsOverlap(appPorts[ii], obj.MappedPorts[jj]) {
					if appPorts[ii].EndPort != appPorts[ii].InternalPort && appPorts[ii].EndPort != 0 {
						return fmt.Errorf("port range %d-%d overlaps with ports in use on the cluster", appPorts[ii].InternalPort, appPorts[ii].EndPort)
					}
					return fmt.Errorf("port %d is already in use on the cluster", appPorts[ii].InternalPort)
				}
			}
		}
		return nil
	})
	return err
}

func removeAppInstFromRefs(appInstKey *edgeproto.AppInstKey, appInstRefs *[]edgeproto.AppInstRefKey) bool {
	ii := 0
	refsChanged := false
	for ; ii < len(*appInstRefs); ii++ {
		aiKey := edgeproto.AppInstKey{}
		aiKey.FromAppInstRefKey(&(*appInstRefs)[ii], &appInstKey.CloudletKey)
		if aiKey.Matches(appInstKey) {
			break
		}
	}
	if ii < len(*appInstRefs) {
		// explicity zero out deleted item to
		// pr*event memory leak
		a := *appInstRefs
		copy(a[ii:], a[ii+1:])
		a[len(a)-1] = edgeproto.AppInstRefKey{}
		*appInstRefs = a[:len(a)-1]
		refsChanged = true
	}
	return refsChanged
}

// createAppInstInternal is used to create dynamic app insts internally,
// bypassing static assignment.
func (s *AppInstApi) createAppInstInternal(cctx *CallContext, in *edgeproto.AppInst, inCb edgeproto.AppInstApi_CreateAppInstServer) (reterr error) {
	var clusterInst edgeproto.ClusterInst
	ctx := inCb.Context()
	cctx.SetOverride(&in.CrmOverride)

	// If the ClusterKey is left blank and a cluster is required,
	// then a cluster will automatically be chosen or created.
	// If a ClusterKey is specified, then the cluster must exist and
	// be allowed to host the AppInst.
	clusterSpecified := false
	if in.ClusterKey.Name != "" {
		clusterSpecified = true
	}
	freeClusterInsts := []edgeproto.ClusterInstKey{}
	if !clusterSpecified {
		// gather free reservable ClusterInsts for the target Cloudlet
		s.all.clusterInstApi.cache.Mux.Lock()
		for key, data := range s.all.clusterInstApi.cache.Objs {
			if !in.Key.CloudletKey.Matches(&data.Obj.Key.CloudletKey) {
				// not the target Cloudlet
				continue
			}
			if data.Obj.Reservable && data.Obj.ReservedBy == "" {
				// free reservable ClusterInst - we will double-check in STM
				freeClusterInsts = append(freeClusterInsts, key)
			}
		}
		s.all.clusterInstApi.cache.Mux.Unlock()
	}

	appInstKey := in.Key
	// create stream once AppInstKey is formed correctly
	sendObj, cb, err := s.startAppInstStream(ctx, cctx, &appInstKey, inCb)
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
	appDeploymentType := ""
	reservedAutoClusterId := -1
	var reservedClusterInstKey *edgeproto.ClusterInstKey
	var cloudletFeatures *edgeproto.PlatformFeatures
	cloudletCompatibilityVersion := uint32(0)
	var cloudletPlatformType edgeproto.PlatformType
	var cloudletLoc dme.Loc

	in.CompatibilityVersion = cloudcommon.GetAppInstCompatibilityVersion()

	defer func() {
		if reterr != nil {
			return
		}
		s.RecordAppInstEvent(ctx, in, cloudcommon.CREATED, cloudcommon.InstanceUp)
		if reservedClusterInstKey != nil {
			s.all.clusterInstApi.RecordClusterInstEvent(ctx, reservedClusterInstKey, cloudcommon.RESERVED, cloudcommon.InstanceUp)
		}
	}()

	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		// reset modified state in case STM hits conflict and runs again
		createCluster = false
		autoClusterType = NoAutoCluster
		sidecarApp = false
		reservedAutoClusterId = -1
		reservedClusterInstKey = nil
		cloudletCompatibilityVersion = 0

		// lookup App so we can get flavor for reservable ClusterInst
		var app edgeproto.App
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

		if in.Flavor.Name == "" {
			in.Flavor = app.DefaultFlavor
		}
		sidecarApp = cloudcommon.IsSideCarApp(&app)
		if sidecarApp && (in.ClusterKey.Name == "" || in.ClusterKey.Organization == "") {
			return fmt.Errorf("Sidecar AppInst (AutoDelete App) must specify the Cluster name and organization to deploy to")
		}
		// make sure cloudlet exists so we don't create refs for missing cloudlet
		cloudlet := edgeproto.Cloudlet{}
		if !s.all.cloudletApi.store.STMGet(stm, &in.Key.CloudletKey, &cloudlet) {
			return errors.New("Specified Cloudlet not found")
		}
		if cloudlet.DeletePrepare {
			return cloudlet.Key.BeingDeletedError()
		}
		cloudletPlatformType = cloudlet.PlatformType
		cloudletLoc = cloudlet.Location
		info := edgeproto.CloudletInfo{}
		if !s.all.cloudletInfoApi.store.STMGet(stm, &in.Key.CloudletKey, &info) {
			return fmt.Errorf("No resource information found for Cloudlet %s", in.Key.CloudletKey)
		}
		cloudletCompatibilityVersion = info.CompatibilityVersion
		cloudletFeatures, err = GetCloudletFeatures(ctx, cloudlet.PlatformType)
		if err != nil {
			return fmt.Errorf("Failed to get features for platform: %s", err)
		}
		if in.DedicatedIp && !cloudletFeatures.SupportsAppInstDedicatedIp {
			return fmt.Errorf("Target cloudlet platform does not support a per-AppInst dedicated IP")
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

		if err := s.all.cloudletInfoApi.checkCloudletReady(cctx, stm, &in.Key.CloudletKey, cloudcommon.Create); err != nil {
			return err
		}

		if cloudletFeatures.IsSingleKubernetesCluster {
			if app.Deployment != cloudcommon.DeploymentTypeKubernetes && app.Deployment != cloudcommon.DeploymentTypeHelm {
				return fmt.Errorf("Cannot deploy %s app to single kubernetes cloudlet", app.Deployment)
			}
			// disable autocluster logic, since there's only one cluster
			if in.ClusterKey.Name != "" {
				// doesn't need to be specified, but if it is,
				// it better be the one and only cluster name.
				if in.ClusterKey.Name != cloudcommon.DefaultClust {
					return fmt.Errorf("Cluster name for single kubernetes cluster cloudlet must be set to %s or left blank", cloudcommon.DefaultClust)
				}
			}
			// set cluster name
			in.ClusterKey.Name = cloudcommon.DefaultClust
			// set cluster org based on single cluster type
			if cloudlet.SingleKubernetesClusterOwner != "" {
				// ST cluster
				if in.ClusterKey.Organization == "" {
					in.ClusterKey.Organization = cloudlet.SingleKubernetesClusterOwner
				}
				if in.ClusterKey.Organization != cloudlet.SingleKubernetesClusterOwner {
					return fmt.Errorf("Cluster organization must be set to %s or left blank", cloudlet.SingleKubernetesClusterOwner)
				}

				autoClusterType = NoAutoCluster
			} else {
				// MT cluster
				if !app.AllowServerless {
					return fmt.Errorf("Target cloudlet platform only supports serverless Apps")
				}
				if in.ClusterKey.Organization == "" {
					in.ClusterKey.Organization = edgeproto.OrganizationEdgeCloud
				}
				if !edgeproto.IsEdgeCloudOrg(in.ClusterKey.Organization) {
					return fmt.Errorf("Cluster organization must be set to %s or left blank", edgeproto.OrganizationEdgeCloud)
				}
				key := in.ClusterInstKey()
				clusterInst := edgeproto.ClusterInst{}
				if !s.all.clusterInstApi.store.STMGet(stm, key, &clusterInst) {
					return key.NotFoundError()
				}
				if clusterInst.DeletePrepare {
					return key.BeingDeletedError()
				}
				err := useMultiTenantClusterInst(stm, ctx, in, &app, sidecarApp, &clusterInst)
				if err != nil {
					return err
				}
				autoClusterType = MultiTenantAutoCluster
			}
		}

		if cloudletCompatibilityVersion < cloudcommon.CRMCompatibilityNewAppInstKey {
			// not backwards compatible
			return fmt.Errorf("Cloudlet %s CRM compatibility version is too old (%d), controller requires at least version %d, please upgrade Cloudlet CRM", in.Key.CloudletKey.Name, cloudletCompatibilityVersion, cloudcommon.CRMCompatibilityNewAppInstKey)
		}

		// Prefer multi-tenant autocluster over reservable autocluster.
		if autoClusterType == ChooseAutoCluster && app.AllowServerless {
			// if default multi-tenant cluster exists, target it
			key := in.ClusterInstKey()
			key.ClusterKey.Name = cloudcommon.DefaultMultiTenantCluster
			key.ClusterKey.Organization = edgeproto.OrganizationEdgeCloud
			clusterInst := edgeproto.ClusterInst{}
			if s.all.clusterInstApi.store.STMGet(stm, key, &clusterInst) {
				if clusterInst.DeletePrepare {
					return key.BeingDeletedError()
				}
				err := useMultiTenantClusterInst(stm, ctx, in, &app, sidecarApp, &clusterInst)
				if err == nil {
					autoClusterType = MultiTenantAutoCluster
					in.ClusterKey = key.ClusterKey
				}
			} else {
				err = key.NotFoundError()
			}
			log.SpanLog(ctx, log.DebugLevelInfo, "try default multi-tenant cluster check", "key", key, "err", err)
		}
		// Check for reservable cluster as the autocluster target.
		if autoClusterType == ChooseAutoCluster {
			// search for free reservable ClusterInst
			log.SpanLog(ctx, log.DebugLevelInfo, "reservable auto-cluster search", "key", in.Key)
			// search for free ClusterInst
			for _, key := range freeClusterInsts {
				cibuf := edgeproto.ClusterInst{}
				if !s.all.clusterInstApi.store.STMGet(stm, &key, &cibuf) {
					continue
				}
				if cibuf.DeletePrepare {
					return key.BeingDeletedError()
				}
				if s.useReservableClusterInst(stm, ctx, in, &app, sidecarApp, &cibuf) == nil {
					autoClusterType = ReservableAutoCluster
					reservedClusterInstKey = &key
					in.ClusterKey = key.ClusterKey
					cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Chose reservable ClusterInst %s to deploy AppInst", cibuf.Key.ClusterKey.Name)})
					break
				}
			}
		}
		// Create reservable cluster if still no autocluster target
		if autoClusterType == ChooseAutoCluster {
			// No free reservable cluster found, create new one.
			cloudletKey := &in.Key.CloudletKey
			refs := edgeproto.CloudletRefs{}
			if !s.all.cloudletRefsApi.store.STMGet(stm, cloudletKey, &refs) {
				initCloudletRefs(&refs, cloudletKey)
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
			in.ClusterKey.Name = fmt.Sprintf("%s%d", cloudcommon.ReservableClusterPrefix, reservedAutoClusterId)
			in.ClusterKey.Organization = edgeproto.OrganizationEdgeCloud
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Creating new auto-cluster named %s to deploy AppInst", in.ClusterKey.Name)})
			log.SpanLog(ctx, log.DebugLevelApi, "Creating new auto-cluster", "key", in.ClusterInstKey())
		}

		if autoClusterType == NoAutoCluster && cloudcommon.IsClusterInstReqd(&app) {
			// Specified ClusterInst must exist
			var clusterInst edgeproto.ClusterInst
			if !s.all.clusterInstApi.store.STMGet(stm, in.ClusterInstKey(), &clusterInst) {
				return in.ClusterInstKey().NotFoundError()
			}
			if clusterInst.DeletePrepare {
				return in.ClusterInstKey().BeingDeletedError()
			}
			if clusterInst.MultiTenant {
				// multi-tenant base cluster
				err := useMultiTenantClusterInst(stm, ctx, in, &app, sidecarApp, &clusterInst)
				if err != nil {
					return fmt.Errorf("Failed to use specified multi-tenant ClusterInst, %v", err)
				}
			} else if clusterInst.Reservable {
				err := s.useReservableClusterInst(stm, ctx, in, &app, sidecarApp, &clusterInst)
				if err != nil {
					return fmt.Errorf("Failed to reserve specified reservable ClusterInst, %v", err)
				}
			}
			if !sidecarApp && !clusterInst.Reservable && in.Key.Organization != in.Key.Organization {
				return fmt.Errorf("Developer name mismatch between AppInst: %s and ClusterInst: %s", in.Key.Organization, in.ClusterKey.Organization)
			}
			// cluster inst exists so we're good.
		}

		if cloudlet.TrustPolicy != "" {
			if !app.Trusted {
				return fmt.Errorf("Cannot start non trusted App on trusted cloudlet")
			}
			trustPolicy := edgeproto.TrustPolicy{}
			tpKey := edgeproto.PolicyKey{
				Name:         cloudlet.TrustPolicy,
				Organization: cloudlet.Key.Organization,
			}
			if !s.all.trustPolicyApi.store.STMGet(stm, &tpKey, &trustPolicy) {
				return errors.New("Trust Policy for cloudlet not found")
			}
			if trustPolicy.DeletePrepare {
				return tpKey.BeingDeletedError()
			}
			err = s.all.appApi.CheckAppCompatibleWithTrustPolicy(ctx, &cloudlet.Key, &app, &trustPolicy)
			if err != nil {
				return fmt.Errorf("App is not compatible with cloudlet trust policy: %v", err)
			}
		}

		// Since autoclusteripaccess is deprecated, set it to unknown
		in.AutoClusterIpAccess = edgeproto.IpAccess_IP_ACCESS_UNKNOWN

		err = validateImageTypeForPlatform(ctx, app.ImageType, cloudlet.PlatformType, cloudletFeatures)
		if err != nil {
			return err
		}

		// Now that we have a cloudlet, and cloudletInfo, we can validate the flavor requested
		vmFlavor := edgeproto.Flavor{}
		if !s.all.flavorApi.store.STMGet(stm, &in.Flavor, &vmFlavor) {
			return in.Flavor.NotFoundError()
		}
		if vmFlavor.DeletePrepare {
			return in.Flavor.BeingDeletedError()
		}
		if app.DeploymentManifest != "" {
			err = cloudcommon.IsValidDeploymentManifestForFlavor(app.Deployment, app.DeploymentManifest, &vmFlavor)
			if err != nil {
				return fmt.Errorf("Invalid deployment manifest, %v", err)
			}
		}

		vmspec, verr := s.all.resTagTableApi.GetVMSpec(ctx, stm, vmFlavor, in.CloudletFlavor, cloudlet, info)
		if verr != nil {
			return verr
		}
		// if needed, master node flavor will be looked up from createClusterInst
		// save original in.Flavor.Name in that case
		in.VmFlavor = vmspec.FlavorName
		in.AvailabilityZone = vmspec.AvailabilityZone
		in.ExternalVolumeSize = vmspec.ExternalVolumeSize
		log.SpanLog(ctx, log.DebugLevelApi, "Selected AppInst Node Flavor", "vmspec", vmspec.FlavorName)
		in.OptRes = s.all.resTagTableApi.AddGpuResourceHintIfNeeded(ctx, stm, vmspec, cloudlet)
		in.Revision = app.Revision
		appDeploymentType = app.Deployment
		// there may be direct access apps still defined, disallow them from being instantiated.
		if app.AccessType == edgeproto.AccessType_ACCESS_TYPE_DIRECT {
			return fmt.Errorf("Direct Access Apps are no longer supported, please re-create App as ACCESS_TYPE_LOAD_BALANCER")
		}

		if err := s.all.autoProvPolicyApi.appInstCheck(ctx, stm, cloudcommon.Create, &app, in); err != nil {
			return err
		}

		refs := edgeproto.CloudletRefs{}
		if !s.all.cloudletRefsApi.store.STMGet(stm, &in.Key.CloudletKey, &refs) {
			initCloudletRefs(&refs, &in.Key.CloudletKey)
		}
		refsChanged := false
		if app.Deployment == cloudcommon.DeploymentTypeVM {
			// no cluster for vms
			in.ClusterKey = edgeproto.ClusterKey{}
			// check resources
			err = s.all.clusterInstApi.validateResources(ctx, stm, nil, &app, in, &cloudlet, &info, &refs, GenResourceAlerts)
			if err != nil {
				return err
			}
			vmAppInstRefKey := edgeproto.AppInstRefKey{}
			vmAppInstRefKey.FromAppInstKey(&in.Key)
			refs.VmAppInsts = append(refs.VmAppInsts, vmAppInstRefKey)
			refsChanged = true
		}
		// Track K8s AppInstances for resource management only if platform supports K8s deployments only
		if platform.TrackK8sAppInst(ctx, &app, cloudletFeatures) {
			err = s.all.clusterInstApi.validateResources(ctx, stm, nil, &app, nil, &cloudlet, &info, &refs, GenResourceAlerts)
			if err != nil {
				return err
			}
			k8sAppInstRefKey := edgeproto.AppInstRefKey{}
			k8sAppInstRefKey.FromAppInstKey(&in.Key)
			refs.K8SAppInsts = append(refs.K8SAppInsts, k8sAppInstRefKey)
			refsChanged = true
		}
		if refsChanged {
			s.all.cloudletRefsApi.store.STMPut(stm, &refs)
		}
		// Iterate to get a unique id. The number of iterations must
		// be fairly low because the STM has a limit on the number of
		// keys it can manage.
		in.UniqueId = ""
		for ii := 0; ii < 10; ii++ {
			salt := ""
			if ii != 0 {
				salt = strconv.Itoa(ii)
			}
			id, err := pfutils.GetAppInstId(ctx, in, &app, salt, cloudletPlatformType)
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
		if err := s.setDnsLabel(stm, in); err != nil {
			return err
		}

		// Set new state to show autocluster clusterinst progress as part of
		// appinst progress
		in.State = edgeproto.TrackedState_CREATING_DEPENDENCIES
		s.store.STMPut(stm, in)
		s.idStore.STMPut(stm, in.UniqueId, &in.Key)
		s.dnsLabelStore.STMPut(stm, &in.Key.CloudletKey, in.DnsLabel)
		s.all.appInstRefsApi.addRef(stm, &in.AppKey, &in.Key)
		if cloudcommon.IsClusterInstReqd(&app) {
			s.all.clusterRefsApi.addRef(stm, in)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if reservedClusterInstKey != nil {
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
			refsFound := s.all.cloudletRefsApi.store.STMGet(stm, &in.Key.CloudletKey, &refs)
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
					s.dnsLabelStore.STMDel(stm, &in.Key.CloudletKey, in.DnsLabel)
					s.all.appInstRefsApi.removeRef(stm, &in.AppKey, &in.Key)
					if cloudcommon.IsClusterInstReqd(&app) {
						s.all.clusterRefsApi.removeRef(stm, in)
					}
					if refsFound {
						if app.Deployment == cloudcommon.DeploymentTypeVM {
							refsChanged = removeAppInstFromRefs(&in.Key, &refs.VmAppInsts)
						}
						if platform.TrackK8sAppInst(ctx, &app, cloudletFeatures) {
							refsChanged = removeAppInstFromRefs(&in.Key, &refs.K8SAppInsts)
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
			if reservedClusterInstKey != nil {
				cinst := edgeproto.ClusterInst{}
				if s.all.clusterInstApi.store.STMGet(stm, reservedClusterInstKey, &cinst) {
					cinst.ReservedBy = ""
					s.all.clusterInstApi.store.STMPut(stm, &cinst)
				}
			}
			return nil
		})
		if reservedClusterInstKey != nil {
			clusterInstReservationEvent(ctx, cloudcommon.FreeClusterEvent, in)
		}
	}()

	clusterInstKey := *in.ClusterInstKey()

	if createCluster {
		// auto-create cluster inst
		clusterInst.Key = clusterInstKey
		clusterInst.Auto = true
		if autoClusterType == ReservableAutoCluster {
			clusterInst.Reservable = true
			clusterInst.ReservedBy = in.Key.Organization
		}
		log.SpanLog(ctx, log.DebugLevelApi,
			"Create auto-ClusterInst",
			"key", clusterInst.Key,
			"AppInst", in)

		// To reduce the proliferation of different reservable ClusterInst
		// configurations, we restrict reservable ClusterInst configs.
		clusterInst.Flavor.Name = in.Flavor.Name
		clusterInst.NodeFlavor = in.CloudletFlavor
		clusterInst.MasterNodeFlavor = in.CloudletFlavor
		// Prefer IP access shared, but some platforms (gcp, etc) only
		// support dedicated.
		clusterInst.IpAccess = edgeproto.IpAccess_IP_ACCESS_UNKNOWN
		clusterInst.Deployment = appDeploymentType
		if appDeploymentType == cloudcommon.DeploymentTypeKubernetes ||
			appDeploymentType == cloudcommon.DeploymentTypeHelm {
			clusterInst.Deployment = cloudcommon.DeploymentTypeKubernetes
			clusterInst.NumMasters = 1
			clusterInst.NumNodes = 1 // TODO support 1 master, zero nodes
			if cloudletPlatformType == edgeproto.PlatformType_PLATFORM_TYPE_K8S_BARE_METAL || cloudletPlatformType == edgeproto.PlatformType_PLATFORM_TYPE_FEDERATION {
				// bare metal k8s clusters are virtual and have no nodes
				log.SpanLog(ctx, log.DebugLevelApi, "Setting num nodes to 0 for k8s baremetal virtual cluster")
				clusterInst.NumNodes = 0
			}
		}
		clusterInst.Liveness = edgeproto.Liveness_LIVENESS_DYNAMIC
		createStart := time.Now()
		cctxauto := cctx.WithAutoCluster()
		err := s.all.clusterInstApi.createClusterInstInternal(cctxauto, &clusterInst, cb)
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
				undoErr := s.all.clusterInstApi.deleteClusterInstInternal(cctxauto.WithUndo().WithCRMUndo(), &clusterInst, cb)
				if undoErr != nil {
					log.SpanLog(ctx, log.DebugLevelApi,
						"Undo create auto-ClusterInst failed",
						"key", clusterInst.Key,
						"undoErr", undoErr)
				}
			}
		}()
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

		if in.Flavor.Name == "" {
			in.Flavor = app.DefaultFlavor
		}
		cloudlet := edgeproto.Cloudlet{}
		if !s.all.cloudletApi.store.STMGet(stm, &in.Key.CloudletKey, &cloudlet) {
			return errors.New("Specified Cloudlet not found")
		}
		clusterInst := edgeproto.ClusterInst{}
		ipaccess := edgeproto.IpAccess_IP_ACCESS_SHARED
		if cloudcommon.IsClusterInstReqd(&app) {
			if !s.all.clusterInstApi.store.STMGet(stm, in.ClusterInstKey(), &clusterInst) {
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
		}

		cloudletRefs := edgeproto.CloudletRefs{}
		cloudletRefsChanged := false
		if !s.all.cloudletRefsApi.store.STMGet(stm, &in.Key.CloudletKey, &cloudletRefs) {
			initCloudletRefs(&cloudletRefs, &in.Key.CloudletKey)
		}

		in.Uri = getAppInstFQDN(in, &cloudlet)
		ports, _ := edgeproto.ParseAppPorts(app.AccessPorts)
		if !cloudcommon.IsClusterInstReqd(&app) {
			for ii := range ports {
				ports[ii].PublicPort = ports[ii].InternalPort
			}
		} else if in.DedicatedIp {
			// Per AppInst dedicated IP
			for ii := range ports {
				ports[ii].PublicPort = ports[ii].InternalPort
			}
		} else if ipaccess == edgeproto.IpAccess_IP_ACCESS_SHARED && !app.InternalPorts {
			// uri points to cloudlet shared root LB
			in.Uri = cloudlet.RootLbFqdn

			if cloudletRefs.RootLbPorts == nil {
				cloudletRefs.RootLbPorts = make(map[int32]int32)
			}

			for ii, port := range ports {
				if port.EndPort != 0 {
					return fmt.Errorf("Shared IP access with port range not allowed")
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
				existingProtoBits, _ := cloudletRefs.RootLbPorts[eport]
				cloudletRefs.RootLbPorts[eport] = addProtocol(protocolBits, existingProtoBits)

				cloudletRefsChanged = true
			}
		} else {
			if isIPAllocatedPerService(ctx, cloudletPlatformType, cloudletFeatures, in.Key.CloudletKey.Organization) {
				// dedicated access in which each service gets a different ip
				for ii := range ports {
					ports[ii].PublicPort = ports[ii].InternalPort
				}
			} else {
				// we need to prevent overlapping ports on the dedicated rootLB
				if err = s.checkPortOverlapDedicatedLB(ports, &clusterInstKey); !cctx.Undo && err != nil {
					return err
				}
				// dedicated access in which IP is that of the LB
				in.Uri = clusterInst.Fqdn
				for ii := range ports {
					ports[ii].PublicPort = ports[ii].InternalPort
				}
			}
		}
		if app.InternalPorts || len(ports) == 0 {
			// older CRMs require app URI regardless of external access to AppInst
			if cloudletCompatibilityVersion >= cloudcommon.CRMCompatibilitySharedRootLBFQDN {
				// no external access to AppInst, no need for URI
				in.Uri = ""
			}
		}
		if err := cloudcommon.CheckFQDNLengths("", in.Uri); err != nil {
			return err
		}
		if len(ports) > 0 {
			in.MappedPorts = ports
			if isIPAllocatedPerService(ctx, cloudletPlatformType, cloudletFeatures, in.Key.CloudletKey.Organization) {
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
	err = edgeproto.WaitForAppInstInfo(ctx, &in.Key, edgeproto.TrackedState_READY,
		CreateAppInstTransitions, edgeproto.TrackedState_CREATE_ERROR,
		s.all.settingsApi.Get().CreateAppInstTimeout.TimeDuration(),
		"Created AppInst successfully", cb.Send,
		edgeproto.WithCrmMsgCh(sendObj.crmMsgCh),
	)
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
		undoErr := s.deleteAppInstInternal(cctx.WithUndo(), in, cb)
		if undoErr != nil {
			log.InfoLog("Undo create AppInst", "undoErr", undoErr)
		}
	}
	if err == nil {
		s.updateCloudletResourcesMetric(ctx, in)
	}
	return err
}

func (s *AppInstApi) useReservableClusterInst(stm concurrency.STM, ctx context.Context, in *edgeproto.AppInst, app *edgeproto.App, sidecarApp bool, cibuf *edgeproto.ClusterInst) error {
	if !cibuf.Reservable {
		return fmt.Errorf("ClusterInst not reservable")
	}
	if sidecarApp {
		// no restrictions, no reservation
		return nil
	}
	if in.Flavor.Name != cibuf.Flavor.Name {
		return fmt.Errorf("flavor mismatch between AppInst and reservable ClusterInst")
	}
	if cibuf.ReservedBy != "" {
		return fmt.Errorf("ClusterInst already reserved")
	}
	targetDeployment := app.Deployment
	if app.Deployment == cloudcommon.DeploymentTypeHelm {
		targetDeployment = cloudcommon.DeploymentTypeKubernetes
	}
	if targetDeployment != cibuf.Deployment {
		return fmt.Errorf("deployment type mismatch between App and reservable ClusterInst")
	}
	// reserve it
	log.SpanLog(ctx, log.DebugLevelApi, "reserving ClusterInst", "cluster", cibuf.Key.ClusterKey.Name, "AppInst", in.Key)
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
		return fmt.Errorf("App must allow serverless deployment to deploy to multi-tenant cluster %s", cibuf.Key.ClusterKey.Name)
	}
	if app.Deployment != cloudcommon.DeploymentTypeKubernetes {
		return fmt.Errorf("Deployment type must be kubernetes for multi-tenant ClusterInst")
	}
	// TODO: check and reserve resources.
	// May need to trigger adding more nodes to multi-tenant
	// cluster if not enough resources.
	return nil
}

func (s *AppInstApi) updateCloudletResourcesMetric(ctx context.Context, in *edgeproto.AppInst) {
	var err error
	metrics := []*edgeproto.Metric{}
	skipMetric := true
	resErr := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		var cloudlet edgeproto.Cloudlet
		if !s.all.cloudletApi.store.STMGet(stm, &in.Key.CloudletKey, &cloudlet) {
			return in.Key.CloudletKey.NotFoundError()
		}
		var app edgeproto.App
		if !s.all.appApi.store.STMGet(stm, &in.AppKey, &app) {
			return in.AppKey.NotFoundError()
		}
		skipMetric = true
		if app.Deployment == cloudcommon.DeploymentTypeVM {
			metrics, err = s.all.clusterInstApi.getCloudletResourceMetric(ctx, stm, &in.Key.CloudletKey)
			skipMetric = false
			return err
		}
		cloudletFeatures, err := GetCloudletFeatures(ctx, cloudlet.PlatformType)
		if err != nil {
			return fmt.Errorf("Failed to get features for platform: %s", err)
		}
		if platform.TrackK8sAppInst(ctx, &app, cloudletFeatures) {
			metrics, err = s.all.clusterInstApi.getCloudletResourceMetric(ctx, stm, &in.Key.CloudletKey)
			skipMetric = false
			return err
		}
		return nil
	})
	if !skipMetric {
		if resErr == nil {
			services.cloudletResourcesInfluxQ.AddMetric(metrics...)
		} else {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to generate cloudlet resource usage metric", "clusterInstKey", in.Key, "err", resErr)
		}
	}
	return
}

func (s *AppInstApi) updateAppInstStore(ctx context.Context, in *edgeproto.AppInst) error {
	_, err := s.store.Update(ctx, in, s.sync.syncWait)
	return err
}

// refreshAppInstInternal returns true if the appinst updated, false otherwise.  False value with no error means no update was needed
func (s *AppInstApi) refreshAppInstInternal(cctx *CallContext, key edgeproto.AppInstKey, appKey edgeproto.AppKey, inCb edgeproto.AppInstApi_RefreshAppInstServer, forceUpdate bool) (retbool bool, reterr error) {
	ctx := inCb.Context()
	log.SpanLog(ctx, log.DebugLevelApi, "refreshAppInstInternal", "key", key)

	updatedRevision := false
	crmUpdateRequired := false

	if err := key.ValidateKey(); err != nil {
		return false, err
	}

	// create stream once AppInstKey is formed correctly
	sendObj, cb, err := s.startAppInstStream(ctx, cctx, &key, inCb)
	if err != nil {
		return false, err
	}
	defer func() {
		s.stopAppInstStream(ctx, cctx, &key, sendObj, reterr, NoCleanupStream)
	}()

	var app edgeproto.App
	var curr edgeproto.AppInst

	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
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
			cloudletErr := s.all.cloudletInfoApi.checkCloudletReady(cctx, stm, &key.CloudletKey, cloudcommon.Update)
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
	if crmUpdateRequired {
		s.RecordAppInstEvent(ctx, &curr, cloudcommon.UPDATE_START, cloudcommon.InstanceDown)

		defer func() {
			if reterr == nil {
				s.RecordAppInstEvent(ctx, &curr, cloudcommon.UPDATE_COMPLETE, cloudcommon.InstanceUp)
			} else {
				s.RecordAppInstEvent(ctx, &curr, cloudcommon.UPDATE_ERROR, cloudcommon.InstanceDown)
			}
		}()
		err = edgeproto.WaitForAppInstInfo(cb.Context(), &key, edgeproto.TrackedState_READY,
			UpdateAppInstTransitions, edgeproto.TrackedState_UPDATE_ERROR,
			s.all.settingsApi.Get().UpdateAppInstTimeout.TimeDuration(),
			"", cb.Send,
			edgeproto.WithCrmMsgCh(sendObj.crmMsgCh),
		)
	}
	if err != nil {
		return false, err
	} else {
		return updatedRevision, s.updateAppInstRevision(ctx, &key, app.Revision)
	}
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

	for instkey, _ := range instances {
		go func(k edgeproto.AppInstKey) {
			log.SpanLog(ctx, log.DebugLevelApi, "updating AppInst", "key", k)
			updated, err := s.refreshAppInstInternal(DefCallContext(), k, appKey, cb, in.ForceUpdate)
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
				cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Failed for AppInst %s[%s], cloudlet %s[%s]: %s", k.Name, k.Organization, k.CloudletKey.Name, k.CloudletKey.Organization, result.errString)})
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
	if _, found := fmap[edgeproto.AppInstFieldPowerState]; found {
		for _, field := range in.Fields {
			if field == edgeproto.AppInstFieldCrmOverride ||
				field == edgeproto.AppInstFieldKey ||
				field == edgeproto.AppInstFieldPowerState ||
				in.IsKeyField(field) {
				continue
			} else if _, ok := edgeproto.UpdateAppInstFieldsMap[field]; ok {
				return fmt.Errorf("If powerstate is to be updated, then no other fields can be modified")
			}
		}
		// Get the request state as user has specified action and not state
		powerState = edgeproto.GetNextPowerState(in.PowerState, edgeproto.RequestState)
		if powerState == edgeproto.PowerState_POWER_STATE_UNKNOWN {
			return fmt.Errorf("Invalid power state specified")
		}
	}

	cctx := DefCallContext()
	cctx.SetOverride(&in.CrmOverride)

	cur := edgeproto.AppInst{}
	changeCount := 0
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		changeCount = cur.CopyInFields(in)
		if changeCount == 0 {
			// nothing changed
			return nil
		}
		if !ignoreCRM(cctx) && powerState != edgeproto.PowerState_POWER_STATE_UNKNOWN {
			var app edgeproto.App
			if !s.all.appApi.store.STMGet(stm, &in.AppKey, &app) {
				return in.AppKey.NotFoundError()
			}
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
	_, err = s.refreshAppInstInternal(cctx, in.Key, in.AppKey, cb, forceUpdate)
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
	clusterInstKey := edgeproto.ClusterInstKey{}

	if err := in.Key.ValidateKey(); err != nil {
		return err
	}

	appInstKey := in.Key
	// create stream once AppInstKey is formed correctly
	sendObj, cb, err := s.startAppInstStream(ctx, cctx, &appInstKey, inCb)
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

	// get appinst info for flavor
	appInstInfo := edgeproto.AppInst{}
	if !s.cache.Get(&in.Key, &appInstInfo) {
		return in.Key.NotFoundError()
	}
	eventCtx := context.WithValue(ctx, in.Key, appInstInfo)
	defer func() {
		if reterr != nil {
			return
		}
		s.RecordAppInstEvent(eventCtx, in, cloudcommon.DELETED, cloudcommon.InstanceDown)
		if reservationFreed {
			s.all.clusterInstApi.RecordClusterInstEvent(ctx, &clusterInstKey, cloudcommon.UNRESERVED, cloudcommon.InstanceDown)
		}
	}()

	log.SpanLog(ctx, log.DebugLevelApi, "deleteAppInstInternal", "AppInst", in)
	// populate the clusterinst developer from the app developer if not already present
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		// clear change tracking vars in case STM is rerun due to conflict.
		reservationFreed = false

		if !s.store.STMGet(stm, &in.Key, in) {
			// already deleted
			return in.Key.NotFoundError()
		}
		if err := validateDeleteState(cctx, "AppInst", in.State, in.Errors, cb.Send); err != nil {
			return err
		}
		if err := s.all.cloudletInfoApi.checkCloudletReady(cctx, stm, &in.Key.CloudletKey, cloudcommon.Delete); err != nil {
			return err
		}

		var cloudlet edgeproto.Cloudlet
		if !s.all.cloudletApi.store.STMGet(stm, &in.Key.CloudletKey, &cloudlet) {
			return fmt.Errorf("For AppInst, %v", in.Key.CloudletKey.NotFoundError())
		}
		app = edgeproto.App{}
		if !s.all.appApi.store.STMGet(stm, &in.AppKey, &app) {
			return fmt.Errorf("For AppInst, %v", in.AppKey.NotFoundError())
		}
		clusterInstReqd := cloudcommon.IsClusterInstReqd(&app)
		clusterInst := edgeproto.ClusterInst{}
		clusterInstKey := in.ClusterInstKey()
		if clusterInstReqd && !s.all.clusterInstApi.store.STMGet(stm, clusterInstKey, &clusterInst) {
			return fmt.Errorf("For AppInst, %v", clusterInstKey.NotFoundError())
		}
		if err := s.all.autoProvPolicyApi.appInstCheck(ctx, stm, cloudcommon.Delete, &app, in); err != nil {
			return err
		}

		cloudletRefs := edgeproto.CloudletRefs{}
		cloudletRefsChanged := false
		hasRefs := s.all.cloudletRefsApi.store.STMGet(stm, &in.Key.CloudletKey, &cloudletRefs)
		if hasRefs && clusterInstReqd && clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_SHARED && !app.InternalPorts && !in.DedicatedIp {
			// shared root load balancer
			log.SpanLog(ctx, log.DebugLevelApi, "refs", "AppInst", in)
			for ii, _ := range in.MappedPorts {

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
				aiKey := edgeproto.AppInstKey{}
				aiKey.FromAppInstRefKey(&cloudletRefs.VmAppInsts[ii], &in.Key.CloudletKey)
				if aiKey.Matches(&in.Key) {
					break
				}
			}
			if ii < len(cloudletRefs.VmAppInsts) {
				// explicity zero out deleted item to
				// prevent memory leak
				a := cloudletRefs.VmAppInsts
				copy(a[ii:], a[ii+1:])
				a[len(a)-1] = edgeproto.AppInstRefKey{}
				cloudletRefs.VmAppInsts = a[:len(a)-1]
				cloudletRefsChanged = true
			}
		}
		cloudletFeatures, err := GetCloudletFeatures(ctx, cloudlet.PlatformType)
		if err != nil {
			return fmt.Errorf("Failed to get features for platform: %s", err)
		}
		if platform.TrackK8sAppInst(ctx, &app, cloudletFeatures) {
			ii := 0
			for ; ii < len(cloudletRefs.K8SAppInsts); ii++ {
				aiKey := edgeproto.AppInstKey{}
				aiKey.FromAppInstRefKey(&cloudletRefs.K8SAppInsts[ii], &in.Key.CloudletKey)
				if aiKey.Matches(&in.Key) {
					break
				}
			}
			if ii < len(cloudletRefs.K8SAppInsts) {
				// explicity zero out deleted item to
				// prevent memory leak
				a := cloudletRefs.K8SAppInsts
				copy(a[ii:], a[ii+1:])
				a[len(a)-1] = edgeproto.AppInstRefKey{}
				cloudletRefs.K8SAppInsts = a[:len(a)-1]
				cloudletRefsChanged = true
			}
		}
		if cloudletRefsChanged {
			s.all.cloudletRefsApi.store.STMPut(stm, &cloudletRefs)
		}
		if clusterInstReqd && clusterInst.ReservedBy != "" && clusterInst.ReservedBy == in.Key.Organization {
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
			s.dnsLabelStore.STMDel(stm, &in.Key.CloudletKey, in.DnsLabel)
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
	// clear all alerts for this appInst
	s.all.alertApi.CleanupAppInstAlerts(ctx, &appInstKey)
	if ignoreCRM(cctx) {
		cb.Send(&edgeproto.Result{Message: "Deleted AppInst successfully"})
	} else {
		err = edgeproto.WaitForAppInstInfo(ctx, &in.Key, edgeproto.TrackedState_NOT_PRESENT,
			DeleteAppInstTransitions, edgeproto.TrackedState_DELETE_ERROR,
			s.all.settingsApi.Get().DeleteAppInstTimeout.TimeDuration(),
			"Deleted AppInst successfully", cb.Send,
			edgeproto.WithCrmMsgCh(sendObj.crmMsgCh),
		)
		if err != nil && cctx.Override == edgeproto.CRMOverride_IGNORE_CRM_ERRORS {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Delete AppInst ignoring CRM failure: %s", err.Error())})
			s.ReplaceErrorState(ctx, in, edgeproto.TrackedState_DELETE_DONE)
			cb.Send(&edgeproto.Result{Message: "Deleted AppInst successfully"})
			err = nil
		}
		if err != nil {
			// crm failed or some other err, undo
			cb.Send(&edgeproto.Result{Message: "Recreating AppInst due to failure"})
			undoErr := s.createAppInstInternal(cctx.WithUndo(), in, cb)
			if undoErr != nil {
				log.InfoLog("Undo delete AppInst", "undoErr", undoErr)
			}
			return err
		}
		if err == nil {
			s.updateCloudletResourcesMetric(ctx, in)
		}
	}
	// delete clusterinst afterwards if it was auto-created and nobody is left using it
	// this is retained for old autoclusters that are not reservable,
	// and can be removed once no old autoclusters exist anymore.
	clusterInst := edgeproto.ClusterInst{}
	if s.all.clusterInstApi.Get(&clusterInstKey, &clusterInst) && clusterInst.Auto && !s.UsesClusterInst(in.Key.Organization, &clusterInstKey) && !clusterInst.Reservable {
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

	s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		applyUpdate := false
		inst := edgeproto.AppInst{}
		if !s.store.STMGet(stm, &in.Key, &inst) {
			// got deleted in the meantime
			return nil
		}
		if in.PowerState != edgeproto.PowerState_POWER_STATE_UNKNOWN &&
			inst.PowerState != in.PowerState {
			inst.PowerState = in.PowerState
			applyUpdate = true
		}
		// If AppInst is ready and state has not been set yet by HealthCheckUpdate, default to Ok.
		if in.State == edgeproto.TrackedState_READY &&
			inst.HealthCheck == dme.HealthCheck_HEALTH_CHECK_UNKNOWN {
			inst.HealthCheck = dme.HealthCheck_HEALTH_CHECK_OK
			applyUpdate = true
		}

		if in.Uri != "" && inst.Uri != in.Uri {
			inst.Uri = in.Uri
			applyUpdate = true
		}
		if in.FedKey.AppInstId != "" && inst.FedKey.AppInstId == "" {
			inst.FedKey = in.FedKey
			fedAppInst := edgeproto.FedAppInst{
				Key:        in.FedKey,
				AppInstKey: in.Key,
			}
			s.fedStore.STMPut(stm, &fedAppInst)
			applyUpdate = true
		}
		if len(in.FedPorts) > 0 {
			log.SpanLog(ctx, log.DebugLevelApi, "Updating ports on federated appinst", "key", in.Key, "ports", in.FedPorts)
			fedPortLookup := map[string]*dme.AppPort{}
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

		if len(in.RuntimeInfo.ContainerIds) > 0 {
			inst.RuntimeInfo = in.RuntimeInfo
			applyUpdate = true
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
		s.dnsLabelStore.STMDel(stm, &inst.Key.CloudletKey, inst.DnsLabel)
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
			s.dnsLabelStore.STMDel(stm, &inst.Key.CloudletKey, inst.DnsLabel)
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
func isIPAllocatedPerService(ctx context.Context, platformType edgeproto.PlatformType, features *edgeproto.PlatformFeatures, operator string) bool {
	log.SpanLog(ctx, log.DebugLevelApi, "isIPAllocatedPerService", "platformType", platformType, "operator", operator)

	if features.IsFake {
		// for a fake cloudlet used in testing, decide based on operator name
		return operator == cloudcommon.OperatorGCP || operator == cloudcommon.OperatorAzure || operator == cloudcommon.OperatorAWS
	}
	return features.IpAllocatedPerService
}

func validateImageTypeForPlatform(ctx context.Context, imageType edgeproto.ImageType, platformType edgeproto.PlatformType, features *edgeproto.PlatformFeatures) error {
	log.SpanLog(ctx, log.DebugLevelApi, "validateImageTypeForPlatform", "imageType", imageType, "platformType", platformType)
	supported := true
	if imageType == edgeproto.ImageType_IMAGE_TYPE_OVF && !features.SupportsImageTypeOvf {
		supported = false
	}
	if imageType == edgeproto.ImageType_IMAGE_TYPE_OVA && !features.SupportsImageTypeOva {
		supported = false
	}
	if !supported {
		platName := edgeproto.PlatformType_name[int32(platformType)]
		return fmt.Errorf("image type %s is not valid for platform type: %s", imageType.String(), platName)
	}
	return nil
}

func allocateIP(ctx context.Context, inst *edgeproto.ClusterInst, cloudlet *edgeproto.Cloudlet, platformType edgeproto.PlatformType, features *edgeproto.PlatformFeatures, refs *edgeproto.CloudletRefs) error {

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
		for ii, _ := range in.MappedPorts {
			setPortFQDNPrefix(&in.MappedPorts[ii], objs)
			if err := cloudcommon.CheckFQDNLengths(in.MappedPorts[ii].FqdnPrefix, in.Uri); err != nil {
				return err
			}
		}
	}
	return nil
}

func setPortFQDNPrefix(port *dme.AppPort, objs []runtime.Object) {
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

func (s *AppInstApi) RecordAppInstEvent(ctx context.Context, appInst *edgeproto.AppInst, event cloudcommon.InstanceEvent, serverStatus string) {
	metric := edgeproto.Metric{}
	metric.Name = cloudcommon.AppInstEvent
	now := time.Now()
	ts, _ := types.TimestampProto(now)
	metric.Timestamp = *ts
	metric.AddStringVal(edgeproto.CloudletKeyTagOrganization, appInst.Key.CloudletKey.Organization)
	metric.AddTag(edgeproto.CloudletKeyTagName, appInst.Key.CloudletKey.Name)
	metric.AddTag(edgeproto.CloudletKeyTagFederatedOrganization, appInst.Key.CloudletKey.FederatedOrganization)
	metric.AddTag(edgeproto.ClusterKeyTagName, appInst.ClusterKey.Name)
	metric.AddTag(edgeproto.ClusterKeyTagOrganization, appInst.ClusterKey.Organization)
	metric.AddTag(edgeproto.AppKeyTagOrganization, appInst.AppKey.Organization)
	metric.AddTag(edgeproto.AppKeyTagName, appInst.AppKey.Name)
	metric.AddTag(edgeproto.AppKeyTagVersion, appInst.AppKey.Version)
	metric.AddTag(edgeproto.AppInstKeyTagName, appInst.Key.Name)
	metric.AddTag(edgeproto.AppInstKeyTagOrganization, appInst.Key.Organization)
	metric.AddTag(cloudcommon.MetricTagOrg, appInst.Key.Organization)
	metric.AddStringVal(cloudcommon.MetricTagEvent, string(event))
	metric.AddStringVal(cloudcommon.MetricTagStatus, serverStatus)

	app := edgeproto.App{}
	if !s.all.appApi.cache.Get(&appInst.AppKey, &app) {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Cannot find appdata for app", "app", appInst.AppKey)
		return
	}
	metric.AddStringVal(cloudcommon.MetricTagDeployment, app.Deployment)

	if app.Deployment == cloudcommon.DeploymentTypeVM {
		metric.AddStringVal(cloudcommon.MetricTagFlavor, appInst.Flavor.Name)
	}
	services.events.AddMetric(&metric)
}

func clusterInstReservationEvent(ctx context.Context, eventName string, appInst *edgeproto.AppInst) {
	nodeMgr.Event(ctx, eventName, appInst.Key.Organization, appInst.GetTags(), nil, edgeproto.ClusterKeyTagName, appInst.ClusterKey.Name, edgeproto.ClusterKeyTagOrganization, appInst.ClusterKey.Organization)
}
