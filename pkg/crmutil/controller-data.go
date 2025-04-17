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

package crmutil

import (
	"context"
	"fmt"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

type GetPlatformFunc func(ctx context.Context, key *edgeproto.CloudletKey) (platform.Platform, error)

// CRMHandler handles converting received changes into platform API calls
// Handler functions should not spawn other threads unless they wait for
// for those threads to complete. The caller handles running the CRMHandler
// functions in separate threads if needed, and relies on knowing when the
// work has been completed.
type CRMHandler struct {
	getPlatform               GetPlatformFunc
	AppCache                  edgeproto.AppCache
	AppInstCache              edgeproto.AppInstCache
	CloudletCache             *edgeproto.CloudletCache
	CloudletInternalCache     edgeproto.CloudletInternalCache
	VMPoolCache               edgeproto.VMPoolCache
	FlavorCache               edgeproto.FlavorCache
	ClusterInstCache          edgeproto.ClusterInstCache
	VMPoolInfoCache           edgeproto.VMPoolInfoCache
	TrustPolicyCache          edgeproto.TrustPolicyCache
	TrustPolicyExceptionCache edgeproto.TrustPolicyExceptionCache
	TPEInstanceStateCache     edgeproto.TPEInstanceStateCache
	AutoProvPolicyCache       edgeproto.AutoProvPolicyCache
	AutoScalePolicyCache      edgeproto.AutoScalePolicyCache
	AlertCache                edgeproto.AlertCache
	SettingsCache             edgeproto.SettingsCache
	ResTagTableCache          edgeproto.ResTagTableCache
	GPUDriverCache            edgeproto.GPUDriverCache
	AlertPolicyCache          edgeproto.AlertPolicyCache
	NetworkCache              edgeproto.NetworkCache
	Settings                  edgeproto.Settings
	NodeMgr                   *svcnode.SvcNodeMgr
}

// NewCRMHandler creates a new CRMHandler. If cache data comes from storage, set sync.
// If cache data comes from the notify framework, leave sync nil.
func NewCRMHandler(getPlatform GetPlatformFunc, nodeMgr *svcnode.SvcNodeMgr) *CRMHandler {
	cd := &CRMHandler{}
	cd.getPlatform = getPlatform
	edgeproto.InitAppCache(&cd.AppCache)
	edgeproto.InitAppInstCache(&cd.AppInstCache)
	edgeproto.InitCloudletInternalCache(&cd.CloudletInternalCache)
	cd.CloudletCache = nodeMgr.CloudletLookup.GetCloudletCache(svcnode.NoRegion)
	edgeproto.InitVMPoolCache(&cd.VMPoolCache)
	edgeproto.InitVMPoolInfoCache(&cd.VMPoolInfoCache)
	edgeproto.InitFlavorCache(&cd.FlavorCache)
	edgeproto.InitClusterInstCache(&cd.ClusterInstCache)
	edgeproto.InitAlertCache(&cd.AlertCache)
	edgeproto.InitTrustPolicyCache(&cd.TrustPolicyCache)
	edgeproto.InitTrustPolicyExceptionCache(&cd.TrustPolicyExceptionCache)
	edgeproto.InitTPEInstanceStateCache(&cd.TPEInstanceStateCache)
	edgeproto.InitAutoProvPolicyCache(&cd.AutoProvPolicyCache)
	edgeproto.InitAutoScalePolicyCache(&cd.AutoScalePolicyCache)
	edgeproto.InitSettingsCache(&cd.SettingsCache)
	edgeproto.InitResTagTableCache(&cd.ResTagTableCache)
	edgeproto.InitGPUDriverCache(&cd.GPUDriverCache)
	edgeproto.InitAlertPolicyCache(&cd.AlertPolicyCache)
	edgeproto.InitNetworkCache(&cd.NetworkCache)
	cd.NodeMgr = nodeMgr
	cd.Settings = *edgeproto.GetDefaultSettings()

	return cd
}

func (cd *CRMHandler) GetCaches() *platform.Caches {
	return &platform.Caches{
		FlavorCache:               &cd.FlavorCache,
		TrustPolicyCache:          &cd.TrustPolicyCache,
		TrustPolicyExceptionCache: &cd.TrustPolicyExceptionCache,
		ClusterInstCache:          &cd.ClusterInstCache,
		AppCache:                  &cd.AppCache,
		AppInstCache:              &cd.AppInstCache,
		ResTagTableCache:          &cd.ResTagTableCache,
		CloudletCache:             cd.CloudletCache,
		CloudletInternalCache:     &cd.CloudletInternalCache,
		VMPoolCache:               &cd.VMPoolCache,
		VMPoolInfoCache:           &cd.VMPoolInfoCache,
		GPUDriverCache:            &cd.GPUDriverCache,
		NetworkCache:              &cd.NetworkCache,
		SettingsCache:             &cd.SettingsCache,
	}
}

// GatherInitialCloudletInfo gathers on the info when the cloudlet is first
// created that the controller needs to know about. New data is written
// to the passed in CloudletInfo.
func (s *CRMHandler) GatherInitialCloudletInfo(ctx context.Context, cloudlet *edgeproto.Cloudlet, pf platform.Platform, cloudletInfo *edgeproto.CloudletInfo, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfo, "Gather initial cloudlet info")

	updateCallback(edgeproto.UpdateTask, "Gathering Cloudlet Info")
	err := s.GatherCloudletInfo(ctx, pf, cloudletInfo)
	if err != nil {
		return err
	}

	resources, err := s.CaptureResourcesSnapshot(ctx, pf, &cloudlet.Key)
	if err != nil {
		return err
	}
	if resources != nil {
		cloudletInfo.ResourcesSnapshot = *resources
	}
	return nil
}

// GatherCloudletInfo gathers all the information about the Cloudlet that
// the controller needs to be able to manage it.
func (cd *CRMHandler) GatherCloudletInfo(ctx context.Context, pf platform.Platform, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "attempting to gather cloudlet info")
	err := pf.GatherCloudletInfo(ctx, info)
	if err != nil {
		return fmt.Errorf("get limits failed: %s", err)
	}
	return nil
}

// GetInsts queries Openstack/Kubernetes to get all the cluster insts
// and app insts that have been created on the Cloudlet.
// It is called once at startup, and is used to repopulate the cache
// after CRM restart/crash. When the CRM connects to the controller,
// it will send the insts in the cache and the controller will resolve
// any discrepancies between the CRM's current state versus the
// controller's intended state.
//
// The controller does not know about all the steps that are used to
// create/delete a ClusterInst/AppInst, so if the CRM crashed in the
// middle of such a task, it is up to the CRM to clean up any unfinished
// state.
func (cd *CRMHandler) GatherInsts() {
	// TODO: Implement me.
	// for _, cluster := range MexClusterShowClustInst() {
	//   key := get key from cluster
	//   cd.clusterInstInfoState(key, edgeproto.TrackedState_READY)
	//   for _, app := range MexAppShowAppInst(cluster) {
	//      key := get key from app
	//      cd.appInstInfoState(key, edgeproto.TrackedState_READY)
	//   }
	// }
}

// Note: these callback functions are called in the context of
// the notify receive thread. If the actions done here not quick,
// they should be done in a separate worker thread.

func (cd *CRMHandler) SettingsChanged(ctx context.Context, old *edgeproto.Settings, new *edgeproto.Settings) {
	cd.Settings = *new
}

func (cd *CRMHandler) CaptureResourcesSnapshot(ctx context.Context, pf platform.Platform, cloudletKey *edgeproto.CloudletKey) (*edgeproto.InfraResourcesSnapshot, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "update cloudlet resources snapshot", "key", cloudletKey)

	resources, err := pf.GetCloudletInfraResources(ctx)
	if err != nil {
		errstr := fmt.Sprintf("Cloudlet resource update failed: %v", err)
		log.SpanLog(ctx, log.DebugLevelInfra, "can't fetch cloudlet resources", "error", errstr, "key", cloudletKey)
		cd.NodeMgr.Event(ctx, "Cloudlet infra resource update failure", cloudletKey.Organization, cloudletKey.GetTags(), err)
		return nil, err
	}
	return resources, nil
}

type NeedsUpdate struct {
	Resources      bool
	AppInstRuntime bool
}

func (cd *CRMHandler) clusterInstDNSChanged(ctx context.Context, pf platform.Platform, oldFQDN string, new *edgeproto.ClusterInst, sender edgeproto.ClusterInstInfoSender) (reterr error) {
	var err error

	log.SpanLog(ctx, log.DebugLevelInfra, "ClusterInstChange for DNS", "key", new.Key, "old dns", oldFQDN, "new dns", new.Fqdn)

	updateClusterCacheCallback := sender.SendStatusIgnoreErr
	// reset status messages
	err = sender.SendState(edgeproto.TrackedState_UPDATING, edgeproto.WithSenderResetStatus())
	if err != nil {
		return err
	}
	err = pf.ChangeClusterInstDNS(ctx, new, oldFQDN, updateClusterCacheCallback)
	if err != nil {
		err := fmt.Errorf("update failed: %s", err)
		sender.SendState(edgeproto.TrackedState_UPDATE_ERROR, edgeproto.WithStateError(err))
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "ClusterInstChange for DNS done", "key", new.Key, "old dns", oldFQDN, "new dns", new.Fqdn)
	sender.SendState(edgeproto.TrackedState_READY)
	return nil
}

func (cd *CRMHandler) ClusterInstChanged(ctx context.Context, target *edgeproto.CloudletKey, new *edgeproto.ClusterInst, sender edgeproto.ClusterInstInfoSender) (nu NeedsUpdate, reterr error) {
	var err error

	fmap := edgeproto.MakeFieldMap(new.Fields)

	dnsUpdate := false
	oldFQDN, ok := new.Annotations[cloudcommon.AnnotationPreviousDNSName]
	if fmap.Has(edgeproto.ClusterInstFieldFqdn) && ok {
		dnsUpdate = true
	}

	if !fmap.Has(edgeproto.ClusterInstFieldState) && !dnsUpdate {
		return nu, nil
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "ClusterInstChange", "key", new.Key, "state", new.State)

	updateClusterCacheCallback := sender.SendStatusIgnoreErr

	pf, err := cd.getPlatform(ctx, target)
	if err != nil {
		return nu, err
	}

	// Special case for dns update
	if dnsUpdate {
		_ = cd.clusterInstDNSChanged(ctx, pf, oldFQDN, new, sender)
		return nu, nil
	}

	if new.State == edgeproto.TrackedState_CREATE_REQUESTED ||
		new.State == edgeproto.TrackedState_UPDATE_REQUESTED ||
		new.State == edgeproto.TrackedState_DELETE_REQUESTED {
		nu.Resources = true
	}
	if new.State == edgeproto.TrackedState_UPDATE_REQUESTED {
		nu.AppInstRuntime = true
	}

	// do request
	if new.State == edgeproto.TrackedState_CREATE_REQUESTED {
		// create
		log.SpanLog(ctx, log.DebugLevelInfra, "ClusterInst create", "ClusterInst", *new)
		// reset status messages
		// create or update k8s cluster on this cloudlet
		err = sender.SendState(edgeproto.TrackedState_CREATING, edgeproto.WithSenderResetStatus())
		if err != nil {
			return nu, err
		}
		var cloudlet edgeproto.Cloudlet

		if !cd.CloudletCache.Get(&new.CloudletKey, &cloudlet) {
			err = new.CloudletKey.NotFoundError()
			sender.SendState(edgeproto.TrackedState_CREATE_ERROR, edgeproto.WithStateError(err))
			return nu, err
		}
		timeout := cd.Settings.CreateClusterInstTimeout.TimeDuration()
		if cloudlet.TimeLimits.CreateClusterInstTimeout != 0 {
			timeout = cloudlet.TimeLimits.CreateClusterInstTimeout.TimeDuration()
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "create cluster inst", "ClusterInst", *new, "timeout", timeout)

		infraAnnotations, err := pf.CreateClusterInst(ctx, new, updateClusterCacheCallback, timeout)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "error cluster create fail", "error", err)
			sender.SendState(edgeproto.TrackedState_CREATE_ERROR, edgeproto.WithStateError(err))
			return nu, err
		}
		if err := cd.clusterInstInfoAnnotations(ctx, sender, infraAnnotations); err != nil {
			return nu, err
		}
		// Get cluster resources and report to controller.
		updateClusterCacheCallback(edgeproto.UpdateTask, "Getting Cluster Infra Resources")
		resources, err := pf.GetClusterInfraResources(ctx, new)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "error getting infra resources", "err", err)
		} else {
			err = cd.clusterInstInfoResources(ctx, sender, resources)
			if err != nil {
				// this can happen if the cluster is deleted
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to set cluster inst resources", "err", err)
			}
		}
		if new.IsCloudletManaged() {
			cmcInfo, err := pf.GetCloudletManagedClusterInfo(ctx, new)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "error getting managed cluster info", "err", err)
			} else {
				err = cd.clusterInstCloudletManagedClusterInfo(ctx, sender, cmcInfo)
				if err != nil {
					// this can happen if the cluster is deleted
					log.SpanLog(ctx, log.DebugLevelInfra, "failed to set cluster inst cloudlet managed cluster info", "err", err)
				}
			}
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "cluster state ready", "ClusterInst", *new)
		sender.SendState(edgeproto.TrackedState_READY)
	} else if new.State == edgeproto.TrackedState_UPDATE_REQUESTED {
		log.SpanLog(ctx, log.DebugLevelInfra, "cluster inst update", "ClusterInst", *new)
		// reset status messages
		err = sender.SendState(edgeproto.TrackedState_UPDATING, edgeproto.WithSenderResetStatus())
		if err != nil {
			return nu, err
		}

		log.SpanLog(ctx, log.DebugLevelInfra, "update cluster inst", "ClusterInst", *new)
		infraAnnotations, err := pf.UpdateClusterInst(ctx, new, updateClusterCacheCallback)
		if err != nil {
			err := fmt.Errorf("update failed: %s", err)
			sender.SendState(edgeproto.TrackedState_UPDATE_ERROR, edgeproto.WithStateError(err))
			return nu, err
		}
		if err := cd.clusterInstInfoAnnotations(ctx, sender, infraAnnotations); err != nil {
			return nu, err
		}
		// Get cluster resources and report to controller.
		updateClusterCacheCallback(edgeproto.UpdateTask, "Getting Cluster Infra Resources")
		resources, err := pf.GetClusterInfraResources(ctx, new)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "error getting infra resources", "err", err)
		} else {
			err = cd.clusterInstInfoResources(ctx, sender, resources)
			if err != nil {
				// this can happen if the cluster is deleted
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to set cluster inst resources", "err", err)
			}
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "cluster state ready", "ClusterInst", *new)
		sender.SendState(edgeproto.TrackedState_READY)
	} else if new.State == edgeproto.TrackedState_DELETE_REQUESTED {
		log.SpanLog(ctx, log.DebugLevelInfra, "cluster inst delete", "ClusterInst", *new)
		// reset status messages
		// clusterInst was deleted
		err = sender.SendState(edgeproto.TrackedState_DELETING, edgeproto.WithSenderResetStatus())
		if err != nil {
			return nu, err
		}

		log.SpanLog(ctx, log.DebugLevelInfra, "delete cluster inst", "ClusterInst", *new)
		err = pf.DeleteClusterInst(ctx, new, updateClusterCacheCallback)
		if err != nil {
			err := fmt.Errorf("Delete failed: %s", err)
			sender.SendState(edgeproto.TrackedState_DELETE_ERROR, edgeproto.WithStateError(err))
			return nu, err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "set cluster inst deleted", "ClusterInst", *new)

		sender.SendState(edgeproto.TrackedState_DELETE_DONE)
	}
	return nu, nil
}

func (cd *CRMHandler) CloudletHasTrustPolicy(ctx context.Context, cloudletKey *edgeproto.CloudletKey) (bool, error) {
	var cloudlet edgeproto.Cloudlet
	if !cd.CloudletCache.Get(cloudletKey, &cloudlet) {
		log.SpanLog(ctx, log.DebugLevelInfra, "CloudletHasTrustPolicy() failed to fetch cloudlet from cache", "cloudletKey", cloudletKey)
		return false, fmt.Errorf("cloudlet %s not found", cloudletKey.String())
	}
	if cloudlet.TrustPolicy == "" {
		// For a TrustPolicy exception, a cloudlet needs to have a TrustPolicy.
		log.SpanLog(ctx, log.DebugLevelInfra, "CloudletHasTrustPolicy() cloudlet does not have a trust policy", "cloudletKey", cloudletKey)
		return false, nil
	}
	return true, nil
}

func (cd *CRMHandler) appInstDNSChanged(ctx context.Context, pf platform.Platform, app *edgeproto.App, oldURI string, new *edgeproto.AppInst, sender edgeproto.AppInstInfoSender) (reterr error) {
	var err error

	updateAppCacheCallback := sender.SendStatusIgnoreErr
	log.SpanLog(ctx, log.DebugLevelInfra, "AppInstDNSChanged", "key", new.Key, "old dns", oldURI, "new dns", new.Uri)

	// reset status messages
	err = sender.SendState(edgeproto.TrackedState_UPDATING, edgeproto.WithSenderResetStatus())
	if err != nil {
		return err
	}
	err = pf.ChangeAppInstDNS(ctx, app, new, oldURI, updateAppCacheCallback)
	if err != nil {
		err := fmt.Errorf("update failed: %s", err)
		sender.SendState(edgeproto.TrackedState_UPDATE_ERROR, edgeproto.WithStateError(err))
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "AppInstDNSChanged done", "key", new.Key, "old dns", oldURI, "new dns", new.Uri)
	sender.SendUpdate(func(info *edgeproto.AppInstInfo) error {
		info.Fields = []string{edgeproto.AppInstInfoFieldUri}
		info.Uri = new.Uri
		return nil
	})
	sender.SendState(edgeproto.TrackedState_READY)
	return nil
}

func (cd *CRMHandler) AppInstChanged(ctx context.Context, target *edgeproto.CloudletKey, new *edgeproto.AppInst, sender edgeproto.AppInstInfoSender) (nu NeedsUpdate, reterr error) {
	var err error

	log.SpanLog(ctx, log.DebugLevelInfra, "appInstChanged", "new", new)

	fmap := edgeproto.MakeFieldMap(new.Fields)
	dnsUpdate := false
	oldURI, ok := new.Annotations[cloudcommon.AnnotationPreviousDNSName]
	if fmap.Has(edgeproto.AppInstFieldUri) && ok {
		dnsUpdate = true
	}

	if !fmap.Has(edgeproto.AppInstFieldState) && !dnsUpdate {
		return nu, nil
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "process app inst change", "key", new.Key, "state", new.State)
	app := edgeproto.App{}
	found := cd.AppCache.Get(&new.AppKey, &app)
	if !found {
		log.SpanLog(ctx, log.DebugLevelInfra, "App not found for AppInst", "key", new.Key)
		return nu, new.AppKey.NotFoundError()
	}
	pf, err := cd.getPlatform(ctx, target)
	if err != nil {
		return nu, err
	}

	// Special case for dns update
	if dnsUpdate {
		_ = cd.appInstDNSChanged(ctx, pf, &app, oldURI, new, sender)
		return nu, nil
	}

	trackChange := app.Deployment == cloudcommon.DeploymentTypeVM || platform.TrackK8sAppInst(ctx, &app, pf.GetFeatures())
	validReqState := new.State == edgeproto.TrackedState_CREATE_REQUESTED ||
		new.State == edgeproto.TrackedState_UPDATE_REQUESTED ||
		new.State == edgeproto.TrackedState_DELETE_REQUESTED
	if trackChange && validReqState {
		nu.Resources = true
	}
	if new.State == edgeproto.TrackedState_CREATE_REQUESTED ||
		new.State == edgeproto.TrackedState_UPDATE_REQUESTED {
		nu.AppInstRuntime = true
	}

	// do request
	updateAppCacheCallback := sender.SendStatusIgnoreErr

	if new.State == edgeproto.TrackedState_CREATE_REQUESTED {
		// reset status messages
		// create
		err = sender.SendState(edgeproto.TrackedState_CREATING, edgeproto.WithSenderResetStatus())
		if err != nil {
			return nu, err
		}

		flavor := edgeproto.Flavor{}
		if new.Flavor.Name != "" {
			flavorFound := cd.FlavorCache.Get(&new.Flavor, &flavor)
			if !flavorFound {
				err = new.Flavor.NotFoundError()
				sender.SendState(edgeproto.TrackedState_CREATE_ERROR, edgeproto.WithStateError(err))
				return nu, err
			}
		}
		clusterInst := edgeproto.ClusterInst{}
		if cloudcommon.IsClusterInstReqd(&app) {
			if !cd.ClusterInstCache.Get(new.GetClusterKey(), &clusterInst) {
				err = new.GetClusterKey().NotFoundError()
				sender.SendState(edgeproto.TrackedState_CREATE_ERROR, edgeproto.WithStateError(err))
				return nu, err
			}
		}

		log.SpanLog(ctx, log.DebugLevelInfra, "update kube config", "AppInst", new, "ClusterInst", clusterInst)

		oldUri := new.Uri
		err = pf.CreateAppInst(ctx, &clusterInst, &app, new, &flavor, sender)
		if err != nil {
			err := fmt.Errorf("Create App Inst failed: %s", err)
			sender.SendState(edgeproto.TrackedState_CREATE_ERROR, edgeproto.WithStateError(err))
			log.SpanLog(ctx, log.DebugLevelInfra, "can't create app inst", "error", err, "key", new.Key)
			ctx = context.WithValue(ctx, cloudcommon.ContextKeyUndo, true)
			derr := pf.DeleteAppInst(ctx, &clusterInst, &app, new, updateAppCacheCallback)
			if derr != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "can't cleanup app inst", "error", derr, "key", new.Key)
			}
			return nu, err
		}
		if new.Uri != "" && oldUri != new.Uri {
			sender.SendUpdate(func(info *edgeproto.AppInstInfo) error {
				info.Fields = []string{edgeproto.AppInstInfoFieldUri}
				info.Uri = new.Uri
				return nil
			})
		}

		log.SpanLog(ctx, log.DebugLevelInfra, "created app inst", "appinst", new, "ClusterInst", clusterInst)

		cd.appInstInfoPowerState(ctx, sender, edgeproto.PowerState_POWER_ON)
		rt, err := pf.GetAppInstRuntime(ctx, &clusterInst, &app, new)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "unable to get AppInstRuntime", "key", new.Key, "err", err)
			sender.SendState(edgeproto.TrackedState_READY)
		} else {
			cd.appInstInfoRuntime(ctx, sender, edgeproto.TrackedState_READY, rt)
		}
	} else if new.State == edgeproto.TrackedState_UPDATE_REQUESTED {
		// reset status messages
		err = sender.SendState(edgeproto.TrackedState_UPDATING, edgeproto.WithSenderResetStatus())
		if err != nil {
			return nu, err
		}
		flavor := edgeproto.Flavor{}
		if new.Flavor.Name != "" {
			flavorFound := cd.FlavorCache.Get(&new.Flavor, &flavor)
			if !flavorFound {
				err = new.Flavor.NotFoundError()
				sender.SendState(edgeproto.TrackedState_CREATE_ERROR, edgeproto.WithStateError(err))
				return nu, err
			}
		}
		// Only proceed with power action if current state and it reflecting state is valid
		nextPowerState := edgeproto.GetNextPowerState(new.PowerState, edgeproto.TransientState)
		if nextPowerState != edgeproto.PowerState_POWER_STATE_UNKNOWN {
			cd.appInstInfoPowerState(ctx, sender, nextPowerState)
			log.SpanLog(ctx, log.DebugLevelInfra, "set power state on AppInst", "key", new.Key, "powerState", new.PowerState, "nextPowerState", nextPowerState)
			err = pf.SetPowerState(ctx, &app, new, updateAppCacheCallback)
			if err != nil {
				err := fmt.Errorf("Set AppInst PowerState failed: %s", err)
				cd.appInstInfoPowerState(ctx, sender, edgeproto.PowerState_POWER_STATE_ERROR)
				sender.SendState(edgeproto.TrackedState_UPDATE_ERROR, edgeproto.WithStateError(err))
				log.SpanLog(ctx, log.DebugLevelInfra, "can't set power state on AppInst", "error", err, "key", new.Key)
				return nu, err
			} else {
				cd.appInstInfoPowerState(ctx, sender, edgeproto.GetNextPowerState(nextPowerState, edgeproto.FinalState))
				sender.SendState(edgeproto.TrackedState_READY)
			}
			return nu, nil
		}
		clusterInst := edgeproto.ClusterInst{}
		if cloudcommon.IsClusterInstReqd(&app) {
			clusterInstFound := cd.ClusterInstCache.Get(new.GetClusterKey(), &clusterInst)
			if !clusterInstFound {
				err = new.GetClusterKey().NotFoundError()
				sender.SendState(edgeproto.TrackedState_UPDATE_ERROR, edgeproto.WithStateError(err))
				return nu, err
			}
		}
		err = pf.UpdateAppInst(ctx, &clusterInst, &app, new, &flavor, updateAppCacheCallback)
		if err != nil {
			err := fmt.Errorf("Update App Inst failed: %s", err)
			sender.SendState(edgeproto.TrackedState_UPDATE_ERROR, edgeproto.WithStateError(err))
			log.SpanLog(ctx, log.DebugLevelInfra, "can't update app inst", "error", err, "key", new.Key)
			return nu, err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "updated app inst", "appisnt", new, "ClusterInst", clusterInst)
		rt, err := pf.GetAppInstRuntime(ctx, &clusterInst, &app, new)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "unable to get AppInstRuntime", "key", new.Key, "err", err)
			sender.SendState(edgeproto.TrackedState_READY)
		} else {
			cd.appInstInfoRuntime(ctx, sender, edgeproto.TrackedState_READY, rt)
		}
	} else if new.State == edgeproto.TrackedState_DELETE_REQUESTED {
		// reset status messages
		err = sender.SendState(edgeproto.TrackedState_DELETING, edgeproto.WithSenderResetStatus())
		if err != nil {
			return nu, err
		}
		clusterInst := edgeproto.ClusterInst{}
		if cloudcommon.IsClusterInstReqd(&app) {
			clusterInstFound := cd.ClusterInstCache.Get(new.GetClusterKey(), &clusterInst)
			if !clusterInstFound {
				err = new.GetClusterKey().NotFoundError()
				sender.SendState(edgeproto.TrackedState_DELETE_ERROR, edgeproto.WithStateError(err))
				return nu, err
			}
		}
		// appInst was deleted
		log.SpanLog(ctx, log.DebugLevelInfra, "delete app inst", "AppInst", new, "ClusterInst", clusterInst)

		err = pf.DeleteAppInst(ctx, &clusterInst, &app, new, updateAppCacheCallback)
		if err != nil {
			err = fmt.Errorf("Delete App Inst failed: %s", err)
			sender.SendState(edgeproto.TrackedState_DELETE_ERROR, edgeproto.WithStateError(err))
			log.SpanLog(ctx, log.DebugLevelInfra, "can't delete app inst", "error", err, "key", new.Key)
			return nu, err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "deleted app inst", "AppInst", new, "ClusterInst", clusterInst)
		sender.SendState(edgeproto.TrackedState_DELETE_DONE)
	}
	return nu, nil
}

func (cd *CRMHandler) clusterInstInfoResources(ctx context.Context, sender edgeproto.ClusterInstInfoSender, resources *edgeproto.InfraResources) error {
	return sender.SendUpdate(func(info *edgeproto.ClusterInstInfo) error {
		info.Fields = []string{edgeproto.ClusterInstInfoFieldResources}
		info.Resources = *resources
		return nil
	})
}

func (cd *CRMHandler) clusterInstCloudletManagedClusterInfo(ctx context.Context, sender edgeproto.ClusterInstInfoSender, cmcInfo *edgeproto.CloudletManagedClusterInfo) error {
	return sender.SendUpdate(func(info *edgeproto.ClusterInstInfo) error {
		info.Fields = []string{edgeproto.ClusterInstInfoFieldCloudletManagedClusterInfo}
		info.CloudletManagedClusterInfo = cmcInfo
		return nil
	})
}

func (cd *CRMHandler) clusterInstInfoAnnotations(ctx context.Context, sender edgeproto.ClusterInstInfoSender, annotations map[string]string) error {
	if annotations == nil {
		return nil
	}
	err := sender.SendUpdate(func(info *edgeproto.ClusterInstInfo) error {
		info.Fields = []string{edgeproto.ClusterInstInfoFieldInfraAnnotations}
		info.InfraAnnotations = annotations
		return nil
	})
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to send annotations", "annotations", annotations, "err", err)
		return err
	}
	return nil
}

func (cd *CRMHandler) appInstInfoPowerState(ctx context.Context, sender edgeproto.AppInstInfoSender, state edgeproto.PowerState) error {
	return sender.SendUpdate(func(info *edgeproto.AppInstInfo) error {
		info.Fields = []string{edgeproto.AppInstInfoFieldPowerState}
		info.PowerState = state
		return nil
	})
}

func (cd *CRMHandler) appInstInfoRuntime(ctx context.Context, sender edgeproto.AppInstInfoSender, state edgeproto.TrackedState, rt *edgeproto.AppInstRuntime) error {
	return sender.SendUpdate(func(info *edgeproto.AppInstInfo) error {
		info.Fields = []string{
			edgeproto.AppInstInfoFieldRuntimeInfo,
			edgeproto.AppInstInfoFieldState,
			edgeproto.AppInstInfoFieldStatus,
		}
		info.State = state
		info.RuntimeInfo = *rt
		info.Status.SetTask(edgeproto.TrackedState_CamelName[int32(state)])
		return nil
	})
}

func (cd *CRMHandler) CloudletDNSChanged(ctx context.Context, pf platform.Platform, oldDNS string, new *edgeproto.Cloudlet, sender edgeproto.CloudletInfoSender) (reterr error) {
	var err error

	fmap := edgeproto.MakeFieldMap(new.Fields)
	log.SpanLog(ctx, log.DebugLevelInfra, "CloudletDNSChanged", "key", new.Key, "old dns", oldDNS, "new dns", new.RootLbFqdn)

	if !fmap.Has(edgeproto.CloudletFieldRootLbFqdn) {
		log.SpanLog(ctx, log.DebugLevelApi, "Nothing changed")
	} else {
		updateCloudletCallback := sender.SendStatusIgnoreErr
		err = sender.SendState(dme.CloudletState_CLOUDLET_STATE_UPGRADE, edgeproto.WithSenderResetStatus())
		if err != nil {
			return err
		}
		err = pf.ChangeCloudletDNS(ctx, new, oldDNS, updateCloudletCallback)
		if err != nil {
			err := fmt.Errorf("update failed: %s", err)
			sender.SendState(dme.CloudletState(edgeproto.TrackedState_UPDATE_ERROR), edgeproto.WithStateError(err))
			return err
		}
	}
	sender.SendUpdate(func(info *edgeproto.CloudletInfo) error {
		info.Fields = []string{
			edgeproto.CloudletInfoFieldState,
		}
		info.State = dme.CloudletState_CLOUDLET_STATE_READY
		return nil
	})
	return nil
}

func (cd *CRMHandler) CloudletChanged(ctx context.Context, target *edgeproto.CloudletKey, new *edgeproto.Cloudlet, sender edgeproto.CloudletInfoSender) (reterr error) {
	if new.State == edgeproto.TrackedState_CREATE_REQUESTED || new.State == edgeproto.TrackedState_DELETE_REQUESTED {
		// This message is for CCRM
		log.SpanLog(ctx, log.DebugLevelInfra, "cloudletChanged ignoring CCRM state", "cloudlet", new)
		return
	}

	// do request
	log.SpanLog(ctx, log.DebugLevelInfra, "cloudletChanged", "cloudlet", new)
	pf, err := cd.getPlatform(ctx, target)
	if err != nil {
		return err
	}

	fmap := edgeproto.MakeFieldMap(new.Fields)
	// Special case for dns update
	oldDNS, ok := new.Annotations[cloudcommon.AnnotationPreviousDNSName]
	if fmap.Has(edgeproto.CloudletFieldRootLbFqdn) && ok {
		_ = cd.CloudletDNSChanged(ctx, pf, oldDNS, new, sender)
		return
	}

	// for federated cloudlet, set cloudletinfo object if it is empty
	if new.Key.FederatedOrganization != "" {
		err = sender.SendUpdate(func(info *edgeproto.CloudletInfo) error {
			info.Fields = []string{
				edgeproto.CloudletInfoFieldState,
				edgeproto.CloudletInfoFieldCompatibilityVersion,
			}
			info.State = dme.CloudletState_CLOUDLET_STATE_READY
			info.CompatibilityVersion = cloudcommon.GetCRMCompatibilityVersion()
			return nil
		})
		if err != nil {
			return err
		}
	}

	nextMaintenanceState := new.MaintenanceState
	if fmap.Has(edgeproto.CloudletFieldMaintenanceState) {
		switch new.MaintenanceState {
		case dme.MaintenanceState_CRM_REQUESTED:
			// TODO: perhaps trigger LBs to reset tcp connections
			// to gracefully force clients to move to another
			// cloudlets - but we may need to add another phase
			// in here to allow DMEs to register that Cloudlet
			// is unavailable before doing so, otherwise clients
			// will just redirected back here.

			// Acknowledge controller that CRM is in maintenance
			nextMaintenanceState = dme.MaintenanceState_CRM_UNDER_MAINTENANCE
		case dme.MaintenanceState_NORMAL_OPERATION_INIT:
			// Set state back to normal so DME will allow clients
			// for this Cloudlet.
			nextMaintenanceState = dme.MaintenanceState_NORMAL_OPERATION
		}
	}
	if nextMaintenanceState != new.MaintenanceState {
		err = sender.SendUpdate(func(info *edgeproto.CloudletInfo) error {
			info.Fields = []string{edgeproto.CloudletInfoFieldMaintenanceState}
			info.MaintenanceState = nextMaintenanceState
			return nil
		})
		if err != nil {
			return err
		}
	}
	if fmap.Has(edgeproto.CloudletFieldTrustPolicyState) {
		switch new.TrustPolicyState {
		case edgeproto.TrackedState_UPDATE_REQUESTED:
			log.SpanLog(ctx, log.DebugLevelInfra, "Updating Trust Policy", "new state", new.TrustPolicyState)
			if new.State != edgeproto.TrackedState_READY {
				log.SpanLog(ctx, log.DebugLevelInfra, "Update policy cannot be done until cloudlet is ready")
				sender.SendUpdate(func(info *edgeproto.CloudletInfo) error {
					info.Fields = []string{edgeproto.CloudletInfoFieldTrustPolicyState}
					info.TrustPolicyState = edgeproto.TrackedState_UPDATE_ERROR
					return nil
				})
			} else {
				sender.SendUpdate(func(info *edgeproto.CloudletInfo) error {
					info.Fields = []string{edgeproto.CloudletInfoFieldTrustPolicyState}
					info.TrustPolicyState = edgeproto.TrackedState_UPDATING
					return nil
				})
				cd.UpdateTrustPolicy(ctx, new, pf, sender)
			}
		}
	}

	updateCloudletCallback := sender.SendStatusIgnoreErr

	stateChange := fmap.Has(edgeproto.CloudletFieldState)
	if stateChange && new.State == edgeproto.TrackedState_UPDATE_REQUESTED {
		sender.SendState(dme.CloudletState_CLOUDLET_STATE_UPGRADE, edgeproto.WithSenderResetStatus())

		err := pf.UpdateCloudlet(ctx, new, updateCloudletCallback)
		if err != nil {
			err = fmt.Errorf("Update Cloudlet failed: %v", err)
			log.InfoLog("can't update cloudlet", "error", err, "key", new.Key)
			sender.SendState(dme.CloudletState_CLOUDLET_STATE_ERRORS, edgeproto.WithStateError(err))
			return err
		}
		resources, err := pf.GetCloudletInfraResources(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Cloudlet resources not found for cloudlet", "key", new.Key, "err", err)
			resources = &edgeproto.InfraResourcesSnapshot{}
		}
		var updatedFlavors []*edgeproto.FlavorInfo
		updatedInfo := &edgeproto.CloudletInfo{}
		err = pf.GatherCloudletInfo(ctx, updatedInfo)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "gather info for cloudlet failed", "key", new.Key, "err", err)
		} else {
			updatedFlavors = updatedInfo.Flavors
		}
		sender.SendUpdate(func(info *edgeproto.CloudletInfo) error {
			info.Fields = []string{
				edgeproto.CloudletInfoFieldState,
				edgeproto.CloudletInfoFieldStatus,
				edgeproto.CloudletInfoFieldResourcesSnapshotPlatformVms,
			}
			info.ResourcesSnapshot.PlatformVms = resources.PlatformVms
			info.State = dme.CloudletState_CLOUDLET_STATE_READY
			info.Status.StatusReset()
			if updatedFlavors != nil {
				info.Flavors = updatedFlavors
				info.Fields = append(info.Fields, edgeproto.CloudletInfoFieldFlavors)
			}
			return nil
		})
	}
	return
}

func (cd *CRMHandler) UpdateTrustPolicy(ctx context.Context, cloudlet *edgeproto.Cloudlet, pf platform.Platform, sender edgeproto.CloudletInfoSender) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateTrustPolicy", "cloudletKey", cloudlet.Key)

	var TrustPolicy edgeproto.TrustPolicy
	if cloudlet.TrustPolicy != "" {
		pkey := edgeproto.PolicyKey{
			Organization: cloudlet.Key.Organization,
			Name:         cloudlet.TrustPolicy,
		}
		if !cd.TrustPolicyCache.Get(&pkey, &TrustPolicy) {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to fetch trust policy from cache")
			return pkey.NotFoundError()
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateTrustPolicy", "cloudlet.TrustPolicy", cloudlet.TrustPolicy, "TrustPolicyCache TrustPolicy", TrustPolicy)
	err := pf.UpdateTrustPolicy(ctx, &TrustPolicy)
	log.SpanLog(ctx, log.DebugLevelInfra, "Update Privacy Done", "err", err)
	newState := edgeproto.TrackedState_NOT_PRESENT
	if err != nil {
		newState = edgeproto.TrackedState_UPDATE_ERROR
	} else if cloudlet.TrustPolicy != "" {
		newState = edgeproto.TrackedState_READY
	}
	return sender.SendUpdate(func(info *edgeproto.CloudletInfo) error {
		info.Fields = []string{edgeproto.CloudletInfoFieldTrustPolicyState}
		info.TrustPolicyState = newState
		return nil
	})
}

// Common code to handle add and removal of trust policy exception rules
func (cd *CRMHandler) HandleTrustPolicyException(ctx context.Context, inst *edgeproto.TPEInstanceState) error {
	cloudlet := edgeproto.Cloudlet{}
	cloudletKey := &inst.Key.CloudletKey
	if !cd.CloudletCache.Get(cloudletKey, &cloudlet) {
		log.SpanLog(ctx, log.DebugLevelApi, "cloudlet not found", "cloudlet", cloudletKey)
		return cloudletKey.NotFoundError()
	}
	pf, err := cd.getPlatform(ctx, cloudletKey)
	if err != nil {
		return err
	}

	tpeKey := inst.Key.TpeKey
	clusterKey := inst.Key.ClusterKey
	log.SetContextTags(ctx, tpeKey.GetTags())
	log.SpanLog(ctx, log.DebugLevelInfra, "HandleTrustPolicyException", "TrustPolicyExceptionKey", tpeKey, "clusterKey", clusterKey)

	if inst.TpeEnable {
		tpe := edgeproto.TrustPolicyException{}
		if !cd.TrustPolicyExceptionCache.Get(&inst.Key.TpeKey, &tpe) {
			// should be here, we may get another request to delete it afterwards
			log.SpanLog(ctx, log.DebugLevelInfra, "HandleTrustPolicyException missing TPE", "TrustPolicyExceptionKey", tpeKey)
			return inst.Key.TpeKey.NotFoundError()
		}
		err := pf.UpdateTrustPolicyException(ctx, &tpe, &clusterKey)
		log.SpanLog(ctx, log.DebugLevelInfra, "platform UpdateTrustPolicyException Done", "err", err)
		return err
	} else {
		err := pf.DeleteTrustPolicyException(ctx, &tpeKey, &clusterKey)
		log.SpanLog(ctx, log.DebugLevelInfra, "platform DeleteTrustPolicyException Done", "err", err)
		return err
	}
}

type UpdateRuntimeCb = func(ctx context.Context, key *edgeproto.AppInstKey, rt *edgeproto.AppInstRuntime, getRuntimeErr error)

// RefreshAppInstRuntime refreshes AppInst runtimes. AppInst may be nil to
// update all AppInsts on a cluster. ClusterInst may be nil to refresh
// all AppInsts on the cloudlet.
func (cd *CRMHandler) RefreshAppInstRuntime(ctx context.Context, cloudletKey *edgeproto.CloudletKey, clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst, updateRuntimeCb UpdateRuntimeCb) error {
	appInsts := []*edgeproto.AppInst{}
	if appInst != nil {
		appInsts = append(appInsts, appInst)
	} else {
		cd.AppInstCache.Show(&edgeproto.AppInst{}, func(ai *edgeproto.AppInst) error {
			if !ai.CloudletKey.Matches(cloudletKey) {
				return nil
			}
			if clusterInst != nil {
				if !ai.GetClusterKey().Matches(&clusterInst.Key) {
					return nil
				}
			}
			cp := edgeproto.AppInst{}
			cp.DeepCopyIn(ai)
			appInsts = append(appInsts, &cp)
			return nil
		})
	}

	pf, err := cd.getPlatform(ctx, cloudletKey)
	if err != nil {
		return err
	}

	for _, ai := range appInsts {
		clusterInst := edgeproto.ClusterInst{}
		if !cd.ClusterInstCache.Get(ai.GetClusterKey(), &clusterInst) {
			log.SpanLog(ctx, log.DebugLevelApi, "refresh appinst runtime, cluster not found", "cluster", clusterInst.Key, "appInst", ai.Key)
			// maybe deleted, continue to update other AppInsts
			continue
		}
		app := edgeproto.App{}
		if !cd.AppCache.Get(&ai.AppKey, &app) {
			log.SpanLog(ctx, log.DebugLevelApi, "refresh appinst runtime, app not found", "cluster", clusterInst.Key, "app", ai.AppKey, "appInst", ai.Key)
			// maybe deleted, continue to update other AppInsts
			continue
		}
		rt, err := pf.GetAppInstRuntime(ctx, &clusterInst, &app, ai)
		updateRuntimeCb(ctx, &ai.Key, rt, err)
		log.SpanLog(ctx, log.DebugLevelApi, "refreshed appinst runtime", "appInst", ai.Key, "err", err)
	}
	return nil
}
