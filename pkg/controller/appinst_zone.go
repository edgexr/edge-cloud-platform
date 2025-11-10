// Copyright 2024 EdgeXR, Inc
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

package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type potentialAppInstCluster struct {
	existingCluster  edgeproto.ClusterKey
	cloudletKey      edgeproto.CloudletKey
	parentPC         *potentialInstCloudlet
	scaleSpec        *resspec.KubeResScaleSpec
	clusterType      ClusterType
	clusterSpecified bool
	resourceScore    uint64
}

type ClusterType string

const (
	ClusterTypeUnknown         ClusterType = "unknown"
	ClusterTypeOwned           ClusterType = "owned"
	ClusterTypeOwnedReservable ClusterType = "owned-reservable"
	ClusterTypeFreeReservable  ClusterType = "free-reservable"
	ClusterTypeMultiTenant     ClusterType = "multi-tenant"
)

const MaxPotentialClusters = 5

func (s *AppInstApi) getPotentialCloudlets(ctx context.Context, cctx *CallContext, in *edgeproto.AppInst, app *edgeproto.App) ([]*potentialInstCloudlet, SkipReasons, error) {
	// determine the potential cloudlets to deploy the instance to
	var potentialCloudletKeys []edgeproto.CloudletKey
	clusterSpecified := false
	cloudletSpecified := false
	if in.ClusterKey.Name != "" {
		// if cluster was specified, then cloudlet and zone are derived
		// from the cluster
		inCluster := edgeproto.ClusterInst{}
		if !s.all.clusterInstApi.cache.Get(&in.ClusterKey, &inCluster) {
			return nil, nil, in.ClusterKey.NotFoundError()
		}
		potentialCloudletKeys = []edgeproto.CloudletKey{inCluster.CloudletKey}
		clusterSpecified = true
		cloudletSpecified = true

	} else if in.CloudletKey.Name != "" {
		// in some cases, internal tools may specify the cloudlet
		potentialCloudletKeys = []edgeproto.CloudletKey{in.CloudletKey}
		cloudletSpecified = true
	} else {
		// in general we pick from the cloudlets in the specified zone
		if in.ZoneKey.Name == "" {
			return nil, nil, errors.New("zone not specified")
		}
		// check if zone exists
		zoneBuf := edgeproto.Zone{}
		if !s.all.zoneApi.cache.Get(&in.ZoneKey, &zoneBuf) {
			return nil, nil, in.ZoneKey.NotFoundError()
		}
		potentialCloudletKeys = s.all.cloudletApi.cache.CloudletsForZone(&in.ZoneKey)
		if len(potentialCloudletKeys) == 0 {
			return nil, nil, errors.New("no available edge sites in zone " + in.ZoneKey.Name)
		}
	}

	sort.Slice(potentialCloudletKeys, func(i, j int) bool {
		return potentialCloudletKeys[i].GetKeyString() < potentialCloudletKeys[j].GetKeyString()
	})
	log.SpanLog(ctx, log.DebugLevelApi, "get potential cloudlets for create AppInst", "appInst", in.Key, "zone", in.ZoneKey, "cloudletIn", in.CloudletKey, "potentialCloudlets", potentialCloudletKeys)

	// collect potential cloudlets from zone
	// Note: we do NOT want to filter by available resources here, because we
	// will be looking for pre-existing clusters that can be used.
	// If an existing cluster is used, no new resources need to be allocated.
	skipReasons := SkipReasons{}
	potentialCloudlets := []*potentialInstCloudlet{}
	for _, ckey := range potentialCloudletKeys {
		pc, skipReason, err := s.validatePotentialCloudlet(ctx, cctx, in, app, &ckey)
		if err != nil {
			if cloudletSpecified {
				// specific cloudlet set by internal tool, return actual error
				return nil, nil, err
			}
			log.SpanLog(ctx, log.DebugLevelApi, "skipping potential cloudlet from AppInst create", "cloudlet", ckey, "err", err)
			skipReasons.add(skipReason)
			continue
		}
		log.SpanLog(ctx, log.DebugLevelApi, "adding potential cloudlet for AppInst create", "appInst", in.Key, "cloudlet", ckey)
		potentialCloudlets = append(potentialCloudlets, pc)
	}
	if len(potentialCloudlets) == 0 {
		reasonsStr := skipReasons.String()
		if reasonsStr != "" {
			if !cloudletSpecified {
				// zone was specified
				reasonsStr = ", some sites were skipped because " + reasonsStr
			} else {
				reasonsStr = ", " + reasonsStr
			}
		}
		if clusterSpecified {
			return nil, nil, fmt.Errorf("cannot deploy to cluster %s%s", in.ClusterKey.Name, reasonsStr)
		} else if cloudletSpecified {
			return nil, nil, fmt.Errorf("cannot deploy to cloudlet %s%s", in.CloudletKey.Name, reasonsStr)
		} else {
			return nil, nil, fmt.Errorf("no available edge sites in zone %s%s", in.ZoneKey.Name, reasonsStr)
		}
	}
	return potentialCloudlets, skipReasons, nil
}

func (s *AppInstApi) validatePotentialCloudlet(ctx context.Context, cctx *CallContext, in *edgeproto.AppInst, app *edgeproto.App, ckey *edgeproto.CloudletKey) (*potentialInstCloudlet, SkipReason, error) {
	pc := &potentialInstCloudlet{}
	if !s.all.cloudletApi.cache.Get(ckey, &pc.cloudlet) {
		return nil, SiteUnavailable, ckey.NotFoundError()
	}
	if !s.all.cloudletInfoApi.cache.Get(ckey, &pc.cloudletInfo) {
		return nil, SiteUnavailable, fmt.Errorf("cloudlet info %s not found", ckey.GetKeyString())
	}
	if err := s.all.cloudletInfoApi.checkCloudletReady(cctx, &pc.cloudlet, &pc.cloudletInfo, cloudcommon.Create); err != nil {
		return nil, SiteUnavailable, errors.New("cloudlet not ready")
	}
	features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, pc.cloudlet.PlatformType)
	if err != nil {
		return nil, SiteFeaturesMissing, err
	}
	if in.DedicatedIp && !features.SupportsAppInstDedicatedIp {
		return nil, NoSupportDedicatedIP, errors.New(NoSupportDedicatedIP)
	}
	if in.EnableIpv6 && !features.SupportsIpv6 {
		return nil, NoSupportDedicatedIP, errors.New(NoSupportDedicatedIP)
	}
	if pc.cloudlet.TrustPolicy != "" {
		if !app.Trusted {
			return nil, RequiresTrustedApp, errors.New("cloudlet has trust policy but app is not trusted")
		}
		trustPolicy := edgeproto.TrustPolicy{}
		tpKey := edgeproto.PolicyKey{
			Name:         pc.cloudlet.TrustPolicy,
			Organization: pc.cloudlet.Key.Organization,
		}
		if !s.all.trustPolicyApi.cache.Get(&tpKey, &trustPolicy) {
			return nil, SiteTrustPolicyMissing, tpKey.NotFoundError()
		}
		err = s.all.appApi.CheckAppCompatibleWithTrustPolicy(ctx, &pc.cloudlet.Key, app, &trustPolicy)
		if err != nil {
			return nil, IncompatibleTrustPolicy, err
		}
	}
	if features.IsSingleKubernetesCluster {
		if !cloudcommon.AppDeploysToKubernetes(app.Deployment) {
			return nil, KubernetesOnly, fmt.Errorf("app deployment %s, but cloudlet only supports kubernetes", app.Deployment)
		}
		// TODO: to allow a partner app provider to deploy over
		// federation, the cloudlet should be able to specify the
		// partner app provider for each federation. For now we
		// just check if it's the same as the local regardless of
		// federation partner.
		appInstOwner := cloudcommon.GetAppInstOwner(in)
		clusterOwner := edgeproto.OrgName(pc.cloudlet.SingleKubernetesClusterOwner)
		// note: skip allow serverless check, as that is meant to
		// avoid multi-tenant clusters, but this is not multi-tenant.
		if clusterOwner != "" && !appInstOwner.Matches(clusterOwner) {
			// no permission for cluster
			err := fmt.Errorf("single kubernetes cluster mismatched owner, appinst owner is %s but cluster owner is %s", appInstOwner, pc.cloudlet.SingleKubernetesClusterOwner)
			if in.ClusterKey.Name != "" {
				// return the reason that they cannot use this cluster
				return nil, MTClusterOrgInvalid, err
			} else {
				// we're just skipping it as an option, don't expose any details
				// of other org's clusters
				return nil, NoSkipReason, err
			}
		}
		if clusterOwner == "" && in.Namespace != "" {
			// TODO: We currently do not allow users to specify the namespace
			// for a multi-tenant cluster, to avoid namespace conflicts.
			// We should allow it at some point but we'd need to determine
			// a scheme to avoid conflicts with other tenants and
			// potentially other instances from the same tenant, perhaps
			// requiring the namespace is prefixed by the org name.
			return nil, MTNamespaceInvalid, fmt.Errorf("cannot specify instance namespace %s for a multi-tenant cluster", in.Namespace)
		}
		if pc.cloudlet.SingleKubernetesNamespace != "" && in.Namespace != "" && pc.cloudlet.SingleKubernetesNamespace != in.Namespace {
			return nil, NamespaceConflict, fmt.Errorf("specified instance namespace %s not allowed, cloudlet limits to %s", in.Namespace, pc.cloudlet.SingleKubernetesNamespace)
		}
	}
	if features.SupportsKubernetesOnly && !cloudcommon.AppDeploysToKubernetes(app.Deployment) {
		return nil, KubernetesOnly, fmt.Errorf("app deployment %s but cloudlet only supports kubernetes", app.Deployment)
	}
	err = validateImageTypeForPlatform(ctx, app.ImageType, pc.cloudlet.PlatformType, pc.features)
	if err != nil {
		return nil, UnsupportedImageType, err
	}
	pc.features = features
	pc.flavorLookup = pc.cloudletInfo.GetFlavorLookup()
	if err := pc.initResCalc(ctx, s.all, nil); err != nil {
		return nil, SiteUnavailable, err
	}
	return pc, NoSkipReason, nil
}

func (s *AppInstApi) getPotentialClusters(ctx context.Context, cctx *CallContext, in *edgeproto.AppInst, app *edgeproto.App, potentialCloudlets []*potentialInstCloudlet) ([]*potentialAppInstCluster, SkipReasons, error) {
	potentialClusters := []*potentialAppInstCluster{}

	if in.ClusterKey.Name != "" {
		// cluster specified by user
		pc := potentialCloudlets[0]
		clusterSpecified := true
		clust, _, _, err := s.validatePotentialCluster(ctx, cctx, in, app, pc, in.ClusterKey, clusterSpecified)
		log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy validate target cluster", "appInst", in.Key, "cluster", in.ClusterKey, "err", err)
		if err != nil {
			// return error if we can't use the cluster specified
			return nil, nil, err
		}
		potentialClusters = append(potentialClusters, clust)
		return potentialClusters, SkipReasons{}, nil
	}

	log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy get potential clusters", "app", app.Key, "appInst", in.Key)

	skipReasons := SkipReasons{}
	for _, pc := range potentialCloudlets {
		refs := edgeproto.CloudletRefs{}
		if !s.all.cloudletRefsApi.cache.Get(&pc.cloudlet.Key, &refs) {
			// no clusters
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy get no clusters", "cloudlet", pc.cloudlet.Key)
			continue
		}
		cloudletPcs, srs := s.getPotentialCloudletClusters(ctx, cctx, in, app, pc, refs.ClusterInsts)
		potentialClusters = append(potentialClusters, cloudletPcs...)
		skipReasons.addAll(srs)
	}
	sort.Sort(PotentialAppInstClusterByResource(potentialClusters))
	if len(potentialClusters) > MaxPotentialClusters {
		return potentialClusters[:MaxPotentialClusters], skipReasons, nil
	}
	return potentialClusters, skipReasons, nil
}

func (s *AppInstApi) getPotentialCloudletClusters(ctx context.Context, cctx *CallContext, in *edgeproto.AppInst, app *edgeproto.App, pc *potentialInstCloudlet, candidates []edgeproto.ClusterKey) ([]*potentialAppInstCluster, SkipReasons) {
	potentialClusters := []*potentialAppInstCluster{}
	clusterSpecified := false
	skipReasons := SkipReasons{}
	log.SpanLog(ctx, log.DebugLevelApi, "get potential cloudlet clusters", "appinst", in.Key, "cloudlet", pc.cloudlet.Key)
	for _, key := range candidates {
		clust, skipReason, logReason, err := s.validatePotentialCluster(ctx, cctx, in, app, pc, key, clusterSpecified)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential cluster", "appinst", in.Key, "cluster", key, "reason", skipReason, "err", err)
			if logReason {
				// only notify users of potential misconfigurations
				// or lack of resources. Common skip reasons, like
				// mismatched deployment types or cluster owned by
				// a different tenant should not be shown.
				skipReasons.add(skipReason)
			}
			continue
		}
		potentialClusters = append(potentialClusters, clust)
	}
	return potentialClusters, skipReasons
}

func (s *AppInstApi) validatePotentialCluster(ctx context.Context, cctx *CallContext, in *edgeproto.AppInst, app *edgeproto.App, pc *potentialInstCloudlet, key edgeproto.ClusterKey, clusterSpecified bool) (*potentialAppInstCluster, SkipReason, bool, error) {
	clusterInst := &edgeproto.ClusterInst{}
	if !s.all.clusterInstApi.cache.Get(&key, clusterInst) {
		return nil, ClusterMissing, false, key.NotFoundError()
	}
	if cloudcommon.AppInstToClusterDeployment(app.Deployment) != clusterInst.Deployment {
		return nil, DeploymentMismatch, false, fmt.Errorf("cannot deploy %s app to %s cluster", app.Deployment, clusterInst.Deployment)
	}
	if clusterInst.MultiTenant && !app.AllowServerless {
		return nil, AppNotServerless, true, fmt.Errorf("app must be serverless to deploy to multi-tenant cluster")
	}
	if clusterInst.MultiTenant && app.ManagesOwnNamespaces {
		return nil, AppManagesOwnNamespace, true, fmt.Errorf("cannot deploy app that manages its own namespaces to a multi-tenant cluster")
	}
	if clusterInst.MultiTenant && in.Namespace != "" {
		return nil, NamespaceConflict, true, fmt.Errorf("cannot specify instance namespace %q for a multi-tenant cluster", in.Namespace)
	}
	clusterType := ClusterTypeUnknown
	if clusterInst.MultiTenant {
		clusterType = ClusterTypeMultiTenant
	} else if clusterInst.Reservable {
		if clusterInst.ReservedBy == "" {
			clusterType = ClusterTypeFreeReservable
		} else if cloudcommon.IsSideCarApp(app) || clusterInst.ReservedBy == in.Key.Organization {
			// we allow dynamic usage of reservable clusters already in
			// use by the tenant
			clusterType = ClusterTypeOwnedReservable
		} else {
			// clusterInst reserved by another tenant
			return nil, ClusterReserved, false, fmt.Errorf("cluster reserved by another tenant")
		}
	} else {
		appInstOwner := cloudcommon.GetAppInstOwner(in)
		if cloudcommon.IsSideCarApp(app) {
			// always allow sidecar apps, but they must directly
			// target the cluster.
			if !clusterSpecified {
				return nil, SidecarAppMustTargetCluster, true, fmt.Errorf("sidecar app must specify target cluster")
			}
		} else if appInstOwner.Matches(edgeproto.OrgName(clusterInst.Key.Organization)) {
			if clusterInst.DisableDynamicAppinstPlacement && !clusterSpecified {
				return nil, NoDynamicPlacement, true, fmt.Errorf("found cluster but dynamic appinst placement is disabled")
			}
		} else {
			// clusterInst owned by another tenant
			return nil, ClusterOwned, false, fmt.Errorf("cluster owned by another tenant")
		}
		clusterType = ClusterTypeOwned
	}
	if err := s.all.clusterInstApi.checkMinKubernetesVersion(clusterInst, in); err != nil {
		return nil, K8SVersionFail, true, fmt.Errorf("k8s version check failed, %s", err)
	}
	if in.EnableIpv6 && !clusterInst.EnableIpv6 {
		return nil, ClusterNoIPV6, true, fmt.Errorf("app requested IPV6 but cluster does not support it")
	}
	refs := edgeproto.ClusterRefs{}
	if !s.all.clusterRefsApi.cache.Get(&clusterInst.Key, &refs) {
		// no error if refs not found
		refs.Key = clusterInst.Key
	}
	// check for conflicts with existing Apps
	// this does not apply to multi-tenant clusters, as each
	// instance will get their own namespace.
	if !clusterInst.MultiTenant {
		targetNamespace := k8smgmt.GetNamespace(clusterInst, app, in)
		for _, aiKey := range refs.Apps {
			log.SpanLog(ctx, log.DebugLevelApi, "check instances already on cluster", "cluster", key, "appinst", aiKey)
			if aiKey.Matches(&in.Key) {
				// for undo, the instance may already be present in refs
				continue
			}
			refAi := &edgeproto.AppInst{}
			if !s.all.appInstApi.cache.Get(&aiKey, refAi) {
				continue
			}
			refApp := &edgeproto.App{}
			if !s.all.appApi.cache.Get(&refAi.AppKey, refApp) {
				continue
			}
			if err := checkAppDuplicateConflict(clusterInst, app, in, targetNamespace, refApp, refAi); err != nil {
				return nil, NoAppDuplicates, true, err
			}
			if cloudcommon.IsSideCarApp(app) || cloudcommon.IsSideCarApp(refApp) {
				// ignore standalone requirements for sidecar apps
				continue
			}
			if in.IsStandalone && !clusterSpecified {
				return nil, StandaloneConflict, true, fmt.Errorf("standalone app cannot be deployed to a cluster that already has an app instance")
			}
			if refAi.IsStandalone && !clusterSpecified {
				return nil, StandaloneConflict, true, fmt.Errorf("cluster already in use by standalone app %s", refApp.Key.GetKeyString())
			}
		}
	}

	ss, free, err := s.all.clusterInstApi.fitsAppResources(ctx, clusterInst, &refs, app, in, pc.flavorLookup, clusterSpecified)
	if pc.features.IsSingleKubernetesCluster {
		// assume kubernetes cluster-as-a-cloudlet cannot scale up
		ss = nil
	}
	if err != nil && ss != nil {
		if pc.resCalc == nil {
			return nil, NoSkipReason, true, fmt.Errorf("internal error, resCalc is nil")
		}
		// cluster does not have enough resources, but can potentially
		// scale up to provide enough. check if the cloudlet can
		// support the scaled up cluster.
		_, scaleErr := pc.resCalc.CloudletFitsScaledSpec(ctx, ss)
		if scaleErr != nil {
			return nil, ClusterNoResources, true, fmt.Errorf("cluster does not have enough resources, and cloudlet does not have enough resources to scale up cluster, %s", err)
		}
		if clusterInst.State != edgeproto.TrackedState_READY {
			return nil, ClusterNoResources, true, fmt.Errorf("cluster requires scaling but is not in ready state, state is %s", clusterInst.State.String())
		}
	} else if ss == nil && err != nil {
		return nil, ClusterNoResources, true, fmt.Errorf("not enough resources in cluster, %s", err)
	}
	clust := potentialAppInstCluster{}
	clust.existingCluster = key
	clust.cloudletKey = pc.cloudlet.Key
	clust.parentPC = pc
	clust.scaleSpec = ss
	clust.clusterType = clusterType
	clust.resourceScore = s.all.clusterInstApi.calcResourceScore(free)
	clust.clusterSpecified = clusterSpecified
	log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy add potential cluster", "appinst", in.Key, "cloudlet", pc.cloudlet.Key, "cluster", key, "clusterType", clusterType, "scaleSpec", ss, "free", free.String(), "score", clust.resourceScore)
	return &clust, NoSkipReason, false, nil
}

func (s *AppInstApi) usePotentialCluster(ctx context.Context, stm concurrency.STM, in *edgeproto.AppInst, app *edgeproto.App, sidecarApp bool, pc *potentialAppInstCluster) (*edgeproto.ClusterInst, error) {
	// attempt to use the specified cluster.
	clusterInst := edgeproto.ClusterInst{}
	if !s.all.clusterInstApi.store.STMGet(stm, &pc.existingCluster, &clusterInst) {
		return nil, pc.existingCluster.NotFoundError()
	}
	if clusterInst.DeletePrepare {
		return nil, pc.existingCluster.BeingDeletedError()
	}
	if clusterInst.MultiTenant {
		err := useMultiTenantClusterInst(stm, ctx, in, app, sidecarApp, &clusterInst)
		if err != nil {
			return nil, err
		}
	} else if clusterInst.Reservable {
		err := s.useReservableClusterInst(stm, ctx, in, app, sidecarApp, &clusterInst)
		if err != nil {
			return nil, err
		}
	} else {
		appInstOwner := cloudcommon.GetAppInstOwner(in)
		// user-specified cluster
		if !sidecarApp && !appInstOwner.Matches(edgeproto.OrgName(clusterInst.Key.Organization)) {
			return nil, fmt.Errorf("developer organization mismatch between AppInst: %s and ClusterInst: %s", appInstOwner, clusterInst.Key.Organization)
		}
	}
	return &clusterInst, nil
}

func (s *AppInstApi) potentialClusterResourceCheck(ctx context.Context, stm concurrency.STM, in *edgeproto.AppInst, app *edgeproto.App, clusterInst *edgeproto.ClusterInst, flavorLookup edgeproto.FlavorLookup, clusterSpecified bool) error {
	// check resources again under STM to ensure no race conditions.
	refs := edgeproto.ClusterRefs{}
	if !s.all.clusterRefsApi.store.STMGet(stm, &clusterInst.Key, &refs) {
		// no error if refs not found
		refs.Key = clusterInst.Key
	}
	_, _, err := s.all.clusterInstApi.fitsAppResources(ctx, clusterInst, &refs, app, in, flavorLookup, clusterSpecified)
	if err != nil {
		return fmt.Errorf("not enough resources in cluster %s, %s", clusterInst.Key.GetKeyString(), err)
	}
	return nil
}

func getPotentialClusterPref(pc *potentialAppInstCluster) int {
	// This allows us to prefer certain types of clusters over others
	// lower values equal higher preference.
	// Prefer clusters where the tenant is already paying for resources,
	// or will have lower resource overhead.
	switch pc.clusterType {
	case ClusterTypeOwned:
		return 1
	case ClusterTypeOwnedReservable:
		return 2
	case ClusterTypeMultiTenant:
		return 3
	case ClusterTypeFreeReservable:
		return 4
	default:
		return 99
	}
}

// PotentialAppInstClusterByResource sorts potential clusters based
// on available resources
type PotentialAppInstClusterByResource []*potentialAppInstCluster

func (a PotentialAppInstClusterByResource) Len() int {
	return len(a)
}

func (a PotentialAppInstClusterByResource) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a PotentialAppInstClusterByResource) Less(i, j int) bool {
	// prefer clusters that don't need scaling
	if a[i].scaleSpec == nil && a[j].scaleSpec != nil {
		return true
	}
	// prefer certain types of clusters
	ipref := getPotentialClusterPref(a[i])
	jpref := getPotentialClusterPref(a[j])
	if ipref != jpref {
		return ipref < jpref
	}
	// prefer more free resources
	if a[i].scaleSpec == nil && a[j].scaleSpec == nil {
		// sort by amount of free space in cluster
		iscore := a[i].resourceScore
		jscore := a[j].resourceScore
		if iscore == jscore {
			return a[i].existingCluster.GetKeyString() < a[j].existingCluster.GetKeyString()
		}
		return iscore > jscore
	}
	if a[i].scaleSpec != nil && a[j].scaleSpec != nil {
		// sort by amount of free space in cloudlet
		parents := PotentialInstCloudletsByResource{}
		parents = append(parents, a[i].parentPC, a[j].parentPC)
		return parents.Less(0, 1)
	}
	return false
}
