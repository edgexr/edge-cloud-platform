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
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type potentialAppInstCluster struct {
	existingCluster edgeproto.ClusterKey
	cloudletKey     edgeproto.CloudletKey
	parentPC        *potentialInstCloudlet
	scaleSpec       *resspec.KubeResScaleSpec
	clusterType     ClusterType
	userSpecified   bool
	resourceScore   uint64
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

func (s *AppInstApi) getPotentialCloudlets(ctx context.Context, cctx *CallContext, in *edgeproto.AppInst, app *edgeproto.App) ([]*potentialInstCloudlet, error) {
	// determine the potential cloudlets to deploy the instance to
	var potentialCloudletKeys []edgeproto.CloudletKey
	clusterSpecified := false
	cloudletSpecified := false
	if in.ClusterKey.Name != "" {
		// if cluster was specified, then cloudlet and zone are derived
		// from the cluster
		inCluster := edgeproto.ClusterInst{}
		if !s.all.clusterInstApi.cache.Get(&in.ClusterKey, &inCluster) {
			return nil, in.ClusterKey.NotFoundError()
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
			return nil, errors.New("zone not specified")
		}
		// check if zone exists
		zoneBuf := edgeproto.Zone{}
		if !s.all.zoneApi.cache.Get(&in.ZoneKey, &zoneBuf) {
			return nil, in.ZoneKey.NotFoundError()
		}
		potentialCloudletKeys = s.all.cloudletApi.cache.CloudletsForZone(&in.ZoneKey)
		if len(potentialCloudletKeys) == 0 {
			return nil, errors.New("no available edge sites in zone " + in.ZoneKey.Name)
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
				return nil, err
			}
			log.SpanLog(ctx, log.DebugLevelApi, "skipping potential cloudlet from AppInst create", "cloudlet", ckey, "err", err)
			skipReasons.add(skipReason)
			continue
		}
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
			return nil, fmt.Errorf("cannot deploy to cluster %s%s", in.ClusterKey.Name, reasonsStr)
		} else if cloudletSpecified {
			return nil, fmt.Errorf("cannot deploy to cloudlet %s%s", in.CloudletKey.Name, reasonsStr)
		} else {
			return nil, fmt.Errorf("no available edge sites in zone %s%s", in.ZoneKey.Name, reasonsStr)
		}
	}
	return potentialCloudlets, nil
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
		if !app.AllowServerless {
			return nil, ServerlessOnly, errors.New(ServerlessOnly)
		}
		if pc.cloudlet.SingleKubernetesClusterOwner != "" && pc.cloudlet.SingleKubernetesClusterOwner != in.Key.Organization {
			// no permission for cluster
			err := fmt.Errorf("single kubernetes cluster mismatched owner, appinst owner is %s but cluster owner is %s", in.Key.Organization, pc.cloudlet.SingleKubernetesClusterOwner)
			if in.ClusterKey.Name != "" {
				// return the reason that they cannot use this cluster
				return nil, MTClusterOrgInvalid, err
			} else {
				// we're just skipping it as an option, don't expose any details
				// of other org's clusters
				return nil, NoSkipReason, err
			}
		}
	}
	if features.SupportsKubernetesOnly && app.Deployment != cloudcommon.DeploymentTypeKubernetes {
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

func (s *AppInstApi) getPotentialClusters(ctx context.Context, cctx *CallContext, in *edgeproto.AppInst, app *edgeproto.App, potentialCloudlets []*potentialInstCloudlet) ([]*potentialAppInstCluster, error) {
	potentialClusters := []*potentialAppInstCluster{}

	if in.ClusterKey.Name != "" {
		// cluster specified by user
		clust := potentialAppInstCluster{}
		clust.existingCluster = in.ClusterKey
		clust.cloudletKey = in.CloudletKey
		clust.userSpecified = true
		clust.parentPC = potentialCloudlets[0]
		potentialClusters = append(potentialClusters, &clust)
		return potentialClusters, nil
	}

	log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy get potential clusters", "app", app.Key, "appInst", in.Key)

	for _, pc := range potentialCloudlets {
		cloudletPcs, err := s.getPotentialCloudletClusters(ctx, cctx, in, app, pc)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to get potential clusters for cloudlet, skipping it", "cloudlet", pc.cloudlet.Key, "err", err)
			continue
		}
		potentialClusters = append(potentialClusters, cloudletPcs...)
	}
	sort.Sort(PotentialAppInstClusterByResource(potentialClusters))
	if len(potentialClusters) > MaxPotentialClusters {
		return potentialClusters[:MaxPotentialClusters], nil
	}
	return potentialClusters, nil
}

func (s *AppInstApi) getPotentialCloudletClusters(ctx context.Context, cctx *CallContext, in *edgeproto.AppInst, app *edgeproto.App, pc *potentialInstCloudlet) ([]*potentialAppInstCluster, error) {
	potentialClusters := []*potentialAppInstCluster{}
	refs := edgeproto.CloudletRefs{}
	if !s.all.cloudletRefsApi.cache.Get(&pc.cloudlet.Key, &refs) {
		return potentialClusters, nil
	}
	log.SpanLog(ctx, log.DebugLevelApi, "get potential cloudlet clusters", "appinst", in.Key, "cloudlet", pc.cloudlet.Key)
	for _, key := range refs.ClusterInsts {
		clusterInst := &edgeproto.ClusterInst{}
		if !s.all.clusterInstApi.cache.Get(&key, clusterInst) {
			log.SpanLog(ctx, log.DebugLevelApi, "cluster not found", "cluster", key)
			continue
		}
		if cloudcommon.AppInstToClusterDeployment(app.Deployment) != clusterInst.Deployment {
			continue
		}
		if clusterInst.MultiTenant && !app.AllowServerless {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential cluster: multi-tenant cluster and app is not serverless", "cluster", key)
			continue
		}
		clusterType := ClusterTypeUnknown
		if !clusterInst.MultiTenant {
			if clusterInst.Reservable {
				if clusterInst.ReservedBy == "" {
					clusterType = ClusterTypeFreeReservable
				} else if clusterInst.ReservedBy == in.Key.Organization {
					// we allow dynamic usage of reservable clusters already in
					// use by the tenant
					clusterType = ClusterTypeOwnedReservable
				} else {
					// clusterInst reserved by another tenant
					continue
				}
			} else if clusterInst.Key.Organization == in.Key.Organization {
				if clusterInst.DisableDynamicAppinstPlacement {
					log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential cluster: owned cluster has disable dynamic appinst placement", "cluster", key)
					continue
				}
				clusterType = ClusterTypeOwned
			} else {
				// clusterInst owned by another tenant
				continue
			}
		} else {
			clusterType = ClusterTypeMultiTenant
		}
		if err := s.all.clusterInstApi.checkMinKubernetesVersion(clusterInst, in); err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential cluster, k8s version check failed", "cluster", key, "err", err)
			continue
		}
		if in.EnableIpv6 && !clusterInst.EnableIpv6 {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential cluster, IPV6 mismatch", "cluster", key, "clusterIPV6", clusterInst.EnableIpv6, "appInstIPV6", in.EnableIpv6)
			continue
		}
		refs := edgeproto.ClusterRefs{}
		if !s.all.clusterRefsApi.cache.Get(&clusterInst.Key, &refs) {
			// no error if refs not found
			refs.Key = clusterInst.Key
		}
		if s.all.clusterInstApi.hasInstanceOfApp(&refs, app) {
			// we don't support multiple instances of the same app in the
			// same cluster
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential cluster, already instance of app in cluster", "cluster", key)
			continue
		}
		ss, free, err := s.all.clusterInstApi.fitsAppResources(ctx, clusterInst, &refs, app, in, pc.flavorLookup)
		if pc.features.IsSingleKubernetesCluster {
			// assume kubernetes cluster-as-a-cloudlet cannot scale up
			ss = nil
		}
		if err != nil && ss != nil {
			if pc.resCalc == nil {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential cluster with scaleSpec, internal error: resCalc is nil for potentialInstCloudlet", "pc", pc)
				continue
			}
			// cluster does not have enough resources, but can potentially
			// scale up to provide enough. check if the cloudlet can
			// support the scaled up cluster.
			_, scaleErr := pc.resCalc.CloudletFitsScaledSpec(ctx, ss)
			if scaleErr != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential cluster, not enough resources for scaling", "cluster", key, "err", err, "scaleErr", scaleErr)
				continue
			}
		} else if ss == nil && err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential cluster, not enough resources", "cluster", key, "err", err)
			continue
		}
		clust := potentialAppInstCluster{}
		clust.existingCluster = key
		clust.cloudletKey = pc.cloudlet.Key
		clust.parentPC = pc
		clust.scaleSpec = ss
		clust.clusterType = clusterType
		clust.resourceScore = s.all.clusterInstApi.calcResourceScore(free)
		potentialClusters = append(potentialClusters, &clust)
		log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy add potential cluster", "cloudlet", pc.cloudlet.Key, "cluster", key, "clusterType", clusterType, "scaleSpec", ss, "free", free.String(), "score", clust.resourceScore)
	}
	return potentialClusters, nil
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
		// user-specified cluster
		if !sidecarApp && in.Key.Organization != clusterInst.Key.Organization {
			return nil, fmt.Errorf("developer organization mismatch between AppInst: %s and ClusterInst: %s", in.Key.Organization, clusterInst.Key.Organization)
		}
	}
	// check resources again under STM to ensure no race conditions.
	refs := edgeproto.ClusterRefs{}
	if !s.all.clusterRefsApi.store.STMGet(stm, &pc.existingCluster, &refs) {
		// no error if refs not found
		refs.Key = pc.existingCluster
	}
	_, _, err := s.all.clusterInstApi.fitsAppResources(ctx, &clusterInst, &refs, app, in, pc.parentPC.flavorLookup)
	if err != nil {
		return nil, fmt.Errorf("not enough resources in cluster %s, %s", pc.existingCluster.GetKeyString(), err)
	}
	return &clusterInst, nil
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
