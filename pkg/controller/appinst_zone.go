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
	userSpecified   bool
	resourceScore   uint64
}

const MaxPotentialClusters = 5

func (s *AppInstApi) getPotentialCloudlets(ctx context.Context, cctx *CallContext, in *edgeproto.AppInst, app *edgeproto.App) ([]*potentialInstCloudlet, error) {
	// determine the potential cloudlets to deploy the instance to
	var potentialCloudletKeys []edgeproto.CloudletKey
	cloudletSpecified := false
	if in.ClusterKey.Name != "" {
		// if cluster was specified, then cloudlet and zone are derived
		// from the cluster
		inCluster := edgeproto.ClusterInst{}
		if !s.all.clusterInstApi.cache.Get(&in.ClusterKey, &inCluster) {
			return nil, in.ClusterKey.NotFoundError()
		}
		potentialCloudletKeys = []edgeproto.CloudletKey{inCluster.CloudletKey}
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
		if in.ClusterKey.Name != "" {
			if reasonsStr == "" {
				// if this happens, there's a problem with the validatePotentialCloudlet
				// function
				log.SpanLog(ctx, log.DebugLevelApi, "unexpected empty reason for no potential cloudlets")
				return nil, fmt.Errorf("cannot deploy to cluster %s", in.ClusterKey.Name)
			} else {
				return nil, fmt.Errorf("cannot deploy to cluster %s, %s", in.ClusterKey.Name, reasonsStr)
			}
		} else {
			if reasonsStr == "" {
				return nil, fmt.Errorf("no available edge sites in zone")
			} else {
				return nil, fmt.Errorf("no available edge sites in zone, some sites were skipped because %s", reasonsStr)
			}
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

	// check for single kubernetes clusters
	for _, pc := range potentialCloudlets {
		if !pc.features.IsSingleKubernetesCluster {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip single k8s cloudlet, not single kubernetes cluster", "cloudlet", pc.cloudlet.Key)
			continue
		}
		if !cloudcommon.AppDeploysToKubernetes(app.Deployment) {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip single k8s cloudlet, app deployment is not kubernetes", "cloudlet", pc.cloudlet.Key)
			continue
		}
		defaultClusterKey := cloudcommon.GetDefaultClustKey(pc.cloudlet.Key, pc.cloudlet.SingleKubernetesClusterOwner)
		cluster := edgeproto.ClusterInst{}
		if !s.all.clusterInstApi.cache.Get(defaultClusterKey, &cluster) {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip single k8s cloudlet, cloudlet not found", "cloudlet", pc.cloudlet.Key)
			continue
		}
		if cluster.MultiTenant && !app.AllowServerless {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip single k8s cloudlet, cluster is multi-tenant and app is not serverless", "cloudlet", pc.cloudlet.Key)
			continue
		}
		refs := edgeproto.ClusterRefs{}
		if !s.all.clusterRefsApi.cache.Get(defaultClusterKey, &refs) {
			// no error if refs not found
			refs.Key = *defaultClusterKey
		}
		// note: assume single kubernetes clusters are not scalable,
		// so ignore any returned scale spec
		_, free, err := s.all.clusterInstApi.fitsAppResources(ctx, &cluster, &refs, app, in, pc.flavorLookup)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip single k8s cloudlet, not enough resources", "cloudlet", pc.cloudlet.Key, "err", err)
			continue
		}
		clust := potentialAppInstCluster{}
		clust.existingCluster = *defaultClusterKey
		clust.cloudletKey = pc.cloudlet.Key
		clust.parentPC = pc
		clust.calcResourceScore(free)
		potentialClusters = append(potentialClusters, &clust)
		log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy add potential single kubernetes cloudlet", "cloudlet", pc.cloudlet.Key, "free", free.String(), "resourceScore", clust.resourceScore)
	}

	// check for default multi-tenant clusters
	if !app.AllowServerless {
		log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential default MT kubernetes clusters, app is not serverless")
	} else {
		for _, pc := range potentialCloudlets {
			clusterKey := cloudcommon.GetDefaultMTClustKey(pc.cloudlet.Key)
			cluster := edgeproto.ClusterInst{}
			if !s.all.clusterInstApi.cache.Get(clusterKey, &cluster) {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential default MT cluster, cluster not found", "cloudlet", pc.cloudlet.Key, "cluster", clusterKey)
				continue
			}
			if !cloudcommon.AppDeploysToKubernetes(app.Deployment) {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential default MT cluster, app deployment is not kubernetes", "cloudlet", pc.cloudlet.Key, "cluster", clusterKey)
				continue
			}
			refs := edgeproto.ClusterRefs{}
			if !s.all.clusterRefsApi.cache.Get(clusterKey, &refs) {
				// no error if refs not found
				refs.Key = *clusterKey
			}
			ss, free, err := s.all.clusterInstApi.fitsAppResources(ctx, &cluster, &refs, app, in, pc.flavorLookup)
			if err != nil && ss != nil {
				// cluster does not have enough resources, but can potentially
				// scale up to provide enough. check if the cloudlet can
				// support the scaled up cluster.
				_, scaleErr := pc.resCalc.CloudletFitsScaledSpec(ctx, ss)
				if scaleErr != nil {
					log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential default MT cluster, not enough resources for scaling", "cloudlet", pc.cloudlet.Key, "err", err, "scaleErr", scaleErr)
					continue
				}
			} else if ss == nil && err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential default MT cluster, not enough resources", "cloudlet", pc.cloudlet.Key, "err", err)
				continue
			}
			clust := potentialAppInstCluster{}
			clust.existingCluster = *clusterKey
			clust.cloudletKey = pc.cloudlet.Key
			clust.parentPC = pc
			clust.scaleSpec = ss
			clust.calcResourceScore(free)
			potentialClusters = append(potentialClusters, &clust)
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy add potential default MT kubernetes cluster", "cloudlet", pc.cloudlet.Key, "scaleSpec", ss, "free", free.String(), "score", clust.resourceScore)
			if len(potentialClusters) > MaxPotentialClusters {
				return potentialClusters, nil
			}
		}
	}

	// check for free reservable cluster
	freeClusterInsts := map[edgeproto.CloudletKey][]edgeproto.ClusterKey{}
	// gather free reservable ClusterInsts for the target Cloudlet
	s.all.clusterInstApi.cache.Mux.Lock()
	for _, data := range s.all.clusterInstApi.cache.Objs {
		if data.Obj.Reservable && data.Obj.ReservedBy == "" {
			// free reservable ClusterInst
			freelist := freeClusterInsts[data.Obj.CloudletKey]
			freelist = append(freelist, data.Obj.Key)
			freeClusterInsts[data.Obj.CloudletKey] = freelist
		}
	}
	s.all.clusterInstApi.cache.Mux.Unlock()
	for _, pc := range potentialCloudlets {
		freelist, ok := freeClusterInsts[pc.cloudlet.Key]
		if !ok || len(freelist) == 0 {
			// no free reservable cluster insts
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip free reservable clusters for cloudlet, none found", "cloudlet", pc.cloudlet.Key)
			continue
		}
		for _, key := range freelist {
			cluster := edgeproto.ClusterInst{}
			if !s.all.clusterInstApi.cache.Get(&key, &cluster) {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential free reservable cluster, cluster not found", "cloudlet", pc.cloudlet.Key, "cluster", cluster.Key)
				continue
			}
			targetDeployment := cloudcommon.AppInstToClusterDeployment(app.Deployment)
			if targetDeployment != cluster.Deployment {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip free reservable cluster, deployment mismatch", "cloudlet", pc.cloudlet.Key, "clusterDep", cluster.Deployment, "appInstDep", targetDeployment)
				continue
			}
			if in.EnableIpv6 && !cluster.EnableIpv6 {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip free reservable cluster, IPV6 mismatch", "cloudlet", pc.cloudlet.Key, "clusterIPV6", cluster.EnableIpv6, "appInstIPV6", in.EnableIpv6)
				continue
			}
			refs := edgeproto.ClusterRefs{}
			if !s.all.clusterRefsApi.cache.Get(&key, &refs) {
				// no error if refs not found
				refs.Key = key
			}
			ss, free, err := s.all.clusterInstApi.fitsAppResources(ctx, &cluster, &refs, app, in, pc.flavorLookup)
			if err != nil && ss != nil {
				_, scaleErr := pc.resCalc.CloudletFitsScaledSpec(ctx, ss)
				if scaleErr != nil {
					log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip free reservable cluster, not enough resources for scaling", "cloudlet", pc.cloudlet.Key, "err", err, "scaleErr", scaleErr)
					continue
				}
			} else if ss == nil && err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip free reservable cluster, not enough resources", "cloudlet", pc.cloudlet.Key, "err", err)
				continue
			}
			clust := potentialAppInstCluster{}
			clust.existingCluster = key
			clust.cloudletKey = pc.cloudlet.Key
			clust.parentPC = pc
			clust.scaleSpec = ss
			clust.calcResourceScore(free)
			potentialClusters = append(potentialClusters, &clust)
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy add free reservable cluster", "cloudlet", pc.cloudlet.Key, "scaleSpec", ss, "free", free.String(), "score", clust.resourceScore)
			if len(potentialClusters) > MaxPotentialClusters {
				return potentialClusters, nil
			}
		}
	}
	sort.Sort(PotentialAppInstClusterByResource(potentialClusters))
	if len(potentialClusters) > MaxPotentialClusters {
		return potentialClusters[:MaxPotentialClusters], nil
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

// calcResourceScore gets a score which represents the available resources
// in a cluster. A higher score means more available resources.
func (s *potentialAppInstCluster) calcResourceScore(free resspec.ResValMap) {
	if free == nil {
		s.resourceScore = 0
		return
	}
	// Calculate score based on weights and free values
	// Because some resources may have no limit, track the number
	// of resources we've scored. We'll divide by this number to
	// get an average per-resource score for comparisons.
	var score, numScored uint64
	for res, weight := range resourceWeights {
		if resVal, ok := free[res]; ok {
			// make a copy
			freeDecVal := edgeproto.NewUdec64(resVal.Value.Whole, resVal.Value.Nanos)
			// multiply by weight to try to promote and remove decimal values
			freeDecVal.Mult(uint32(weight))

			score += freeDecVal.Whole
			numScored++
		}
	}
	if numScored == 0 {
		score = 0
	} else {
		score /= numScored
	}
	s.resourceScore = score
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
