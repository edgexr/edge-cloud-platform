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
	"go.etcd.io/etcd/client/v3/concurrency"
)

type potentialAppInstCluster struct {
	existingCluster edgeproto.ClusterKey
	cloudletKey     edgeproto.CloudletKey
	parentPC        *potentialInstCloudlet
	userSpecified   bool
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
		if app.Deployment != cloudcommon.DeploymentTypeKubernetes && app.Deployment != cloudcommon.DeploymentTypeHelm {
			return nil, KubernetesOnly, fmt.Errorf("app deployment %s, but cloudlet only supports kubernetes", app.Deployment)
		}
		if !app.AllowServerless {
			return nil, ServerlessOnly, errors.New(ServerlessOnly)
		}
		if pc.cloudlet.SingleKubernetesClusterOwner != "" && pc.cloudlet.SingleKubernetesClusterOwner != in.Key.Organization {
			// this one we don't give a reason since they don't have permissions.
			return nil, NoSkipReason, fmt.Errorf("single kubernetes cluster mismatched owner, appinst owner is %s but cluster owner is %s", in.Key.Organization, pc.cloudlet.SingleKubernetesClusterOwner)
		}
	}
	err = validateImageTypeForPlatform(ctx, app.ImageType, pc.cloudlet.PlatformType, pc.features)
	if err != nil {
		return nil, UnsupportedImageType, err
	}
	pc.features = features
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
		if app.Deployment != cloudcommon.DeploymentTypeKubernetes && app.Deployment != cloudcommon.DeploymentTypeHelm {
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
		clust := potentialAppInstCluster{}
		clust.existingCluster = *defaultClusterKey
		clust.cloudletKey = pc.cloudlet.Key
		clust.parentPC = pc
		potentialClusters = append(potentialClusters, &clust)
		log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy add potential single kubernetes cloudlet", "cloudlet", pc.cloudlet.Key)
		if len(potentialClusters) > MaxPotentialClusters {
			return potentialClusters, nil
		}
	}

	// check for default multi-tenant clusters
	if !app.AllowServerless {
		log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential default MT kubernetes clusters, app is not serverless")
	} else {
		for _, pc := range potentialCloudlets {
			clusterKey := cloudcommon.GetDefaultMTClustKey(pc.cloudlet.Key)
			if !s.all.clusterInstApi.cache.HasKey(clusterKey) {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential default MT cluster, cluster not found", "cloudlet", pc.cloudlet.Key, "cluster", clusterKey)
				continue
			}
			if app.Deployment != cloudcommon.DeploymentTypeKubernetes && app.Deployment != cloudcommon.DeploymentTypeHelm {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip potential default MT cluster, app deployment is not kubernetes", "cloudlet", pc.cloudlet.Key, "cluster", clusterKey)
				continue
			}
			clust := potentialAppInstCluster{}
			clust.existingCluster = *clusterKey
			clust.cloudletKey = pc.cloudlet.Key
			clust.parentPC = pc
			potentialClusters = append(potentialClusters, &clust)
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy add potential default MT kubernetes cluster", "cloudlet", pc.cloudlet.Key)
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
			if cluster.Flavor.Name != in.Flavor.Name {
				// flavor mismatch
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip free reservable cluster, flavor mismatch", "cloudlet", pc.cloudlet.Key, "clusterFlavor", cluster.Flavor.Name, "appInstFlavor", in.Flavor.Name)
				continue
			}
			targetDeployment := app.Deployment
			if app.Deployment == cloudcommon.DeploymentTypeHelm {
				targetDeployment = cloudcommon.DeploymentTypeKubernetes
			}
			if targetDeployment != cluster.Deployment {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip free reservable cluster, deployment mismatch", "cloudlet", pc.cloudlet.Key, "clusterDep", cluster.Deployment, "appInstDep", targetDeployment)
				continue
			}
			if in.EnableIpv6 && !cluster.EnableIpv6 {
				log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy skip free reservable cluster, IPV6 mismatch", "cloudlet", pc.cloudlet.Key, "clusterIPV6", cluster.EnableIpv6, "appInstIPV6", in.EnableIpv6)
				continue
			}
			clust := potentialAppInstCluster{}
			clust.existingCluster = key
			clust.cloudletKey = pc.cloudlet.Key
			clust.parentPC = pc
			potentialClusters = append(potentialClusters, &clust)
			log.SpanLog(ctx, log.DebugLevelApi, "AppInst deploy add free reservable cluster", "cloudlet", pc.cloudlet.Key)
			if len(potentialClusters) > MaxPotentialClusters {
				return potentialClusters, nil
			}
		}
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
	return &clusterInst, nil
}
