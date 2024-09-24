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
)

func (s *ClusterInstApi) getPotentialCloudlets(ctx context.Context, cctx *CallContext, in *edgeproto.ClusterInst) ([]*potentialInstCloudlet, error) {
	// determine the potential cloudlets to deploy the instance to
	var potentialCloudletKeys []edgeproto.CloudletKey
	cloudletSpecified := false
	if in.CloudletKey.Name != "" {
		// in some cases, internal tools may specify the cloudlet
		potentialCloudletKeys = []edgeproto.CloudletKey{in.CloudletKey}
		cloudletSpecified = true
	} else {
		// in general we pick matching cloudlets from the specified zone
		if in.ZoneKey.Name == "" {
			return nil, errors.New("zone not specified")
		}
		if !s.all.zoneApi.cache.HasKey(&in.ZoneKey) {
			return nil, in.ZoneKey.NotFoundError()
		}
		potentialCloudletKeys = s.all.cloudletApi.cache.CloudletsForZone(&in.ZoneKey)
		if len(potentialCloudletKeys) == 0 {
			return nil, errors.New("no available edge sites in zone " + in.ZoneKey.Name)
		}
	}

	// sort for determinism
	sort.Slice(potentialCloudletKeys, func(i, j int) bool {
		return potentialCloudletKeys[i].GetKeyString() < potentialCloudletKeys[j].GetKeyString()
	})
	log.SpanLog(ctx, log.DebugLevelApi, "get potential cloudlets for create ClusterInst", "clusterInst", in.Key, "zone", in.ZoneKey, "cloudletIn", in.CloudletKey, "potentialCloudletKeys", potentialCloudletKeys)

	skipReasons := SkipReasons{}
	potentialCloudlets := []*potentialInstCloudlet{}
	for _, ckey := range potentialCloudletKeys {
		pc, skipReason, err := s.validatePotentialCloudlet(ctx, cctx, in, &ckey)
		if err != nil {
			if cloudletSpecified {
				// specific cloudlet set by internal tool, return actual error
				return nil, err
			}
			log.SpanLog(ctx, log.DebugLevelApi, "skipping potential cloudlet from ClusterInst create", "cloudlet", ckey, "err", err)
			skipReasons.add(skipReason)
			continue
		}
		potentialCloudlets = append(potentialCloudlets, pc)
	}
	if len(potentialCloudlets) == 0 {
		reasonsStr := skipReasons.String()
		if reasonsStr == "" {
			return nil, fmt.Errorf("no available edge sites in zone")
		} else {
			return nil, fmt.Errorf("no available edge sites in zone, some sites were skipped because %s", reasonsStr)
		}
	}
	return potentialCloudlets, nil
}

// TODO: check that cloudlet has enough available resources for new ClusterInst
func (s *ClusterInstApi) validatePotentialCloudlet(ctx context.Context, cctx *CallContext, in *edgeproto.ClusterInst, ckey *edgeproto.CloudletKey) (*potentialInstCloudlet, SkipReason, error) {
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
	if features.IsSingleKubernetesCluster {
		return nil, NoSupportClusterInst, errors.New(NoSupportClusterInst)
	}
	if features.SupportsKubernetesOnly && in.Deployment != cloudcommon.DeploymentTypeKubernetes {
		return nil, KubernetesOnly, fmt.Errorf("app deployment %s but cloudlet only supports kubernetes", in.Deployment)
	}
	if in.SharedVolumeSize != 0 && !features.SupportsSharedVolume {
		return nil, NoSupportSharedVolumes, errors.New(NoSupportSharedVolumes)
	}
	if in.EnableIpv6 && !features.SupportsIpv6 {
		return nil, NoSupportIPV6, errors.New(NoSupportIPV6)
	}
	if in.Deployment == cloudcommon.DeploymentTypeKubernetes {
		if features.NoClusterSupport && in.NumNodes != 0 {
			// Special case for k8s baremetal because multi-tenanancy is
			// managed by the platform, not the Controller. There is no
			// real cluster, just pods, so numnodes is not used. Once we
			// consolidate the code so that the Controller manages it,
			// then there will no longer be any ClusterInst object created
			// (it will be AppInst only), so this check can be removed.
			return nil, NoSupportNumNodes, errors.New(NoSupportNumNodes)
		}
		if features.KubernetesRequiresWorkerNodes && in.NumNodes == 0 {
			return nil, RequiresNumNodes, errors.New(RequiresNumNodes)
		}
	}
	if in.MultiTenant && !features.SupportsMultiTenantCluster {
		return nil, NoSupportMultiTenantCluster, errors.New(NoSupportMultiTenantCluster)
	}
	if len(in.Networks) > 0 && !features.SupportsAdditionalNetworks {
		return nil, NoSupportNetworks, errors.New(NoSupportNetworks)
	}
	if in.IpAccess == edgeproto.IpAccess_IP_ACCESS_SHARED {
		if isIPAllocatedPerService(ctx, pc.cloudlet.PlatformType, features, pc.cloudlet.Key.Organization) {
			return nil, NoSupportSharedIPAccess, errors.New(NoSupportSharedIPAccess)
		}
	}
	if in.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		if features.CloudletServicesLocal && !features.IsFake {
			return nil, NoSupportDedicatedIPAccess, errors.New(NoSupportDedicatedIPAccess)
		}
	}

	pc.features = features
	return pc, NoSkipReason, nil
}
