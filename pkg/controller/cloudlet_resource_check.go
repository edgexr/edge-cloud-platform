// Copyright 2024 EdgeXR, Inc
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
	"fmt"
	"slices"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
)

// CloudletResCalc is used to do cloudlet resource calculations
type CloudletResCalc struct {
	all         *AllApis
	stm         *edgeproto.OptionalSTM
	cloudletKey *edgeproto.CloudletKey
	deps        CloudletResCalcDeps
	usedVals    resspec.ResValMap // cached calculation of used resources in cloudlet
}

type CloudletResCalcDeps struct {
	cloudlet     *edgeproto.Cloudlet
	cloudletInfo *edgeproto.CloudletInfo
	cloudletRefs *edgeproto.CloudletRefs
	features     *edgeproto.PlatformFeatures
	lbFlavor     *edgeproto.FlavorInfo
}

func NewCloudletResCalc(all *AllApis, stm *edgeproto.OptionalSTM, cloudletKey *edgeproto.CloudletKey) *CloudletResCalc {
	return &CloudletResCalc{
		all:         all,
		stm:         stm,
		cloudletKey: cloudletKey,
	}
}

// InitDeps initializes any dependencies that haven't been externally set.
// This serves as a cache to avoid having to do multiple look ups,
// especially for lbFlavor which requires a network call.
func (s *CloudletResCalc) InitDeps(ctx context.Context) error {
	if s.deps.cloudlet == nil {
		cloudlet := &edgeproto.Cloudlet{}
		if !s.all.cloudletApi.cache.STMGet(s.stm, s.cloudletKey, cloudlet) {
			return s.cloudletKey.NotFoundError()
		}
		s.deps.cloudlet = cloudlet
	}
	if s.deps.cloudletInfo == nil {
		cloudletInfo := &edgeproto.CloudletInfo{}
		if !s.all.cloudletInfoApi.cache.STMGet(s.stm, s.cloudletKey, cloudletInfo) {
			return fmt.Errorf("cloudletInfo for %s", s.cloudletKey.NotFoundError())
		}
		s.deps.cloudletInfo = cloudletInfo
	}
	if s.deps.cloudletRefs == nil {
		cloudletRefs := &edgeproto.CloudletRefs{}
		if !s.all.cloudletRefsApi.cache.STMGet(s.stm, s.cloudletKey, cloudletRefs) {
			cloudletRefs.Key = *s.cloudletKey
		}
		s.deps.cloudletRefs = cloudletRefs
	}
	if s.deps.features == nil {
		features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, s.deps.cloudlet.PlatformType)
		if err != nil {
			return err
		}
		s.deps.features = features
	}
	if s.deps.lbFlavor == nil {
		lbFlavor, err := s.all.clusterInstApi.GetRootLBFlavorInfo(ctx, s.stm, s.deps.cloudlet, s.deps.cloudletInfo)
		if err != nil {
			return err
		}
		s.deps.lbFlavor = lbFlavor
	}
	return nil
}

// Check that a new VMApp will fit in the cloudlet
func (s *CloudletResCalc) CloudletFitsVMApp(ctx context.Context, app *edgeproto.App, vmAppInst *edgeproto.AppInst) ([]string, error) {
	if err := s.InitDeps(ctx); err != nil {
		return nil, err
	}
	reqd := NewCloudletResources()
	err := reqd.AddVMAppInstResources(ctx, app, vmAppInst, s.deps.lbFlavor)
	if err != nil {
		return nil, err
	}
	reqdVals, err := s.all.cloudletApi.totalCloudletResources(ctx, s.stm, s.deps.cloudlet, s.deps.cloudletInfo, reqd)
	if err != nil {
		return nil, err
	}
	return s.cloudletFitsReqdVals(ctx, reqdVals)
}

func (s *CloudletResCalc) CloudletFitsCluster(ctx context.Context, clusterInst, oldClusterInst *edgeproto.ClusterInst) ([]string, error) {
	if err := s.InitDeps(ctx); err != nil {
		return nil, err
	}
	isManagedK8s := false
	if s.deps.features.KubernetesRequiresWorkerNodes {
		isManagedK8s = true
	}
	reqd := NewCloudletResources()
	err := reqd.AddClusterInstResources(ctx, clusterInst, s.deps.lbFlavor, isManagedK8s)
	if err != nil {
		return nil, err
	}
	reqdVals, err := s.all.cloudletApi.totalCloudletResources(ctx, s.stm, s.deps.cloudlet, s.deps.cloudletInfo, reqd)
	if err != nil {
		return nil, err
	}
	if oldClusterInst != nil {
		// oldClusterInst will be set for an update
		old := NewCloudletResources()
		err := old.AddClusterInstResources(ctx, clusterInst, s.deps.lbFlavor, isManagedK8s)
		if err != nil {
			return nil, err
		}
		oldVals, err := s.all.cloudletApi.totalCloudletResources(ctx, s.stm, s.deps.cloudlet, s.deps.cloudletInfo, reqd)
		if err != nil {
			return nil, err
		}
		underflow := false
		reqdVals.SubFloorAll(oldVals, &underflow)
	}
	return s.cloudletFitsReqdVals(ctx, reqdVals)
}

func (s *CloudletResCalc) CloudletFitsScaledSpec(ctx context.Context, scaleSpec *resspec.KubeResScaleSpec) ([]string, error) {
	reqd := resspec.ResValMap{}
	if scaleSpec.CPUPoolScale != nil {
		pool := scaleSpec.CPUPoolScale
		reqd.AddAllMult(pool.PerNodeResources, pool.NumNodesChange)
	}
	if scaleSpec.GPUPoolScale != nil {
		pool := scaleSpec.GPUPoolScale
		reqd.AddAllMult(pool.PerNodeResources, pool.NumNodesChange)
	}
	return s.cloudletFitsReqdVals(ctx, reqd)
}

func (s *CloudletResCalc) getUsedResVals(ctx context.Context) (resspec.ResValMap, error) {
	if s.usedVals != nil {
		return s.usedVals, nil
	}
	// gather used resources as CloudletResources
	usedResources, err := s.getCloudletUsedResources(ctx)
	if err != nil {
		return nil, err
	}
	// convert used resources to ResValMap
	usedVals, err := s.all.cloudletApi.totalCloudletResources(ctx, s.stm, s.deps.cloudlet, s.deps.cloudletInfo, usedResources)
	if err != nil {
		return nil, err
	}
	s.usedVals = usedVals
	return usedVals, nil
}

// getMaxResourceVals gets a map of each resource and either max value
// infraSnapshot comes from cloudletInfo.ResourceSnapshot.Info
func getMaxResourceVals(infraSnapshot []edgeproto.InfraResource, quotas []edgeproto.ResourceQuota) map[string]uint64 {
	maxVals := map[string]uint64{}
	for _, infraRes := range infraSnapshot {
		maxVals[infraRes.Name] = infraRes.InfraMaxValue
	}
	for _, quota := range quotas {
		v, ok := maxVals[quota.Name]
		if !ok || v > quota.Value {
			maxVals[quota.Name] = quota.Value
		}
	}
	return maxVals
}

type ResLimit struct {
	Name           string
	Units          string
	InfraMaxValue  uint64
	QuotaMaxValue  uint64
	AlertThreshold int32
}

type ResLimitMap map[string]*ResLimit

func (s ResLimitMap) SortedKeys() []string {
	keys := []string{}
	for k := range s {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func (s ResLimitMap) String() string {
	strs := []string{}
	for _, resName := range s.SortedKeys() {
		res := s[resName]
		str := resName
		if res.InfraMaxValue > 0 {
			str += fmt.Sprintf(" infraMax:%d%s", res.InfraMaxValue, res.Units)
		}
		if res.QuotaMaxValue > 0 {
			str += fmt.Sprintf(" quota:%d%s", res.QuotaMaxValue, res.Units)
		}
		if res.AlertThreshold > 0 {
			str += fmt.Sprintf(" alertThreshold:%d%%", res.AlertThreshold)
		}
		strs = append(strs, str)
	}
	return strings.Join(strs, ", ")

}

// getResourceLimits creates a resource map of resources that are
// limited by the cloudlet's max values or quota values.
// Resources without limits are not presented.
func (s *CloudletResCalc) getResourceLimits() ResLimitMap {
	limits := ResLimitMap{}

	// add limits from infra-reported max value
	for _, infraRes := range s.deps.cloudletInfo.ResourcesSnapshot.Info {
		if infraRes.InfraMaxValue == 0 {
			continue
		}
		res := &ResLimit{
			InfraMaxValue: infraRes.InfraMaxValue,
			Units:         infraRes.Units,
		}
		if res.Units == "" {
			res.Units = cloudcommon.CommonCloudletResources[infraRes.Name]
		}
		limits[infraRes.Name] = res
	}
	// add limits from quotas
	for _, quota := range s.deps.cloudlet.ResourceQuotas {
		if quota.Value == 0 && quota.AlertThreshold == 0 {
			continue
		}
		res, ok := limits[quota.Name]
		if !ok {
			res = &ResLimit{}
			res.Units = cloudcommon.CommonCloudletResources[quota.Name]
			limits[quota.Name] = res
		}
		res.QuotaMaxValue = quota.Value
		thresh := s.deps.cloudlet.DefaultResourceAlertThreshold
		if quota.AlertThreshold > 0 {
			// Set threshold values from Resource quotas
			thresh = quota.AlertThreshold
		}
		res.AlertThreshold = thresh
	}
	return limits
}
