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
	math "math"
	"slices"
	"sort"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
)

// CloudletResCalc is used to do cloudlet resource calculations
type CloudletResCalc struct {
	all         *AllApis
	stm         *edgeproto.OptionalSTM
	cloudletKey *edgeproto.CloudletKey
	deps        CloudletResCalcDeps
	usedVals    resspec.ResValMap // cached calculation of used resources in cloudlet
	options     CloudletResCalcOptions
}

type CloudletResCalcDeps struct {
	cloudlet     *edgeproto.Cloudlet
	cloudletInfo *edgeproto.CloudletInfo
	cloudletRefs *edgeproto.CloudletRefs
	features     *edgeproto.PlatformFeatures
	lbFlavor     *edgeproto.FlavorInfo
}

type CloudletResCalcOptions struct {
	skipLB         bool // don't try to count LB resources
	skipAdditional bool // don't try to count additional resources
}

var resourceWeights = map[string]uint64{
	cloudcommon.ResourceVcpus: 1000,
	cloudcommon.ResourceRamMb: 1,
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
	if s.deps.lbFlavor == nil && !s.options.skipLB {
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
	reqdVals, err := s.all.cloudletApi.totalCloudletResources(ctx, s.stm, s.deps.cloudlet, s.deps.cloudletInfo, reqd, s.options)
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
	reqdVals, err := s.all.cloudletApi.totalCloudletResources(ctx, s.stm, s.deps.cloudlet, s.deps.cloudletInfo, reqd, s.options)
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
		oldVals, err := s.all.cloudletApi.totalCloudletResources(ctx, s.stm, s.deps.cloudlet, s.deps.cloudletInfo, reqd, s.options)
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
	usedVals, err := s.all.cloudletApi.totalCloudletResources(ctx, s.stm, s.deps.cloudlet, s.deps.cloudletInfo, usedResources, s.options)
	if err != nil {
		return nil, err
	}
	s.usedVals = usedVals
	return usedVals, nil
}

func (s *CloudletResCalc) cloudletFitsReqdVals(ctx context.Context, reqdVals resspec.ResValMap) ([]string, error) {
	if err := s.InitDeps(ctx); err != nil {
		return nil, err
	}
	usedVals, err := s.getUsedResVals(ctx)
	if err != nil {
		return nil, err
	}
	resLimits := s.getResourceLimits(ctx)

	log.SpanLog(ctx, log.DebugLevelApi, "cloudletFitsReqdVals", "cloudlet", s.cloudletKey.GetKeyString(), "reqdVals", reqdVals.String(), "usedVals", usedVals.String(), "resLimits", resLimits.String())

	warnings := []string{}

	// sort for deterministic error messages
	resNames := []string{}
	for resName := range resLimits {
		resNames = append(resNames, resName)
	}
	sort.Strings(resNames)

	// Theoretical Validation
	errsStr := []string{}
	for _, resName := range resNames {
		resInfo := resLimits[resName]
		max := resInfo.QuotaMaxValue
		if max == 0 {
			max = resInfo.InfraMaxValue
		}
		if max == 0 {
			// no limits on resource
			continue
		}
		if resInfo.QuotaMaxValue > 0 && resInfo.InfraMaxValue > 0 {
			if resInfo.QuotaMaxValue > resInfo.InfraMaxValue {
				warnings = append(warnings, fmt.Sprintf("[quota] invalid quota set for %s, quota max value %d is more than infra max value %d", resName, resInfo.QuotaMaxValue, resInfo.InfraMaxValue))
			}
		}
		thAvailableResVal := edgeproto.NewUdec64(max, 0)
		usedVal := edgeproto.NewUdec64(0, 0)
		if usedRes, ok := usedVals[resName]; ok {
			usedVal = usedRes.Value.Clone()
		}
		underflow := false
		thAvailableResVal.SubFloor(usedVal, &underflow)
		if usedVal.GreaterThanUint64(max) {
			warnings = append(warnings, fmt.Sprintf("[quota] invalid quota set for %s, quota max value %d is less than used resource value %s", resName, max, usedVal.DecString()))
		}
		if resInfo.AlertThreshold > 0 && usedVal.Float()*100/float64(max) > float64(resInfo.AlertThreshold) {
			warnings = append(warnings, fmt.Sprintf("more than %d%% of %s (%s%s of %d%s) is used by the cloudlet", resInfo.AlertThreshold, resName, usedVal.DecString(), resInfo.Units, max, resInfo.Units))
		}
		resReqd, ok := reqdVals[resName]
		if !ok {
			continue
		}
		if resReqd.Value.GreaterThan(thAvailableResVal) {
			errsStr = append(errsStr, fmt.Sprintf("required %s is %s%s but only %s%s out of %d%s is available", resName, resReqd.Value.DecString(), resInfo.Units, thAvailableResVal.DecString(), resInfo.Units, max, resInfo.Units))
		}
	}

	err = nil
	if len(errsStr) > 0 {
		errsOut := strings.Join(errsStr, ", ")
		err = fmt.Errorf("not enough resources available: %s", errsOut)
	}
	if err != nil {
		return warnings, err
	}

	infraUsedVals := map[string]*edgeproto.InfraResource{}
	for _, infraRes := range s.deps.cloudletInfo.ResourcesSnapshot.Info {
		res := infraRes
		infraUsedVals[infraRes.Name] = &res
	}

	// Infra based validation
	errsStr = []string{}
	for _, resName := range resNames {
		resInfo := resLimits[resName]
		if resInfo.InfraMaxValue == 0 {
			// no limits on resource
			continue
		}
		infraUsed := uint64(0)
		if infraRes, ok := infraUsedVals[resName]; ok {
			infraUsed = infraRes.Value
		}
		infraAvailableResVal := resInfo.InfraMaxValue - infraUsed
		if resInfo.AlertThreshold > 0 && float64(infraUsed*100)/float64(resInfo.InfraMaxValue) > float64(resInfo.AlertThreshold) {
			warnings = append(warnings, fmt.Sprintf("more than %d%% of %s (%d%s of %d%s) is used on the infra managed by the cloudlet", resInfo.AlertThreshold, resName, infraUsed, resInfo.Units, resInfo.InfraMaxValue, resInfo.Units))
		}
		resReqd, ok := reqdVals[resName]
		if !ok {
			// this resource is not tracked by controller, skip it
			continue
		}
		if resReqd.Value.GreaterThanUint64(infraAvailableResVal) {
			errsStr = append(errsStr, fmt.Sprintf("required %s is %s%s but only %d%s out of %d%s is available", resName, resReqd.Value.DecString(), resInfo.Units, infraAvailableResVal, resInfo.Units, resInfo.InfraMaxValue, resInfo.Units))
		}
	}
	err = nil
	if len(errsStr) > 0 {
		errsOut := strings.Join(errsStr, ", ")
		err = fmt.Errorf("[infra] not enough resources available: %s", errsOut)
	}

	return warnings, err
}

// getMaxResourceVals gets a map of each resource and either max value
// infraSnapshot comes from cloudletInfo.ResourceSnapshot.Info
func getMaxResourceVals(infraSnapshot []edgeproto.InfraResource, quotas []edgeproto.ResourceQuota) map[string]uint64 {
	maxVals := map[string]uint64{}
	for _, infraRes := range infraSnapshot {
		maxVals[infraRes.ResKey()] = infraRes.InfraMaxValue
	}
	for _, quota := range quotas {
		resKey := quota.ResKey()
		v, ok := maxVals[resKey]
		if !ok || v > quota.Value {
			maxVals[resKey] = quota.Value
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
	ResourceType   string
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

func (s ResLimitMap) AddMax(name, resourceType, units string, max uint64) {
	resKey := edgeproto.BuildResKey(resourceType, name)
	res, ok := s[resKey]
	if !ok {
		res = &ResLimit{
			Name:         name,
			Units:        units,
			ResourceType: resourceType,
		}
		s[resKey] = res
	}
	res.InfraMaxValue += max
}

func (s ResLimitMap) AddQuota(name, resourceType, units string, quota uint64, alertThreshold int32) {
	resKey := edgeproto.BuildResKey(resourceType, name)
	res, ok := s[resKey]
	if !ok {
		res = &ResLimit{
			Name:         name,
			Units:        units,
			ResourceType: resourceType,
		}
		s[resKey] = res
	}
	res.QuotaMaxValue += quota
	res.AlertThreshold = alertThreshold
}

// getResourceLimits creates a resource map of resources that are
// limited by the cloudlet's max values or quota values.
// Resources without limits are not presented.
func (s *CloudletResCalc) getResourceLimits(ctx context.Context) ResLimitMap {
	limits := ResLimitMap{}
	s.addResourceLimits(ctx, limits)
	return limits
}

func (s *CloudletResCalc) addResourceLimits(ctx context.Context, limits ResLimitMap) {
	// add limits from infra-reported max value
	for _, infraRes := range s.deps.cloudletInfo.ResourcesSnapshot.Info {
		if infraRes.InfraMaxValue == 0 {
			continue
		}
		limits.AddMax(infraRes.Name, infraRes.Type, infraRes.Units, infraRes.InfraMaxValue)
	}
	// resource limits from kubernetes-cluster-as-a-cloudlet come
	// from node pools
	kresCounts := resspec.ResValMap{}
	for _, pool := range s.deps.cloudletInfo.NodePools {
		if pool.NodeResources == nil {
			continue
		}
		err := kresCounts.AddNodeResources(pool.NodeResources, pool.NumNodes)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to add node pool resources", "pool", pool.Name, "err", err)
		}
	}
	for _, kres := range kresCounts {
		limits.AddMax(kres.Name, kres.ResourceType, kres.Units, kres.Value.Whole)
	}

	// add limits from quotas
	for _, quota := range s.deps.cloudlet.ResourceQuotas {
		if quota.Value == 0 && quota.AlertThreshold == 0 {
			continue
		}
		units := cloudcommon.CommonCloudletResources[quota.ResKey()]
		thresh := s.deps.cloudlet.DefaultResourceAlertThreshold
		if quota.AlertThreshold > 0 {
			// Set threshold values from Resource quotas
			thresh = quota.AlertThreshold
		}
		limits.AddQuota(quota.Name, quota.ResourceType, units, quota.Value, thresh)
	}
}

// calcResourceScoreFromUsed gets a score which represents the available resources
// on a cloudlet. A higher score means more available resources.
func (s *CloudletResCalc) calcResourceScoreFromUsed(usedVals resspec.ResValMap) uint64 {
	// get max value for each resource on cloudlet
	maxVals := getMaxResourceVals(s.deps.cloudletInfo.ResourcesSnapshot.Info, s.deps.cloudlet.ResourceQuotas)
	// Calculate score based on weights and free values
	// Because some resources may have no limit, track the number
	// of resources we've scored. We'll divide by this number to
	// get an average per-resource score for comparisons.
	var score, numScored uint64
	for res, weight := range resourceWeights {
		max, ok := maxVals[res]
		if !ok {
			continue // no limit
		}
		free := max * weight
		if usedVal, ok := usedVals[res]; ok {
			// make a copy
			usedDecVal := edgeproto.NewUdec64(usedVal.Value.Whole, usedVal.Value.Nanos)
			// multiply by weight to try to promote and remove decimal values
			usedDecVal.Mult(uint32(weight))
			// subtract from free, dropping decimal value
			if usedDecVal.Whole > free {
				// avoid underflow
				free = 0
			} else {
				free -= usedDecVal.Whole
			}
		}
		score += free
		numScored++
	}
	if numScored == 0 {
		score = math.MaxUint64
	} else {
		score /= numScored
	}
	return score
}
