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
	math "math"
	"sort"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
)

// Collect resources in use within a Cluster.
// Resources may be set by node resources for docker clusters,
// or cpu/gpu pools for Kubernetes clusters.

// Calculate used resources within a kubernetes cluster.
// If a newAppInst is being created, we will ignore it if it's
// already in the refs due to an earlier failed create.
func (s *ClusterInstApi) calcKubernetesClusterUsedResources(refs *edgeproto.ClusterRefs, newAppInst *edgeproto.AppInst) (resspec.ResValMap, resspec.ResValMap, error) {
	// calculate resources already allocated in a cluster
	cpuPoolVals := resspec.ResValMap{}
	gpuPoolVals := resspec.ResValMap{}
	err := s.walkClusterAppInsts(refs, newAppInst, func(app *edgeproto.App, appInst *edgeproto.AppInst) error {
		if appInst.KubernetesResources == nil {
			return nil
		}
		if cloudcommon.IsSideCarApp(app) {
			// ignore sidecar apps for resource calculation, as
			// reservable clusterinsts don't take them into account
			// when being sized for an App.
			return nil
		}
		kr := appInst.KubernetesResources
		if err := cpuPoolVals.AddNodePoolResources(kr.CpuPool); err != nil {
			return err
		}
		if err := gpuPoolVals.AddNodePoolResources(kr.GpuPool); err != nil {
			return err
		}
		return nil
	})
	return cpuPoolVals, gpuPoolVals, err
}

// Calculate used resources within a VM-based cluster.
// If a newAppInst is being created, we will ignore it if it's
// already in the refs due to an earlier failed create.
func (s *ClusterInstApi) calcVMClusterUsedResources(refs *edgeproto.ClusterRefs, newAppInst *edgeproto.AppInst) (resspec.ResValMap, error) {
	resVals := resspec.ResValMap{}
	err := s.walkClusterAppInsts(refs, newAppInst, func(app *edgeproto.App, appInst *edgeproto.AppInst) error {
		if appInst.NodeResources == nil {
			return nil
		}
		if err := resVals.AddNodeResources(appInst.NodeResources, 1); err != nil {
			return err
		}
		return nil
	})
	return resVals, err
}

// helper function to walk the appInsts referenced by clusterRefs.
func (s *ClusterInstApi) walkClusterAppInsts(refs *edgeproto.ClusterRefs, newAppInst *edgeproto.AppInst, cb func(app *edgeproto.App, appInst *edgeproto.AppInst) error) error {
	for _, aikey := range refs.Apps {
		if newAppInst != nil && newAppInst.Key.Matches(&aikey) {
			// when running create again to clear a create error,
			// the instance being created may already be present
			// in the refs. Don't double-count it.
			continue
		}
		appInst := edgeproto.AppInst{}
		if !s.all.appInstApi.cache.Get(&aikey, &appInst) {
			return aikey.NotFoundError()
		}
		app := edgeproto.App{}
		if !s.all.appApi.cache.Get(&appInst.AppKey, &app) {
			return appInst.AppKey.NotFoundError()
		}
		if err := cb(&app, &appInst); err != nil {
			return err
		}
	}
	return nil
}

// GetNodePoolsFromReqs derives a Kuberentes autocluster
// cluster size from the AppInst resource requirements.
func GetNodePoolsFromReqs(ctx context.Context, kr *edgeproto.KubernetesResources) ([]*edgeproto.NodePool, error) {
	if kr == nil {
		return nil, errors.New("missing kubernetes resource definition")
	}
	nodePools := []*edgeproto.NodePool{}
	if kr.CpuPool != nil {
		nodePool := NodePoolFromResources("cpupool", kr.CpuPool)
		nodePools = append(nodePools, nodePool)
	}
	if kr.GpuPool != nil {
		nodePool := NodePoolFromResources("gpupool", kr.GpuPool)
		nodePools = append(nodePools, nodePool)
	}
	return nodePools, nil
}

// GetNodeResourcesFromReqs derives a VM autocluster size from
// the AppInst resource requirements.
func GetNodeResourcesFromReqs(ctx context.Context, nr *edgeproto.NodeResources) (*edgeproto.NodeResources, error) {
	if nr == nil {
		return nil, errors.New("missing node resources definition")
	}
	return nr.Clone(), nil
}

// NodePoolFromResources returns a NodePool that satisfies the
// minimum requirements of the specified NodePoolResources.
func NodePoolFromResources(name string, pr *edgeproto.NodePoolResources) *edgeproto.NodePool {
	nr := edgeproto.NodeResources{
		Vcpus: pr.Topology.MinNodeVcpus,
		Ram:   pr.Topology.MinNodeMemory,
		Disk:  pr.Topology.MinNodeDisk,
	}
	// per node requirements are derived from total resource
	// requirement divided by the number of nodes.
	numNodes := uint64(pr.Topology.MinNumberOfNodes)
	if numNodes == 0 {
		numNodes = 1
	}
	if nr.Vcpus == 0 {
		perNode := pr.TotalVcpus.Float() / float64(numNodes)
		nr.Vcpus = uint64(math.Ceil(perNode))
	}
	if nr.Ram == 0 {
		perNode := float64(pr.TotalMemory) / float64(numNodes)
		nr.Ram = uint64(math.Ceil(perNode))
	}
	if nr.Disk == 0 {
		perNode := float64(pr.TotalDisk) / float64(numNodes)
		nr.Disk = uint64(math.Ceil(perNode))
	}
	if len(pr.TotalOptRes) > 0 {
		nr.OptResMap = map[string]string{}
		optResVals := resspec.ResValMap{}
		optResVals.AddOptResMap(pr.TotalOptRes, 1)
		for _, res := range optResVals {
			perNode := res.Value.Float() / float64(numNodes)
			val := fmt.Sprintf("%d", uint64(math.Ceil(perNode)))
			nr.OptResMap[res.OptResMapKey] = res.OptResMapSpec + ":" + val
		}
	}

	return &edgeproto.NodePool{
		Name:          name,
		NumNodes:      uint32(numNodes),
		NodeResources: &nr,
	}
}

// calcResourceScore gets a score which represents the available resources
// in a cluster. A higher score means more available resources.
func (s *ClusterInstApi) calcResourceScore(free resspec.ResValMap) uint64 {
	if free == nil {
		return 0
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
	return score
}

// calcKubernetesClusterTotalResources calculates the total amount of
// resources in the cluster.
func calcKubernetesClusterTotalResources(ci *edgeproto.ClusterInst, flavorLookup edgeproto.FlavorLookup) (resspec.ResValMap, resspec.ResValMap, error) {
	cpuRes := resspec.ResValMap{}
	gpuRes := resspec.ResValMap{}

	for _, pool := range ci.NodePools {
		var res *resspec.ResValMap
		if cloudcommon.NodeResourcesGPUCount(pool.NodeResources) > 0 {
			res = &gpuRes
		} else {
			res = &cpuRes
		}
		infraRes, err := resspec.GetInfraNodeResources(pool.NodeResources, flavorLookup)
		if err != nil {
			return nil, nil, fmt.Errorf("pool %s %s", pool.Name, err)
		}
		// convert pool to generic set of numeric resources
		infraResCounts, err := resspec.NodeResourcesToResValMap(infraRes)
		if err != nil {
			return nil, nil, fmt.Errorf("pool %s resources %s", pool.Name, err)
		}
		res.AddAllMult(infraResCounts, pool.NumNodes)
	}
	return cpuRes, gpuRes, nil
}

func calcVMClusterTotalResources(ci *edgeproto.ClusterInst, flavorLookup edgeproto.FlavorLookup) (resspec.ResValMap, error) {
	if ci.NodeResources == nil {
		return resspec.ResValMap{}, nil
	}
	nodeRes, err := resspec.GetInfraNodeResources(ci.NodeResources, flavorLookup)
	if err != nil {
		return nil, err
	}
	resVals, err := resspec.NodeResourcesToResValMap(nodeRes)
	if err != nil {
		return nil, err
	}
	return resVals, nil
}

func clusterResValToInfra(usedVals, totalVals resspec.ResValMap) []*edgeproto.InfraResource {
	out := []*edgeproto.InfraResource{}
	// add in used values with total
	for resName, resVal := range usedVals {
		infraRes := edgeproto.InfraResource{}
		infraRes.Name = resName
		infraRes.Value = resVal.Value.Whole
		infraRes.Units = resVal.Units
		if total, ok := totalVals[resName]; ok {
			infraRes.InfraMaxValue = total.Value.Whole
		}
		out = append(out, &infraRes)
	}
	// add in total values if not found in used.
	for resName, resVal := range totalVals {
		if _, found := usedVals[resName]; found {
			continue
		}
		infraRes := edgeproto.InfraResource{}
		infraRes.Name = resName
		infraRes.Units = resVal.Units
		infraRes.InfraMaxValue = resVal.Value.Whole
		out = append(out, &infraRes)
	}
	sort.Slice(out[:], func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func (s *ClusterInstApi) getClusterResourceUsage(ctx context.Context, ci *edgeproto.ClusterInst, flavorLookup edgeproto.FlavorLookup) (*edgeproto.ClusterResourceUsage, error) {
	var underflow bool
	refs := &edgeproto.ClusterRefs{}
	if !s.all.clusterRefsApi.cache.Get(&ci.Key, refs) {
		refs.Key = ci.Key
	}
	usage := edgeproto.ClusterResourceUsage{}
	usage.Key = ci.Key
	usage.ZoneKey = ci.ZoneKey
	usage.CloudletKey = ci.CloudletKey
	if ci.Reservable {
		usage.ReservedBy = ci.ReservedBy
	}
	if ci.Deployment == cloudcommon.DeploymentTypeKubernetes {
		// For Kubernetes, resource decisions are made independently
		// based on whether nodes have GPU resources or not.
		// So we separate into cpu/gpu/total. Total is just for
		// user reference and not actually used for decisions.
		cpuUsed, gpuUsed, err := s.calcKubernetesClusterUsedResources(refs, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get used resources for cluster %s, %s", ci.Key.GetKeyString(), err)
		}
		cpuTotal, gpuTotal, err := calcKubernetesClusterTotalResources(ci, flavorLookup)
		if err != nil {
			return nil, fmt.Errorf("failed to get total resources for cluster %s, %s", ci.Key.GetKeyString(), err)
		}
		cpuFree := cpuTotal.Clone()
		cpuFree.SubFloorAll(cpuUsed, &underflow)
		gpuFree := gpuTotal.Clone()
		gpuFree.SubFloorAll(gpuUsed, &underflow)
		usage.CpuPoolsResources = clusterResValToInfra(cpuUsed, cpuTotal)
		usage.GpuPoolsResources = clusterResValToInfra(gpuUsed, gpuTotal)
		usage.CpuPoolsResourceScore = s.calcResourceScore(cpuFree)
		usage.GpuPoolsResourceScore = s.calcResourceScore(gpuFree)
		// calculate overall values
		cpuUsed.AddAllMult(gpuUsed, 1)
		cpuTotal.AddAllMult(gpuTotal, 1)
		free := cpuTotal.Clone()
		free.SubFloorAll(cpuUsed, &underflow)
		usage.TotalResources = clusterResValToInfra(cpuUsed, cpuTotal)
		usage.ResourceScore = s.calcResourceScore(free)
	} else {
		used, err := s.calcVMClusterUsedResources(refs, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get used resources for cluster %s, %s", ci.Key.GetKeyString(), err)
		}
		total, err := calcVMClusterTotalResources(ci, flavorLookup)
		if err != nil {
			return nil, fmt.Errorf("failed to get total resources for cluster %s, %s", ci.Key.GetKeyString(), err)
		}
		free := total.Clone()
		free.SubFloorAll(used, &underflow)
		usage.TotalResources = clusterResValToInfra(used, total)
		usage.ResourceScore = s.calcResourceScore(free)
	}
	return &usage, nil
}
