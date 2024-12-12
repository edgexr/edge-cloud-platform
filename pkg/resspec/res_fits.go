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

package resspec

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

type SkipReasons []string

func (s *SkipReasons) add(reason string) {
	*s = append(*s, reason)
}

type PoolScaleSpec struct {
	PoolName         string
	NumNodesChange   uint32
	PerNodeResources ResValMap
}

type KubeResScaleSpec struct {
	CPUPoolScale *PoolScaleSpec
	GPUPoolScale *PoolScaleSpec
}

// KubernetesResourcesFits checks if the resource requirements fits
// in the Kubernetes cluster. It returns a scaleSpec if the resources
// don't fit, but the cluster could be scaled to fit them.
// It also returns the amount of free resources in the cluster, for
// sorting purposes.
func KubernetesResourcesFits(ctx context.Context, clusterInst *edgeproto.ClusterInst, reqs *edgeproto.KubernetesResources, cpuUsed, gpuUsed ResValMap, flavorLookup edgeproto.FlavorLookup) (*KubeResScaleSpec, ResValMap, error) {
	var fitsErr error
	kubeSS := KubeResScaleSpec{}
	free := ResValMap{}
	if reqs.CpuPool != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "check kubernetes cpupool fits", "requests", reqs.CpuPool, "used", cpuUsed, "total", clusterInst.NodePools)
		ss, cpufree, err := NodePoolFits(ctx, reqs.CpuPool, cpuUsed, clusterInst.NodePools, flavorLookup)
		if err != nil {
			fitsErr = fmt.Errorf("cpu pool requirements not met, %s", err)
		}
		kubeSS.CPUPoolScale = ss
		free.AddAllMult(cpufree, 1)
	}
	if reqs.GpuPool != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "check kubernetes gpupool fits", "requests", reqs.GpuPool, "used", gpuUsed, "total", clusterInst.NodePools)
		ss, gpufree, err := NodePoolFits(ctx, reqs.GpuPool, gpuUsed, clusterInst.NodePools, flavorLookup)
		if err != nil && fitsErr == nil {
			fitsErr = fmt.Errorf("gpu pool requirements not met, %s", err)
		}
		kubeSS.GPUPoolScale = ss
		free.AddAllMult(gpufree, 1)
	}
	if fitsErr == nil {
		return nil, free, nil
	}
	if kubeSS.CPUPoolScale != nil || kubeSS.GPUPoolScale != nil {
		return &kubeSS, free, fitsErr
	}
	return nil, free, fitsErr
}

// NodePoolFits checks if the specified resources can fit into the Node Pools.
// Note that we do not control which node pool Kubernetes will assign the
// resources to, so we can only check the total resources of all combined
// pools. We also assume that CPU pools and GPU pools are separate sets
// of pools, and non-GPU workloads will not be deployed to pools with
// GPU resources (we may need to use affinities to enforce this).
// This returns the calculated total resources available in the
// valid pools.
// TODO: consider taking into account OS overhead.
// Returns a pool that can be scaled to accomodate the resource
// requirements if it doesn't fit.
// Returns calculated free space.
func NodePoolFits(ctx context.Context, reqs *edgeproto.NodePoolResources, used ResValMap, nodePools []*edgeproto.NodePool, flavorLookup edgeproto.FlavorLookup) (*PoolScaleSpec, ResValMap, error) {
	// convert topology to generic set of numeric resources
	reqMins, err := TopologyToResValMap(&reqs.Topology)
	if err != nil {
		return nil, nil, fmt.Errorf("requested topology %s", err)
	}
	reqMinKeys := reqMins.SortedKeys()
	reqsGpuCount := cloudcommon.NodePoolResourcesGPUCount(reqs)

	total := ResValMap{}
	reasons := SkipReasons{}
	var scalablePool *edgeproto.NodePool
	var scalablePoolNodeRes ResValMap
	for _, pool := range nodePools {
		if pool.NodeResources == nil {
			return nil, nil, fmt.Errorf("pool %s node resources not defined", pool.Name)
		}

		// TODO: we may want to generalize this check to all optional
		// resources, rather than just GPUs.
		poolGpuCount := cloudcommon.NodeResourcesGPUCount(pool.NodeResources)
		if reqsGpuCount == 0 && poolGpuCount > 0 {
			// this avoids using a gpu pool when the requestor
			// doesn't need it.
			reasons.add("skipped gpu pool " + pool.Name + " because no request for gpu")
			continue
		}
		if reqsGpuCount > 0 && poolGpuCount == 0 {
			// don't use a cpu pool if we need gpus
			reasons.add("skipped cpu pool " + pool.Name + " because requesting for gpu")
			continue
		}

		infraRes, err := GetInfraNodeResources(pool.NodeResources, flavorLookup)
		if err != nil {
			return nil, nil, fmt.Errorf("pool %s %s", pool.Name, err)
		}
		// convert pool to generic set of numeric resources
		infraResCounts, err := NodeResourcesToResValMap(infraRes)
		if err != nil {
			return nil, nil, fmt.Errorf("pool %s resources %s", pool.Name, err)
		}
		// Skip the pool if it does not meet the minimum requirements,
		// as we assume that the workloads cannot be deployed to it.
		// This is an overly conservative assumption, as some of the
		// workloads may require lower minimums.
		skip := false
		for _, resName := range reqMinKeys {
			reqMin := reqMins[resName]
			infraCount, ok := infraResCounts[resName]
			if !ok {
				reasons.add(fmt.Sprintf("skipped pool %s because requested resource %s not present", pool.Name, resName))
				skip = true
				break
			}
			if infraCount.Value.LessThan(&reqMin.Value) {
				reasons.add(fmt.Sprintf("skipped pool %s because node resource %s %s%s does not meet min reqs of %s%s", pool.Name, resName, infraCount.Value.DecString(), infraCount.Units, reqMin.Value.DecString(), reqMin.Units))
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if pool.Scalable && scalablePool == nil {
			// we only pick one pool to potentially scale
			scalablePool = pool
			scalablePoolNodeRes = infraResCounts
		}
		total.AddAllMult(infraResCounts, pool.NumNodes)
	}

	reqTotals, err := NodePoolResourcesToResValMap(reqs)
	if err != nil {
		return nil, nil, fmt.Errorf("requested total resources %s", err)
	}
	free := total.Clone()
	underflow := false
	free.SubFloorAll(used, &underflow)
	fitsErr := ResValsFits(reqTotals, free, reasons)

	log.SpanLog(ctx, log.DebugLevelApi, "node pool fits", "reqs", reqTotals.String(), "total", total.String(), "used", used.String(), "free", free.String(), "skippools", reasons, "underflow", underflow, "fitsErr", fitsErr)

	if fitsErr == nil {
		return nil, free, nil
	}
	if scalablePool == nil {
		return nil, free, fitsErr
	}
	// doesn't fit, calculate how much pool would need to scale to fit
	// needed = req + used - total
	// numNodes = needed / nodeRes
	req := reqTotals.Clone()
	req.AddAllMult(used, 1)
	req.SubFloorAll(total, &underflow)
	numNodes := req.DivFactorLargest(scalablePoolNodeRes)
	scaleSpec := PoolScaleSpec{
		PoolName:         scalablePool.Name,
		NumNodesChange:   numNodes,
		PerNodeResources: scalablePoolNodeRes,
	}
	log.SpanLog(ctx, log.DebugLevelApi, "node pool scale", "needs", req.String(), "pool", scalablePool.Name, "poolNodeRes", scalablePoolNodeRes.String(), "numNodes", numNodes)
	return &scaleSpec, free, fitsErr
}

// NodeResourceFits checks if the requested resources will fit into
// the existing clusterInst.
func NodeResourcesFits(ctx context.Context, clusterInst *edgeproto.ClusterInst, reqs *edgeproto.NodeResources, used ResValMap, flavorLookup edgeproto.FlavorLookup) error {
	if reqs == nil {
		return errors.New("request missing node resources definition")
	}
	if clusterInst.NodeResources == nil {
		return errors.New("cluster inst missing node resources definition")
	}
	clusterInfraRes, err := GetInfraNodeResources(clusterInst.NodeResources, flavorLookup)
	if err != nil {
		return fmt.Errorf("cluster resources %s", err)
	}

	// convert node resources to ResValMaps for calculations
	reqVals, err := NodeResourcesToResValMap(reqs)
	if err != nil {
		return fmt.Errorf("requested resources %s", err)
	}
	clusterVals, err := NodeResourcesToResValMap(clusterInfraRes)
	if err != nil {
		return fmt.Errorf("cluster resources %s", err)
	}

	log.SpanLog(ctx, log.DebugLevelApi, "check cluster inst resource fits", "reqs", reqVals.String(), "used", used.String(), "cluster", clusterVals.String())

	underflow := false
	freeVals := clusterVals.Clone()
	freeVals.SubFloorAll(used, &underflow)
	return ResValsFits(reqVals, freeVals, SkipReasons{})
}

func ResValsFits(reqVals, freeVals ResValMap, skipReasons SkipReasons) error {
	notEnough := []string{}
	resNames := reqVals.SortedKeys()
	for _, resName := range resNames {
		reqVal := reqVals[resName]
		freeVal, ok := freeVals[resName]
		if !ok {
			freeVal = &ResVal{}
		}
		if reqVal.Value.GreaterThan(&freeVal.Value) {
			notEnough = append(notEnough, fmt.Sprintf("want %s%s %s but only %s%s free", reqVal.Value.DecString(), reqVal.Units, resName, freeVal.Value.DecString(), reqVal.Units))
		}
	}
	if len(notEnough) > 0 {
		skipped := ""
		if len(skipReasons) > 0 {
			skipped = ", " + strings.Join(skipReasons, ", ")
		}
		return errors.New(strings.Join(notEnough, ", ") + skipped)
	}
	return nil
}

func NodeResourcesToResValMap(nr *edgeproto.NodeResources) (ResValMap, error) {
	resVals := ResValMap{}
	if err := resVals.AddNodeResources(nr, 1); err != nil {
		return nil, err
	}
	return resVals, nil
}

func NodePoolResourcesToResValMap(npr *edgeproto.NodePoolResources) (ResValMap, error) {
	resVals := ResValMap{}
	if err := resVals.AddNodePoolResources(npr); err != nil {
		return nil, err
	}
	return resVals, nil
}

func TopologyToResValMap(top *edgeproto.NodePoolTopology) (ResValMap, error) {
	resVals := ResValMap{}
	if top == nil {
		return resVals, nil
	}
	resVals.AddVcpus(top.MinNodeVcpus, 0)
	resVals.AddRam(top.MinNodeMemory)
	resVals.AddDisk(top.MinNodeDisk)
	// optional resources
	err := resVals.AddOptResMap(top.MinNodeOptRes, 1)
	if err != nil {
		return nil, err
	}
	return resVals, nil
}

// GetInfraNodeResources gets the node resources as set by the
// infrastructure. For infrastructures without quantized flavors,
// this just returns the resources as specified by the user.
// For infastructure that uses quantized flavors, this returns
// the resources as specified by the matching flavor.
func GetInfraNodeResources(nr *edgeproto.NodeResources, flavorLookup edgeproto.FlavorLookup) (*edgeproto.NodeResources, error) {
	if nr.InfraNodeFlavor != "" {
		// resources are quantized to infra-specific flavor,
		// use those values
		flavorInfo, ok := flavorLookup[nr.InfraNodeFlavor]
		if !ok {
			return nil, fmt.Errorf("infra node flavor %s not found", nr.InfraNodeFlavor)
		}
		infraNR := &edgeproto.NodeResources{
			Vcpus: flavorInfo.Vcpus,
			Ram:   flavorInfo.Ram,
			Disk:  flavorInfo.Disk,
			// TODO: Have flavorInfo store OptResMap instead of
			// PropMap, i.e. infra code should convert infra-specific
			// PropMap to EdgeCloud based OptResMap.
			// For now just use the ones specified by the user
			OptResMap: nr.OptResMap,
		}
		return infraNR, nil
	}
	return nr.Clone(), nil
}
