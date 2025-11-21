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

package edgeproto

import (
	"errors"
	fmt "fmt"
)

const DefaultNodePoolName = "defaultpool"

func (s *NodeResources) Validate() error {
	if s == nil {
		return errors.New("missing node resources")
	}
	if s.InfraNodeFlavor == "" {
		if s.Vcpus == 0 {
			return errors.New("vcpus must be greater than 0, or infra node flavor must be specified")
		}
		if s.Ram == 0 {
			return errors.New("memory must be greater than 0, or infra node flavor must be specified")
		}
	}
	return nil
}

func (s *NodePool) Validate() error {
	if s.Name == "" {
		return errors.New("missing name")
	}
	if s.NumNodes == 0 {
		return errors.New("num nodes must be greater than 0")
	}
	if s.NodeResources == nil {
		return errors.New("missing node resources")
	}
	if err := s.NodeResources.Validate(); err != nil {
		return err
	}
	return nil
}

func (s *NodePoolResources) Validate() error {
	if s.TotalVcpus.IsZero() {
		return errors.New("total required vcpus must be greater than 0")
	}
	if s.TotalMemory <= 0 {
		return errors.New("total required memory must be greater than 0")
	}
	if s.Topology.MinNumberOfNodes <= 0 {
		// assume a single node
		s.Topology.MinNumberOfNodes = 1
	}
	return nil
}

func (s *KubernetesResources) Validate() error {
	if s == nil {
		return errors.New("missing kubernetes resources")
	}
	if s.CpuPool == nil && s.GpuPool == nil {
		return errors.New("no pools specified")
	}
	if s.CpuPool != nil {
		if err := s.CpuPool.Validate(); err != nil {
			return fmt.Errorf("cpu pool %s", err)
		}
	}
	if s.GpuPool != nil {
		if err := s.GpuPool.Validate(); err != nil {
			return fmt.Errorf("gpu pool %s", err)
		}
		if len(s.GpuPool.TotalGpus) == 0 && (s.GpuPool.TotalOptRes == nil || s.GpuPool.TotalOptRes["gpu"] == "") {
			return errors.New("gpu pool has no gpus specified")
		}
	}
	return nil
}

func (s *Flavor) ToNodeResources() *NodeResources {
	return &NodeResources{
		Vcpus:     s.Vcpus,
		Ram:       s.Ram,
		Disk:      s.Disk,
		Gpus:      s.Gpus,
		OptResMap: s.OptResMap,
	}
}

func (s *Flavor) ToKubernetesResources() *KubernetesResources {
	pool := &NodePoolResources{
		TotalVcpus:  *NewUdec64(s.Vcpus, 0),
		TotalMemory: s.Ram,
		TotalGpus:   s.Gpus,
		Topology: NodePoolTopology{
			MinNodeVcpus:  s.Vcpus,
			MinNodeMemory: s.Ram,
			MinNodeGpus:   s.Gpus,
		},
	}
	gpuCount := 0
	if _, ok := s.OptResMap["gpu"]; ok {
		gpuCount = 1
	}
	kr := &KubernetesResources{}
	if gpuCount > 0 {
		kr.GpuPool = pool
	} else {
		kr.CpuPool = pool
	}
	return kr
}

func (s *NodeResources) SetFromFlavor(flavor *Flavor) {
	s.Vcpus = flavor.Vcpus
	s.Ram = flavor.Ram
	s.Disk = flavor.Disk
	s.Gpus = flavor.Gpus
	s.OptResMap = flavor.OptResMap
}

func (s *NodePool) SetFromFlavor(flavor *Flavor) {
	if s.NodeResources == nil {
		s.NodeResources = &NodeResources{}
	}
	s.NodeResources.SetFromFlavor(flavor)
}

func (s *KubernetesResources) SetFromFlavor(flavor *Flavor) {
	var pool *NodePoolResources
	if flavor.Gpus != nil {
		if s.GpuPool == nil {
			s.GpuPool = &NodePoolResources{}
		}
		pool = s.GpuPool
	} else {
		if s.CpuPool == nil {
			s.CpuPool = &NodePoolResources{}
		}
		pool = s.CpuPool
	}
	pool.TotalVcpus = *NewUdec64(flavor.Vcpus, 0)
	pool.TotalMemory = flavor.Ram
	pool.TotalDisk = flavor.Disk
	pool.TotalGpus = flavor.Gpus
	pool.TotalOptRes = flavor.OptResMap
	pool.Topology.MinNodeVcpus = flavor.Vcpus
	pool.Topology.MinNodeMemory = flavor.Ram
	pool.Topology.MinNodeDisk = flavor.Disk
	pool.Topology.MinNodeGpus = flavor.Gpus
	pool.Topology.MinNodeOptRes = flavor.OptResMap
}

func (s *ClusterInst) EnsureDefaultNodePool() {
	if len(s.NodePools) == 0 {
		s.NodePools = []*NodePool{{
			Name:          DefaultNodePoolName,
			NodeResources: &NodeResources{},
		}}
	}
}

func (s *ClusterInst) GetNumNodes() uint32 {
	numNodes := uint32(0)
	for _, pool := range s.NodePools {
		numNodes += pool.NumNodes
	}
	return numNodes
}

type FlavorLookup map[string]*FlavorInfo

func (s *CloudletInfo) GetFlavorLookup() FlavorLookup {
	lookup := FlavorLookup{}
	for _, flavorInfo := range s.Flavors {
		lookup[flavorInfo.Name] = flavorInfo
	}
	return lookup
}

// BuildReskey builds a unique key for a resource.
// Nominal resources like "vcpus" and "ram" are are
// returned as-is, while typed resources like GPUs
// returned scoped to the resource type, i.e.
// "gpu/nvidia-t4".
func BuildResKey(resourceType, name string) string {
	if resourceType == "" {
		return name
	}
	return fmt.Sprintf("%s/%s", resourceType, name)
}

func BuildResKeyDesc(resourceType, name string) string {
	if resourceType == "" {
		return name
	} else {
		return fmt.Sprintf("%s %s", resourceType, name)
	}
}

func (s *ResourceQuota) ResKey() string {
	return BuildResKey(s.ResourceType, s.Name)
}

func (s *InfraResource) ResKey() string {
	return BuildResKey(s.Type, s.Name)
}

func (s *ResourceQuota) ResKeyDesc() string {
	return BuildResKeyDesc(s.ResourceType, s.Name)
}

func (s *InfraResource) ResKeyDesc() string {
	return BuildResKeyDesc(s.Type, s.Name)
}

func (s *GPUResource) WithCount(count uint32) *GPUResource {
	gr := s.Clone()
	gr.Count = count
	return gr
}
