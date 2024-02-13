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

package fakecommon

import (
	"context"
	"fmt"
	"sync"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

const (
	ResourceAdd    = true
	ResourceRemove = false
)

// Resources allows adding up resources from edgeproto objects.
// This is used to fake resource consumption by mirroring what
// the Controller thinks the platform should have.
type Resources struct {
	mux             sync.Mutex
	ramUsed         uint64
	ramMax          uint64
	vcpusUsed       uint64
	vcpusMax        uint64
	diskUsed        uint64
	diskMax         uint64
	externalIpsUsed uint64
	externalIpsMax  uint64
	instancesUsed   uint64

	cloudletFlavors map[string]*edgeproto.FlavorInfo
	lbFlavorName    string // load balancer VM flavor name

	platformVMs  []edgeproto.VmInfo
	clusterVMs   map[edgeproto.ClusterInstKey][]edgeproto.VmInfo
	vmAppInstVMs map[edgeproto.AppInstKey][]edgeproto.VmInfo
}

func (s *Resources) Init() {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.ramUsed = 0
	s.vcpusUsed = 0
	s.diskUsed = 0
	s.externalIpsUsed = 0
	s.instancesUsed = 0
	s.platformVMs = make([]edgeproto.VmInfo, 0)
	s.cloudletFlavors = map[string]*edgeproto.FlavorInfo{}
	s.clusterVMs = make(map[edgeproto.ClusterInstKey][]edgeproto.VmInfo)
}

func (s *Resources) SetCloudletFlavors(flavors []*edgeproto.FlavorInfo, lbFlavorName string) {
	s.mux.Lock()
	defer s.mux.Unlock()

	for _, flavor := range flavors {
		s.cloudletFlavors[flavor.Name] = flavor
	}
	s.lbFlavorName = lbFlavorName
}

func (s *Resources) SetMaxResources(ramMax, vcpusMax, diskMax, externalIpsMax uint64) {
	s.ramMax = ramMax
	s.vcpusMax = vcpusMax
	s.diskMax = diskMax
	s.externalIpsMax = externalIpsMax
}

// SetUserResources sets the count of user (cluster, appInst) resources
func (s *Resources) SetUserResources(ctx context.Context, caches *platform.Caches) error {
	if caches == nil {
		return fmt.Errorf("caches is nil")
	}
	clusterInstKeys := []edgeproto.ClusterInstKey{}
	caches.ClusterInstCache.GetAllKeys(ctx, func(k *edgeproto.ClusterInstKey, modRev int64) {
		clusterInstKeys = append(clusterInstKeys, *k)
	})
	for _, k := range clusterInstKeys {
		var clusterInst edgeproto.ClusterInst
		if caches.ClusterInstCache.Get(&k, &clusterInst) {
			s.AddClusterResources(&clusterInst)
		}
	}

	appInstKeys := []edgeproto.AppInstKey{}
	caches.AppInstCache.GetAllKeys(ctx, func(k *edgeproto.AppInstKey, modRev int64) {
		appInstKeys = append(appInstKeys, *k)
	})
	for _, k := range appInstKeys {
		var appInst edgeproto.AppInst
		if caches.AppInstCache.Get(&k, &appInst) {
			var app edgeproto.App
			if caches.AppCache.Get(&appInst.AppKey, &app) {
				if app.Deployment == cloudcommon.DeploymentTypeVM {
					s.AddVmAppResCount(ctx, &app, &appInst)
				}
			}
		}
	}
	return nil
}

func (s *Resources) AddPlatformVM(info edgeproto.VmInfo) {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.platformVMs = append(s.platformVMs, info)
	s.updateCommonResourcesUsedLocked(info.InfraFlavor, ResourceAdd)
}

// RemoveClusterResources removes the cluster resources from the current
// resource count.
func (s *Resources) RemoveClusterResources(key *edgeproto.ClusterInstKey) {
	s.mux.Lock()
	defer s.mux.Unlock()

	nodes, ok := s.clusterVMs[*key]
	if !ok {
		return
	}
	for _, node := range nodes {
		s.updateCommonResourcesUsedLocked(node.InfraFlavor, ResourceRemove)
		if node.Type == cloudcommon.NodeTypeDedicatedRootLB.String() {
			s.externalIpsUsed--
		}
	}
	delete(s.clusterVMs, *key)
}

// AddClusterResCount adds the cluster resources to the current
// resource count.
func (s *Resources) AddClusterResources(clusterInst *edgeproto.ClusterInst) {
	s.mux.Lock()
	defer s.mux.Unlock()

	vmNameSuffix := k8smgmt.GetCloudletClusterName(&clusterInst.Key)
	if len(s.clusterVMs) == 0 {
		s.clusterVMs = make(map[edgeproto.ClusterInstKey][]edgeproto.VmInfo)
	}
	if _, ok := s.clusterVMs[clusterInst.Key]; !ok {
		s.clusterVMs[clusterInst.Key] = []edgeproto.VmInfo{}
	}
	for ii := uint32(0); ii < clusterInst.NumMasters; ii++ {
		s.clusterVMs[clusterInst.Key] = append(s.clusterVMs[clusterInst.Key], edgeproto.VmInfo{
			Name:        fmt.Sprintf("fake-master-%d-%s", ii+1, vmNameSuffix),
			Type:        cloudcommon.NodeTypeK8sClusterMaster.String(),
			InfraFlavor: clusterInst.MasterNodeFlavor,
			Status:      "ACTIVE",
		})
		s.updateCommonResourcesUsedLocked(clusterInst.MasterNodeFlavor, ResourceAdd)
	}
	for ii := uint32(0); ii < clusterInst.NumNodes; ii++ {
		s.clusterVMs[clusterInst.Key] = append(s.clusterVMs[clusterInst.Key], edgeproto.VmInfo{
			Name:        fmt.Sprintf("fake-node-%d-%s", ii+1, vmNameSuffix),
			Type:        cloudcommon.NodeTypeK8sClusterNode.String(),
			InfraFlavor: clusterInst.NodeFlavor,
			Status:      "ACTIVE",
		})
		s.updateCommonResourcesUsedLocked(clusterInst.NodeFlavor, ResourceAdd)
	}
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		s.clusterVMs[clusterInst.Key] = append(s.clusterVMs[clusterInst.Key], edgeproto.VmInfo{
			Name:        clusterInst.Fqdn,
			Type:        cloudcommon.NodeTypeDedicatedRootLB.String(),
			InfraFlavor: s.lbFlavorName,
			Status:      "ACTIVE",
		})
		s.updateCommonResourcesUsedLocked(s.lbFlavorName, ResourceAdd)
		s.externalIpsUsed += 1
	}
}

func (s *Resources) GetClusterResources(key *edgeproto.ClusterInstKey) *edgeproto.InfraResources {
	s.mux.Lock()
	defer s.mux.Unlock()

	resources := edgeproto.InfraResources{}
	if vms, ok := s.clusterVMs[*key]; ok {
		resources.Vms = append(resources.Vms, vms...)
	}
	return &resources
}

// UpdateVmAppResCount adds the VM-deployment based AppInst
// resources to the current resource count.
func (s *Resources) AddVmAppResCount(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if app.Deployment == cloudcommon.DeploymentTypeVM {
		key := getVmAppKey(appInst)
		if _, ok := s.clusterVMs[key]; !ok {
			s.clusterVMs[key] = []edgeproto.VmInfo{}
		}
		s.clusterVMs[key] = append(s.clusterVMs[key], edgeproto.VmInfo{
			Name:        appInst.DnsLabel,
			Type:        cloudcommon.NodeTypeAppVM.String(),
			InfraFlavor: appInst.VmFlavor,
			Status:      "ACTIVE",
		})
		s.updateCommonResourcesUsedLocked(appInst.VmFlavor, ResourceAdd)
		s.externalIpsUsed += 1 // VMApp create a dedicated LB that consumes one IP
	}
}

func (s *Resources) RemoveVmAppResCount(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if app.Deployment == cloudcommon.DeploymentTypeVM {
		key := getVmAppKey(appInst)
		delete(s.clusterVMs, key)
		s.updateCommonResourcesUsedLocked(appInst.VmFlavor, ResourceRemove)
		s.externalIpsUsed--
	}
}

func getVmAppKey(appInst *edgeproto.AppInst) edgeproto.ClusterInstKey {
	return edgeproto.ClusterInstKey{
		ClusterKey: edgeproto.ClusterKey{
			Name: appInst.DnsLabel,
		},
	}
}

func (s *Resources) UpdateCommonResourcesUsed(flavorName string, add bool) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	return s.updateCommonResourcesUsedLocked(flavorName, add)
}

func (s *Resources) updateCommonResourcesUsedLocked(flavorName string, add bool) error {
	flavor, found := s.cloudletFlavors[flavorName]
	if !found {
		return fmt.Errorf("cloudlet flavor %s not found", flavorName)
	}
	if add {
		s.ramUsed += flavor.Ram
		s.vcpusUsed += flavor.Vcpus
		s.diskUsed += flavor.Disk
		s.instancesUsed++
	} else {
		s.ramUsed -= flavor.Ram
		s.vcpusUsed -= flavor.Vcpus
		s.diskUsed -= flavor.Disk
		s.instancesUsed--
	}
	return nil
}

func (s *Resources) UpdateExternalIP(add bool) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if add {
		s.externalIpsUsed++
	} else {
		s.externalIpsUsed--
	}
}

func (s *Resources) GetSnapshot() *edgeproto.InfraResourcesSnapshot {
	s.mux.Lock()
	defer s.mux.Unlock()

	snapshot := edgeproto.InfraResourcesSnapshot{}
	snapshot.PlatformVms = s.platformVMs
	snapshot.Info = []edgeproto.InfraResource{{
		Name:          cloudcommon.ResourceRamMb,
		Value:         s.ramUsed,
		InfraMaxValue: s.ramMax,
		Units:         cloudcommon.ResourceRamUnits,
	}, {
		Name:          cloudcommon.ResourceVcpus,
		Value:         s.vcpusUsed,
		InfraMaxValue: s.vcpusMax,
	}, {
		Name:          cloudcommon.ResourceDiskGb,
		Value:         s.diskUsed,
		InfraMaxValue: s.diskMax,
	}, {
		Name:          cloudcommon.ResourceExternalIPs,
		Value:         s.externalIpsUsed,
		InfraMaxValue: s.externalIpsMax,
	}, {
		Name:  cloudcommon.ResourceInstances,
		Value: s.instancesUsed,
	},
	}
	return &snapshot
}
