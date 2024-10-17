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
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
)

// CloudletResources collect resources in use within a Cloudlet.
// Resources may be set by infra flavors, or by node resources
// if the platform does not have quantized flavors.
type CloudletResources struct {
	nonFlavorVals     resspec.ResValMap
	flavors           map[string]int // count of flavors used by name
	lbNodeCount       int
	platformNodeCount int
	vms               []edgeproto.VMResource // list of VMs to pass to platform GetClusterAdditionalResources()
	numVms            int
}

func NewCloudletResources() *CloudletResources {
	return &CloudletResources{
		flavors: make(map[string]int),
	}
}

func (s *CloudletResources) AddRes(clusterKey *edgeproto.ClusterKey, nr *edgeproto.NodeResources, nodeType string, count uint32) error {
	if count == 0 || nr == nil {
		return nil
	}
	if nr.InfraNodeFlavor != "" {
		// quantized to platform flavor
		s.AddFlavor(clusterKey, nr.InfraNodeFlavor, nodeType, count)
	} else {
		err := s.nonFlavorVals.AddNodeResources(nr, count)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *CloudletResources) AddFlavor(clusterKey *edgeproto.ClusterKey, flavorName string, nodeType string, count uint32) {
	if count == 0 {
		return
	}
	s.flavors[flavorName] += int(count)
	// also track VMs for GetClusterAdditionalResources() functions.
	vmRes := edgeproto.VMResource{
		Key:      *clusterKey,
		VmFlavor: flavorName,
		Type:     nodeType,
		Count:    count,
	}
	s.vms = append(s.vms, vmRes)
	s.numVms += int(count)
	// for external IPs, track LB and platformVM counts
	if cloudcommon.IsLBNode(nodeType) {
		s.lbNodeCount++
	} else if cloudcommon.IsPlatformNode(nodeType) {
		s.platformNodeCount++
	}
}

// AddPlatformVMs adds in resources in use by the platform VM which
// runs CRM and Shepherd.
func (s *CloudletResources) AddPlatformVMs(ctx context.Context, cloudletInfo *edgeproto.CloudletInfo) {
	for _, vm := range cloudletInfo.ResourcesSnapshot.PlatformVms {
		if vm.InfraFlavor == "" {
			continue
		}
		s.AddFlavor(&edgeproto.ClusterKey{}, vm.InfraFlavor, vm.Type, 1)
	}
}

// AddClusterInstResources adds in resources in use by the cluster.
// Optionally the oldClusterInst can be specified if we are
// calculating resources for an update.
func (s *CloudletResources) AddClusterInstResources(ctx context.Context, clusterInst *edgeproto.ClusterInst, rootLBFlavor *edgeproto.FlavorInfo, isManagedK8s bool) error {
	log.SpanLog(ctx, log.DebugLevelApi, "AddClusterInstResources", "clusterinst key", clusterInst.Key, "root lb flavor", rootLBFlavor.Name, "managed k8s", isManagedK8s, "nodeRes", clusterInst.NodeResources, "nodepools", clusterInst.NodePools)

	if clusterInst.Deployment == cloudcommon.DeploymentTypeDocker {
		s.AddRes(&clusterInst.Key, clusterInst.NodeResources, cloudcommon.NodeTypeDockerClusterNode.String(), 1)
	} else {
		s.AddFlavor(&clusterInst.Key, clusterInst.MasterNodeFlavor, cloudcommon.NodeTypeK8sClusterMaster.String(), clusterInst.NumMasters)
		for _, pool := range clusterInst.NodePools {
			s.AddRes(&clusterInst.Key, pool.NodeResources, cloudcommon.NodeTypeK8sClusterNode.String(), pool.NumNodes)
		}
	}

	// For managed-k8s platforms, ignore rootLB for resource calculation
	if !isManagedK8s && clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		if rootLBFlavor == nil {
			return fmt.Errorf("missing rootlb flavor")
		}
		s.AddFlavor(&clusterInst.Key, rootLBFlavor.Name, cloudcommon.NodeTypeDedicatedRootLB.String(), 1)
	}
	return nil
}

// AddVMAppInstResources adds in resources in use by the VM AppInst.
func (s *CloudletResources) AddVMAppInstResources(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, rootLBFlavor *edgeproto.FlavorInfo) error {
	log.SpanLog(ctx, log.DebugLevelApi, "AddVMAppInstsResources", "appinst key", appInst.Key)

	s.AddRes(appInst.GetClusterKey(), appInst.NodeResources, cloudcommon.NodeTypeAppVM.String(), 1)

	if app.AccessType == edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
		s.AddFlavor(appInst.GetClusterKey(), rootLBFlavor.Name, cloudcommon.NodeTypeDedicatedRootLB.String(), 1)
	}
	return nil
}
