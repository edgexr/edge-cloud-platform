// Copyright 2022 MobiledgeX, Inc
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

package managedk8s

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	ssh "github.com/edgexr/golang-ssh"
)

const MaxKubeCredentialsWait = 10 * time.Second

func (m *ManagedK8sPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateClusterInst", "clusterInst", clusterInst)
	clusterName := m.Provider.NameSanitize(k8smgmt.GetCloudletClusterName(clusterInst))
	updateCallback(edgeproto.UpdateTask, "Creating Kubernetes Cluster: "+clusterName)
	client, err := m.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	if len(clusterInst.NodePools) == 0 {
		return errors.New("no node pools specified for cluster")
	}
	// for now, only support a single node pool
	if len(clusterInst.NodePools) > 1 {
		return errors.New("currently only one node pool is supported")
	}
	pool := clusterInst.NodePools[0]

	kconf := k8smgmt.GetKconfName(clusterInst)
	err = m.createClusterInstInternal(ctx, client, clusterName, kconf, pool.NumNodes, pool.NodeResources.InfraNodeFlavor, updateCallback)
	if err != nil {
		if !clusterInst.SkipCrmCleanupOnFailure {
			log.SpanLog(ctx, log.DebugLevelInfra, "Cleaning up clusterInst after failure", "clusterInst", clusterInst)
			delerr := m.deleteClusterInstInternal(ctx, clusterName, updateCallback)
			if delerr != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "fail to cleanup cluster")
			}
		}
	}
	return err
}

func (m *ManagedK8sPlatform) createClusterInstInternal(ctx context.Context, client ssh.Client, clusterName string, kconf string, numNodes uint32, flavor string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "createClusterInstInternal", "clusterName", clusterName, "numNodes", numNodes, "flavor", flavor)
	var err error
	if err = m.Provider.Login(ctx); err != nil {
		return err
	}
	// perform any actions to create prereq resource before the cluster
	if err = m.Provider.CreateClusterPrerequisites(ctx, clusterName); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in creating cluster prereqs", "err", err)
		return err
	}
	if err = m.Provider.RunClusterCreateCommand(ctx, clusterName, numNodes, flavor); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in creating cluster", "err", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "cluster create done")

	err = m.SetupClusterKconf(ctx, clusterName, kconf)
	if err != nil {
		return err
	}
	return nil
}

func (m *ManagedK8sPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteClusterInst", "clusterInst", clusterInst)
	clusterName := m.Provider.NameSanitize(k8smgmt.GetCloudletClusterName(clusterInst))
	err := m.deleteClusterInstInternal(ctx, clusterName, updateCallback)
	if err != nil {
		return err
	}
	client, err := m.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	return k8smgmt.CleanupClusterConfig(ctx, client, clusterInst)
}

func (m *ManagedK8sPlatform) deleteClusterInstInternal(ctx context.Context, clusterName string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleteClusterInstInternal", "clusterName", clusterName)
	if err := m.Provider.Login(ctx); err != nil {
		return err
	}
	return m.Provider.RunClusterDeleteCommand(ctx, clusterName)
}

func (m *ManagedK8sPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Update cluster inst not implemented")
}

func (s *ManagedK8sPlatform) ChangeClusterInstDNS(ctx context.Context, clusterInst *edgeproto.ClusterInst, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("cluster dns change not implemented")
}

func (m *ManagedK8sPlatform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletInfraResources")
	var resources edgeproto.InfraResourcesSnapshot
	// NOTE: resource.PlatformVms will be empty. Because for a managed K8s
	//       platform there are no platform VM resources as
	//       we don't run CRM/RootLB VMs on those platforms
	resourcesInfo, err := m.Provider.GetCloudletInfraResourcesInfo(ctx)
	if err == nil {
		resources.Info = resourcesInfo
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to get cloudlet infra resources info", "err", err)
	}
	return &resources, nil
}

func (m *ManagedK8sPlatform) GetClusterInfraResources(ctx context.Context, cluster *edgeproto.ClusterInst) (*edgeproto.InfraResources, error) {
	return nil, fmt.Errorf("GetClusterInfraResources not implemented for managed k8s")
}
