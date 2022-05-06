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
	"fmt"
	"os"
	"time"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

const MaxKubeCredentialsWait = 10 * time.Second

func (m *ManagedK8sPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateClusterInst", "clusterInst", clusterInst)
	clusterName := m.Provider.NameSanitize(k8smgmt.GetCloudletClusterName(&clusterInst.Key))
	updateCallback(edgeproto.UpdateTask, "Creating Kubernetes Cluster: "+clusterName)
	client, err := m.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	kconf := k8smgmt.GetKconfName(clusterInst)
	err = m.createClusterInstInternal(ctx, client, clusterName, kconf, clusterInst.NumNodes, clusterInst.NodeFlavor, updateCallback)
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
	// rename any existing kubeconfig to .save
	infracommon.BackupKubeconfig(ctx, client)
	if err = m.Provider.RunClusterCreateCommand(ctx, clusterName, numNodes, flavor); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in creating cluster", "err", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "cluster create done")

	if err = m.Provider.GetCredentials(ctx, clusterName); err != nil {
		return err
	}
	kconfFile := infracommon.DefaultKubeconfig()
	start := time.Now()
	for {
		// make sure the kubeconf is present and of nonzero length.  If not keep
		// waiting for it to show up to MaxKubeCredentialsWait
		finfo, err := os.Stat(kconfFile)
		if err == nil && finfo.Size() > 0 {
			break
		}
		time.Sleep(time.Second * 1)
		elapsed := time.Since(start)
		if elapsed >= (MaxKubeCredentialsWait) {
			return fmt.Errorf("Could not find kubeconfig file after GetCredentials: %s", kconfFile)
		}
	}
	if err = pc.CopyFile(client, kconfFile, kconf); err != nil {
		return err
	}
	return nil
}

func (m *ManagedK8sPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteClusterInst", "clusterInst", clusterInst)
	clusterName := m.Provider.NameSanitize(k8smgmt.GetCloudletClusterName(&clusterInst.Key))
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
	return m.Provider.RunClusterDeleteCommand(ctx, clusterName)
}

func (m *ManagedK8sPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Update cluster inst not implemented")
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

func (m *ManagedK8sPlatform) GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error) {
	return nil, fmt.Errorf("GetClusterInfraResources not implemented for managed k8s")
}
