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
	certscache "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs-cache"
	ssh "github.com/edgexr/golang-ssh"
)

const MaxKubeCredentialsWait = 10 * time.Second

func (m *ManagedK8sPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (annotations map[string]string, reterr error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateClusterInst", "clusterInst", clusterInst)
	clusterName := m.Provider.NameSanitize(k8smgmt.GetCloudletClusterName(clusterInst))
	updateCallback(edgeproto.UpdateTask, "Creating Kubernetes Cluster: "+clusterName)
	client, err := m.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return nil, err
	}
	if len(clusterInst.NodePools) == 0 {
		return nil, errors.New("no node pools specified for cluster")
	}
	// for now, only support a single node pool
	if len(clusterInst.NodePools) > 1 {
		return nil, errors.New("currently only one node pool is supported")
	}

	defer func() {
		if reterr == nil || clusterInst.SkipCrmCleanupOnFailure {
			return
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Cleaning up clusterInst after failure", "clusterInst", clusterInst)
		delerr := m.deleteClusterInstInternal(ctx, clusterName, clusterInst, updateCallback)
		if delerr != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to cleanup cluster", "delerr", delerr)
		}
	}()

	infraAnnotations, err := m.createClusterInstInternal(ctx, client, clusterName, clusterInst, updateCallback)
	if err != nil {
		return nil, err
	}
	addonInfo, err := m.Provider.GetClusterAddonInfo(ctx, clusterName, clusterInst)
	if err != nil {
		return nil, err
	}

	names, err := m.ensureKubeconfig(ctx, clusterInst)
	if err != nil {
		return nil, err
	}
	wildcardName := certscache.GetWildcardName(clusterInst.Fqdn)
	refreshOpts := k8smgmt.RefreshCertsOpts{
		CommerialCerts: m.CommonPf.PlatformConfig.CommercialCerts,
		InitCluster:    true,
	}
	err = k8smgmt.SetupIngressNginx(ctx, client, names.GetKConfNames(), m.CommonPf.PlatformConfig.CloudletKey, m.CommonPf.PlatformConfig.ProxyCertsCache, wildcardName, refreshOpts, updateCallback, addonInfo.IngressNginxOps...)
	if err != nil {
		return nil, err
	}
	return infraAnnotations, err
}

func (m *ManagedK8sPlatform) createClusterInstInternal(ctx context.Context, client ssh.Client, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "createClusterInstInternal", "clusterName", clusterName, "nodePools", clusterInst.NodePools)
	var err error
	if err = m.Provider.Login(ctx); err != nil {
		return nil, err
	}
	// perform any actions to create prereq resource before the cluster
	if err = m.Provider.CreateClusterPrerequisites(ctx, clusterName); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in creating cluster prereqs", "err", err)
		return nil, err
	}
	infraAnnotations, err := m.Provider.RunClusterCreateCommand(ctx, clusterName, clusterInst)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in creating cluster", "err", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "cluster create done", "annotations", infraAnnotations)
	return infraAnnotations, nil
}

func (m *ManagedK8sPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteClusterInst", "clusterInst", clusterInst)
	clusterName := m.Provider.NameSanitize(k8smgmt.GetCloudletClusterName(clusterInst))
	err := m.deleteClusterInstInternal(ctx, clusterName, clusterInst, updateCallback)
	if err != nil {
		return err
	}
	client, err := m.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	return k8smgmt.CleanupClusterConfig(ctx, client, clusterInst)
}

func (m *ManagedK8sPlatform) deleteClusterInstInternal(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleteClusterInstInternal", "clusterName", clusterName)
	if err := m.Provider.Login(ctx); err != nil {
		return err
	}
	return m.Provider.RunClusterDeleteCommand(ctx, clusterName, clusterInst)
}

func (m *ManagedK8sPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateClusterInst", "clusterInst", clusterInst)
	if len(clusterInst.NodePools) == 0 {
		return nil, errors.New("no node pools specified for cluster")
	}
	// for now, only support a single node pool
	if len(clusterInst.NodePools) > 1 {
		return nil, errors.New("currently only one node pool is supported")
	}
	if err := m.Provider.Login(ctx); err != nil {
		return nil, err
	}
	clusterName := m.Provider.NameSanitize(k8smgmt.GetCloudletClusterName(clusterInst))

	infraAnnotations, err := m.Provider.RunClusterUpdateCommand(ctx, clusterName, clusterInst)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in updating cluster", "err", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "cluster update done", "annotations", infraAnnotations)
	return infraAnnotations, nil
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

// ensureKubeconfig ensures the cluster's admin kubeconfig is
// present locally.
func (m *ManagedK8sPlatform) ensureKubeconfig(ctx context.Context, clusterInst *edgeproto.ClusterInst) (*k8smgmt.KubeNames, error) {
	clusterName := m.Provider.NameSanitize(k8smgmt.GetCloudletClusterName(clusterInst))
	names, err := k8smgmt.GetKubeNames(clusterInst, &edgeproto.App{}, &edgeproto.AppInst{})
	if err != nil {
		return nil, err
	}
	client := m.getClient()
	kconfData, err := m.Provider.GetCredentials(ctx, clusterName, clusterInst)
	if err != nil {
		return nil, err
	}
	err = k8smgmt.EnsureKubeconfigs(ctx, client, names, kconfData)
	if err != nil {
		return nil, err
	}
	return names, nil
}
