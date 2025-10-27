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
	"io/fs"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/k8spm"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/osmano/osmwm"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	certscache "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs-cache"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	ssh "github.com/edgexr/golang-ssh"
)

// ManagedK8sProvider is an interface that platforms implement to perform the details of interfacing with managed kubernetes services
type ManagedK8sProvider interface {
	GetFeatures() *edgeproto.PlatformFeatures
	GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error
	Init(accessVars map[string]string, properties *infracommon.InfraProperties, commonPf *infracommon.CommonPlatform) error
	Login(ctx context.Context) error
	// GetCredentials retrieves kubeconfig credentials from the cluster
	GetCredentials(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) ([]byte, error)
	NameSanitize(name string) string
	CreateClusterPrerequisites(ctx context.Context, clusterName string) error
	// RunClusterCreateCommand creates the specified cluster, returning any infra annotations to add to the cluster.
	RunClusterCreateCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error)
	// RunClusterUpdateCommand updates the specified cluster, returning any infra annotations to add to the cluster.
	// Check clusterInst.Fields to see which fields are updated.
	RunClusterUpdateCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error)
	RunClusterDeleteCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error
	GetClusterAddonInfo(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (*k8smgmt.ClusterAddonInfo, error)
	GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error)
	GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource
	GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error
	// get all clusters, including ones not created by us
	GetAllClusters(ctx context.Context) ([]*edgeproto.CloudletManagedCluster, error)
	// RegisterClusterInst registers an existing cloudlet managed cluster.
	// It should check that the cluster exists, and return the same types of
	// annotations as RunClusterCreateCommand.
	RegisterCluster(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (map[string]string, error)
}

const KconfPerms fs.FileMode = 0644

// ManagedK8sPlatform contains info needed by all Managed Kubernetes Providers
type ManagedK8sPlatform struct {
	Type     string
	CommonPf infracommon.CommonPlatform
	Provider ManagedK8sProvider
	infracommon.CommonEmbedded
	k8spm.K8sPlatformMgr
	caches *platform.Caches
}

func (m *ManagedK8sPlatform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Init", "type", m.Type)
	features := m.GetFeatures()
	props := features.Properties
	m.caches = caches

	log.SpanLog(ctx, log.DebugLevelInfra, "Init provider")
	accessVars, err := platformConfig.AccessApi.GetCloudletAccessVars(ctx)
	if err != nil {
		return err
	}

	if err := m.CommonPf.InitInfraCommon(ctx, platformConfig, props); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon failed", "err", err)
		return err
	}
	err = m.Provider.Init(accessVars, &m.CommonPf.Properties, &m.CommonPf)
	if err != nil {
		return err
	}
	var workloadMgr k8smgmt.WorkloadMgr
	val, ok := m.CommonPf.Properties.GetValue(cloudcommon.WorkloadManager)
	if ok && val == "osm" {
		wm := &osmwm.OSMWorkloadMgr{}
		if err := wm.Init(m, accessVars, &m.CommonPf.Properties); err != nil {
			return err
		}
		workloadMgr = wm
	} else {
		workloadMgr = &k8smgmt.K8SWorkloadMgr{}
	}
	m.K8sPlatformMgr.Init(m, features, &m.CommonPf, workloadMgr)
	return m.Provider.Login(ctx)
}

func (m *ManagedK8sPlatform) InitHAConditional(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (m *ManagedK8sPlatform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "mk8s-1.0"
}

func (m *ManagedK8sPlatform) GetFeatures() *edgeproto.PlatformFeatures {
	features := m.Provider.GetFeatures()
	features.RequiresCrmOffEdge = true
	features.UsesIngress = true
	if features.Properties == nil {
		features.Properties = make(map[string]*edgeproto.PropertyInfo)
	}
	features.Properties[cloudcommon.IngressControllerPresent] = cloudcommon.IngressControllerPresentProp
	features.Properties[cloudcommon.WorkloadManager] = cloudcommon.WorkloadManagerProp
	features.Properties[cloudcommon.NamespaceLabels] = cloudcommon.NamespaceLabelsProp
	return features
}

func (m *ManagedK8sPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return m.Provider.GatherCloudletInfo(ctx, info)
}

func (m *ManagedK8sPlatform) getClient() ssh.Client {
	return &pc.LocalClient{}
}

func (m *ManagedK8sPlatform) GetClusterClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error) {
	return m.getClient(), nil
}

func (m *ManagedK8sPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return m.getClient(), nil
}

func (m *ManagedK8sPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return m.getClient(), nil
}

func (m *ManagedK8sPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

// called by controller, make sure it doesn't make any calls to infra API
func (m *ManagedK8sPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource {
	return m.Provider.GetClusterAdditionalResources(ctx, cloudlet, vmResources)
}

func (m *ManagedK8sPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return m.Provider.GetClusterAdditionalResourceMetric(ctx, cloudlet, resMetric, resources)
}

func (m *ManagedK8sPlatform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &edgeproto.Flavor{}, nil
}

func (m *ManagedK8sPlatform) GetClusterCredentials(ctx context.Context, clusterInst *edgeproto.ClusterInst) ([]byte, error) {
	clusterName := m.Provider.NameSanitize(k8smgmt.GetCloudletClusterName(clusterInst))
	return m.Provider.GetCredentials(ctx, clusterName, clusterInst)
}

func (m *ManagedK8sPlatform) RefreshCerts(ctx context.Context, certsCache *certscache.ProxyCertsCache) error {
	// refresh cert for every cluster if needed
	clusters := []*edgeproto.ClusterInst{}
	err := m.caches.ClusterInstCache.Show(&edgeproto.ClusterInst{}, func(clusterInst *edgeproto.ClusterInst) error {
		cluster := clusterInst.Clone()
		clusters = append(clusters, cluster)
		return nil
	})
	if err != nil {
		return err
	}
	client := m.getClient()
	cloudletKey := m.CommonPf.PlatformConfig.CloudletKey

	errs := []string{}
	for _, clusterInst := range clusters {
		names, err := m.ensureKubeconfig(ctx, clusterInst)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		wildcardName := certscache.GetWildcardName(clusterInst.Fqdn)
		refreshOpts := k8smgmt.RefreshCertsOpts{
			CommerialCerts: m.CommonPf.PlatformConfig.CommercialCerts,
		}
		err = k8smgmt.RefreshCert(ctx, client, names.GetKConfNames(), cloudletKey, certsCache, k8smgmt.IngressNginxNamespace, wildcardName, refreshOpts)
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to refresh some cluster certificates", "errs", errs)
		return fmt.Errorf("failed to refresh some cluster certificates: %s", strings.Join(errs, ", "))
	}
	return nil
}
