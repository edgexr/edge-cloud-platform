// Copyright 2025 EdgeXR, Inc
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

// Package sitenodepool provides a platform for managing applications
// on a static set of user-created compute nodes (bare metal or VMs).
package sitenodepool

import (
	"context"
	"errors"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/k8spm"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	ssh "github.com/edgexr/golang-ssh"
)

type SiteNodePool struct {
	CommonPf infracommon.CommonPlatform
	caches   *platform.Caches
	infracommon.CommonEmbedded
	k8spm.K8sPlatformMgr
}

func NewPlatform() platform.Platform {
	return &SiteNodePool{}
}

func (s *SiteNodePool) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:                  platform.PlatformTypeSiteNodePool,
		SupportsMultiTenantCluster:    true,
		SupportsKubernetesOnly:        true,
		KubernetesRequiresWorkerNodes: true,
		IpAllocatedPerService:         true,
		RequiresCrmOffEdge:            true,
		UsesIngress:                   true,
		NodeUsage:                     edgeproto.NodeUsageUserDefined,
		ResourceQuotaProperties:       cloudcommon.CommonResourceQuotaProps,
	}
}

func (s *SiteNodePool) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Init")
	s.caches = caches

	features := s.GetFeatures()
	if err := s.CommonPf.InitInfraCommon(ctx, platformConfig, features.Properties); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon failed", "err")
		return err
	}
	workloadMgr := &k8smgmt.K8SWorkloadMgr{}
	s.K8sPlatformMgr.Init(s, features, &s.CommonPf, workloadMgr)
	return nil
}

func (s *SiteNodePool) InitHAConditional(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *SiteNodePool) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "k8sop-1.0"
}

func (s *SiteNodePool) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return nil
}

func (s *SiteNodePool) getClient() ssh.Client {
	// k8s runs all kubectl commands locally
	return &pc.LocalClient{}
}

func (s *SiteNodePool) GetClusterClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *SiteNodePool) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *SiteNodePool) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *SiteNodePool) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

func (s *SiteNodePool) NameSanitize(name string) string {
	return name
}

// TODO
func (s *SiteNodePool) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	var resources []edgeproto.InfraResource
	return resources, nil
}

// TODO
func (s *SiteNodePool) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource {
	resInfo := make(map[string]edgeproto.InfraResource)
	return resInfo
}

// TODO
func (s *SiteNodePool) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

func (s *SiteNodePool) GetClusterCredentials(ctx context.Context, clusterInst *edgeproto.ClusterInst) ([]byte, error) {
	// TODO:
	// create ssh.Client from one of the cluster master site nodes
	// call into rke2 package to get kubeconfig using ssh.Client
	//return []byte(kubeconfig), nil
	return nil, errors.New("TODO")
}
