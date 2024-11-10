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

package k8sop

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	k8scommon "github.com/edgexr/edge-cloud-platform/pkg/platform/k8s-common"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	ssh "github.com/edgexr/golang-ssh"
)

// k8s operator runs the crm as a pod inside the cluster it managers
// with rbac perms to be able to run kubectl in the pod. So no
// kubeconfig is needed.
const NoKubeconfig = ""

// Working dir corresponds to the persistent volume claim in the
// cloudlet operator.
const WorkingDir = "/root/config"

type K8sOperator struct {
	Type       string
	CommonPf   infracommon.CommonPlatform
	properties *infracommon.InfraProperties
	caches     *platform.Caches
	infracommon.CommonEmbedded
}

func NewPlatform() platform.Platform {
	return &K8sOperator{}
}

func (s *K8sOperator) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:                  platform.PlatformTypeK8SOperator,
		SupportsMultiTenantCluster:    true,
		SupportsKubernetesOnly:        true,
		KubernetesRequiresWorkerNodes: true,
		IpAllocatedPerService:         true,
		IsSingleKubernetesCluster:     true,
		IsPrebuiltKubernetesCluster:   true,
		ResourceQuotaProperties:       cloudcommon.CommonResourceQuotaProps,
	}
}

func (s *K8sOperator) getClient() ssh.Client {
	// k8s operator runs all kubectl commands locally in the pod
	return &pc.LocalClient{
		WorkingDir: WorkingDir,
	}
}

func (s *K8sOperator) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Init", "type", s.Type)
	s.caches = caches

	if err := s.CommonPf.InitInfraCommon(ctx, platformConfig, map[string]*edgeproto.PropertyInfo{}); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon failed", "err")
		return err
	}
	return nil
}

func (s *K8sOperator) InitHAConditional(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *K8sOperator) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "k8sop-1.0"
}

func (s *K8sOperator) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo")
	var err error
	info.Flavors, err = k8scommon.GetFlavorList(ctx, s.caches)
	if err != nil {
		return err
	}
	info.NodeInfos, err = k8smgmt.GetNodeInfos(ctx, s.getClient(), NoKubeconfig)
	return err
}

func (s *K8sOperator) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *K8sOperator) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *K8sOperator) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

func (s *K8sOperator) NameSanitize(name string) string {
	return name
}

// TODO
func (k *K8sOperator) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	var resources []edgeproto.InfraResource
	return resources, nil
}

// TODO
func (k *K8sOperator) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource {
	resInfo := make(map[string]edgeproto.InfraResource)
	return resInfo
}

// TODO
func (k *K8sOperator) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}
