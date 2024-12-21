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

// Package k8ssite provides a platform for managing applications
// in a pre-existing Kubernetes cluster as the entire cloudlet.
package k8ssite

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	k8scommon "github.com/edgexr/edge-cloud-platform/pkg/platform/k8s-common"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	"github.com/edgexr/edge-cloud-platform/pkg/workloadmgrs/k8swm"
	ssh "github.com/edgexr/golang-ssh"
)

const NoKubeconfig = ""

type K8sSite struct {
	accessVars map[string]string
	CommonPf   infracommon.CommonPlatform
	caches     *platform.Caches
	infracommon.CommonEmbedded
	k8swm.K8sWorkloadMgr
}

func NewPlatform() platform.Platform {
	return &K8sSite{}
}

func (s *K8sSite) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:                  platform.PlatformTypeK8SSite,
		SupportsMultiTenantCluster:    true,
		SupportsKubernetesOnly:        true,
		KubernetesRequiresWorkerNodes: true,
		IpAllocatedPerService:         true,
		IsSingleKubernetesCluster:     true,
		IsPrebuiltKubernetesCluster:   true,
		RequiresCrmOffEdge:            true,
		UsesIngress:                   true,
		ResourceQuotaProperties:       cloudcommon.CommonResourceQuotaProps,
		AccessVars:                    AccessVarProps,
		Properties:                    Props,
	}
}

func (s *K8sSite) getClient() ssh.Client {
	// k8s runs all kubectl commands locally
	return &pc.LocalClient{}
}

func (s *K8sSite) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Init")
	s.caches = caches

	err := s.InitApiAccessProperties(ctx, platformConfig.AccessApi, platformConfig.EnvVars)
	if err != nil {
		return err
	}

	features := s.GetFeatures()
	if err := s.CommonPf.InitInfraCommon(ctx, platformConfig, features.Properties); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon failed", "err")
		return err
	}
	s.K8sWorkloadMgr.Init(s, features, &s.CommonPf)
	return nil
}

func (s *K8sSite) InitHAConditional(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *K8sSite) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "k8sop-1.0"
}

const KconfPerms fs.FileMode = 0644

func (s *K8sSite) ensureKubeconfig() (*k8smgmt.KconfNames, error) {
	key := s.CommonPf.PlatformConfig.CloudletKey
	kconfNames := k8smgmt.GetCloudletKConfNames(key)
	kconfName := kconfNames.KconfName
	data := s.accessVars[KUBECONFIG]
	// check if file exists and is correct
	out, err := os.ReadFile(kconfName)
	if err == nil && string(out) == data {
		return kconfNames, nil
	}
	// write out file
	err = os.WriteFile(kconfName, []byte(s.accessVars[KUBECONFIG]), KconfPerms)
	if err != nil {
		return nil, fmt.Errorf("failed to write kubeconfig file %s, %s", kconfName, err)
	}
	return kconfNames, nil
}

func (s *K8sSite) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo")
	var err error
	info.Flavors, err = k8scommon.GetFlavorList(ctx, s.caches)
	if err != nil {
		return err
	}
	kconfNames, err := s.ensureKubeconfig()
	if err != nil {
		return err
	}
	info.NodeInfos, err = k8smgmt.GetNodeInfos(ctx, s.getClient(), kconfNames.KconfArg)
	if err != nil {
		return err
	}
	clusterVersion, err := k8smgmt.GetClusterVersion(ctx, s.getClient(), kconfNames.KconfArg)
	if err != nil {
		return err
	}
	if info.Properties == nil {
		info.Properties = make(map[string]string)
	}
	info.Properties[cloudcommon.AnnotationKubernetesVersion] = clusterVersion

	// set total resource limits based on sum of all nodes
	vcpus := edgeproto.Udec64{}
	ram := edgeproto.Udec64{}
	disk := edgeproto.Udec64{}
	for _, nodeInfo := range info.NodeInfos {
		for res, val := range nodeInfo.Allocatable {
			switch res {
			case cloudcommon.ResourceVcpus:
				vcpus.Add(val)
			case cloudcommon.ResourceRamMb:
				ram.Add(val)
			case cloudcommon.ResourceDiskGb:
				disk.Add(val)
			}
		}
	}
	info.OsMaxVcores = vcpus.Whole
	info.OsMaxRam = ram.Whole
	info.OsMaxVolGb = disk.Whole
	info.NodePools = k8smgmt.GetNodePools(ctx, info.NodeInfos)
	return err
}

func (s *K8sSite) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *K8sSite) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *K8sSite) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

func (s *K8sSite) NameSanitize(name string) string {
	return name
}

// TODO
func (k *K8sSite) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	var resources []edgeproto.InfraResource
	return resources, nil
}

// TODO
func (k *K8sSite) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource {
	resInfo := make(map[string]edgeproto.InfraResource)
	return resInfo
}

// TODO
func (k *K8sSite) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

func (m *K8sSite) GetClusterCredentials(ctx context.Context, clusterInst *edgeproto.ClusterInst) ([]byte, error) {
	kubeconfig, ok := m.accessVars[KUBECONFIG]
	if !ok {
		return nil, errors.New(KUBECONFIG + " access var not set")
	}
	if kubeconfig == "" {
		return nil, errors.New(KUBECONFIG + " access var is empty")
	}
	return []byte(kubeconfig), nil
}
