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
	"io/fs"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	ssh "github.com/edgexr/golang-ssh"
)

// ManagedK8sProvider is an interface that platforms implement to perform the details of interfacing with managed kubernetes services
type ManagedK8sProvider interface {
	GetFeatures() *edgeproto.PlatformFeatures
	GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error
	SetProperties(props *infracommon.InfraProperties) error
	Login(ctx context.Context) error
	GetCredentials(ctx context.Context, clusterName string) ([]byte, error)
	NameSanitize(name string) string
	CreateClusterPrerequisites(ctx context.Context, clusterName string) error
	RunClusterCreateCommand(ctx context.Context, clusterName string, numNodes uint32, flavor string) error
	RunClusterDeleteCommand(ctx context.Context, clusterName string) error
	InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error
	GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error)
	GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource
	GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error
}

const KconfPerms fs.FileMode = 0644

// ManagedK8sPlatform contains info needed by all Managed Kubernetes Providers
type ManagedK8sPlatform struct {
	Type     string
	CommonPf infracommon.CommonPlatform
	Provider ManagedK8sProvider
	infracommon.CommonEmbedded
}

func (m *ManagedK8sPlatform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Init", "type", m.Type)
	features := m.Provider.GetFeatures()
	props := features.Properties

	log.SpanLog(ctx, log.DebugLevelInfra, "Init provider")
	err := m.Provider.InitApiAccessProperties(ctx, platformConfig.AccessApi, platformConfig.EnvVars)
	if err != nil {
		return err
	}

	if err := m.CommonPf.InitInfraCommon(ctx, platformConfig, props); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon failed", "err", err)
		return err
	}
	err = m.Provider.SetProperties(&m.CommonPf.Properties)
	if err != nil {
		return err
	}
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
	return features
}

func (m *ManagedK8sPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return m.Provider.GatherCloudletInfo(ctx, info)
}

func (m *ManagedK8sPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (m *ManagedK8sPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (m *ManagedK8sPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

// called by controller, make sure it doesn't make any calls to infra API
func (m *ManagedK8sPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	return m.Provider.GetClusterAdditionalResources(ctx, cloudlet, vmResources, infraResMap)
}

func (m *ManagedK8sPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return m.Provider.GetClusterAdditionalResourceMetric(ctx, cloudlet, resMetric, resources)
}

func (m *ManagedK8sPlatform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &edgeproto.Flavor{}, nil
}
