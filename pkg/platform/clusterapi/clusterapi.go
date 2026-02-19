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

// Package clusterapi provides a platform based on Cluster API.
package clusterapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/metal3"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/managedk8s"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
	clusterctl "sigs.k8s.io/cluster-api/cmd/clusterctl/api/v1alpha3"
)

const ClusterAPIVersion = "v1.11.3"

// ClusterAPI provides a platform based on Cluster API.
// https://cluster-api.sigs.k8s.io/
// https://cluster-api.sigs.k8s.io/reference/providers
//
// It is the responsibility of the operator to set up the Cluster API
// management cluster, including the cluster API operators, the underlying
// cluster API providers, and the existing bare metal machine instances,
// for example BareMetalHosts in metal3.
//
// This platform takes as input the Kubeconfig to access the namespace of
// the management cluster that serves as the target for CAPI cluster manifests.
// This code is independent of the Infrastructure provider.
type ClusterAPI struct {
	properties  *infracommon.InfraProperties
	accessVars  map[string]string
	namespace   string
	infra       string
	cloudletKey edgeproto.CloudletKey
	accessApi   platform.AccessApi
	caches      *platform.Caches
}

func NewPlatform() platform.Platform {
	return &managedk8s.ManagedK8sPlatform{
		Provider: &ClusterAPI{},
	}
}

func (s *ClusterAPI) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:                  platform.PlatformTypeClusterAPI,
		SupportsMultiTenantCluster:    true,
		SupportsKubernetesOnly:        true,
		KubernetesManagedControlPlane: true,
		IpAllocatedPerService:         true,
		RequiresCrmOffEdge:            true,
		UsesIngress:                   true,
		ResourceCalcByFlavorCounts:    true,
		SupportsBareMetal:             true,
		ResourceQuotaProperties:       cloudcommon.CommonResourceQuotaProps,
		AccessVars:                    AccessVarProps,
		Properties:                    Props,
	}
}

func (s *ClusterAPI) getClient() ssh.Client {
	// k8s runs all kubectl commands locally
	return &pc.LocalClient{}
}

func (s *ClusterAPI) Init(accessVars map[string]string, properties *infracommon.InfraProperties, commonPf *infracommon.CommonPlatform, caches *platform.Caches) error {
	s.accessVars = accessVars
	s.properties = properties
	s.namespace, _ = properties.GetValue(ManagementNamespace)
	s.infra, _ = properties.GetValue(InfrastructureProvider)
	// validate infra
	if s.namespace == "" {
		return fmt.Errorf("missing required property %s", ManagementNamespace)
	}
	if s.infra != "metal3" {
		return fmt.Errorf("infra %s not supported, only metal3 is supported", s.infra)
	}
	s.cloudletKey = *commonPf.PlatformConfig.CloudletKey
	s.accessApi = commonPf.PlatformConfig.AccessApi
	s.caches = caches
	return nil
}

const KconfPerms fs.FileMode = 0644

// This is the kubeconfig that points to the Cluster API management cluster.
func (s *ClusterAPI) ensureCAPIKubeconfig(ctx context.Context, client ssh.Client) (*k8smgmt.KconfNames, error) {
	data := s.accessVars[cloudcommon.Kubeconfig]
	kconfNames := k8smgmt.GetCloudletKConfNames(&s.cloudletKey)
	kconfName := kconfNames.KconfName
	err := k8smgmt.EnsureKubeconfig(ctx, client, kconfName, []byte(data))
	if err != nil {
		return nil, fmt.Errorf("failed to ensure capi management cluster kubeconfig, %s", err)
	}
	return kconfNames, nil
}

func (s *ClusterAPI) ensureClusterCtl(ctx context.Context, client ssh.Client) (string, error) {
	cmd := "which clusterctl"
	out, err := client.Output(cmd)
	if err == nil {
		return strings.TrimSpace(out), nil
	}
	cmd = fmt.Sprintf("curl -L https://github.com/kubernetes-sigs/cluster-api/releases/download/%s/clusterctl-linux-amd64 -o clusterctl", ClusterAPIVersion)
	log.SpanLog(ctx, log.DebugLevelInfra, "installing clusterctl", "cmd", cmd)
	out, err = client.Output(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to download clusterctl, %s: %s, %s", cmd, out, err)
	}
	cmd = "install -o root -g root -m 0755 clusterctl /usr/bin/clusterctl"
	out, err = client.Output(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to install clusterctl, %s: %s, %s", cmd, out, err)
	}
	return "/usr/bin/clusterctl", nil
}

func (s *ClusterAPI) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo")

	client := s.getClient()
	names, err := s.ensureCAPIKubeconfig(ctx, client)
	if err != nil {
		return err
	}
	namespace, _ := s.properties.GetValue(ManagementNamespace)

	// verify infra provider, as part of Create Cloudlet
	providers, err := s.getProviders(ctx, names)
	if err != nil {
		return err
	}
	infraProviderFound := false
	for _, provider := range providers {
		if provider.Type == string(clusterctl.InfrastructureProviderType) && provider.ProviderName == s.infra {
			infraProviderFound = true
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "found cluster api provider", "name", provider.ProviderName, "type", provider.Type)
	}
	if !infraProviderFound {
		return fmt.Errorf("infra provider %s not found in Cluster API management cluster", s.infra)
	}

	// gather hardware resources from
	flavorData, err := metal3.UpdateBareMetalHostFlavors(ctx, client, names, namespace)
	if err != nil {
		return err
	}
	info.Flavors = flavorData.Flavors
	// TODO: metal3 machine templates use HostSelector labels to determine
	// which hosts to use. Therefore resources on a BareMetalHost must be
	// converted to labels, which can then be set on the Metal3MachineTemplate
	// during cluster create to limit which hosts the cluster API will use.

	// set total resource limits based on sum of all nodes
	info.OsMaxVcores = flavorData.Vcpus.Whole
	info.OsMaxRam = flavorData.Ram.Whole
	info.OsMaxVolGb = flavorData.Disk.Whole
	return err
}

func (s *ClusterAPI) GetClusterClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *ClusterAPI) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *ClusterAPI) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *ClusterAPI) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

func (s *ClusterAPI) Login(ctx context.Context) error {
	return nil
}

func (s *ClusterAPI) NameSanitize(name string) string {
	return name
}

func (s *ClusterAPI) getProviders(ctx context.Context, capiNames *k8smgmt.KconfNames) ([]clusterctl.Provider, error) {
	providers := clusterctl.ProviderList{}
	cmd := fmt.Sprintf("kubectl %s get providers.clusterctl.cluster.x-k8s.io -A -o json", capiNames.KconfArg)
	log.SpanLog(ctx, log.DebugLevelInfra, "CAPI get providers", "cmd", cmd)
	out, err := s.getClient().Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("CAPI get providers failed, %s, %s, %s", cmd, out, err)
	}
	err = json.Unmarshal([]byte(out), &providers)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal provider data, %s", err)
	}
	return providers.Items, nil
}

func (s *ClusterAPI) GetBareMetalHosts(ctx context.Context) ([]*edgeproto.BareMetalHost, error) {
	client := s.getClient()
	names, err := s.ensureCAPIKubeconfig(ctx, client)
	if err != nil {
		return nil, err
	}
	hosts, err := metal3.GetBareMetalHosts(ctx, client, names, s.namespace, "")
	if err != nil {
		return nil, err
	}
	out := []*edgeproto.BareMetalHost{}
	for _, host := range hosts {
		h := metal3.ConvertUp(ctx, &host, &s.cloudletKey)
		out = append(out, h)
	}
	return out, nil
}
