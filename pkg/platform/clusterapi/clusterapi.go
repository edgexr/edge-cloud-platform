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
	"sort"

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
		KubernetesRequiresWorkerNodes: true,
		IpAllocatedPerService:         true,
		RequiresCrmOffEdge:            true,
		UsesIngress:                   true,
		ResourceQuotaProperties:       cloudcommon.CommonResourceQuotaProps,
		AccessVars:                    AccessVarProps,
		Properties:                    Props,
	}
}

func (s *ClusterAPI) getClient() ssh.Client {
	// k8s runs all kubectl commands locally
	return &pc.LocalClient{}
}

func (s *ClusterAPI) Init(accessVars map[string]string, properties *infracommon.InfraProperties, commonPf *infracommon.CommonPlatform) error {
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

	// XXX Treat BareMetalHosts as flavors?
	hosts, err := metal3.GetBareMetalHosts(ctx, client, names, namespace)
	if err != nil {
		return err
	}
	// gather hardware resources from baremetalhosts.
	// TODO: we need a way to add a limited count of flavors available
	// for resource management.
	vcpus := edgeproto.Udec64{}
	ram := edgeproto.Udec64{}
	disk := edgeproto.Udec64{}
	flavors := map[string]*edgeproto.FlavorInfo{}
	for _, host := range hosts {
		if host.Status.HardwareDetails != nil {
			hw := host.Status.HardwareDetails
			vcpus.AddUint64(uint64(hw.CPU.Count))
			ram.AddUint64(uint64(hw.RAMMebibytes))
			diskTotalGb := uint64(0)
			for _, st := range hw.Storage {
				diskTotalGb += uint64(st.SizeBytes / 1024 / 1024 / 1024)
			}
			// We require that the operator adds GPU labels to the
			// BareMetalHosts when they are creating them. These labels
			// should follow the standard labels that an Nvidia/AMD GPU
			// operator would apply to kubernetes nodes. This will be
			// used for resource tracking and allocation.
			gpus, _, err := k8smgmt.GetNodeGPUInfo(host.Labels)
			if err != nil {
				return fmt.Errorf("failed to get GPU info from labels on bare metal host %s, %s", host.Name, err)
			}
			// generate flavor for the node
			flavor := edgeproto.FlavorInfo{
				Vcpus: uint64(hw.CPU.Count),
				Ram:   uint64(hw.RAMMebibytes),
				Disk:  diskTotalGb,
				Gpus:  gpus,
			}
			flavor.Name = flavor.ResBasedName()
			if _, found := flavors[flavor.Name]; !found {
				flavors[flavor.Name] = &flavor
			}
		}
	}
	for _, flavor := range flavors {
		info.Flavors = append(info.Flavors, flavor)
	}
	sort.Slice(info.Flavors, func(i, j int) bool {
		fi := info.Flavors[i]
		fj := info.Flavors[j]
		if fi.Vcpus == fj.Vcpus {
			return fi.Ram < fj.Ram
		}
		return fi.Vcpus < fj.Vcpus
	})
	// TODO: metal3 machine templates use HostSelector labels to determine
	// which hosts to use. Therefore resources on a BareMetalHost must be
	// converted to labels, which can then be set on the Metal3MachineTemplate
	// during cluster create to limit which hosts the cluster API will use.

	// set total resource limits based on sum of all nodes
	info.OsMaxVcores = vcpus.Whole
	info.OsMaxRam = ram.Whole
	info.OsMaxVolGb = disk.Whole
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
