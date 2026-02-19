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

package clusterapi

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

const ManagementNamespace = "ManagementNamespace"
const InfrastructureProvider = "InfrastructureProvider"
const FloatingVIPsSubnet = "FloatingVIPsSubnet"
const FloatingControlVIPsSubnet = "FloatingControlVIPsSubnet"
const ImageURL = "ImageURL"
const ImageFormat = "ImageFormat"
const ImageChecksum = "ImageChecksum"
const ImageChecksumType = "ImageChecksumType"
const ConsolePassword = "ConsolePassword"
const KubeletFeatureGates = "FeatureGates"

var AccessVarProps = map[string]*edgeproto.PropertyInfo{
	cloudcommon.Kubeconfig: {
		Name:        "Kubernetes cluster config file data",
		Description: "Contents of Kubernetes cluster config file used with kubectl to access the cluster running the Cluster API operator and provider metal3 operator, may be scoped to the namespace that contains the BareMetalHosts",
		Mandatory:   true,
	},
	ConsolePassword: {
		Name:        "Console Password",
		Description: "Password for console access to the bare metal machine once provisioned",
	},
}

var Props = map[string]*edgeproto.PropertyInfo{
	ManagementNamespace: {
		Name:        "Management Namespace",
		Description: "Kubernetes namespace where the Infrastructure provider's bare metal machines are defined and where the Cluster API clusters will be created",
		Value:       "",
		Mandatory:   true,
	},
	InfrastructureProvider: {
		Name:        "Infrastructure Provider",
		Description: "The infrastructure provider that is installed, see https://cluster-api.sigs.k8s.io/reference/providers#infrastructure, defaults to metal3",
		Value:       "metal3",
	},
	cloudcommon.FloatingVIPs: {
		Name:        "Floating VIPs",
		Description: "List of available virtual IPs, one is required per workload cluster. Format is a comma separated list of a mix of single IPs or startIP-endIP ranges, i.e. \"192.168.0.150-192.168.0.200\"",
		Value:       "",
		Mandatory:   true,
	},
	FloatingVIPsSubnet: {
		Name:        "Floating VIPs Subnet",
		Description: "Subnet for the Floating VIPs, i.e. 32 or 24",
		Value:       "",
		Mandatory:   true,
	},
	cloudcommon.FloatingControlVIPs: {
		Name:        "Floating Control Plane VIPs",
		Description: "List of available virtual IPs for control plane assignment. If not specified, IPs are taken from the Floating VIPs pool. Format is a comma separated list of a mix of single IPs or startIP-endIP ranges, i.e. \"192.168.0.150-192.168.0.200\"",
		Value:       "",
		Mandatory:   true,
	},
	FloatingControlVIPsSubnet: {
		Name:        "Floating Control Plane VIPs Subnet",
		Description: "Subnet for the Floating control plane VIPs, i.e. 32 or 24",
		Value:       "",
		Mandatory:   true,
	},
	ImageURL: {
		Name:        "Image URL",
		Description: "URL to download the OS image for the bare metal nodes, this should point to an image server reachable by the BMC of the bare metal nodes",
		Value:       "",
		Mandatory:   true,
	},
	ImageChecksum: {
		Name:        "Image Checksum",
		Description: "Checksum of the OS image",
		Value:       "",
		Mandatory:   true,
	},
	ImageChecksumType: {
		Name:        "Image Checksum Type",
		Description: "Type of checksum for the OS image, e.g. sha256, sha512; defaults to sha256",
		Value:       "sha256",
		Mandatory:   false,
	},
	ImageFormat: {
		Name:        "Image Format",
		Description: "Format of the OS image, e.g. qcow2, raw; defaults to qcow2",
		Value:       "qcow2",
		Mandatory:   false,
	},
	KubeletFeatureGates: {
		Name:        "Kubelet Feature Gates",
		Description: "List of Kubelet feature gates, format is a comma separated list of feature=value pairs, e.g. \"KubeletCrashLoopBackOffMax=true,KubeletEnsureSecretPulledImages=true\"",
	},
}

func (s *ClusterAPI) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {
	accessVars, err := accessApi.GetCloudletAccessVars(ctx)
	if err != nil {
		return err
	}
	s.accessVars = accessVars
	return nil
}
