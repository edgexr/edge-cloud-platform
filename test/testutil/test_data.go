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

package testutil

import (
	fmt "fmt"
	"strings"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/gogo/protobuf/types"
)

func FlavorData() []edgeproto.Flavor {
	return []edgeproto.Flavor{{
		Key: edgeproto.FlavorKey{
			Name: "x1.tiny",
		},
		Ram:   1024,
		Vcpus: 1,
		Disk:  1,
	}, {
		Key: edgeproto.FlavorKey{
			Name: "x1.small",
		},
		Ram:   2048,
		Vcpus: 2,
		Disk:  2,
	}, {
		Key: edgeproto.FlavorKey{
			Name: "x1.medium",
		},
		Ram:   4096,
		Vcpus: 4,
		Disk:  4,
	}, {
		Key: edgeproto.FlavorKey{
			Name: "x1.large",
		},
		Ram:   8192,
		Vcpus: 10,
		Disk:  40,
	}, {
		Key: edgeproto.FlavorKey{
			Name: "x1.tiny.gpu",
		},
		Ram:   1024,
		Vcpus: 1,
		Disk:  1,
		OptResMap: map[string]string{
			"gpu": "pci:1",
		},
	}, {
		Key: edgeproto.FlavorKey{
			Name: "x1.small.vgpu",
		},
		Ram:   2048,
		Vcpus: 2,
		Disk:  2,
		OptResMap: map[string]string{
			"gpu": "vgpu:1",
		},
	}}
}

func DevData() []string {
	return []string{
		"AtlanticInc",
		"Eaiever",
		"Untomt",
		"MakerLLC",
	}
}

func ClusterKeys() []edgeproto.ClusterKey {
	return []edgeproto.ClusterKey{{
		Name: "Pillimos",
	}, {
		Name: "Ever.Ai",
	}, {
		Name: "Untomt",
	}, {
		Name: "Big-Pillimos",
	}, {
		Name: "Reservable",
	}, {
		Name: cloudcommon.DefaultMultiTenantCluster,
	}, {
		Name: "dockerCluster",
	}}
}

func AppData() []edgeproto.App {
	devData := DevData()
	flavorData := FlavorData()
	autoProvPolicyData := AutoProvPolicyData()
	return []edgeproto.App{{ // 0
		Key: edgeproto.AppKey{
			Organization: devData[0],
			Name:         "Pillimo Go!",
			Version:      "1.0.0",
		},
		ImageType:       edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessPorts:     "tcp:443,tcp:10002,udp:10002",
		AccessType:      edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor:   flavorData[0].Key,
		AllowServerless: true,
		ServerlessConfig: &edgeproto.ServerlessConfig{
			Vcpus: *edgeproto.NewUdec64(0, 500*edgeproto.DecMillis),
			Ram:   20,
		},
		Trusted: true, // This is a Trusted App.
	}, { // edgeproto.App // 1
		Key: edgeproto.AppKey{
			Organization: devData[0],
			Name:         "Pillimo Go!",
			Version:      "1.0.1",
		},
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessPorts:   "tcp:80,tcp:443,tcp:81:tls",
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[0].Key,
	}, { // edgeproto.App // 2
		Key: edgeproto.AppKey{
			Organization: devData[0],
			Name:         "Hunna Stoll Go! Go!",
			Version:      "0.0.1",
		},
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessPorts:   "tcp:443,udp:11111",
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[1].Key,
	}, { // edgeproto.App // 3
		Key: edgeproto.AppKey{
			Organization: devData[1],
			Name:         "AI",
			Version:      "1.2.0",
		},
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_QCOW,
		ImagePath:     "http://somerepo/image/path/ai/1.2.0#md5:7e9cfcb763e83573a4b9d9315f56cc5f",
		AccessPorts:   "tcp:8080",
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[1].Key,
	}, { // edgeproto.App // 4
		Key: edgeproto.AppKey{
			Organization: devData[2],
			Name:         "my reality",
			Version:      "0.0.1",
		},
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_QCOW,
		ImagePath:     "http://somerepo/image/path/myreality/0.0.1#md5:7e9cfcb763e83573a4b9d9315f56cc5f",
		AccessPorts:   "udp:1024",
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[2].Key,
	}, { // edgeproto.App // 5
		Key: edgeproto.AppKey{
			Organization: devData[3],
			Name:         "helmApp",
			Version:      "0.0.1",
		},
		Deployment:    "helm",
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_HELM,
		AccessPorts:   "udp:2024",
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[2].Key,
	}, { // edgeproto.App // 6
		Key: edgeproto.AppKey{
			Organization: devData[0],
			Name:         "Nelon",
			Version:      "0.0.2",
		},
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessPorts:   "tcp:80,udp:8001,tcp:065535",
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[1].Key,
	}, { // edgeproto.App // 7
		Key: edgeproto.AppKey{
			Organization: devData[0],
			Name:         "NoPorts",
			Version:      "1.0.0",
		},
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[0].Key,
	}, { // edgeproto.App // 8
		Key: edgeproto.AppKey{
			Organization: devData[0],
			Name:         "PortRangeApp",
			Version:      "1.0.0",
		},
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessPorts:   "tcp:80,tcp:443,udp:10002,tcp:5000-5002", // new port range notation
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[0].Key,
	}, { // edgeproto.App // 9
		Key: edgeproto.AppKey{
			Organization: edgeproto.OrganizationEdgeCloud,
			Name:         "AutoDeleteApp",
			Version:      "1.0.0",
		},
		ImageType:       edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessType:      edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor:   flavorData[0].Key,
		DelOpt:          edgeproto.DeleteType_AUTO_DELETE,
		AllowServerless: true,
		ServerlessConfig: &edgeproto.ServerlessConfig{
			Vcpus: *edgeproto.NewUdec64(0, 200*edgeproto.DecMillis),
			Ram:   10,
		},
		InternalPorts: true,
	}, { // edgeproto.App // 10
		Key: edgeproto.AppKey{
			Organization: devData[1],
			Name:         "Dev1App",
			Version:      "0.0.1",
		},
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessPorts:   "tcp:443,udp:11111",
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[1].Key,
	}, { // edgeproto.App // 11
		Key: edgeproto.AppKey{
			Organization: devData[0],
			Name:         "Pillimo Go!",
			Version:      "1.0.2",
		},
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessPorts:   "tcp:10003",
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[0].Key,
		AutoProvPolicies: []string{
			autoProvPolicyData[0].Key.Name,
			autoProvPolicyData[3].Key.Name,
		},
	}, { // edgeproto.App // 12
		Key: edgeproto.AppKey{
			Organization: devData[0],
			Name:         "vm lb",
			Version:      "1.0.2",
		},
		Deployment:    "vm",
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_QCOW,
		ImagePath:     "http://somerepo/image/path/myreality/0.0.1#md5:7e9cfcb763e83573a4b9d9315f56cc5f",
		AccessPorts:   "tcp:10003",
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[0].Key,
	}, { // edgeproto.App // 13 - EdgeCloud app
		Key: edgeproto.AppKey{
			Organization: edgeproto.OrganizationEdgeCloud,
			Name:         "SampleApp",
			Version:      "1.0.0",
		},
		ImageType:       edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessType:      edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		AccessPorts:     "tcp:889",
		DefaultFlavor:   flavorData[0].Key,
		AllowServerless: true,
		ServerlessConfig: &edgeproto.ServerlessConfig{
			Vcpus: *edgeproto.NewUdec64(0, 500*edgeproto.DecMillis),
			Ram:   20,
		},
	}, { // edgeproto.App // 14
		Key: edgeproto.AppKey{
			Organization: devData[0],
			Name:         "Pillimo MT",
			Version:      "1.0.0",
		},
		ImageType:       edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessPorts:     "tcp:444",
		AccessType:      edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor:   flavorData[0].Key,
		AllowServerless: true,
		ServerlessConfig: &edgeproto.ServerlessConfig{
			Vcpus: *edgeproto.NewUdec64(0, 500*edgeproto.DecMillis),
			Ram:   20,
		},
	}, { // edgeproto.App // 15
		Key: edgeproto.AppKey{
			Organization: devData[0],
			Name:         "Pillimo Docker!",
			Version:      "1.0.1",
		},
		Deployment:    cloudcommon.DeploymentTypeDocker,
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessPorts:   "tcp:80,tcp:443,tcp:81:tls",
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[0].Key,
	}, { // edgeproto.App // 16
		Key: edgeproto.AppKey{
			Organization: devData[0],
			Name:         "Custom-k8s",
			Version:      "1.0",
		},
		Deployment:    cloudcommon.DeploymentTypeKubernetes,
		ImageType:     edgeproto.ImageType_IMAGE_TYPE_DOCKER,
		AccessPorts:   "tcp:80,tcp:443,tcp:81:tls",
		AccessType:    edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		DefaultFlavor: flavorData[0].Key,
	}}
}

func OperatorData() []string {
	return []string{
		"UFGT Inc.",
		"xmobx",
		"Zerilu",
		"Denton telecom",
	}
}

func OperatorCodeData() []edgeproto.OperatorCode {
	return []edgeproto.OperatorCode{{
		Code:         "31170",
		Organization: "UFGT Inc.",
	}, {
		Code:         "31026",
		Organization: "xmobx",
	}, {
		Code:         "310110",
		Organization: "Zerilu",
	}, {
		Code:         "2621",
		Organization: "Denton telecom",
	}}
}

func CloudletData() []edgeproto.Cloudlet {
	flavorData := FlavorData()
	operatorData := OperatorData()
	restblkeys := Restblkeys()
	gpuDriverData := GPUDriverData()
	return []edgeproto.Cloudlet{{
		Key: edgeproto.CloudletKey{
			Organization: operatorData[0],
			Name:         "San Jose Site",
		},
		IpSupport:     edgeproto.IpSupport_IP_SUPPORT_DYNAMIC,
		NumDynamicIps: 100,
		Location: dme.Loc{
			Latitude:  37.338207,
			Longitude: -121.886330,
		},
		PlatformType:                  edgeproto.PlatformType_PLATFORM_TYPE_FAKE,
		Flavor:                        flavorData[0].Key,
		NotifySrvAddr:                 "127.0.0.1:51001",
		CrmOverride:                   edgeproto.CRMOverride_IGNORE_CRM,
		PhysicalName:                  "SanJoseSite",
		Deployment:                    "docker",
		DefaultResourceAlertThreshold: 80,
		ResourceQuotas: []edgeproto.ResourceQuota{{
			Name:           "GPUs",
			Value:          10,
			AlertThreshold: 10,
		}, {
			Name:           "RAM",
			AlertThreshold: 30,
		}, {
			Name:           "vCPUs",
			Value:          99,
			AlertThreshold: 20,
		}},
		ResTagMap: map[string]*edgeproto.ResTagTableKey{
			"gpu": &restblkeys[3],
		},
		GpuConfig: edgeproto.GPUConfig{
			Driver: gpuDriverData[0].Key,
		},
	}, { // edgeproto.Cloudlet
		Key: edgeproto.CloudletKey{
			Organization: operatorData[0],
			Name:         "New York Site",
		},
		IpSupport:     edgeproto.IpSupport_IP_SUPPORT_DYNAMIC,
		NumDynamicIps: 100,
		Location: dme.Loc{
			Latitude:  40.712776,
			Longitude: -74.005974,
		},
		PlatformType:                  edgeproto.PlatformType_PLATFORM_TYPE_FAKE,
		Flavor:                        flavorData[0].Key,
		NotifySrvAddr:                 "127.0.0.1:51002",
		CrmOverride:                   edgeproto.CRMOverride_IGNORE_CRM,
		PhysicalName:                  "NewYorkSite",
		Deployment:                    "docker",
		DefaultResourceAlertThreshold: 80,
	}, { // edgeproto.Cloudlet
		Key: edgeproto.CloudletKey{
			Organization: operatorData[1],
			Name:         "San Francisco Site",
		},
		IpSupport:     edgeproto.IpSupport_IP_SUPPORT_DYNAMIC,
		NumDynamicIps: 100,
		Location: dme.Loc{
			Latitude:  37.774929,
			Longitude: -122.419418,
		},
		Flavor:         flavorData[0].Key,
		PlatformType:   edgeproto.PlatformType_PLATFORM_TYPE_FAKE,
		NotifySrvAddr:  "127.0.0.1:51003",
		InfraApiAccess: edgeproto.InfraApiAccess_RESTRICTED_ACCESS,
		InfraConfig: edgeproto.InfraConfig{
			FlavorName:          flavorData[0].Key.Name,
			ExternalNetworkName: "testnet",
		},
		// CrmOverride not needed because of RestrictedAccess
		PhysicalName:                  "SanFranciscoSite",
		Deployment:                    "docker",
		DefaultResourceAlertThreshold: 80,
	}, { // edgeproto.Cloudlet
		Key: edgeproto.CloudletKey{
			Organization: operatorData[2],
			Name:         "Hawaii Site",
		},
		IpSupport:     edgeproto.IpSupport_IP_SUPPORT_DYNAMIC,
		NumDynamicIps: 10,
		Location: dme.Loc{
			Latitude:  21.306944,
			Longitude: -157.858337,
		},
		Flavor:                        flavorData[0].Key,
		PlatformType:                  edgeproto.PlatformType_PLATFORM_TYPE_FAKE,
		NotifySrvAddr:                 "127.0.0.1:51004",
		CrmOverride:                   edgeproto.CRMOverride_IGNORE_CRM,
		PhysicalName:                  "HawaiiSite",
		Deployment:                    "docker",
		DefaultResourceAlertThreshold: 80,
	}}
}

func ClusterInstData() []edgeproto.ClusterInst {
	devData := DevData()
	flavorData := FlavorData()
	clusterKeys := ClusterKeys()
	cloudletData := CloudletData()
	autoScalePolicyData := AutoScalePolicyData()
	return []edgeproto.ClusterInst{{ // 0
		Key: edgeproto.ClusterInstKey{
			ClusterKey:   clusterKeys[0],
			CloudletKey:  cloudletData[0].Key,
			Organization: devData[0],
		},
		Flavor:     flavorData[0].Key,
		IpAccess:   edgeproto.IpAccess_IP_ACCESS_DEDICATED,
		NumMasters: 1,
		NumNodes:   2,
	}, { // edgeproto.ClusterInst // 1
		Key: edgeproto.ClusterInstKey{
			ClusterKey:   clusterKeys[0],
			CloudletKey:  cloudletData[1].Key,
			Organization: devData[0],
		},
		Flavor:     flavorData[0].Key,
		IpAccess:   edgeproto.IpAccess_IP_ACCESS_SHARED,
		NumMasters: 1,
		NumNodes:   2,
	}, { // edgeproto.ClusterInst // 2
		Key: edgeproto.ClusterInstKey{
			ClusterKey:   clusterKeys[0],
			CloudletKey:  cloudletData[2].Key,
			Organization: devData[3],
		},
		Flavor:          flavorData[0].Key,
		NumMasters:      1,
		NumNodes:        2,
		AutoScalePolicy: autoScalePolicyData[2].Key.Name,
	}, { // edgeproto.ClusterInst // 3
		Key: edgeproto.ClusterInstKey{
			ClusterKey:   clusterKeys[1],
			CloudletKey:  cloudletData[0].Key,
			Organization: devData[0],
		},
		Flavor:          flavorData[1].Key,
		IpAccess:        edgeproto.IpAccess_IP_ACCESS_DEDICATED,
		NumMasters:      1,
		NumNodes:        3,
		AutoScalePolicy: autoScalePolicyData[0].Key.Name,
	}, { // edgeproto.ClusterInst // 4
		Key: edgeproto.ClusterInstKey{
			ClusterKey:   clusterKeys[1],
			CloudletKey:  cloudletData[1].Key,
			Organization: devData[3],
		},
		Flavor:     flavorData[1].Key,
		IpAccess:   edgeproto.IpAccess_IP_ACCESS_SHARED,
		NumMasters: 1,
		NumNodes:   3,
	}, { // edgeproto.ClusterInst // 5
		Key: edgeproto.ClusterInstKey{
			ClusterKey:   clusterKeys[2],
			CloudletKey:  cloudletData[2].Key,
			Organization: devData[3],
		},
		Flavor:     flavorData[2].Key,
		IpAccess:   edgeproto.IpAccess_IP_ACCESS_DEDICATED,
		NumMasters: 1,
		NumNodes:   4,
	}, { // edgeproto.ClusterInst // 6
		Key: edgeproto.ClusterInstKey{
			ClusterKey:   clusterKeys[3],
			CloudletKey:  cloudletData[3].Key,
			Organization: devData[3],
		},
		Flavor:     flavorData[2].Key,
		NumMasters: 1,
		NumNodes:   3,
	}, { // edgeproto.ClusterInst // 7
		Key: edgeproto.ClusterInstKey{
			ClusterKey:   clusterKeys[4],
			CloudletKey:  cloudletData[0].Key,
			Organization: edgeproto.OrganizationEdgeCloud,
		},
		Flavor:     flavorData[0].Key,
		IpAccess:   edgeproto.IpAccess_IP_ACCESS_SHARED,
		NumMasters: 1,
		NumNodes:   2,
		Reservable: true,
	}, { // edgeproto.ClusterInst // 8
		Key: edgeproto.ClusterInstKey{
			ClusterKey:   clusterKeys[5], // multi-tenant cluster
			CloudletKey:  cloudletData[0].Key,
			Organization: edgeproto.OrganizationEdgeCloud,
		},
		Flavor:           flavorData[0].Key,
		IpAccess:         edgeproto.IpAccess_IP_ACCESS_SHARED,
		NumMasters:       1,
		NumNodes:         5,
		MasterNodeFlavor: flavorData[2].Key.Name, // medium
		MultiTenant:      true,
	}, { // edgeproto.ClusterInst // 9
		Key: edgeproto.ClusterInstKey{
			ClusterKey:   clusterKeys[6],
			CloudletKey:  cloudletData[1].Key,
			Organization: devData[0],
		},
		Deployment: cloudcommon.DeploymentTypeDocker,
		Flavor:     flavorData[0].Key,
		IpAccess:   edgeproto.IpAccess_IP_ACCESS_DEDICATED,
	}}
}

// These are the cluster insts that will be created automatically
// from appinsts that have not specified a cluster.
func ClusterInstAutoData() []edgeproto.ClusterInst {
	devData := DevData()
	flavorData := FlavorData()
	cloudletData := CloudletData()
	return []edgeproto.ClusterInst{{
		// from AppInstData[3] -> AppData[1]
		Key: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: "reservable0",
			},
			CloudletKey:  cloudletData[1].Key,
			Organization: edgeproto.OrganizationEdgeCloud,
		},
		Flavor:     flavorData[0].Key,
		NumMasters: 1,
		NumNodes:   1,
		State:      edgeproto.TrackedState_READY,
		Auto:       true,
		Reservable: true,
		ReservedBy: devData[0],
	}, { // edgeproto.ClusterInst
		// from AppInstData[4] -> AppData[2]
		Key: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: "reservable0",
			},
			CloudletKey:  cloudletData[2].Key,
			Organization: edgeproto.OrganizationEdgeCloud,
		},
		Flavor:     flavorData[1].Key,
		NumMasters: 1,
		NumNodes:   1,
		State:      edgeproto.TrackedState_READY,
		Auto:       true,
		Reservable: true,
		ReservedBy: devData[0],
	}, { // edgeproto.ClusterInst
		// from AppInstData[6] -> AppData[6]
		Key: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: "reservable1",
			},
			CloudletKey:  cloudletData[2].Key,
			Organization: edgeproto.OrganizationEdgeCloud,
		},
		Flavor:     flavorData[1].Key,
		NumMasters: 1,
		NumNodes:   1,
		State:      edgeproto.TrackedState_READY,
		Auto:       true,
		Reservable: true,
		ReservedBy: devData[0],
	}, { // edgeproto.ClusterInst
		// from AppInstData[12] -> AppData[13]
		Key: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: "reservable0",
			},
			CloudletKey:  cloudletData[3].Key,
			Organization: edgeproto.OrganizationEdgeCloud,
		},
		Flavor:     flavorData[0].Key,
		NumMasters: 1,
		NumNodes:   1,
		State:      edgeproto.TrackedState_READY,
		Auto:       true,
		Reservable: true,
		ReservedBy: edgeproto.OrganizationEdgeCloud,
	}}
}

func AppInstData() []edgeproto.AppInst {
	cloudletData := CloudletData()
	appData := AppData()
	clusterInstData := ClusterInstData()
	clusterInstAutoData := ClusterInstAutoData()
	return []edgeproto.AppInst{{ // 0
		Key: edgeproto.AppInstKey{
			AppKey:         appData[0].Key,
			ClusterInstKey: *clusterInstData[0].Key.Virtual(""),
		},
		CloudletLoc: cloudletData[0].Location,
	}, { // edgeproto.AppInst // 1
		Key: edgeproto.AppInstKey{
			AppKey:         appData[0].Key,
			ClusterInstKey: *clusterInstData[3].Key.Virtual(""),
		},
		CloudletLoc: cloudletData[0].Location,
	}, { // edgeproto.AppInst // 2
		Key: edgeproto.AppInstKey{
			AppKey:         appData[0].Key,
			ClusterInstKey: *clusterInstData[1].Key.Virtual(""),
		},
		CloudletLoc: cloudletData[1].Location,
	}, { // edgeproto.AppInst // 3
		Key: edgeproto.AppInstKey{
			AppKey: appData[1].Key,
			// ClusterInst is ClusterInstAutoData[0]
			ClusterInstKey: *clusterInstAutoData[0].Key.Virtual(util.K8SSanitize("autocluster" + appData[1].Key.Name)),
		},
		CloudletLoc: cloudletData[1].Location,
	}, { // edgeproto.AppInst // 4
		Key: edgeproto.AppInstKey{
			AppKey: appData[2].Key,
			// ClusterInst is ClusterInstAutoData[1]
			ClusterInstKey: *clusterInstAutoData[1].Key.Virtual(util.K8SSanitize("autocluster" + appData[2].Key.Name)),
		},
		CloudletLoc: cloudletData[2].Location,
	}, { // edgeproto.AppInst // 5
		Key: edgeproto.AppInstKey{
			AppKey:         appData[5].Key,
			ClusterInstKey: *clusterInstData[2].Key.Virtual(""),
		},
		CloudletLoc: cloudletData[2].Location,
	}, { // edgeproto.AppInst // 6
		Key: edgeproto.AppInstKey{
			AppKey: appData[6].Key,
			// ClusterInst is ClusterInstAutoData[2]
			ClusterInstKey: *clusterInstAutoData[2].Key.Virtual(util.K8SSanitize("autocluster" + appData[6].Key.Name)),
		},
		CloudletLoc: cloudletData[2].Location,
	}, { // edgeproto.AppInst // 7
		Key: edgeproto.AppInstKey{
			AppKey:         appData[6].Key,
			ClusterInstKey: *clusterInstData[0].Key.Virtual(""),
		},
		CloudletLoc: cloudletData[0].Location,
	}, { // edgeproto.AppInst // 8
		Key: edgeproto.AppInstKey{
			AppKey:         appData[7].Key,
			ClusterInstKey: *clusterInstData[0].Key.Virtual(""),
		},
		CloudletLoc: cloudletData[0].Location,
	}, { // edgeproto.AppInst // 9
		Key: edgeproto.AppInstKey{
			AppKey:         appData[9].Key, //auto-delete app
			ClusterInstKey: *clusterInstData[0].Key.Virtual(""),
		},
		CloudletLoc: cloudletData[0].Location,
	}, { // edgeproto.AppInst // 10
		Key: edgeproto.AppInstKey{
			AppKey:         appData[9].Key, //auto-delete app
			ClusterInstKey: *clusterInstAutoData[0].Key.Virtual(""),
		},
		CloudletLoc:     cloudletData[1].Location,
		RealClusterName: clusterInstAutoData[0].Key.ClusterKey.Name,
	}, { // edgeproto.AppInst // 11
		Key: edgeproto.AppInstKey{
			AppKey: appData[12].Key, //vm app with lb
			ClusterInstKey: edgeproto.VirtualClusterInstKey{
				CloudletKey: cloudletData[0].Key,
			},
		},
		CloudletLoc: cloudletData[1].Location,
	}, { // edgeproto.AppInst // 12 - deploy EdgeCloud app to reservable autocluster
		Key: edgeproto.AppInstKey{
			AppKey:         appData[13].Key, // edgecloud sample app
			ClusterInstKey: *clusterInstAutoData[3].Key.Virtual(util.K8SSanitize("autocluster" + appData[13].Key.Name)),
		},
		CloudletLoc: cloudletData[3].Location,
	}, { // edgeproto.AppInst // 13
		Key: edgeproto.AppInstKey{
			AppKey:         appData[0].Key,
			ClusterInstKey: *clusterInstData[8].Key.Virtual("autocluster-mt1"),
		},
		CloudletLoc: cloudletData[0].Location,
	}, { // edgeproto.AppInst // 14
		Key: edgeproto.AppInstKey{
			AppKey:         appData[9].Key, // sidecar app
			ClusterInstKey: *clusterInstData[8].Key.Virtual(""),
		},
		CloudletLoc: cloudletData[0].Location,
	}, { // edgeproto.AppInst // 15
		Key: edgeproto.AppInstKey{
			AppKey:         appData[13].Key,
			ClusterInstKey: *clusterInstData[8].Key.Virtual("autocluster-mt3"),
		},
		CloudletLoc: cloudletData[0].Location,
	}, { // edgeproto.AppInst // 16
		Key: edgeproto.AppInstKey{
			AppKey:         appData[14].Key,
			ClusterInstKey: *clusterInstData[8].Key.Virtual("autocluster-mt2"),
		},
		CloudletLoc: cloudletData[0].Location,
	}, { // edgeproto.AppInst // 17
		Key: edgeproto.AppInstKey{
			AppKey:         appData[15].Key,
			ClusterInstKey: *clusterInstData[9].Key.Virtual(""),
		},
		CloudletLoc: cloudletData[0].Location,
	}}
}

func AppInstInfoData() []edgeproto.AppInstInfo {
	appInstData := AppInstData()
	return []edgeproto.AppInstInfo{{
		Key: appInstData[0].Key,
	}, {
		Key: appInstData[1].Key,
	}, {
		Key: appInstData[2].Key,
	}, {
		Key: appInstData[3].Key,
	}, {
		Key: appInstData[4].Key,
	}, {
		Key: appInstData[5].Key,
	}, {
		Key: appInstData[6].Key,
	}, {
		Key: appInstData[7].Key,
	}}
}

func GetAppInstRefsData() []edgeproto.AppInstRefs {
	createdAppInsts := CreatedAppInstData()
	appData := AppData()
	appInstData := AppInstData()
	return []edgeproto.AppInstRefs{{
		Key: appData[0].Key,
		Insts: map[string]uint32{
			appInstData[0].Key.GetKeyString():  1,
			appInstData[1].Key.GetKeyString():  1,
			appInstData[2].Key.GetKeyString():  1,
			appInstData[13].Key.GetKeyString(): 1,
		},
	}, { // edgeproto.AppInstRefs
		Key: appData[1].Key,
		Insts: map[string]uint32{
			appInstData[3].Key.GetKeyString(): 1,
		},
	}, { // edgeproto.AppInstRefs
		Key: appData[2].Key,
		Insts: map[string]uint32{
			appInstData[4].Key.GetKeyString(): 1,
		},
	}, { // edgeproto.AppInstRefs
		Key:   appData[3].Key,
		Insts: map[string]uint32{},
	}, { // edgeproto.AppInstRefs
		Key:   appData[4].Key,
		Insts: map[string]uint32{},
	}, { // edgeproto.AppInstRefs
		Key: appData[5].Key,
		Insts: map[string]uint32{
			appInstData[5].Key.GetKeyString(): 1,
		},
	}, { // edgeproto.AppInstRefs
		Key: appData[6].Key,
		Insts: map[string]uint32{
			appInstData[6].Key.GetKeyString(): 1,
			appInstData[7].Key.GetKeyString(): 1,
		},
	}, { // edgeproto.AppInstRefs
		Key: appData[7].Key,
		Insts: map[string]uint32{
			appInstData[8].Key.GetKeyString(): 1,
		},
	}, { // edgeproto.AppInstRefs
		Key:   appData[8].Key,
		Insts: map[string]uint32{},
	}, { // edgeproto.AppInstRefs
		Key: appData[9].Key,
		Insts: map[string]uint32{
			appInstData[9].Key.GetKeyString():  1,
			appInstData[10].Key.GetKeyString(): 1,
			appInstData[14].Key.GetKeyString(): 1,
		},
	}, { // edgeproto.AppInstRefs
		Key:   appData[10].Key,
		Insts: map[string]uint32{},
	}, { // edgeproto.AppInstRefs
		Key:   appData[11].Key,
		Insts: map[string]uint32{},
	}, { // edgeproto.AppInstRefs
		Key: appData[12].Key,
		Insts: map[string]uint32{
			createdAppInsts[11].Key.GetKeyString(): 1,
		},
	}, { // edgeproto.AppInstRefs
		Key: appData[13].Key,
		Insts: map[string]uint32{
			appInstData[12].Key.GetKeyString(): 1,
			appInstData[15].Key.GetKeyString(): 1,
		},
	}, { // edgeproto.AppInstRefs
		Key: appData[14].Key,
		Insts: map[string]uint32{
			appInstData[16].Key.GetKeyString(): 1,
		},
	}, { // edgeproto.AppInstRefs
		Key: appData[15].Key,
		Insts: map[string]uint32{
			appInstData[17].Key.GetKeyString(): 1,
		},
	}, { // edgeproto.AppInstRefs
		Key:   appData[16].Key,
		Insts: map[string]uint32{},
	}}
}

func CloudletInfoData() []edgeproto.CloudletInfo {
	cloudletData := CloudletData()
	return []edgeproto.CloudletInfo{{
		Key:         cloudletData[0].Key,
		State:       dme.CloudletState_CLOUDLET_STATE_READY,
		OsMaxRam:    65536,
		OsMaxVcores: 16,
		OsMaxVolGb:  500,
		Flavors: []*edgeproto.FlavorInfo{{
			Name:  "flavor.tiny1",
			Vcpus: uint64(1),
			Ram:   uint64(512),
			Disk:  uint64(10),
		}, {
			Name:  "flavor.tiny2",
			Vcpus: uint64(1),
			Ram:   uint64(1024),
			Disk:  uint64(10),
		}, {
			Name:  "flavor.small",
			Vcpus: uint64(2),
			Ram:   uint64(1024),
			Disk:  uint64(20),
		}, {
			Name:  "flavor.medium",
			Vcpus: uint64(4),
			Ram:   uint64(4096),
			Disk:  uint64(40),
		}, {
			Name:  "flavor.lg-master",
			Vcpus: uint64(4),
			Ram:   uint64(8192),
			Disk:  uint64(60),
		}, {
			// restagtbl/clouldlet resource map tests
			Name:    "flavor.large",
			Vcpus:   uint64(10),
			Ram:     uint64(8192),
			Disk:    uint64(40),
			PropMap: map[string]string{"pci_passthrough": "alias=t4:1"},
		}, {
			Name:    "flavor.large2",
			Vcpus:   uint64(10),
			Ram:     uint64(8192),
			Disk:    uint64(40),
			PropMap: map[string]string{"pci_passthrough": "alias=t4:1", "nas": "ceph-20:1"},
		}, {
			Name:    "flavor.large-pci",
			Vcpus:   uint64(10),
			Ram:     uint64(8192),
			Disk:    uint64(40),
			PropMap: map[string]string{"pci": "NP4:1"},
		}, {
			Name:    "flavor.large-nvidia",
			Vcpus:   uint64(10),
			Ram:     uint64(8192),
			Disk:    uint64(40),
			PropMap: map[string]string{"vgpu": "nvidia-63:1"},
		}, {
			Name:    "flavor.large-generic-gpu",
			Vcpus:   uint64(10),
			Ram:     uint64(8192),
			Disk:    uint64(80),
			PropMap: map[string]string{"vmware": "vgpu=1"},
		}, {
			// A typical case where two flavors are identical in their
			// nominal resources, and differ only by gpu vs vgpu
			// These cases require a fully qualifed request in the mex flavors optresmap
			Name:    "flavor.m4.large-gpu",
			Vcpus:   uint64(12),
			Ram:     uint64(4096),
			Disk:    uint64(20),
			PropMap: map[string]string{"pci_passthrough": "alias=t4gpu:1"},
		}, {
			Name:    "flavor.m4.large-vgpu",
			Vcpus:   uint64(12),
			Ram:     uint64(4096),
			Disk:    uint64(20),
			PropMap: map[string]string{"resources": "VGPU=1"},
		}},
		ResourcesSnapshot: edgeproto.InfraResourcesSnapshot{
			Info: []edgeproto.InfraResource{{
				Name:          "RAM",
				Value:         uint64(1024),
				InfraMaxValue: uint64(102400),
			}, {
				Name:          "vCPUs",
				Value:         uint64(10),
				InfraMaxValue: uint64(109),
			}, {
				Name:          "Disk",
				Value:         uint64(20),
				InfraMaxValue: uint64(5000),
			}, {
				Name:          "GPUs",
				Value:         uint64(6),
				InfraMaxValue: uint64(20),
			}, {
				Name:          "External IPs",
				Value:         uint64(2),
				InfraMaxValue: uint64(10),
			}},
		},
		CompatibilityVersion: cloudcommon.GetCRMCompatibilityVersion(),
		Properties: map[string]string{
			"supports-mt": "true", // cloudcommon.CloudletSupportsMT
		},
	}, { // edgeproto.CloudletInfo
		Key:         cloudletData[1].Key,
		State:       dme.CloudletState_CLOUDLET_STATE_READY,
		OsMaxRam:    65536,
		OsMaxVcores: 16,
		OsMaxVolGb:  500,
		Flavors: []*edgeproto.FlavorInfo{{
			Name:  "flavor.small1",
			Vcpus: uint64(2),
			Ram:   uint64(2048),
			Disk:  uint64(10),
		}, {
			Name:  "flavor.small2",
			Vcpus: uint64(2),
			Ram:   uint64(1024),
			Disk:  uint64(20),
		}, {
			Name:  "flavor.medium1",
			Vcpus: uint64(2),
			Ram:   uint64(4096),
			Disk:  uint64(40),
		}},
		ResourcesSnapshot: edgeproto.InfraResourcesSnapshot{
			Info: []edgeproto.InfraResource{{
				Name:          "RAM",
				Value:         uint64(1024),
				InfraMaxValue: uint64(61440),
			}, {
				Name:          "vCPUs",
				Value:         uint64(10),
				InfraMaxValue: uint64(100),
			}, {
				Name:          "Disk",
				Value:         uint64(20),
				InfraMaxValue: uint64(5000),
			}, {
				Name:          "External IPs",
				Value:         uint64(2),
				InfraMaxValue: uint64(10),
			}},
		},
		CompatibilityVersion: cloudcommon.GetCRMCompatibilityVersion(),
	}, { // edgeproto.CloudletInfo
		Key:         cloudletData[2].Key,
		State:       dme.CloudletState_CLOUDLET_STATE_READY,
		OsMaxRam:    65536,
		OsMaxVcores: 16,
		OsMaxVolGb:  500,
		Flavors: []*edgeproto.FlavorInfo{{
			Name:  "flavor.medium1",
			Vcpus: uint64(4),
			Ram:   uint64(8192),
			Disk:  uint64(80),
		}, {
			Name:  "flavor.medium2",
			Vcpus: uint64(4),
			Ram:   uint64(4096),
			Disk:  uint64(40),
		}, {
			Name:  "flavor.medium3",
			Vcpus: uint64(4),
			Ram:   uint64(2048),
			Disk:  uint64(20),
		}},
		ResourcesSnapshot: edgeproto.InfraResourcesSnapshot{
			Info: []edgeproto.InfraResource{{
				Name:          "RAM",
				Value:         uint64(1024),
				InfraMaxValue: uint64(61440),
			}, {
				Name:          "vCPUs",
				Value:         uint64(10),
				InfraMaxValue: uint64(100),
			}, {
				Name:          "Disk",
				Value:         uint64(20),
				InfraMaxValue: uint64(5000),
			}, {
				Name:          "External IPs",
				Value:         uint64(2),
				InfraMaxValue: uint64(10),
			}},
		},
		CompatibilityVersion: cloudcommon.GetCRMCompatibilityVersion(),
	}, { // edgeproto.CloudletInfo
		Key:         cloudletData[3].Key,
		State:       dme.CloudletState_CLOUDLET_STATE_READY,
		OsMaxRam:    65536,
		OsMaxVcores: 16,
		OsMaxVolGb:  500,
		Flavors: []*edgeproto.FlavorInfo{{
			Name:  "flavor.large",
			Vcpus: uint64(8),
			Ram:   uint64(101024),
			Disk:  uint64(100),
		}, {
			Name:  "flavor.medium",
			Vcpus: uint64(4),
			Ram:   uint64(1),
			Disk:  uint64(1),
		}},
		ResourcesSnapshot: edgeproto.InfraResourcesSnapshot{
			Info: []edgeproto.InfraResource{{
				Name:          "RAM",
				Value:         uint64(1024),
				InfraMaxValue: uint64(1024000),
			}, {
				Name:          "vCPUs",
				Value:         uint64(10),
				InfraMaxValue: uint64(100),
			}, {
				Name:          "Disk",
				Value:         uint64(20),
				InfraMaxValue: uint64(5000),
			}, {
				Name:          "External IPs",
				Value:         uint64(2),
				InfraMaxValue: uint64(10),
			}},
		},
		CompatibilityVersion: cloudcommon.GetCRMCompatibilityVersion(),
	}}
}

// To figure out what resources are used on each Cloudlet,
// see ClusterInstData to see what clusters are instantiated on what Cloudlet.
func CloudletRefsData() []edgeproto.CloudletRefs {
	cloudletData := CloudletData()
	clusterInstData := ClusterInstData()
	return []edgeproto.CloudletRefs{{
		// ClusterInstData[0,3,7,8]:
		Key: cloudletData[0].Key,
		ClusterInsts: []edgeproto.ClusterInstRefKey{{
			ClusterKey:   clusterInstData[0].Key.ClusterKey,
			Organization: clusterInstData[0].Key.Organization,
		}, {
			ClusterKey:   clusterInstData[3].Key.ClusterKey,
			Organization: clusterInstData[3].Key.Organization,
		}, {
			ClusterKey:   clusterInstData[7].Key.ClusterKey,
			Organization: clusterInstData[7].Key.Organization,
		}, {
			ClusterKey:   clusterInstData[8].Key.ClusterKey,
			Organization: clusterInstData[8].Key.Organization,
		}},
		UsedDynamicIps: 2,
	}, { // edgeproto.CloudletRefs
		// ClusterInstData[1,4,9]:
		Key: cloudletData[1].Key,
		ClusterInsts: []edgeproto.ClusterInstRefKey{{
			ClusterKey:   clusterInstData[1].Key.ClusterKey,
			Organization: clusterInstData[1].Key.Organization,
		}, {
			ClusterKey:   clusterInstData[4].Key.ClusterKey,
			Organization: clusterInstData[4].Key.Organization,
		}, {
			ClusterKey:   clusterInstData[9].Key.ClusterKey,
			Organization: clusterInstData[9].Key.Organization,
		}},
		UsedDynamicIps: 1,
	}, { // edgeproto.CloudletRefs
		// ClusterInstData[2,5]:
		Key: cloudletData[2].Key,
		ClusterInsts: []edgeproto.ClusterInstRefKey{{
			ClusterKey:   clusterInstData[2].Key.ClusterKey,
			Organization: clusterInstData[2].Key.Organization,
		}, {
			ClusterKey:   clusterInstData[5].Key.ClusterKey,
			Organization: clusterInstData[5].Key.Organization,
		}},
		UsedDynamicIps: 1,
	}, { // edgeproto.CloudletRefs
		// ClusterInstData[6]:
		Key: cloudletData[3].Key,
		ClusterInsts: []edgeproto.ClusterInstRefKey{{
			ClusterKey:   clusterInstData[6].Key.ClusterKey,
			Organization: clusterInstData[6].Key.Organization,
		}},
	}}
}

// These Refs are after creating both cluster insts and app insts.
// Some of the app insts trigger creating auto-clusterinsts,
// and ports are reserved with the creation of app insts.
func CloudletRefsWithAppInstsData() []edgeproto.CloudletRefs {
	cloudletData := CloudletData()
	clusterInstData := ClusterInstData()
	clusterInstAutoData := ClusterInstAutoData()
	appInstData := AppInstData()
	return []edgeproto.CloudletRefs{{
		// ClusterInstData[0,3,7,8]: (dedicated,dedicated,shared,shared)
		// AppInstData[0,1] -> ports[tcp:443;tcp:443]:
		// AppInstData[13,14,15,16] -> App[0,9,13,14] -> ports[tcp:443,tcp:10002,udp:10002;;tcp:889;tcp:444]
		Key: cloudletData[0].Key,
		ClusterInsts: []edgeproto.ClusterInstRefKey{{
			ClusterKey:   clusterInstData[0].Key.ClusterKey,
			Organization: clusterInstData[0].Key.Organization,
		}, {
			ClusterKey:   clusterInstData[3].Key.ClusterKey,
			Organization: clusterInstData[3].Key.Organization,
		}, {
			ClusterKey:   clusterInstData[7].Key.ClusterKey,
			Organization: clusterInstData[7].Key.Organization,
		}, {
			ClusterKey:   clusterInstData[8].Key.ClusterKey,
			Organization: clusterInstData[8].Key.Organization,
		}},
		RootLbPorts: map[int32]int32{443: 1, 10002: 3, 889: 1, 444: 1},
		VmAppInsts: []edgeproto.AppInstRefKey{{
			AppKey: appInstData[11].Key.AppKey,
			ClusterInstKey: edgeproto.ClusterInstRefKey{
				ClusterKey:   appInstData[11].Key.ClusterInstKey.ClusterKey,
				Organization: appInstData[11].Key.ClusterInstKey.Organization,
			},
		}},
		UsedDynamicIps: 2,
	}, { // edgeproto.CloudletRefs
		// ClusterInstData[1,4,9], ClusterInstAutoData[0]: (shared,shared,dedicated,shared)
		// AppInstData[2,3] -> ports[tcp:443;tcp:80,tcp:443,tcp:81,udp:10002]
		Key: cloudletData[1].Key,
		ClusterInsts: []edgeproto.ClusterInstRefKey{{
			ClusterKey:   clusterInstData[1].Key.ClusterKey,
			Organization: clusterInstData[1].Key.Organization,
		}, {
			ClusterKey:   clusterInstData[4].Key.ClusterKey,
			Organization: clusterInstData[4].Key.Organization,
		}, {
			ClusterKey:   clusterInstAutoData[0].Key.ClusterKey,
			Organization: clusterInstAutoData[0].Key.Organization,
		}, {
			ClusterKey:   clusterInstData[9].Key.ClusterKey,
			Organization: clusterInstData[9].Key.Organization,
		}},
		RootLbPorts:            map[int32]int32{80: 1, 81: 1, 443: 1, 10000: 1, 10002: 3},
		ReservedAutoClusterIds: 1,
		UsedDynamicIps:         1,
	}, { // edgeproto.CloudletRefs
		// ClusterInstData[2,5], ClusterInstAutoData[1,2]: (shared,dedicated,shared,shared)
		// AppInstData[4,5,6] -> ports[tcp:443,udp:11111;udp:2024;tcp:80,udp:8001,tcp:65535]
		Key: cloudletData[2].Key,
		ClusterInsts: []edgeproto.ClusterInstRefKey{{
			ClusterKey:   clusterInstData[2].Key.ClusterKey,
			Organization: clusterInstData[2].Key.Organization,
		}, {
			ClusterKey:   clusterInstData[5].Key.ClusterKey,
			Organization: clusterInstData[5].Key.Organization,
		}, {
			ClusterKey:   clusterInstAutoData[1].Key.ClusterKey,
			Organization: clusterInstAutoData[1].Key.Organization,
		}, {
			ClusterKey:   clusterInstAutoData[2].Key.ClusterKey,
			Organization: clusterInstAutoData[2].Key.Organization,
		}},
		UsedDynamicIps:         1,
		RootLbPorts:            map[int32]int32{443: 1, 11111: 2, 2024: 2, 80: 1, 8001: 2, 65535: 1},
		ReservedAutoClusterIds: 3,
	}, { // edgeproto.CloudletRefs
		// ClusterInstData[6]: (no app insts on this clusterinst) (shared),
		// ClusterInstAutoData[3]: (shared)
		// AppInstData[12] -> ports[tcp:889]
		Key: cloudletData[3].Key,
		ClusterInsts: []edgeproto.ClusterInstRefKey{{
			ClusterKey:   clusterInstData[6].Key.ClusterKey,
			Organization: clusterInstData[6].Key.Organization,
		}, {
			ClusterKey:   clusterInstAutoData[3].Key.ClusterKey,
			Organization: clusterInstAutoData[3].Key.Organization,
		}},
		RootLbPorts:            map[int32]int32{889: 1},
		ReservedAutoClusterIds: 1,
	}}
}

func CloudletPoolData() []edgeproto.CloudletPool {
	operatorData := OperatorData()
	cloudletData := CloudletData()
	return []edgeproto.CloudletPool{{
		Key: edgeproto.CloudletPoolKey{
			Organization: operatorData[1],
			Name:         "private",
		},
		Cloudlets: []edgeproto.CloudletKey{
			cloudletData[2].Key,
		},
	}, { // edgeproto.CloudletPool
		Key: edgeproto.CloudletPoolKey{
			Organization: operatorData[2],
			Name:         "test-and-dev",
		},
		Cloudlets: []edgeproto.CloudletKey{
			cloudletData[3].Key,
		},
	}, { // edgeproto.CloudletPool
		Key: edgeproto.CloudletPoolKey{
			Organization: operatorData[2],
			Name:         "enterprise",
		},
		Cloudlets: []edgeproto.CloudletKey{
			cloudletData[3].Key,
		},
	}}
}

func Restblkeys() []edgeproto.ResTagTableKey {
	return []edgeproto.ResTagTableKey{{
		Name:         "gpu",
		Organization: "UFGT Inc.",
	}, {
		Name:         "nas",
		Organization: "UFGT Inc.",
	}, {
		Name:         "nic",
		Organization: "UFGT Inc.",
	}, {
		Name:         "gput4",
		Organization: "UFGT Inc.",
	}}
}

func ResTagTableData() []edgeproto.ResTagTable {
	restblkeys := Restblkeys()
	return []edgeproto.ResTagTable{{
		Key:  restblkeys[0],
		Tags: map[string]string{"vmware": "vgpu=1"},
	}, {
		Key:  restblkeys[1],
		Tags: map[string]string{"vcpu": "nvidia-72", "pci-passthru": "NP4:2"},
	}, {
		Key:  restblkeys[2],
		Tags: map[string]string{"vcpu": "nvidia-63", "pci-passthru": "T4:1"},
	}, {
		Key:  restblkeys[3],
		Tags: map[string]string{"pci": "t4:1"},
	}}
}

func AlertData() []edgeproto.Alert {
	clusterInstData := ClusterInstData()
	appInstData := AppInstData()
	return []edgeproto.Alert{{
		Labels: map[string]string{
			"alertname":   "AutoScaleUp",
			"cloudletorg": clusterInstData[0].Key.CloudletKey.Organization,
			"cloudlet":    clusterInstData[0].Key.CloudletKey.Name,
			"cluster":     clusterInstData[0].Key.ClusterKey.Name,
			"clusterorg":  clusterInstData[0].Key.Organization,
			"severity":    "none",
		},
		Annotations: map[string]string{
			"message": "Policy threshold to scale up cluster reached",
		},
		State: "firing",
		ActiveAt: dme.Timestamp{
			Seconds: 1257894000,
			Nanos:   2343569,
		},
		Value: 1,
	}, { // edgeproto.Alert
		Labels: map[string]string{
			"alertname":   "AutoScaleDown",
			"cloudletorg": clusterInstData[0].Key.CloudletKey.Organization,
			"cloudlet":    clusterInstData[0].Key.CloudletKey.Name,
			"cluster":     clusterInstData[0].Key.ClusterKey.Name,
			"clusterorg":  clusterInstData[0].Key.Organization,
			"severity":    "none",
		},
		Annotations: map[string]string{
			"message": "Policy threshold to scale down cluster reached",
		},
		State: "pending",
		ActiveAt: dme.Timestamp{
			Seconds: 1257894001,
			Nanos:   642398,
		},
		Value: 1,
	}, { // edgeproto.Alert
		Labels: map[string]string{
			"alertname":   "AutoScaleUp",
			"cloudletorg": clusterInstData[1].Key.CloudletKey.Organization,
			"cloudlet":    clusterInstData[1].Key.CloudletKey.Name,
			"cluster":     clusterInstData[1].Key.ClusterKey.Name,
			"clusterorg":  clusterInstData[1].Key.Organization,
			"severity":    "critical",
		},
		Annotations: map[string]string{
			"message": "Cluster offline",
		},
		State: "firing",
		ActiveAt: dme.Timestamp{
			Seconds: 1257894002,
			Nanos:   42398457,
		},
		Value: 1,
	}, { // edgeproto.Alert
		Labels: map[string]string{
			"alertname":   "AppInstDown",
			"app":         appInstData[0].Key.AppKey.Name,
			"appver":      appInstData[0].Key.AppKey.Version,
			"apporg":      appInstData[0].Key.AppKey.Organization,
			"cloudletorg": clusterInstData[7].Key.CloudletKey.Organization,
			"cloudlet":    clusterInstData[7].Key.CloudletKey.Name,
			"cluster":     clusterInstData[7].Key.ClusterKey.Name,
			"clusterorg":  clusterInstData[7].Key.Organization,
			"status":      "1",
		},
		State: "firing",
		ActiveAt: dme.Timestamp{
			Seconds: 1257894002,
			Nanos:   42398457,
		},
	}, { // edgeproto.Alert
		Labels: map[string]string{
			"alertname":   "AppInstDown",
			"app":         appInstData[0].Key.AppKey.Name,
			"appver":      appInstData[0].Key.AppKey.Version,
			"apporg":      appInstData[0].Key.AppKey.Organization,
			"cloudletorg": appInstData[0].Key.ClusterInstKey.CloudletKey.Organization,
			"cloudlet":    appInstData[0].Key.ClusterInstKey.CloudletKey.Name,
			"cluster":     appInstData[0].Key.ClusterInstKey.ClusterKey.Name,
			"clusterorg":  appInstData[0].Key.ClusterInstKey.Organization,
			"status":      "2",
		},
		State: "firing",
		ActiveAt: dme.Timestamp{
			Seconds: 1257894002,
			Nanos:   42398457,
		},
	}}
}

func AutoScalePolicyData() []edgeproto.AutoScalePolicy {
	devData := DevData()
	return []edgeproto.AutoScalePolicy{{
		Key: edgeproto.PolicyKey{
			Name:         "auto-scale-policy",
			Organization: devData[0],
		},
		MinNodes:           1,
		MaxNodes:           3,
		ScaleUpCpuThresh:   80,
		ScaleDownCpuThresh: 20,
		TriggerTimeSec:     60,
	}, { // edgeproto.AutoScalePolicy
		Key: edgeproto.PolicyKey{
			Name:         "auto-scale-policy",
			Organization: devData[1],
		},
		MinNodes:           4,
		MaxNodes:           8,
		ScaleUpCpuThresh:   60,
		ScaleDownCpuThresh: 40,
		TriggerTimeSec:     30,
	}, { // edgeproto.AutoScalePolicy
		Key: edgeproto.PolicyKey{
			Name:         "auto-scale-policy",
			Organization: devData[3],
		},
		MinNodes:           1,
		MaxNodes:           3,
		ScaleUpCpuThresh:   90,
		ScaleDownCpuThresh: 10,
		TriggerTimeSec:     60,
	}}
}

func AutoProvPolicyData() []edgeproto.AutoProvPolicy {
	devData := DevData()
	return []edgeproto.AutoProvPolicy{{
		Key: edgeproto.PolicyKey{
			Name:         "auto-prov-policy",
			Organization: devData[0],
		},
		DeployClientCount:   2,
		DeployIntervalCount: 2,
	}, { // edgeproto.AutoProvPolicy
		Key: edgeproto.PolicyKey{
			Name:         "auto-prov-policy",
			Organization: devData[1],
		},
		DeployClientCount:   1,
		DeployIntervalCount: 1,
	}, { // edgeproto.AutoProvPolicy
		Key: edgeproto.PolicyKey{
			Name:         "auto-prov-policy",
			Organization: devData[3],
		},
		DeployClientCount:   20,
		DeployIntervalCount: 4,
	}, { // edgeproto.AutoProvPolicy
		Key: edgeproto.PolicyKey{
			Name:         "auto-prov-policy2",
			Organization: devData[0],
		},
		DeployClientCount:   10,
		DeployIntervalCount: 10,
	}}
}

func TrustPolicyData() []edgeproto.TrustPolicy {
	cloudletData := CloudletData()
	return []edgeproto.TrustPolicy{{
		Key: edgeproto.PolicyKey{
			Name:         "trust-policy0",
			Organization: cloudletData[2].Key.Organization,
		},
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "8.100.0.0/16",
			PortRangeMin: 443,
			PortRangeMax: 443,
		}, {
			Protocol:     "UDP",
			RemoteCidr:   "0.0.0.0/0",
			PortRangeMin: 53,
			PortRangeMax: 53,
		}},
	}, { // edgeproto.TrustPolicy
		Key: edgeproto.PolicyKey{
			Name:         "trust-policy1",
			Organization: cloudletData[2].Key.Organization,
		},
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "8.100.0.0/16",
			PortRangeMin: 443,
			PortRangeMax: 443,
		}, {
			Protocol:     "UDP",
			RemoteCidr:   "0.0.0.0/0",
			PortRangeMin: 53,
			PortRangeMax: 53,
		}},
	}, { // edgeproto.TrustPolicy
		Key: edgeproto.PolicyKey{
			Name:         "trust-policy2",
			Organization: cloudletData[2].Key.Organization,
		},
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:   "ICMP",
			RemoteCidr: "0.0.0.0/0",
		}, {
			Protocol:     "TCP",
			RemoteCidr:   "10.0.0.0/8",
			PortRangeMin: 1,
			PortRangeMax: 65535,
		}},
	}}
}

func TrustPolicyErrorData() []edgeproto.TrustPolicy {
	cloudletData := CloudletData()
	return []edgeproto.TrustPolicy{{
		// Failure case, max port > min port
		Key: edgeproto.PolicyKey{
			Name:         "trust-policy3",
			Organization: cloudletData[2].Key.Organization,
		},
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "10.1.0.0/16",
			PortRangeMin: 201,
			PortRangeMax: 110,
		}},
	}, { // edgeproto.TrustPolicy
		// Failure case, bad CIDR
		Key: edgeproto.PolicyKey{
			Name:         "trust-policy4",
			Organization: cloudletData[2].Key.Organization,
		},
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "10.0.0.0/50",
			PortRangeMin: 22,
			PortRangeMax: 22,
		}},
	}, { // edgeproto.TrustPolicy
		// Failure case, missing min port but max port present
		Key: edgeproto.PolicyKey{
			Name:         "trust-policy5",
			Organization: cloudletData[2].Key.Organization,
		},
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "47.186.0.0/16",
			PortRangeMax: 22,
		}},
	}}
}

func TrustPolicyExceptionData() []edgeproto.TrustPolicyException {
	devData := DevData()
	operatorData := OperatorData()
	return []edgeproto.TrustPolicyException{{
		Key: edgeproto.TrustPolicyExceptionKey{
			AppKey: edgeproto.AppKey{
				Organization: devData[0],
				Name:         "Pillimo Go!",
				Version:      "1.0.0",
			},
			CloudletPoolKey: edgeproto.CloudletPoolKey{
				Organization: operatorData[2],
				Name:         "test-and-dev",
			},
			Name: "trust-policyexception1",
		},
		State: edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_APPROVAL_REQUESTED,
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "10.1.0.0/16",
			PortRangeMin: 201,
			PortRangeMax: 210,
		}},
	}, { // edgeproto.TrustPolicyException
		Key: edgeproto.TrustPolicyExceptionKey{
			AppKey: edgeproto.AppKey{
				Organization: devData[0],
				Name:         "Pillimo Go!",
				Version:      "1.0.0",
			},
			CloudletPoolKey: edgeproto.CloudletPoolKey{
				Organization: operatorData[2],
				Name:         "test-and-dev",
			},
			Name: "trust-policyexception2",
		},
		State: edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_APPROVAL_REQUESTED,
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "10.0.0.0/8",
			PortRangeMin: 22,
			PortRangeMax: 22,
		}},
	}, { // edgeproto.TrustPolicyException
		Key: edgeproto.TrustPolicyExceptionKey{
			AppKey: edgeproto.AppKey{
				Organization: devData[0],
				Name:         "Pillimo Go!",
				Version:      "1.0.0",
			},
			CloudletPoolKey: edgeproto.CloudletPoolKey{
				Organization: operatorData[2],
				Name:         "test-and-dev",
			},
			Name: "trust-policyexception3",
		},
		State: edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_APPROVAL_REQUESTED,
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "47.186.0.0/16",
			PortRangeMin: 22,
			PortRangeMax: 22,
		}},
	}}
}

func TrustPolicyExceptionErrorData() []edgeproto.TrustPolicyException {
	devData := DevData()
	operatorData := OperatorData()
	return []edgeproto.TrustPolicyException{{
		// Failure case, max port > min port
		Key: edgeproto.TrustPolicyExceptionKey{
			AppKey: edgeproto.AppKey{
				Organization: devData[0],
				Name:         "Pillimo Go!",
				Version:      "1.0.0",
			},
			CloudletPoolKey: edgeproto.CloudletPoolKey{
				Organization: operatorData[2],
				Name:         "test-and-dev",
			},
			Name: "trust-policyexception11",
		},
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "10.1.0.0/16",
			PortRangeMin: 201,
			PortRangeMax: 110,
		}},
	}, { // edgeproto.TrustPolicyException
		// Failure case, bad CIDR
		Key: edgeproto.TrustPolicyExceptionKey{
			AppKey: edgeproto.AppKey{
				Organization: devData[0],
				Name:         "Pillimo Go!",
				Version:      "2.0.0",
			},
			CloudletPoolKey: edgeproto.CloudletPoolKey{
				Organization: operatorData[2],
				Name:         "test-and-dev",
			},
			Name: "trust-policyexception12",
		},
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "10.0.0.0/50",
			PortRangeMin: 22,
			PortRangeMax: 22,
		}},
	}, { // edgeproto.TrustPolicyException
		// Failure case, missing min port but max port present
		Key: edgeproto.TrustPolicyExceptionKey{
			AppKey: edgeproto.AppKey{
				Organization: devData[0],
				Name:         "Pillimo Go!",
				Version:      "3.0.0",
			},
			CloudletPoolKey: edgeproto.CloudletPoolKey{
				Organization: operatorData[2],
				Name:         "test-and-dev",
			},
			Name: "trust-policyexception13",
		},
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "47.186.0.0/16",
			PortRangeMax: 22,
		}},
	}, { // edgeproto.TrustPolicyException
		// Failure case, App does not exist
		Key: edgeproto.TrustPolicyExceptionKey{
			AppKey: edgeproto.AppKey{
				Organization: devData[0],
				Name:         "Pillimo does not exist!",
				Version:      "13.0.0",
			},
			CloudletPoolKey: edgeproto.CloudletPoolKey{
				Organization: operatorData[2],
				Name:         "test-and-dev",
			},
			Name: "trust-policyexception13",
		},
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "47.186.0.0/16",
			PortRangeMin: 22,
			PortRangeMax: 22,
		}},
	}, { // edgeproto.TrustPolicyException
		// Failure case, CloudletPoolKey does not exist
		Key: edgeproto.TrustPolicyExceptionKey{
			AppKey: edgeproto.AppKey{
				Organization: devData[0],
				Name:         "Pillimo Go!",
				Version:      "1.0.0",
			},
			CloudletPoolKey: edgeproto.CloudletPoolKey{
				Organization: operatorData[2],
				Name:         "test-and-dev-does-not-exist",
			},
			Name: "trust-policyexception13",
		},
		OutboundSecurityRules: []edgeproto.SecurityRule{{
			Protocol:     "TCP",
			RemoteCidr:   "47.186.0.0/16",
			PortRangeMin: 22,
			PortRangeMax: 22,
		}},
	}}
}

func AppInstClientKeyData() []edgeproto.AppInstClientKey {
	appInstData := AppInstData()
	return []edgeproto.AppInstClientKey{{
		AppInstKey: appInstData[0].Key,
	}, {
		AppInstKey: appInstData[3].Key,
	}}
}

func AppInstClientData() []edgeproto.AppInstClient {
	appInstClientKeyData := AppInstClientKeyData()
	return []edgeproto.AppInstClient{{
		ClientKey: appInstClientKeyData[0],
		Location: dme.Loc{
			Latitude:  1.0,
			Longitude: 1.0,
		},
	}, { // edgeproto.AppInstClient
		ClientKey: appInstClientKeyData[0],
		Location: dme.Loc{
			Latitude:  1.0,
			Longitude: 2.0,
		},
	}, { // edgeproto.AppInstClient
		ClientKey: appInstClientKeyData[0],
		Location: dme.Loc{
			Latitude:  1.0,
			Longitude: 3.0,
		},
	}, { // edgeproto.AppInstClient
		ClientKey: appInstClientKeyData[1],
		Location: dme.Loc{
			Latitude:  1.0,
			Longitude: 2.0,
		},
	}}
}

func PlatformDeviceClientDataKeys() []edgeproto.DeviceKey {
	return []edgeproto.DeviceKey{{
		UniqueIdType: "platos",
		UniqueId:     "1",
	}, {
		UniqueIdType: "platos",
		UniqueId:     "2",
	}, {
		UniqueIdType: "Mex",
		UniqueId:     "1",
	}, {
		UniqueIdType: "GSAFKDF:platos:platosEnablementLayer",
		UniqueId:     "1",
	}, {
		UniqueIdType: "SAMSUNG:CaseDeviceTest",
		UniqueId:     "1",
	}}
}

func PlatformDeviceClientData() []edgeproto.Device {
	platformDeviceClientDataKeys := PlatformDeviceClientDataKeys()
	return []edgeproto.Device{{
		Key: platformDeviceClientDataKeys[0],
		// 2009-11-10 23:00:00 +0000 UTC
		FirstSeen: GetTimestamp(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)),
	}, { // edgeproto.Device
		Key: platformDeviceClientDataKeys[1],
		// 2009-11-10 23:00:00 +0000 UTC
		FirstSeen: GetTimestamp(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)),
	}, { // edgeproto.Device
		Key: platformDeviceClientDataKeys[2],
		// 2009-12-10 23:00:00 +0000 UTC
		FirstSeen: GetTimestamp(time.Date(2009, time.December, 10, 23, 0, 0, 0, time.UTC)),
	}, { // edgeproto.Device
		Key: platformDeviceClientDataKeys[3],
		// 2009-10-10 23:30:00 +0000 UTC
		FirstSeen: GetTimestamp(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)),
	}, { // edgeproto.Device
		Key: platformDeviceClientDataKeys[4],
		// 2009-12-10 23:30:00 +0000 UTC
		FirstSeen: GetTimestamp(time.Date(2009, time.December, 10, 23, 0, 0, 0, time.UTC)),
	}}
}

func VMPoolData() []edgeproto.VMPool {
	operatorData := OperatorData()
	return []edgeproto.VMPool{{
		Key: edgeproto.VMPoolKey{
			Organization: operatorData[0],
			Name:         "San Jose Site",
		},
		Vms: []edgeproto.VM{{
			Name: "vm1",
			NetInfo: edgeproto.VMNetInfo{
				ExternalIp: "192.168.1.101",
				InternalIp: "192.168.100.101",
			},
			Flavor: &edgeproto.FlavorInfo{
				Name:  "vm1-flavor",
				Vcpus: uint64(2),
				Ram:   uint64(2048),
				Disk:  uint64(20),
			},
		}, {
			Name: "vm2",
			NetInfo: edgeproto.VMNetInfo{
				ExternalIp: "192.168.1.102",
				InternalIp: "192.168.100.102",
			},
			Flavor: &edgeproto.FlavorInfo{
				Name:  "vm2-flavor",
				Vcpus: uint64(2),
				Ram:   uint64(2048),
				Disk:  uint64(20),
			},
		}, {
			Name: "vm3",
			NetInfo: edgeproto.VMNetInfo{
				InternalIp: "192.168.100.103",
			},
			Flavor: &edgeproto.FlavorInfo{
				Name:  "vm3-flavor",
				Vcpus: uint64(2),
				Ram:   uint64(2048),
				Disk:  uint64(20),
			},
		}, {
			Name: "vm4",
			NetInfo: edgeproto.VMNetInfo{
				InternalIp: "192.168.100.104",
			},
			Flavor: &edgeproto.FlavorInfo{
				Name:  "vm4-flavor",
				Vcpus: uint64(2),
				Ram:   uint64(2048),
				Disk:  uint64(20),
			},
		}, {
			Name: "vm5",
			NetInfo: edgeproto.VMNetInfo{
				InternalIp: "192.168.100.105",
			},
			Flavor: &edgeproto.FlavorInfo{
				Name:  "vm5-flavor",
				Vcpus: uint64(3),
				Ram:   uint64(4096),
				Disk:  uint64(50),
			},
		}},
	}, { // edgeproto.VMPool
		Key: edgeproto.VMPoolKey{
			Organization: operatorData[0],
			Name:         "New York Site",
		},
		Vms: []edgeproto.VM{{
			Name: "vm1",
			NetInfo: edgeproto.VMNetInfo{
				ExternalIp: "192.168.1.101",
				InternalIp: "192.168.100.101",
			},
			Flavor: &edgeproto.FlavorInfo{
				Name:  "vm1-flavor",
				Vcpus: uint64(2),
				Ram:   uint64(2048),
				Disk:  uint64(20),
			},
		}, {
			Name: "vm2",
			NetInfo: edgeproto.VMNetInfo{
				ExternalIp: "192.168.1.102",
				InternalIp: "192.168.100.102",
			},
			Flavor: &edgeproto.FlavorInfo{
				Name:  "vm2-flavor",
				Vcpus: uint64(2),
				Ram:   uint64(2048),
				Disk:  uint64(20),
			},
		}, {
			Name: "vm3",
			NetInfo: edgeproto.VMNetInfo{
				InternalIp: "192.168.100.103",
			},
			Flavor: &edgeproto.FlavorInfo{
				Name:  "vm3-flavor",
				Vcpus: uint64(2),
				Ram:   uint64(2048),
				Disk:  uint64(20),
			},
		}},
	}, { // edgeproto.VMPool
		Key: edgeproto.VMPoolKey{
			Organization: operatorData[1],
			Name:         "San Francisco Site",
		},
		Vms: []edgeproto.VM{{
			Name: "vm1",
			NetInfo: edgeproto.VMNetInfo{
				InternalIp: "192.168.100.101",
			},
			Flavor: &edgeproto.FlavorInfo{
				Name:  "vm1-flavor",
				Vcpus: uint64(2),
				Ram:   uint64(2048),
				Disk:  uint64(20),
			},
		}, {
			Name: "vm2",
			NetInfo: edgeproto.VMNetInfo{
				InternalIp: "192.168.100.102",
			},
			Flavor: &edgeproto.FlavorInfo{
				Name:  "vm2-flavor",
				Vcpus: uint64(2),
				Ram:   uint64(2048),
				Disk:  uint64(20),
			},
		}},
	}}
}

func GPUDriverData() []edgeproto.GPUDriver {
	operatorData := OperatorData()
	return []edgeproto.GPUDriver{{
		Key: edgeproto.GPUDriverKey{
			Organization: operatorData[0],
			Name:         "nvidia-450",
		},
	}, { // edgeproto.GPUDriver
		Key: edgeproto.GPUDriverKey{
			Name: "nvidia-490",
		},
	}, { // edgeproto.GPUDriver
		Key: edgeproto.GPUDriverKey{
			Organization: operatorData[1],
			Name:         "nvidia-999",
		},
	}, { // edgeproto.GPUDriver
		Key: edgeproto.GPUDriverKey{
			Organization: operatorData[0],
			Name:         "nvidia-vgpu",
		},
	}}
}

func AlertPolicyData() []edgeproto.AlertPolicy {
	devData := DevData()
	return []edgeproto.AlertPolicy{{
		// Warning alert with no labels/annotations
		Key: edgeproto.AlertPolicyKey{
			Name:         "testAlert1",
			Organization: devData[0],
		},
		CpuUtilizationLimit:  80,
		MemUtilizationLimit:  70,
		DiskUtilizationLimit: 70,
		Severity:             "warning",
		Description:          "Sample description",
		TriggerTime:          edgeproto.Duration(30 * time.Second),
	}, { // edgeproto.AlertPolicy
		// Warning alert with Active Connections
		Key: edgeproto.AlertPolicyKey{
			Name:         "testAlert2",
			Organization: devData[0],
		},
		ActiveConnLimit: 10,
		Severity:        "info",
		TriggerTime:     edgeproto.Duration(5 * time.Minute),
	}, { // edgeproto.AlertPolicy
		// Error alert with extra labels
		Key: edgeproto.AlertPolicyKey{
			Name:         "testAlert3",
			Organization: devData[1],
		},
		CpuUtilizationLimit: 100,
		Severity:            "error",
		TriggerTime:         edgeproto.Duration(30 * time.Second),
		Labels: map[string]string{
			"testLabel1": "testValue1",
			"testLabel2": "testValue2",
		},
		Annotations: map[string]string{
			"testAnnotation1": "description1",
			"testAnnotation2": "description2",
		},
	}, { // edgeproto.AlertPolicy
		// Warning alert with two triggers and no description
		Key: edgeproto.AlertPolicyKey{
			Name:         "testAlert4",
			Organization: devData[1],
		},
		CpuUtilizationLimit: 80,
		MemUtilizationLimit: 80,
		Severity:            "warning",
		TriggerTime:         edgeproto.Duration(30 * time.Second),
	}, { // edgeproto.AlertPolicy
		// Warning alert with two triggers description and title annotations
		Key: edgeproto.AlertPolicyKey{
			Name:         "testAlert5",
			Organization: devData[1],
		},
		CpuUtilizationLimit: 80,
		MemUtilizationLimit: 80,
		Severity:            "warning",
		Description:         "Sample description",
		TriggerTime:         edgeproto.Duration(30 * time.Second),
		Annotations: map[string]string{
			"title":       "CustomAlertName",
			"description": "Custom Description",
		},
	}}
}

func NetworkData() []edgeproto.Network {
	cloudletData := CloudletData()
	return []edgeproto.Network{{
		Key: edgeproto.NetworkKey{
			Name:        "network0",
			CloudletKey: cloudletData[2].Key,
		},
		ConnectionType: edgeproto.NetworkConnectionType_CONNECT_TO_LOAD_BALANCER,
		Routes: []edgeproto.Route{{
			DestinationCidr: "3.100.0.0/16",
			NextHopIp:       "3.100.0.1",
		}, {
			DestinationCidr: "3.100.10.0/24",
			NextHopIp:       "3.100.10.1",
		}},
	}, { // edgeproto.Network
		Key: edgeproto.NetworkKey{
			Name:        "network1",
			CloudletKey: cloudletData[2].Key,
		},
		ConnectionType: edgeproto.NetworkConnectionType_CONNECT_TO_CLUSTER_NODES,
		Routes: []edgeproto.Route{{
			DestinationCidr: "4.100.0.0/16",
			NextHopIp:       "4.100.0.1",
		}, {
			DestinationCidr: "4.100.10.0/24",
			NextHopIp:       "4.100.10.1",
		}},
	}, { // edgeproto.Network
		Key: edgeproto.NetworkKey{
			Name:        "network2",
			CloudletKey: cloudletData[2].Key,
		},
		ConnectionType: edgeproto.NetworkConnectionType_CONNECT_TO_ALL,
		Routes: []edgeproto.Route{{
			DestinationCidr: "5.100.0.0/16",
			NextHopIp:       "5.100.0.1",
		}},
	}}
}

func NetworkErrorData() []edgeproto.Network {
	cloudletData := CloudletData()
	return []edgeproto.Network{{
		// bad cidr
		Key: edgeproto.NetworkKey{
			Name:        "networkbadcidr",
			CloudletKey: cloudletData[2].Key,
		},
		ConnectionType: edgeproto.NetworkConnectionType_CONNECT_TO_CLUSTER_NODES,
		Routes: []edgeproto.Route{{
			DestinationCidr: "abcd",
			NextHopIp:       "3.100.0.1",
		}},
	}, { // edgeproto.Network
		// bad next hop ip
		Key: edgeproto.NetworkKey{
			Name:        "networkbadroute",
			CloudletKey: cloudletData[2].Key,
		},
		ConnectionType: edgeproto.NetworkConnectionType_CONNECT_TO_LOAD_BALANCER,
		Routes: []edgeproto.Route{{
			DestinationCidr: "4.100.0.0/16",
			NextHopIp:       "xyz",
		}},
	}, { // edgeproto.Network
		// missing connection type
		Key: edgeproto.NetworkKey{
			Name:        "networknoconntype",
			CloudletKey: cloudletData[2].Key,
		},
		Routes: []edgeproto.Route{{
			DestinationCidr: "4.100.0.0/16",
			NextHopIp:       "4.100.0.0/16",
		}},
	}}
}

func GetTimestamp(t time.Time) *types.Timestamp {
	ts, _ := types.TimestampProto(t)
	return ts
}

func IsAutoClusterAutoDeleteApp(key *edgeproto.AppInstKey) bool {
	if !strings.HasPrefix(key.ClusterInstKey.ClusterKey.Name, "autocluster") && !strings.HasPrefix(key.ClusterInstKey.ClusterKey.Name, "reservable") {
		return false
	}
	for _, app := range AppData() {
		if app.Key.Matches(&key.AppKey) {
			return app.DelOpt == edgeproto.DeleteType_AUTO_DELETE
		}
	}
	panic(fmt.Sprintf("App definition not found for %v", key))
}

// Get the AppInst data after it has been created by the Controller.
// This is for tests that are using data as if it has already been
// created and processed by the Controller, given that the controller
// may modify certain fields during create.
func CreatedAppInstData() []edgeproto.AppInst {
	clusterInstAutoData := ClusterInstAutoData()
	insts := []edgeproto.AppInst{}
	for ii, appInst := range AppInstData() {
		switch ii {
		case 3:
			// grab expected autocluster real name
			appInst.RealClusterName = clusterInstAutoData[0].Key.ClusterKey.Name
		case 4:
			appInst.RealClusterName = clusterInstAutoData[1].Key.ClusterKey.Name
		case 6:
			appInst.RealClusterName = clusterInstAutoData[2].Key.ClusterKey.Name
		case 11:
			appInst.Key.ClusterInstKey.Organization = appInst.Key.AppKey.Organization
			appInst.Key.ClusterInstKey.ClusterKey.Name = "defaultclust"
		}
		insts = append(insts, appInst)
	}
	return insts
}
