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

package platform

// Builtin platform names. These should only be referenced
// from platform-specific code. Platform independent code
// should base its logic off of the platform features.
// This is because additional platforms may be added with
// new names, but the platform-independent code must be able
// to handle new platforms without prior knowledge of their
// names.
const (
	PlatformTypeAWSEC2            = "awsec2"
	PlatformTypeAWSEKS            = "awseks"
	PlatformTypeAzure             = "azure"
	PlatformTypeDind              = "dind" // docker in docker
	PlatformTypeEdgebox           = "edgebox"
	PlatformTypeLocalhost         = "localhost"
	PlatformTypeFake              = "fake"
	PlatformTypeFakeInfra         = "fakeinfra"
	PlatformTypeFakeEdgebox       = "fakeedgebox"
	PlatformTypeFakeSingleCluster = "fakesinglecluster"
	PlatformTypeFakePublicCloud   = "fakepubliccloud"
	PlatformTypeFakeVMPool        = "fakevmpool"
	PlatformTypeFederation        = "federation"
	PlatformTypeGCP               = "gcp"
	PlatformTypeK8SBareMetal      = "k8sbaremetal"
	PlatformTypeK8SSite           = "k8ssite"
	PlatformTypeKind              = "kind" // kubernetes in docker
	PlatformTypeKindInfra         = "kindinfra"
	PlatformTypeMock              = "mock"
	PlatformTypeMockManagedK8S    = "mockmanagedk8s"
	PlatformTypeOpenstack         = "openstack"
	PlatformTypeVCD               = "vcd"
	PlatformTypeVMPool            = "vmpool"
	PlatformTypeVSphere           = "vsphere"
	PlatformTypeOSMK8S            = "osmk8s"
)
