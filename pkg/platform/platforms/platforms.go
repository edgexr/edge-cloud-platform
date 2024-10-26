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

package platforms

import (
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	awsec2 "github.com/edgexr/edge-cloud-platform/pkg/platform/aws/aws-ec2"
	awseks "github.com/edgexr/edge-cloud-platform/pkg/platform/aws/aws-eks"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/azure"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/dind"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/fake"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/fakeinfra"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/gcp"
	k8sbm "github.com/edgexr/edge-cloud-platform/pkg/platform/k8s-baremetal"
	k8sop "github.com/edgexr/edge-cloud-platform/pkg/platform/k8s-operator"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/kind"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/kindinfra"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/localhost"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/mock"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/openstack"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/osmano/osmk8s"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/vcd"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/vmpool"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/vsphere"
	"github.com/edgexr/edge-cloud-platform/pkg/plugin/platform/common"
)

// Builder for built-in platforms.

var builders = []platform.PlatformBuilder{
	dind.NewPlatform,
	fake.NewPlatform,
	fake.NewPlatformSingleCluster,
	kind.NewPlatform,
	fake.NewPlatformVMPool,
	openstack.NewPlatform,
	vsphere.NewPlatform,
	vmpool.NewPlatform,
	vcd.NewPlatform,
	awsec2.NewPlatform,
	azure.NewPlatform,
	gcp.NewPlatform,
	awseks.NewPlatform,
	fakeinfra.NewPlatform,
	k8sbm.NewPlatform,
	k8sop.NewPlatform,
	kindinfra.NewPlatform,
	mock.NewPlatform,
	localhost.NewPlatform,
	osmk8s.NewPlatform,
}

type PlatformsData struct {
	PlatformsFeatures map[string]edgeproto.PlatformFeatures
	PlatformsBuilders map[string]platform.PlatformBuilder
}

var All = platform.NewPlatformCollection(builders)

func GetClusterSvc() (platform.ClusterSvc, error) {
	return &common.ClusterSvc{}, nil
}
