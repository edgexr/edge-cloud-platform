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

package fake

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

type PlatformSingleCluster struct {
	Platform
}

func NewPlatformSingleCluster() platform.Platform {
	return &PlatformSingleCluster{}
}

func (s *PlatformSingleCluster) GetFeatures() *edgeproto.PlatformFeatures {
	features := s.Platform.GetFeatures()
	features.PlatformType = platform.PlatformTypeFakeSingleCluster
	features.IsSingleKubernetesCluster = true
	features.SupportsAppInstDedicatedIp = true
	return features
}

func (s *PlatformSingleCluster) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	s.Platform.GatherCloudletInfo(ctx, info)
	numNodes := uint64(10)
	info.NodePools = []*edgeproto.NodePool{{
		Name:     "cpupool",
		NumNodes: uint32(numNodes),
		NodeResources: &edgeproto.NodeResources{
			Vcpus: info.OsMaxVcores / numNodes,
			Ram:   info.OsMaxRam / numNodes,
			Disk:  info.OsMaxVolGb / numNodes,
		},
	}}
	return nil
}
