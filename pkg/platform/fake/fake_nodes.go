// Copyright 2025 EdgeXR, Inc
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

type FakeSiteNodes struct {
	Platform
}

func NewPlatformSiteNodes() platform.Platform {
	return &FakeSiteNodes{}
}

func (s *FakeSiteNodes) GetFeatures() *edgeproto.PlatformFeatures {
	features := s.Platform.GetFeatures()
	features.PlatformType = platform.PlatformTypeFakeSiteNodes
	features.NodeUsage = edgeproto.NodeUsageUserDefined
	return features
}

func (s *FakeSiteNodes) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return nil
}

func (s *FakeSiteNodes) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	return &edgeproto.InfraResourcesSnapshot{}, nil
}
