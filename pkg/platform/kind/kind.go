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

package kind

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/xind"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
)

type Platform struct {
	xind.Xind
}

func NewPlatform() platform.Platform {
	return &Platform{}
}

func (s *Platform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	return s.Xind.InitCommon(ctx, platformConfig, caches, s, updateCallback)
}

func (s *Platform) InitHAConditional(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) error {
	return s.Xind.InitHAConditional(ctx, updateCallback)
}

func (s *Platform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return s.Xind.GetInitHAConditionalCompatibilityVersion(ctx)
}

func (s *Platform) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:                 platform.PlatformTypeKind,
		SupportsMultiTenantCluster:   true,
		CloudletServicesLocal:        true,
		NoKubernetesClusterAutoScale: true,
		ResourceQuotaProperties:      cloudcommon.CommonResourceQuotaProps,
	}
}
