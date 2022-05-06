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

package dind

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud-platform/cloud-resource-manager/platform/common/xind"
	"github.com/edgexr/edge-cloud-platform/cloud-resource-manager/redundancy"
	"github.com/edgexr/edge-cloud-platform/edgeproto"
)

type Platform struct {
	xind.Xind
}

func (s *Platform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	return s.Xind.InitCommon(ctx, platformConfig, caches, s, updateCallback)
}

func (s *Platform) InitHAConditional(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	return s.Xind.InitHAConditional(ctx, platformConfig, updateCallback)
}

func (s *Platform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return s.Xind.GetInitHAConditionalCompatibilityVersion(ctx)
}

func (s *Platform) ActiveChanged(ctx context.Context, platformActive bool) error {
	return nil
}

func (s *Platform) NameSanitize(name string) string {
	return name
}
