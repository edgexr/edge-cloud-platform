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

package kindinfra

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	pf "github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/fakeinfra"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/kind"
	intprocess "github.com/edgexr/edge-cloud-platform/pkg/process"
)

// Kind platform with multi-tenant cluster support.
// We may also want to add shepherd/envoy to test metrics.
type Platform struct {
	kind.Platform
}

func NewPlatform() platform.Platform {
	return &Platform{}
}

func (s *Platform) GetFeatures() *edgeproto.PlatformFeatures {
	features := s.Platform.GetFeatures()
	features.PlatformType = platform.PlatformTypeKindInfra
	return features
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	err := s.Platform.GatherCloudletInfo(ctx, info)
	if err != nil {
		return err
	}
	if info.Properties == nil {
		info.Properties = make(map[string]string)
	}
	info.OsMaxRam = 81920
	info.OsMaxVcores = 100
	info.OsMaxVolGb = 500
	return nil
}

func (s *Platform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *pf.PlatformInitConfig, flavor *edgeproto.Flavor, caches *pf.Caches, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	cloudletResourcesCreated, err := s.Platform.CreateCloudlet(ctx, cloudlet, pfConfig, pfInitConfig, flavor, caches, updateCallback)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	if err = fakeinfra.ShepherdStartup(ctx, cloudlet, pfConfig, updateCallback); err != nil {
		return cloudletResourcesCreated, err
	}
	return cloudletResourcesCreated, fakeinfra.CloudletPrometheusStartup(ctx, cloudlet, pfConfig, caches, updateCallback)
}

func (s *Platform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *pf.PlatformInitConfig, caches *pf.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	err := s.Platform.DeleteCloudlet(ctx, cloudlet, pfConfig, pfInitConfig, caches, updateCallback)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Stopping Shepherd")
	return intprocess.StopShepherdService(ctx, cloudlet)
}
