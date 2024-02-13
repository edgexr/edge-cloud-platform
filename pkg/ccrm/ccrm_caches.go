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

package ccrm

import (
	"context"
	"sync"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

// CCRMCaches is an object that holds all the cached data.
// Handlers may register callbacks on the caches.

type CCRMCaches struct {
	PlatformFeaturesCache      edgeproto.PlatformFeaturesCache
	CloudletCache              *edgeproto.CloudletCache
	CloudletNodeCache          edgeproto.CloudletNodeCache
	CloudletInfoCache          edgeproto.CloudletInfoCache
	FlavorCache                edgeproto.FlavorCache
	VMPoolCache                edgeproto.VMPoolCache
	VMPoolInfoCache            edgeproto.VMPoolInfoCache
	SettingsCache              edgeproto.SettingsCache
	ResTagTableCache           edgeproto.ResTagTableCache
	GPUDriverCache             edgeproto.GPUDriverCache
	VMPool                     edgeproto.VMPool
	VMPoolMux                  sync.Mutex
	CloudletOnboardingInfoSend *notify.CloudletOnboardingInfoSend
	platformBuilders           map[string]platform.PlatformBuilder
	nodeType                   string
}

func (s *CCRMCaches) Init(ctx context.Context, nodeType string, nodeMgr *node.NodeMgr, platformBuilders map[string]platform.PlatformBuilder) {
	s.nodeType = nodeType
	s.platformBuilders = platformBuilders
	s.CloudletCache = nodeMgr.CloudletLookup.GetCloudletCache(node.NoRegion)
	edgeproto.InitPlatformFeaturesCache(&s.PlatformFeaturesCache)
	edgeproto.InitFlavorCache(&s.FlavorCache)
	edgeproto.InitVMPoolCache(&s.VMPoolCache)
	edgeproto.InitVMPoolInfoCache(&s.VMPoolInfoCache)
	edgeproto.InitCloudletInfoCache(&s.CloudletInfoCache)
	edgeproto.InitSettingsCache(&s.SettingsCache)
	edgeproto.InitResTagTableCache(&s.ResTagTableCache)
	edgeproto.InitGPUDriverCache(&s.GPUDriverCache)
	edgeproto.InitCloudletNodeCache(&s.CloudletNodeCache)
	s.CloudletOnboardingInfoSend = notify.NewCloudletOnboardingInfoSend()

	for _, builder := range platformBuilders {
		plat := builder()
		features := plat.GetFeatures()
		features.NodeType = s.nodeType
		s.PlatformFeaturesCache.Update(ctx, features, 0)
	}
}

func (s *CCRMCaches) InitNotify(client *notify.Client, nodeMgr *node.NodeMgr) {
	client.RegisterRecvCloudletCache(s.CloudletCache)
	client.RegisterRecvCloudletNodeCache(&s.CloudletNodeCache)
	client.RegisterRecvFlavorCache(&s.FlavorCache)
	client.RegisterRecvVMPoolCache(&s.VMPoolCache)
	client.RegisterRecvSettingsCache(&s.SettingsCache)
	client.RegisterRecvResTagTableCache(&s.ResTagTableCache)
	client.RegisterRecvGPUDriverCache(&s.GPUDriverCache)

	client.RegisterSendPlatformFeaturesCache(&s.PlatformFeaturesCache)
	client.RegisterSendCloudletInfoCache(&s.CloudletInfoCache)
	client.RegisterSendVMPoolInfoCache(&s.VMPoolInfoCache)
	client.RegisterSend(s.CloudletOnboardingInfoSend)

	nodeMgr.RegisterClient(client)
}

func (s *CCRMCaches) getPlatform(platformType string) (platform.Platform, bool) {
	// We may want to cache platform objects per cloudlet,
	// but for now follow what the Controller used to do,
	// which is to create a new object each time.
	builder, ok := s.platformBuilders[platformType]
	if !ok {
		return nil, false
	}
	plat := builder()
	return plat, true
}

func (s *CCRMCaches) getPlatformCaches() *platform.Caches {
	// Some platform types require caches
	caches := platform.Caches{
		SettingsCache:     &s.SettingsCache,
		FlavorCache:       &s.FlavorCache,
		CloudletCache:     s.CloudletCache,
		CloudletInfoCache: &s.CloudletInfoCache,
		VMPoolCache:       &s.VMPoolCache,
	}
	return &caches
}
