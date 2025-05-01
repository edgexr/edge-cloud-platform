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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

// CCRMCaches is an object that holds all the cached data.
// Handlers may register callbacks on the caches.

type CCRMCaches struct {
	PlatformFeaturesCache edgeproto.PlatformFeaturesCache
	CloudletNodeCache     edgeproto.CloudletNodeCache
	AppInstInfoCache      edgeproto.AppInstInfoCache
	CloudletInfoCache     edgeproto.CloudletInfoCache
	ClusterInstInfoCache  edgeproto.ClusterInstInfoCache
	CloudletNodeRefsCache edgeproto.CloudletNodeRefsCache
}

func (s *CCRMCaches) Init(ctx context.Context) {
	edgeproto.InitPlatformFeaturesCache(&s.PlatformFeaturesCache)
	edgeproto.InitCloudletNodeCache(&s.CloudletNodeCache)
	edgeproto.InitAppInstInfoCache(&s.AppInstInfoCache)
	edgeproto.InitClusterInstInfoCache(&s.ClusterInstInfoCache)
	edgeproto.InitCloudletInfoCache(&s.CloudletInfoCache)
	edgeproto.InitCloudletNodeRefsCache(&s.CloudletNodeRefsCache)
}
