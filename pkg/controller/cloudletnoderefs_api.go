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

package controller

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
)

type CloudletNodeRefsApi struct {
	all   *AllApis
	sync  *regiondata.Sync
	store edgeproto.CloudletNodeRefsStore
	cache edgeproto.CloudletNodeRefsCache
}

func NewCloudletNodeRefsApi(sync *regiondata.Sync, all *AllApis) *CloudletNodeRefsApi {
	refsAPI := CloudletNodeRefsApi{}
	refsAPI.all = all
	refsAPI.sync = sync
	refsAPI.cache.InitCacheWithSync(sync)
	refsAPI.store = refsAPI.cache.Store
	return &refsAPI
}

func (s *CloudletNodeRefsApi) Delete(ctx context.Context, key *edgeproto.CloudletKey, wait func(int64)) {
	in := edgeproto.CloudletNodeRefs{Key: *key}
	s.store.Delete(ctx, &in, wait)
}

func (s *CloudletNodeRefsApi) ShowCloudletNodeRefs(in *edgeproto.CloudletNodeRefs, cb edgeproto.CloudletNodeRefsApi_ShowCloudletNodeRefsServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.CloudletNodeRefs) error {
		return cb.Send(obj)
	})
	return err
}
