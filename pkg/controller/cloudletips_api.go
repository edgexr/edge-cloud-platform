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
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudletips"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
)

type CloudletIPsApi struct {
	all         *AllApis
	sync        *regiondata.Sync
	cache       edgeproto.CloudletIPsCache
	cloudletIPs *cloudletips.CloudletIPs
}

func NewCloudletIPsApi(sync *regiondata.Sync, all *AllApis) *CloudletIPsApi {
	cloudletIPsApi := CloudletIPsApi{}
	cloudletIPsApi.all = all
	cloudletIPsApi.sync = sync
	cloudletIPsApi.cache.InitCacheWithSync(sync)
	cloudletIPsApi.cloudletIPs = cloudletips.NewCloudletIPs(sync.GetKVStore(), cloudletIPsApi.cache.Store, all.cloudletApi.cache.Store, all.clusterInstApi.cache.Store)
	return &cloudletIPsApi
}

func (s *CloudletIPsApi) ShowCloudletIPs(in *edgeproto.CloudletIPs, cb edgeproto.CloudletIPsApi_ShowCloudletIPsServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.CloudletIPs) error {
		err := cb.Send(obj)
		return err
	})
	return err
}
