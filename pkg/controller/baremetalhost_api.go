// Copyright 2026 EdgeXR, Inc
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
	"errors"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
)

type BareMetalHostApi struct {
	all *AllApis
}

func NewBareMetalHostApi(sync *regiondata.Sync, all *AllApis) *BareMetalHostApi {
	return &BareMetalHostApi{
		all: all,
	}
}

func (s *BareMetalHostApi) ShowBareMetalHost(in *edgeproto.BareMetalHost, cb edgeproto.BareMetalHostApi_ShowBareMetalHostServer) error {
	ctx := cb.Context()
	keys := []edgeproto.CloudletKey{}
	filter := edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			Organization: in.Key.Organization,
			Name:         in.Key.Cloudlet,
		},
	}
	err := s.all.cloudletApi.cache.Show(&filter, func(obj *edgeproto.Cloudlet) error {
		keys = append(keys, obj.Key)
		return nil
	})
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	errs := []string{}
	for _, key := range keys {
		err = s.showBareMetalHosts(ctx, &key, in, cb)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", key.GetKeyString(), err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, ", "))
	}
	return nil
}

func (s *BareMetalHostApi) showBareMetalHosts(ctx context.Context, key *edgeproto.CloudletKey, filter *edgeproto.BareMetalHost, cb edgeproto.BareMetalHostApi_ShowBareMetalHostServer) error {
	cloudlet := edgeproto.Cloudlet{}
	if !s.all.cloudletApi.cache.Get(key, &cloudlet) {
		return key.NotFoundError()
	}
	// only supports CCRM-based cloudlets
	if cloudlet.CrmOnEdge {
		return nil
	}
	features := edgeproto.PlatformFeatures{}
	featuresKey := edgeproto.PlatformFeaturesKey(cloudlet.PlatformType)
	if !s.all.platformFeaturesApi.cache.Get(&featuresKey, &features) {
		return featuresKey.NotFoundError()
	}
	if !features.SupportsBareMetal {
		return nil
	}
	conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
	if err != nil {
		return err
	}
	api := edgeproto.NewCloudletPlatformAPIClient(conn)
	outStream, err := api.GetBareMetalHosts(ctx, key)
	if err != nil {
		return err
	}
	return cloudcommon.StreamRecv(ctx, outStream, func(obj *edgeproto.BareMetalHost) error {
		if obj.Matches(filter, edgeproto.MatchFilter()) {
			return cb.Send(obj)
		}
		return nil
	})
}
