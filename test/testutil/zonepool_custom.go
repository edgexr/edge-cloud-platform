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

package testutil

import (
	"context"
	fmt "fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

func (s *DummyServer) AddZonePoolMember(ctx context.Context, in *edgeproto.ZonePoolMember) (*edgeproto.Result, error) {
	cache := &s.ZonePoolCache

	cache.Mux.Lock()
	defer cache.Mux.Unlock()
	data, found := cache.Objs[in.Key]
	if !found {
		return &edgeproto.Result{}, in.Key.NotFoundError()
	}
	for ii, _ := range data.Obj.Zones {
		if data.Obj.Zones[ii].Matches(&in.Zone) {
			return &edgeproto.Result{}, fmt.Errorf("Already exists")
		}
	}
	data.Obj.Zones = append(data.Obj.Zones, &in.Zone)

	return &edgeproto.Result{}, nil
}

func (s *DummyServer) RemoveZonePoolMember(ctx context.Context, in *edgeproto.ZonePoolMember) (*edgeproto.Result, error) {
	cache := &s.ZonePoolCache

	cache.Mux.Lock()
	defer cache.Mux.Unlock()
	data, found := cache.Objs[in.Key]
	if !found {
		return &edgeproto.Result{}, in.Key.NotFoundError()
	}
	for ii, zone := range data.Obj.Zones {
		if zone.Matches(&in.Zone) {
			data.Obj.Zones = append(data.Obj.Zones[:ii], data.Obj.Zones[ii+1:]...)
			break
		}
	}

	return &edgeproto.Result{}, nil
}
