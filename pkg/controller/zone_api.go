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

package controller

import (
	"context"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/oklog/ulid/v2"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type ZoneApi struct {
	all   *AllApis
	sync  *regiondata.Sync
	store edgeproto.ZoneStore
	cache edgeproto.ZoneCache
}

func NewZoneApi(sync *regiondata.Sync, all *AllApis) *ZoneApi {
	zoneApi := ZoneApi{}
	zoneApi.all = all
	zoneApi.sync = sync
	zoneApi.cache.InitCacheWithSync(sync)
	zoneApi.store = zoneApi.cache.Store
	return &zoneApi
}

func (s *ZoneApi) CreateZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	// Note: federated Zones are only created internally by the system.
	// Users cannot create federated Zones.
	if err := in.Validate(edgeproto.ZoneAllFieldsMap); err != nil {
		return &edgeproto.Result{}, err
	}
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if s.store.STMGet(stm, &in.Key, nil) {
			return in.Key.ExistsError()
		}
		// for federation, id must be lower case
		in.ObjId = strings.ToLower(ulid.Make().String())
		s.store.STMPut(stm, in)
		return nil
	})
	return &edgeproto.Result{}, err
}

func (s *ZoneApi) DeleteZone(ctx context.Context, in *edgeproto.Zone) (res *edgeproto.Result, reterr error) {
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, in) {
			return in.Key.NotFoundError()
		}
		if in.DeletePrepare {
			return in.Key.BeingDeletedError()
		}
		// set delete prepare so no new instances can be created
		in.DeletePrepare = true
		s.store.STMPut(stm, in)
		return nil
	})
	if err != nil {
		return &edgeproto.Result{}, err
	}
	// undo temporary state change if there was a failure
	defer func() {
		if reterr == nil {
			return
		}
		// revert delete prepare and temporarily retired cloudlets
		undoErr := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			if !s.store.STMGet(stm, &in.Key, in) {
				return in.Key.NotFoundError()
			}
			in.DeletePrepare = false
			s.store.STMPut(stm, in)
			return nil
		})
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to undo zone delete", "zone", in.Key, "undoErr", undoErr)
		}
	}()

	autoProvPolicies := s.all.autoProvPolicyApi.UsesZone(&in.Key)
	if len(autoProvPolicies) > 0 {
		strs := []string{}
		for _, key := range autoProvPolicies {
			strs = append(strs, key.GetKeyString())
		}
		return &edgeproto.Result{}, fmt.Errorf("zone in use by AutoProvPolicy %s", strings.Join(strs, ", "))
	}
	cloudlets := s.all.cloudletApi.UsesZone(&in.Key)
	if len(cloudlets) > 0 {
		return &edgeproto.Result{}, fmt.Errorf("zone in use by cloudlets %s", strings.Join(cloudlets, ", "))
	}
	zonePoolKeys := s.all.zonePoolApi.UsesZone(&in.Key)
	if len(zonePoolKeys) > 0 {
		strs := []string{}
		for _, key := range zonePoolKeys {
			strs = append(strs, key.GetKeyString())
		}
		return &edgeproto.Result{}, fmt.Errorf("zone in use by ZonePool %s", strings.Join(strs, ", "))
	}

	// Delete zone
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		zone := &edgeproto.Zone{}
		if !s.store.STMGet(stm, &in.Key, zone) {
			return in.Key.NotFoundError()
		}
		if !zone.DeletePrepare {
			return fmt.Errorf("delete zone %s expected zone to be in delete prepare, but was not", in.Key.GetKeyString())
		}
		s.store.STMDel(stm, &in.Key)
		return nil
	})
	return &edgeproto.Result{}, err
}

func (s *ZoneApi) UpdateZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	if err := in.ValidateUpdateFields(); err != nil {
		return &edgeproto.Result{}, err
	}

	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		zone := &edgeproto.Zone{}
		if !s.store.STMGet(stm, &in.Key, zone) {
			return in.Key.NotFoundError()
		}
		if zone.DeletePrepare {
			return in.Key.BeingDeletedError()
		}
		changed := zone.CopyInFields(in)
		if changed == 0 {
			return nil
		}
		s.store.STMPut(stm, zone)
		return nil
	})
	return &edgeproto.Result{}, err
}

func (s *ZoneApi) ShowZone(in *edgeproto.Zone, cb edgeproto.ZoneApi_ShowZoneServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.Zone) error {
		err := cb.Send(obj)
		return err
	})
	return err
}
