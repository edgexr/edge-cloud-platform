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

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type ZonePoolApi struct {
	all   *AllApis
	sync  *regiondata.Sync
	store edgeproto.ZonePoolStore
	cache *edgeproto.ZonePoolCache
}

func NewZonePoolApi(sync *regiondata.Sync, all *AllApis) *ZonePoolApi {
	zonePoolApi := ZonePoolApi{}
	zonePoolApi.all = all
	zonePoolApi.sync = sync
	zonePoolApi.store = edgeproto.NewZonePoolStore(sync.GetKVStore())
	zonePoolApi.cache = nodeMgr.ZonePoolLookup.GetZonePoolCache(svcnode.NoRegion)
	sync.RegisterCache(zonePoolApi.cache)
	return &zonePoolApi
}

func (s *ZonePoolApi) CreateZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	if err := in.Validate(edgeproto.ZonePoolAllFieldsMap); err != nil {
		return &edgeproto.Result{}, err
	}

	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if s.store.STMGet(stm, &in.Key, nil) {
			return in.Key.ExistsError()
		}
		for ii, _ := range in.Zones {
			in.Zones[ii].Organization = in.Key.Organization
		}
		if err := s.checkZonesExist(stm, in); err != nil {
			return err
		}
		in.CreatedAt = dme.TimeToTimestamp(time.Now())
		s.store.STMPut(stm, in)
		return nil
	})
	return &edgeproto.Result{}, err
}

func (s *ZonePoolApi) DeleteZonePool(ctx context.Context, in *edgeproto.ZonePool) (res *edgeproto.Result, reterr error) {
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cur := edgeproto.ZonePool{}
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		if cur.DeletePrepare {
			return in.Key.BeingDeletedError()
		}
		cur.DeletePrepare = true
		s.store.STMPut(stm, &cur)
		return nil
	})
	if err != nil {
		return &edgeproto.Result{}, err
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			cur := edgeproto.ZonePool{}
			if !s.store.STMGet(stm, &in.Key, &cur) {
				return nil
			}
			if cur.DeletePrepare {
				cur.DeletePrepare = false
				s.store.STMPut(stm, &cur)
			}
			return nil
		})
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to undo delete prepare", "key", in.Key, "err", undoErr)
		}
	}()

	if tpeKey := s.all.trustPolicyExceptionApi.TrustPolicyExceptionForZonePoolKeyExists(&in.Key); tpeKey != nil {
		return &edgeproto.Result{}, fmt.Errorf("ZonePool in use by Trust Policy Exception %s", tpeKey.GetKeyString())
	}
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, nil) {
			return in.Key.NotFoundError()
		}
		s.store.STMDel(stm, &in.Key)
		return nil
	})
	return &edgeproto.Result{}, err
}

func (s *ZonePoolApi) UpdateZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	cur := edgeproto.ZonePool{}
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cur = edgeproto.ZonePool{}
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		for ii, _ := range in.Zones {
			in.Zones[ii].Organization = in.Key.Organization
		}
		changed := cur.CopyInFields(in)
		if err := cur.Validate(nil); err != nil {
			return err
		}
		if changed == 0 {
			return nil
		}
		if err := s.checkZonesExist(stm, &cur); err != nil {
			return err
		}
		if k := s.all.trustPolicyExceptionApi.TrustPolicyExceptionForZonePoolKeyExists(&in.Key); k != nil {
			return fmt.Errorf("Not allowed to update ZonePool when TrustPolicyException %s is applied", k.GetKeyString())
		}
		cur.UpdatedAt = dme.TimeToTimestamp(time.Now())
		s.store.STMPut(stm, &cur)
		return nil
	})
	return &edgeproto.Result{}, err
}

func (s *ZonePoolApi) checkZonesExist(stm concurrency.STM, in *edgeproto.ZonePool) error {
	notFound := []string{}
	for _, key := range in.Zones {
		key.Organization = in.Key.Organization
		zone := edgeproto.Zone{}
		if !s.all.zoneApi.store.STMGet(stm, key, &zone) {
			notFound = append(notFound, key.GetKeyString())
		}
		if zone.DeletePrepare {
			return key.BeingDeletedError()
		}
	}
	if len(notFound) > 0 {
		return fmt.Errorf("Zones %s not found", strings.Join(notFound, ", "))
	}
	return nil
}

func (s *ZonePoolApi) ShowZonePool(in *edgeproto.ZonePool, cb edgeproto.ZonePoolApi_ShowZonePoolServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.ZonePool) error {
		err := cb.Send(obj)
		return err
	})
	return err
}

func (s *ZonePoolApi) AddZonePoolMember(ctx context.Context, in *edgeproto.ZonePoolMember) (*edgeproto.Result, error) {
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cur := edgeproto.ZonePool{}
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		in.Zone.Organization = in.Key.Organization
		for _, clKey := range cur.Zones {
			if clKey.Matches(&in.Zone) {
				return fmt.Errorf("Zone already part of pool")
			}
		}
		cur.Zones = append(cur.Zones, &in.Zone)
		if err := s.checkZonesExist(stm, &cur); err != nil {
			return err
		}
		s.store.STMPut(stm, &cur)
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.all.trustPolicyExceptionApi.applyAllTPEsForZoneInPool(ctx, in.Zone, in.Key)
	return &edgeproto.Result{}, err
}

func (s *ZonePoolApi) RemoveZonePoolMember(ctx context.Context, in *edgeproto.ZonePoolMember) (*edgeproto.Result, error) {
	cur := edgeproto.ZonePool{}
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cur = edgeproto.ZonePool{}
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		changed := false
		in.Zone.Organization = in.Key.Organization
		for ii, _ := range cur.Zones {
			if cur.Zones[ii].Matches(&in.Zone) {
				cur.Zones = append(cur.Zones[:ii], cur.Zones[ii+1:]...)
				changed = true
				break
			}
		}
		if !changed {
			return nil
		}
		s.store.STMPut(stm, &cur)
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.all.trustPolicyExceptionApi.applyAllTPEsForZoneInPool(ctx, in.Zone, in.Key)
	return &edgeproto.Result{}, err
}

func (s *ZonePoolApi) GetZonePoolKeysForZoneKey(in *edgeproto.ZoneKey) []edgeproto.ZonePoolKey {
	return s.cache.GetPoolsForZoneKey(in)
}

func (s *ZonePoolApi) HasZonePool(key *edgeproto.ZonePoolKey) bool {
	return s.cache.HasKey(key)
}

func (s *ZonePoolApi) validateZonePoolExists(key *edgeproto.ZonePoolKey) bool {
	return s.HasZonePool(key)
}

func (s *ZonePoolApi) UsesZone(key *edgeproto.ZoneKey) []edgeproto.ZonePoolKey {
	zKeys := []edgeproto.ZonePoolKey{}
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for zKey, data := range s.cache.Objs {
		if zKey.Organization != key.Organization {
			continue
		}
		pool := data.Obj
		for _, zoneKey := range pool.Zones {
			if zoneKey.Matches(key) {
				zKeys = append(zKeys, zKey)
				break
			}
		}
	}
	return zKeys
}
