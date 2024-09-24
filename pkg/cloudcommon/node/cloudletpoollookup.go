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

package node

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

// ZonePoolLookup interface used by events to determine if cloudlet
// is in a ZonePool for proper RBAC marking of events.
type ZonePoolLookup interface {
	InPool(region string, key edgeproto.ZoneKey) bool
	GetZonePoolCache(region string) *edgeproto.ZonePoolCache
	Dumpable() map[string]interface{}
}

type ZonePoolCache struct {
	cache       edgeproto.ZonePoolCache
	PoolsByZone edgeproto.ZonePoolByZoneKey
}

func (s *ZonePoolCache) Init() {
	edgeproto.InitZonePoolCache(&s.cache)
	s.PoolsByZone.Init()
	s.cache.AddUpdatedCb(s.updatedPool)
	s.cache.AddDeletedCb(s.deletedPool)
}

func (s *ZonePoolCache) updatedPool(ctx context.Context, old, new *edgeproto.ZonePool) {
	s.PoolsByZone.Updated(old, new)
}

func (s *ZonePoolCache) deletedPool(ctx context.Context, old *edgeproto.ZonePool) {
	s.PoolsByZone.Deleted(old)
}

func (s *ZonePoolCache) Dumpable() map[string]interface{} {
	return s.PoolsByZone.Dumpable()
}

func (s *ZonePoolCache) InPool(region string, key edgeproto.ZoneKey) bool {
	return s.PoolsByZone.HasRef(key)
}

func (s *ZonePoolCache) GetZonePoolCache(region string) *edgeproto.ZonePoolCache {
	return &s.cache
}
