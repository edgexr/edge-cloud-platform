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
	"sort"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type PlatformFeaturesApi struct {
	all   *AllApis
	sync  *regiondata.Sync
	store edgeproto.PlatformFeaturesStore
	cache edgeproto.PlatformFeaturesCache
}

func NewPlatformFeaturesApi(sync *regiondata.Sync, all *AllApis) *PlatformFeaturesApi {
	platformFeaturesApi := PlatformFeaturesApi{}
	platformFeaturesApi.all = all
	platformFeaturesApi.sync = sync
	platformFeaturesApi.store = edgeproto.NewPlatformFeaturesStore(sync.GetKVStore())
	edgeproto.InitPlatformFeaturesCache(&platformFeaturesApi.cache)
	sync.RegisterCache(&platformFeaturesApi.cache)
	return &platformFeaturesApi
}

func (s *PlatformFeaturesApi) ShowPlatformFeatures(in *edgeproto.PlatformFeatures, cb edgeproto.PlatformFeaturesApi_ShowPlatformFeaturesServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.PlatformFeatures) error {
		if obj.IsFake && !*testMode {
			// don't show users fake platforms, they are only for testing
			return nil
		}
		return cb.Send(obj)
	})
	return err
}

// DeletePlatformFeatures for platforms that are no longer supported.
// PlatformFeatures are populated by CCRMs, but we do not clean
// them up if a CCRM goes offline because there may still be Cloudlets
// referencing them. If the CCRM is not just temporarily offline,
// but has been removed from the system, then this API allows the
// admin the manually remove features for platforms that are no
// longer supported.
func (s *PlatformFeaturesApi) DeletePlatformFeatures(ctx context.Context, in *edgeproto.PlatformFeatures) (res *edgeproto.Result, reterr error) {
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cur := edgeproto.PlatformFeatures{}
		if !s.store.STMGet(stm, in.GetKey(), &cur) {
			return in.GetKey().NotFoundError()
		}
		if cur.DeletePrepare {
			return in.GetKey().BeingDeletedError()
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
			cur := edgeproto.PlatformFeatures{}
			if !s.store.STMGet(stm, in.GetKey(), &cur) {
				return nil
			}
			if cur.DeletePrepare {
				cur.DeletePrepare = false
				s.store.STMPut(stm, &cur)
			}
			return nil
		})
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to undo delete prepare", "key", in.GetKey(), "err", undoErr)
		}
	}()
	if inuse, keys := s.all.cloudletApi.UsesPlatformFeatures(in.GetKey()); inuse {
		return &edgeproto.Result{}, fmt.Errorf("PlatformType in use by Cloudlets %s", strings.Join(keys, ", "))
	}
	return s.store.Delete(ctx, in, s.sync.SyncWait)
}

func (s *PlatformFeaturesApi) ShowPlatformFeaturesForZone(key *edgeproto.ZoneKey, cb edgeproto.PlatformFeaturesApi_ShowPlatformFeaturesForZoneServer) error {
	ctx := cb.Context()
	// collect matching zone keys
	zoneKeys := map[edgeproto.ZoneKey]struct{}{}
	filter := edgeproto.Zone{
		Key: *key,
	}
	err := s.all.zoneApi.cache.Show(&filter, func(zone *edgeproto.Zone) error {
		zoneKeys[zone.Key] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	// collect platform types for matching zones
	platforms := map[string]struct{}{}
	err = s.all.cloudletApi.cache.Show(&edgeproto.Cloudlet{}, func(cloudlet *edgeproto.Cloudlet) error {
		zoneKey := cloudlet.GetZone()
		if zoneKey.IsSet() {
			if _, found := zoneKeys[*zoneKey]; found {
				platforms[cloudlet.PlatformType] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// get all the platform features
	pfs := []*edgeproto.PlatformFeatures{}
	for pftype := range platforms {
		pf, err := s.GetCloudletFeatures(ctx, pftype)
		if err != nil {
			return err
		}
		pfs = append(pfs, pf)
	}
	// sort for deterministic output
	sort.Slice(pfs, func(i, j int) bool {
		return pfs[i].PlatformType < pfs[j].PlatformType
	})
	for _, pf := range pfs {
		if err := cb.Send(pf); err != nil {
			return err
		}
	}
	return nil
}

func (s *PlatformFeaturesApi) GetCloudletFeatures(ctx context.Context, platformType string) (*edgeproto.PlatformFeatures, error) {
	key := edgeproto.PlatformFeaturesKey(platformType)
	features := edgeproto.PlatformFeatures{}
	if !s.cache.Get(&key, &features) {
		return nil, key.NotFoundError()
	}
	return &features, nil
}

// Update platformFeatures, sent by CCRM to Controller
func (s *PlatformFeaturesApi) Update(ctx context.Context, in *edgeproto.PlatformFeatures, rev int64) {
	// Write to Etcd the features sent by the CCRM so it will persist
	// even it the CCRM goes offline in case there are cloudlets still
	// using it.
	res, err := s.store.Put(ctx, in, s.sync.SyncWait)
	log.SpanLog(ctx, log.DebugLevelApi, "put platform features", "platformType", in.PlatformType, "nodeType", in.NodeType, "res", res, "err", err)
}

func (s *PlatformFeaturesApi) Delete(ctx context.Context, in *edgeproto.PlatformFeatures, rev int64) {
	// require admin to remove platforms
}

func (s *PlatformFeaturesApi) Prune(ctx context.Context, keys map[edgeproto.PlatformFeaturesKey]struct{}) {
	// require admin to remove platforms
}

func (s *PlatformFeaturesApi) Flush(ctx context.Context, notifyId int64) {
	// require admin to remove platforms
}

func (s *PlatformFeaturesApi) FeaturesByPlatform() map[string]edgeproto.PlatformFeatures {
	ptof := map[string]edgeproto.PlatformFeatures{}
	s.cache.Show(&edgeproto.PlatformFeatures{}, func(features *edgeproto.PlatformFeatures) error {
		ptof[features.PlatformType] = *features
		return nil
	})
	return ptof
}
