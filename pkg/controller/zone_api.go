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
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
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
	cloudlets := s.all.cloudletApi.CloudletsUsingZone(&in.Key)
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

// getZoneByID finds the Zone by ID. If not found returns nil Zone instead
// of an error.
func (s *ZoneApi) getZoneByID(ctx context.Context, id string) (*edgeproto.Zone, error) {
	filter := &edgeproto.Zone{
		ObjId: id,
	}
	var zone *edgeproto.Zone
	err := s.cache.Show(filter, func(obj *edgeproto.Zone) error {
		zone = obj
		return nil
	})
	if err != nil {
		return nil, err
	}
	return zone, nil
}

func (s *ZoneApi) ShowZoneGPUs(filter *edgeproto.Zone, cb edgeproto.ZoneApi_ShowZoneGPUsServer) error {
	ctx := cb.Context()
	// get all matching zones
	zones := []edgeproto.ZoneKey{}
	err := s.cache.Show(filter, func(zone *edgeproto.Zone) error {
		zones = append(zones, zone.Key)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(zones, func(i, j int) bool {
		return zones[i].GetKeyString() < zones[j].GetKeyString()
	})
	for _, zkey := range zones {
		zoneGPUs, err := s.getZoneGPUs(ctx, &zkey)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to get GPUs for zone", "zone", zkey, "err", err)
			continue
		}
		if len(zoneGPUs.Gpus) == 0 {
			continue
		}
		err = cb.Send(zoneGPUs)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *ZoneApi) getZoneGPUs(ctx context.Context, zkey *edgeproto.ZoneKey) (*edgeproto.ZoneGPUs, error) {
	// get all cloudlets for zone
	ckeys := []edgeproto.CloudletKey{}
	err := s.all.cloudletApi.cache.Show(&edgeproto.Cloudlet{}, func(cloudlet *edgeproto.Cloudlet) error {
		if cloudlet.Key.Organization != zkey.Organization {
			return nil
		}
		if cloudlet.Zone != zkey.Name {
			return nil
		}
		ckeys = append(ckeys, cloudlet.Key)
		return nil
	})
	if err != nil {
		return nil, err
	}
	usedVals := resspec.ResValMap{}
	limits := ResLimitMap{}
	gpuInfos := map[string]*edgeproto.GPUResource{}

	for _, ckey := range ckeys {
		if err := s.all.cloudletApi.addGPUsUsage(ctx, &ckey, usedVals, limits, gpuInfos); err != nil {
			return nil, err
		}
	}
	gpus := []*edgeproto.GPUResource{}
	for _, gpu := range gpuInfos {
		resKey := edgeproto.BuildResKey(cloudcommon.ResourceTypeGPU, gpu.ModelId)
		max := 0
		if limit, ok := limits[resKey]; ok {
			if limit.QuotaMaxValue > 0 {
				max = int(limit.QuotaMaxValue)
			} else {
				max = int(limit.InfraMaxValue)
			}
		}
		used := 0
		if res, ok := usedVals[resKey]; ok {
			used = int(res.Value.Whole)
		}
		// set gpu count to 1 if there are gpus available
		if max == 0 || max > used {
			gpu.Count = 1
		} else {
			gpu.Count = 0
		}
		gpus = append(gpus, gpu)
	}
	sort.Slice(gpus, func(i, j int) bool {
		return gpus[i].ModelId < gpus[j].ModelId
	})
	zoneGPUs := &edgeproto.ZoneGPUs{
		ZoneKey: *zkey,
		Gpus:    gpus,
	}
	return zoneGPUs, nil
}
