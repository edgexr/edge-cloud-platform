package main

import (
	"fmt"

	"github.com/coreos/etcd/clientv3/concurrency"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type TrustPolicyApi struct {
	all   *AllApis
	sync  *Sync
	store edgeproto.TrustPolicyStore
	cache edgeproto.TrustPolicyCache
}

func NewTrustPolicyApi(sync *Sync, all *AllApis) *TrustPolicyApi {
	trustPolicyApi := TrustPolicyApi{}
	trustPolicyApi.all = all
	trustPolicyApi.sync = sync
	trustPolicyApi.store = edgeproto.NewTrustPolicyStore(sync.store)
	edgeproto.InitTrustPolicyCache(&trustPolicyApi.cache)
	sync.RegisterCache(&trustPolicyApi.cache)
	return &trustPolicyApi
}

func (s *TrustPolicyApi) CreateTrustPolicy(in *edgeproto.TrustPolicy, cb edgeproto.TrustPolicyApi_CreateTrustPolicyServer) error {
	ctx := cb.Context()
	log.SpanLog(ctx, log.DebugLevelApi, "CreateTrustPolicy", "policy", in)

	// port range max is optional, set it to min if min is present but not max
	for i, o := range in.OutboundSecurityRules {
		if o.PortRangeMax == 0 {
			log.SpanLog(ctx, log.DebugLevelApi, "Setting PortRangeMax equal to min", "PortRangeMin", o.PortRangeMin)
			in.OutboundSecurityRules[i].PortRangeMax = o.PortRangeMin
		}
	}
	if err := in.Validate(nil); err != nil {
		return err
	}
	_, err := s.store.Create(ctx, in, s.sync.syncWait)
	return err

}

func (s *TrustPolicyApi) UpdateTrustPolicy(in *edgeproto.TrustPolicy, cb edgeproto.TrustPolicyApi_UpdateTrustPolicyServer) error {
	ctx := cb.Context()
	cur := edgeproto.TrustPolicy{}
	changed := 0

	// port range max is optional, set it to min if min is present but not max
	for i, o := range in.OutboundSecurityRules {
		if o.PortRangeMax == 0 {
			log.SpanLog(ctx, log.DebugLevelApi, "Setting PortRangeMax equal to min", "PortRangeMin", o.PortRangeMin, "TrustPolicy:", in.GetKey().Name)
			in.OutboundSecurityRules[i].PortRangeMax = o.PortRangeMin
		}
	}

	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		changed = cur.CopyInFields(in)
		if err := cur.Validate(nil); err != nil {
			return err
		}
		if err := s.all.cloudletApi.ValidateCloudletsUsingTrustPolicy(ctx, &cur); err != nil {
			return err
		}
		if changed == 0 {
			return nil
		}
		s.store.STMPut(stm, &cur)
		return nil
	})
	if err != nil {
		return err
	}
	return s.all.cloudletApi.UpdateCloudletsUsingTrustPolicy(ctx, &cur, cb)
}

func (s *TrustPolicyApi) DeleteTrustPolicy(in *edgeproto.TrustPolicy, cb edgeproto.TrustPolicyApi_DeleteTrustPolicyServer) (reterr error) {
	ctx := cb.Context()
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cur := edgeproto.TrustPolicy{}
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		if cur.DeletePrepare {
			return fmt.Errorf("AutoProvPolicy already being deleted")
		}
		cur.DeletePrepare = true
		s.store.STMPut(stm, &cur)
		return nil
	})
	if err != nil {
		return err
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			cur := edgeproto.TrustPolicy{}
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

	// look for cloudlets in any state
	if k := s.all.cloudletApi.UsesTrustPolicy(&in.Key, edgeproto.TrackedState_TRACKED_STATE_UNKNOWN); k != nil {
		return fmt.Errorf("Policy in use by Cloudlet %s", k.GetKeyString())
	}
	_, err = s.store.Delete(ctx, in, s.sync.syncWait)
	return err
}

func (s *TrustPolicyApi) ShowTrustPolicy(in *edgeproto.TrustPolicy, cb edgeproto.TrustPolicyApi_ShowTrustPolicyServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.TrustPolicy) error {
		err := cb.Send(obj)
		return err
	})
	return err
}

func (s *TrustPolicyApi) STMFind(stm concurrency.STM, name, org string, policy *edgeproto.TrustPolicy) error {
	key := edgeproto.PolicyKey{}
	key.Name = name
	key.Organization = org
	if !s.store.STMGet(stm, &key, policy) {
		return fmt.Errorf("TrustPolicy %s for organization %s not found", name, org)
	}
	return nil
}

func (s *TrustPolicyApi) GetTrustPolicies(policies map[edgeproto.PolicyKey]*edgeproto.TrustPolicy) {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for _, data := range s.cache.Objs {
		pol := data.Obj
		copy := &edgeproto.TrustPolicy{}
		copy.DeepCopyIn(pol)
		policies[pol.Key] = copy
	}
}
