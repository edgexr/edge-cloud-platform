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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type TrustPolicyExceptionApi struct {
	all       *AllApis
	sync      *regiondata.Sync
	store     edgeproto.TrustPolicyExceptionStore
	cache     edgeproto.TrustPolicyExceptionCache
	instStore edgeproto.TPEInstanceStateStore
	instCache edgeproto.TPEInstanceStateCache
}

func NewTrustPolicyExceptionApi(sync *regiondata.Sync, all *AllApis) *TrustPolicyExceptionApi {
	trustPolicyExceptionApi := TrustPolicyExceptionApi{}
	trustPolicyExceptionApi.all = all
	trustPolicyExceptionApi.sync = sync
	trustPolicyExceptionApi.store = edgeproto.NewTrustPolicyExceptionStore(sync.GetKVStore())
	trustPolicyExceptionApi.instStore = edgeproto.NewTPEInstanceStateStore(sync.GetKVStore())
	edgeproto.InitTrustPolicyExceptionCache(&trustPolicyExceptionApi.cache)
	edgeproto.InitTPEInstanceStateCache(&trustPolicyExceptionApi.instCache)
	sync.RegisterCache(&trustPolicyExceptionApi.cache)
	sync.RegisterCache(&trustPolicyExceptionApi.instCache)
	return &trustPolicyExceptionApi
}

func (s *TrustPolicyExceptionApi) CreateTrustPolicyException(ctx context.Context, in *edgeproto.TrustPolicyException) (*edgeproto.Result, error) {

	log.SpanLog(ctx, log.DebugLevelApi, "CreateTrustPolicyException", "policy", in)
	in.FixupSecurityRules(ctx)
	if err := in.Validate(nil); err != nil {
		return nil, err
	}
	in.State = edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_APPROVAL_REQUESTED
	log.SpanLog(ctx, log.DebugLevelApi, "Setting TrustPolicyExceptionState", "state", in.State)

	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if s.store.STMGet(stm, &in.Key, nil) {
			return in.Key.ExistsError()
		}
		app := edgeproto.App{}
		if !s.all.appApi.store.STMGet(stm, &in.Key.AppKey, &app) {
			return in.Key.AppKey.NotFoundError()
		}
		if app.DeletePrepare {
			return in.Key.AppKey.BeingDeletedError()
		}
		if !app.Trusted {
			return fmt.Errorf("Non trusted app: %s not compatible with trust policy: %s", strings.TrimSpace(app.Key.String()), in.Key.String())
		}
		zonePool := edgeproto.ZonePool{}
		if !s.all.zonePoolApi.store.STMGet(stm, &in.Key.ZonePoolKey, &zonePool) {
			return in.Key.ZonePoolKey.NotFoundError()
		}
		if zonePool.DeletePrepare {
			return in.Key.ZonePoolKey.BeingDeletedError()
		}
		s.store.STMPut(stm, in)
		return nil
	})
	return &edgeproto.Result{}, err
}

func (s *TrustPolicyExceptionApi) UpdateTrustPolicyException(ctx context.Context, in *edgeproto.TrustPolicyException) (res *edgeproto.Result, reterr error) {

	log.SpanLog(ctx, log.DebugLevelApi, "UpdateTrustPolicyException", "policy", in)

	cur := edgeproto.TrustPolicyException{}

	fmap := edgeproto.MakeFieldMap(in.Fields)

	rulesSpecified := fmap.HasOrHasChild(edgeproto.TrustPolicyExceptionFieldOutboundSecurityRules)

	var oldState, newState edgeproto.TrustPolicyExceptionState
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		log.SpanLog(ctx, log.DebugLevelApi, "UpdateTrustPolicyException", "in state", in.State.String(), "cur state", cur.State.String())
		oldState = cur.State

		stateSpecified := fmap.Has(edgeproto.TrustPolicyExceptionFieldState)
		if stateSpecified {
			// caller specified state change, for an update, an operator can only specify state
			if in.State != edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_ACTIVE &&
				in.State != edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_REJECTED {
				return fmt.Errorf("New state must be either Active or Rejected")
			}
		}
		if rulesSpecified && cur.State != edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_APPROVAL_REQUESTED {
			return fmt.Errorf("Can update security rules only when trust policy exception is still in approval requested state")
		}

		if !stateSpecified && !rulesSpecified {
			log.SpanLog(ctx, log.DebugLevelApi, "UpdateTrustPolicyException rule/state not changed", "state", cur.State.String())
			return nil
		}
		// Copy in user specified fields only
		changed := cur.CopyInFields(in)
		if changed == 0 {
			log.SpanLog(ctx, log.DebugLevelApi, "UpdateTrustPolicyException no changes", "state", cur.State.String())
			return nil // no changes
		}
		cur.FixupSecurityRules(ctx)
		// Use validate to make sure rules are not empty
		if err := cur.Validate(nil); err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelApi, "UpdateTrustPolicyException", "state", cur.State.String())
		s.store.STMPut(stm, &cur)
		newState = cur.State
		return nil
	})

	if err != nil {
		return nil, err
	}

	if newState != oldState {
		if newState == edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_ACTIVE || newState == edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_REJECTED {
			s.applyTPE(ctx, in.Key)
		}
	}
	return &edgeproto.Result{}, nil
}

func (s *TrustPolicyExceptionApi) DeleteTrustPolicyException(ctx context.Context, in *edgeproto.TrustPolicyException) (*edgeproto.Result, error) {
	wasActive := false
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cur := edgeproto.TrustPolicyException{}
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		if cur.State == edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_ACTIVE {
			wasActive = true
		}
		s.store.STMDel(stm, &in.Key)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if wasActive {
		s.applyTPE(ctx, in.Key)
	}
	return &edgeproto.Result{}, nil
}

func (s *TrustPolicyExceptionApi) ShowTrustPolicyException(in *edgeproto.TrustPolicyException, cb edgeproto.TrustPolicyExceptionApi_ShowTrustPolicyExceptionServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.TrustPolicyException) error {
		err := cb.Send(obj)
		return err
	})
	return err
}

func (s *TrustPolicyExceptionApi) GetTrustPolicyExceptionRules(ckey *edgeproto.ZonePoolKey, appKey *edgeproto.AppKey) []*edgeproto.SecurityRule {
	var rules []*edgeproto.SecurityRule

	filter := edgeproto.TrustPolicyException{
		Key: edgeproto.TrustPolicyExceptionKey{
			ZonePoolKey: *ckey,
			AppKey:          *appKey,
		},
	}

	s.cache.Show(&filter, func(pol *edgeproto.TrustPolicyException) error {
		for _, r := range pol.OutboundSecurityRules {
			rule := edgeproto.SecurityRule{}
			rule.DeepCopyIn(&r)
			rules = append(rules, &rule)
		}
		return nil
	})

	return rules
}

func (s *TrustPolicyExceptionApi) GetTrustPolicyExceptionForZonePoolKey(cKey *edgeproto.ZonePoolKey) *edgeproto.TrustPolicyException {

	var TrustPolicyException *edgeproto.TrustPolicyException

	filter := edgeproto.TrustPolicyException{
		Key: edgeproto.TrustPolicyExceptionKey{
			ZonePoolKey: *cKey,
		},
	}

	s.cache.Show(&filter, func(tpe *edgeproto.TrustPolicyException) error {
		TrustPolicyException = tpe
		return nil
	})

	return TrustPolicyException
}

func (s *TrustPolicyExceptionApi) TrustPolicyExceptionForZonePoolKeyExists(cKey *edgeproto.ZonePoolKey) *edgeproto.TrustPolicyExceptionKey {
	tpe := s.GetTrustPolicyExceptionForZonePoolKey(cKey)
	if tpe != nil {
		return &tpe.Key
	}
	return nil
}

func (s *TrustPolicyExceptionApi) GetTrustPolicyExceptionForAppKey(appKey *edgeproto.AppKey) *edgeproto.TrustPolicyException {

	var TrustPolicyException *edgeproto.TrustPolicyException

	filter := edgeproto.TrustPolicyException{
		Key: edgeproto.TrustPolicyExceptionKey{
			AppKey: *appKey,
		},
	}

	s.cache.Show(&filter, func(tpe *edgeproto.TrustPolicyException) error {
		TrustPolicyException = tpe
		return nil
	})

	return TrustPolicyException
}

func (s *TrustPolicyExceptionApi) TrustPolicyExceptionForAppKeyExists(appKey *edgeproto.AppKey) *edgeproto.TrustPolicyExceptionKey {
	tp := s.GetTrustPolicyExceptionForAppKey(appKey)
	if tp != nil {
		return &tp.Key
	}
	return nil
}
