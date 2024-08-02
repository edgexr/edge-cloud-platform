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

package ccrm

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"go.etcd.io/etcd/client/v3/concurrency"
)

// ApplyAppInst implements a GRPC AppInstPlatform server method
func (s *CCRMHandler) ApplyAppInst(in *edgeproto.AppInst, stream edgeproto.AppInstPlatformAPI_ApplyAppInstServer) error {
	ctx := stream.Context()
	responseSender := edgeproto.NewAppInstInfoSendUpdater(ctx, stream, in.Key)
	needsUpdate, err := s.crmHandler.AppInstChanged(ctx, &in.Key.CloudletKey, in, responseSender)
	if err == nil && needsUpdate.Resources {
		s.vmResourceActionEnd(ctx, &in.Key.CloudletKey)
	}
	if err == nil && needsUpdate.AppInstRuntime {
		s.refreshAppInstRuntime(ctx, &in.Key.CloudletKey, nil, in)
	}
	return err
}

func (s *CCRMHandler) ApplyTrustPolicyException(ctx context.Context, in *edgeproto.TPEInstanceState) (*edgeproto.Result, error) {
	err := s.crmHandler.HandleTrustPolicyException(ctx, in)
	return &edgeproto.Result{}, err
}

func (s *CCRMHandler) refreshAppInstRuntime(ctx context.Context, cloudletKey *edgeproto.CloudletKey, clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst) {
	err := s.crmHandler.RefreshAppInstRuntime(ctx, cloudletKey, clusterInst, appInst, func(ctx context.Context, key *edgeproto.AppInstKey, rt *edgeproto.AppInstRuntime, getRuntimeErr error) {
		if getRuntimeErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to get runtime info for appinst", "appinst", key, "err", getRuntimeErr)
		} else if rt != nil {
			_, err := s.sync.GetKVStore().ApplySTM(ctx, func(stm concurrency.STM) error {
				inst := edgeproto.AppInst{}
				if !s.crmHandler.AppInstCache.Store.STMGet(stm, &appInst.Key, &inst) {
					// deleted in the meantime?
					return nil
				}
				inst.RuntimeInfo = *rt
				s.crmHandler.AppInstCache.Store.STMPut(stm, &inst)
				return nil
			})
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to write appinst runtime", "appinst", key, "err", err)
			}
		}
	})
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to refresh appinst runtime", "err", err)
	}
}
