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

package main

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/passhash"
	"github.com/sethvargo/go-password/password"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type CloudletNodeApi struct {
	all   *AllApis
	sync  *Sync
	store edgeproto.CloudletNodeStore
	cache edgeproto.CloudletNodeCache
}

func NewCloudletNodeApi(sync *Sync, all *AllApis) *CloudletNodeApi {
	api := CloudletNodeApi{}
	api.all = all
	api.sync = sync
	api.store = edgeproto.NewCloudletNodeStore(sync.store)
	edgeproto.InitCloudletNodeCache(&api.cache)
	sync.RegisterCache(&api.cache)
	return &api
}

func (s *CloudletNodeApi) CreateCloudletNode(ctx context.Context, in *edgeproto.CloudletNode) (*edgeproto.Result, error) {
	pass, err := s.CreateCloudletNodeReq(ctx, in)
	if err != nil {
		return &edgeproto.Result{}, err
	}
	return &edgeproto.Result{
		Message: pass,
	}, nil
}

func (s *CloudletNodeApi) UpdateCloudletNode(ctx context.Context, in *edgeproto.CloudletNode) (*edgeproto.Result, error) {
	if err := in.ValidateUpdateFields(); err != nil {
		return &edgeproto.Result{}, err
	}
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cur := edgeproto.CloudletNode{}
		if !s.store.STMGet(stm, &in.Key, &cur) {
			return in.Key.NotFoundError()
		}
		changeCount := cur.CopyInFields(in)
		if changeCount == 0 {
			// nothing changed
			return nil
		}
		s.store.STMPut(stm, &cur)
		return nil
	})
	if err != nil {
		return &edgeproto.Result{}, err
	}
	return &edgeproto.Result{}, nil
}

func (s *CloudletNodeApi) ShowCloudletNode(in *edgeproto.CloudletNode, cb edgeproto.CloudletNodeApi_ShowCloudletNodeServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.CloudletNode) error {
		cp := *obj
		cp.PasswordHash = ""
		cp.Salt = ""
		cp.Iter = 0
		return cb.Send(&cp)
	})
	return err
}

func (s *CloudletNodeApi) DeleteCloudletNode(ctx context.Context, in *edgeproto.CloudletNode) (*edgeproto.Result, error) {
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, nil) {
			return in.Key.NotFoundError()
		}
		s.store.STMDel(stm, &in.Key)
		return nil
	})
	return &edgeproto.Result{}, err
}

func (s *CloudletNodeApi) CreateCloudletNodeReq(ctx context.Context, node *edgeproto.CloudletNode) (string, error) {
	pass, err := password.Generate(48, 10, 10, false, false)
	if err != nil {
		return "", fmt.Errorf("failed to generate password: %s", err)
	}
	passhash, salt, iter := passhash.NewPasshash(pass)
	node.PasswordHash = passhash
	node.Salt = salt
	node.Iter = int32(iter)
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		nodeCheck := edgeproto.CloudletNode{}
		if s.store.STMGet(stm, &node.Key, &nodeCheck) {
			log.SpanLog(ctx, log.DebugLevelApi, "warning, node already exists, overwriting", "existing", nodeCheck)
		}
		cloudlet := edgeproto.Cloudlet{}
		if !s.all.cloudletApi.store.STMGet(stm, &node.Key.CloudletKey, &cloudlet) {
			return node.Key.CloudletKey.NotFoundError()
		}
		if cloudlet.DeletePrepare {
			return cloudlet.Key.BeingDeletedError()
		}
		s.store.STMPut(stm, node)
		return nil
	})
	if err != nil {
		return "", err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "created cloudlet node", "cloudlet", node.Key.CloudletKey, "name", node.Key.Name, "type", node.NodeType)
	return pass, nil
}

func (s *CloudletNodeApi) DeleteCloudletNodeReq(ctx context.Context, key *edgeproto.CloudletNodeKey) error {
	node := &edgeproto.CloudletNode{
		Key: *key,
	}
	_, err := s.DeleteCloudletNode(ctx, node)
	log.SpanLog(ctx, log.DebugLevelApi, "deleted cloudlet node", "node", key, "err", err)
	return err
}

func (s *CloudletNodeApi) cleanupNodes(ctx context.Context, key *edgeproto.CloudletKey) {
	toDelete := []*edgeproto.CloudletNode{}
	s.cache.Mux.Lock()
	for _, data := range s.cache.Objs {
		if key.Matches(&data.Obj.Key.CloudletKey) {
			toDelete = append(toDelete, data.Obj)
		}
	}
	s.cache.Mux.Unlock()
	for _, val := range toDelete {
		s.store.Delete(ctx, val, s.sync.syncWait)
	}
}
