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

package edgeproto

import (
	"sync"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	context "golang.org/x/net/context"
)

type FreeReservableClusterInstCache struct {
	InstsByCloudlet map[CloudletKey]map[ClusterKey]*ClusterInst
	KeyToCloudlet   map[ClusterKey]CloudletKey // for delete
	Mux             sync.Mutex
}

func (s *FreeReservableClusterInstCache) Init() {
	s.InstsByCloudlet = make(map[CloudletKey]map[ClusterKey]*ClusterInst)
	s.KeyToCloudlet = make(map[ClusterKey]CloudletKey)
}

func (s *FreeReservableClusterInstCache) Update(ctx context.Context, in *ClusterInst, rev int64) {
	if !in.Reservable {
		return
	}
	s.Mux.Lock()
	defer s.Mux.Unlock()
	cinsts, found := s.InstsByCloudlet[in.CloudletKey]
	if !found {
		cinsts = make(map[ClusterKey]*ClusterInst)
		s.InstsByCloudlet[in.CloudletKey] = cinsts
	}
	if in.ReservedBy != "" {
		delete(cinsts, in.Key)
		delete(s.KeyToCloudlet, in.Key)
	} else {
		cinsts[in.Key] = in
		s.KeyToCloudlet[in.Key] = in.CloudletKey
	}
}

func (s *FreeReservableClusterInstCache) Delete(ctx context.Context, in *ClusterInst, rev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	// The passed in ClusterInst is only guaranteed to have the
	// key set. To be able to look up by cloudlet, we maintain a
	// separate lookup table to map cluster keys to cloudlet keys.
	cloudletKey, ok := s.KeyToCloudlet[in.Key]
	if !ok {
		return
	}
	cinsts, found := s.InstsByCloudlet[cloudletKey]
	if !found {
		return
	}
	delete(cinsts, in.Key)
	if len(cinsts) == 0 {
		delete(s.InstsByCloudlet, in.CloudletKey)
	}
	delete(s.KeyToCloudlet, in.Key)
}

func (s *FreeReservableClusterInstCache) Prune(ctx context.Context, validKeys map[ClusterKey]struct{}) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for cloudletKey, cmap := range s.InstsByCloudlet {
		for clusterKey, _ := range cmap {
			if _, ok := validKeys[clusterKey]; !ok {
				delete(cmap, clusterKey)
				delete(s.KeyToCloudlet, clusterKey)
			}
		}
		if len(cmap) == 0 {
			delete(s.InstsByCloudlet, cloudletKey)
		}
	}
}

func (s *FreeReservableClusterInstCache) Flush(ctx context.Context, notifyId int64) {}

func (s *FreeReservableClusterInstCache) GetForCloudlet(key *CloudletKey, deployment, flavor string, deploymentTransformFunc func(string) string) *ClusterKey {
	// need a transform func to avoid import cycle
	deployment = deploymentTransformFunc(deployment)
	s.Mux.Lock()
	defer s.Mux.Unlock()
	cinsts, found := s.InstsByCloudlet[*key]
	log.DebugLog(log.DebugLevelDmereq, "GetForCloudlet", "key", *key, "found", found, "num-insts", len(cinsts))
	if found && len(cinsts) > 0 {
		for key, clust := range cinsts {
			if deployment == clust.Deployment && flavor == clust.Flavor.Name {
				return &key
			}
		}
	}
	return nil
}

func (s *FreeReservableClusterInstCache) GetCount() int {
	count := 0
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, m := range s.InstsByCloudlet {
		count += len(m)
	}
	return count
}

func (s *FreeReservableClusterInstCache) GetTypeString() string {
	return "FreeReservableClusterInstCache"
}
