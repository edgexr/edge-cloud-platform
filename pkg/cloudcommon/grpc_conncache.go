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

package cloudcommon

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/util/tasks"
	"github.com/opentracing/opentracing-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GRPCConnCache struct {
	sync.Mutex
	addrs       map[string]string
	cache       map[string]*grpc.ClientConn
	used        map[string]bool
	cleanupTask tasks.PeriodicTask
}

const connCacheCleanupInterval = 30 * time.Minute

func NewGRPCConnCache(addrsByKey map[string]string) *GRPCConnCache {
	rcc := &GRPCConnCache{}
	rcc.addrs = addrsByKey
	rcc.cache = make(map[string]*grpc.ClientConn)
	rcc.used = make(map[string]bool)
	rcc.cleanupTask = *tasks.NewPeriodicTask(rcc)
	return rcc
}

func (s *GRPCConnCache) Start() {
	s.cleanupTask.Start()
}

func (s *GRPCConnCache) Stop() {
	s.cleanupTask.Stop()
}

func (s *GRPCConnCache) GetConn(ctx context.Context, key string) (*grpc.ClientConn, error) {
	// Although we hold the lock while doing the connect, the
	// connect is non-blocking, so will not actually block us.
	s.Lock()
	defer s.Unlock()
	conn, found := s.cache[key]
	var err error
	if !found {
		addr, found := s.addrs[key]
		if !found {
			return nil, fmt.Errorf("no GRPC address in cache for key %s", key)
		}
		// Note that we assume the service mesh to handle mTLS between
		// internal services, thus setting insecure mode here.
		conn, err = grpc.Dial(addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithChainUnaryInterceptor(
				log.UnaryClientTraceGrpc,
			),
			grpc.WithChainStreamInterceptor(
				log.StreamClientTraceGrpc,
			),
			grpc.WithDefaultCallOptions(grpc.ForceCodec(&ProtoCodec{})),
		)
		if err != nil {
			return nil, err
		}
		s.cache[key] = conn
	}
	s.used[key] = true
	return conn, nil
}

// SetConn allows for manually injecting a client connection.
// Can be used for unit testing with grpc.bufconn.
func (s *GRPCConnCache) SetConn(key string, conn *grpc.ClientConn) {
	s.Lock()
	defer s.Unlock()
	s.cache[key] = conn
}

func (s *GRPCConnCache) Run(ctx context.Context) {
	s.Lock()
	defer s.Unlock()
	for region, conn := range s.cache {
		used := s.used[region]
		if used {
			s.used[region] = false
		} else {
			// cleanup
			conn.Close()
			delete(s.cache, region)
			delete(s.used, region)
		}
	}
}

func (s *GRPCConnCache) GetInterval() time.Duration {
	return connCacheCleanupInterval
}

func (s *GRPCConnCache) StartSpan() opentracing.Span {
	return log.StartSpan(log.DebugLevelApi, "conn cache cleanup")
}
