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
	"net"
	"strings"
	"sync"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/tls"
	"github.com/edgexr/edge-cloud-platform/pkg/version"
	"google.golang.org/grpc"
)

type ControllerApi struct {
	all   *AllApis
	sync  *regiondata.Sync
	store edgeproto.ControllerStore
	cache edgeproto.ControllerCache
}

var controllerAliveLease int64

func NewControllerApi(sync *regiondata.Sync, all *AllApis) *ControllerApi {
	controllerApi := ControllerApi{}
	controllerApi.all = all
	controllerApi.sync = sync
	controllerApi.store = edgeproto.NewControllerStore(sync.GetKVStore())
	edgeproto.InitControllerCache(&controllerApi.cache)
	sync.RegisterCache(&controllerApi.cache)
	return &controllerApi
}

// register controller puts this controller into the etcd database
// with a lease and keepalive, such that if this controller
// is shut-down/disappears, etcd will automatically remove it
// from the database after the ttl time.
// We use this mechanism to keep track of the controllers that are online.
// Note that the calls to etcd will block if etcd is not reachable.
func (s *ControllerApi) registerController(ctx context.Context, lease int64) error {
	ctrl := edgeproto.Controller{}
	buildInfo := version.GetBuildInfo(ctx)
	ctrl.Key.Addr = *externalApiAddr
	ctrl.BuildMaster = buildInfo.BuildMaster
	ctrl.BuildHead = buildInfo.BuildHead
	ctrl.BuildAuthor = buildInfo.BuildAuthor
	ctrl.Hostname = cloudcommon.Hostname()
	_, err := s.store.Put(ctx, &ctrl, s.sync.SyncWait, objstore.WithLease(lease))
	return err
}

func (s *ControllerApi) ShowController(in *edgeproto.Controller, cb edgeproto.ControllerApi_ShowControllerServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.Controller) error {
		err := cb.Send(obj)
		return err
	})
	return err
}

// RunJobs spawns a thread per controller to run the passed in
// function. RunJobs blocks until all threads are done.
func (s *ControllerApi) RunJobs(ctx context.Context, run func(ctx context.Context, arg interface{}, addr string) error, arg interface{}) error {
	var joberr error
	var mux sync.Mutex

	wg := sync.WaitGroup{}
	s.cache.Mux.Lock()
	for _, data := range s.cache.Objs {
		ctrl := data.Obj
		wg.Add(1)
		go func(ctrlAddr string) {
			err := run(ctx, arg, ctrlAddr)
			if err != nil {
				mux.Lock()
				if err != nil {
					joberr = err
				}
				mux.Unlock()
				log.SpanLog(ctx, log.DebugLevelApi, "run job failed", "addr", ctrlAddr, "err", err)
			}
			wg.Done()
		}(ctrl.Key.Addr)
	}
	s.cache.Mux.Unlock()
	wg.Wait()
	return joberr
}

func ControllerConnect(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		// This is an IP address. Within kubernetes,
		// controllers will need to connect to each other via
		// IP address, which will not be a SAN defined on the cert.
		// So set the hostname(SNI) on the TLS query to a valid SAN.
		host = nodeMgr.CommonNames()[0]
	}
	tlsConfig, err := nodeMgr.InternalPki.GetClientTlsConfig(ctx,
		nodeMgr.CommonNamePrefix(),
		svcnode.CertIssuerRegional,
		[]svcnode.MatchCA{svcnode.SameRegionalMatchCA()},
		svcnode.WithTlsServerName(host))
	if err != nil {
		return nil, err
	}
	conn, err := grpc.Dial(addr,
		tls.GetGrpcDialOption(tlsConfig),
		grpc.WithUnaryInterceptor(log.UnaryClientTraceGrpc),
		grpc.WithStreamInterceptor(log.StreamClientTraceGrpc),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(&cloudcommon.ProtoCodec{})),
	)
	if err != nil {
		return nil, fmt.Errorf("Connect to server %s failed: %s", addr, err.Error())
	}
	return conn, nil
}

func notifyRootConnect(ctx context.Context, notifyAddrs string) (*grpc.ClientConn, error) {
	if notifyAddrs == "" {
		return nil, fmt.Errorf("No parent notify address specified, cannot connect to notify root")
	}
	addrs := strings.Split(notifyAddrs, ",")
	tlsConfig, err := nodeMgr.InternalPki.GetClientTlsConfig(ctx,
		nodeMgr.CommonNamePrefix(),
		svcnode.CertIssuerRegional,
		[]svcnode.MatchCA{svcnode.GlobalMatchCA()},
		svcnode.WithTlsServerName(addrs[0]))
	if err != nil {
		return nil, err
	}
	conn, err := grpc.Dial(addrs[0],
		tls.GetGrpcDialOption(tlsConfig),
		grpc.WithUnaryInterceptor(log.UnaryClientTraceGrpc),
		grpc.WithStreamInterceptor(log.StreamClientTraceGrpc),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(&cloudcommon.ProtoCodec{})),
	)
	if err != nil {
		return nil, fmt.Errorf("Connect to server %s failed: %s", addrs[0], err.Error())
	}
	return conn, nil
}
