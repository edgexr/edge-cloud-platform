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

package autoprov

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

func TestDeploy(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelNotify | log.DebugLevelApi | log.DebugLevelMetrics)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// dummy controller
	appInstCache := &edgeproto.AppInstCache{}
	edgeproto.InitAppInstCache(appInstCache)
	dc := newDummyController(appInstCache, nil)
	dc.start()
	defer dc.stop()
	dialOpts = grpc.WithContextDialer(dc.getBufDialer())
	testDialOpt = grpc.WithInsecure()

	inst := edgeproto.AppInst{}
	inst.Key.Name = "foo"
	inst.AppKey.Name = "foo"
	go goAppInstApi(ctx, &inst, cloudcommon.Create, "test", "")

	inst2 := edgeproto.AppInst{}
	inst2.Key.Name = "foo2"
	inst2.AppKey.Name = "foo2"
	go goAppInstApi(ctx, &inst2, cloudcommon.Create, "test", "")

	err := dc.waitForAppInsts(ctx, 2)
	require.Nil(t, err)

	go goAppInstApi(ctx, &inst2, cloudcommon.Delete, "test", "")
	err = dc.waitForAppInsts(ctx, 1)
	require.Nil(t, err)

	go goAppInstApi(ctx, &inst, cloudcommon.Delete, "test", "")
	err = dc.waitForAppInsts(ctx, 0)
	require.Nil(t, err)
}

type DummyController struct {
	appInstCache     *edgeproto.AppInstCache
	appInstRefsCache *edgeproto.AppInstRefsCache
	serv             *grpc.Server
	lis              *bufconn.Listener
	failCreate       bool
	failDelete       bool
	failCreateInsts  map[edgeproto.AppCloudletKeyPair]struct{}
	failDeleteInsts  map[edgeproto.AppCloudletKeyPair]struct{}
}

func newDummyController(appInstCache *edgeproto.AppInstCache, appInstRefsCache *edgeproto.AppInstRefsCache) *DummyController {
	d := DummyController{}
	d.appInstCache = appInstCache
	d.appInstRefsCache = appInstRefsCache
	d.failCreateInsts = make(map[edgeproto.AppCloudletKeyPair]struct{})
	d.failDeleteInsts = make(map[edgeproto.AppCloudletKeyPair]struct{})
	d.serv = grpc.NewServer(
		grpc.UnaryInterceptor(cloudcommon.AuditUnaryInterceptor),
		grpc.StreamInterceptor(cloudcommon.AuditStreamInterceptor),
		grpc.ForceServerCodec(&cloudcommon.ProtoCodec{}))
	edgeproto.RegisterAppInstApiServer(d.serv, &d)
	return &d
}

func (s *DummyController) start() {
	s.lis = bufconn.Listen(1024 * 1024)
	go func() {
		if err := s.serv.Serve(s.lis); err != nil {
			log.FatalLog("Failed to serve", "error", err)
		}
	}()
}

func (s *DummyController) stop() {
	s.serv.Stop()
	s.lis.Close()
}

func (s *DummyController) getBufDialer() func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, url string) (net.Conn, error) {
		return s.lis.Dial()
	}
}

func (s *DummyController) waitForAppInsts(ctx context.Context, count int) error {
	for i := 0; i < 50; i++ {
		if s.appInstCache.GetCount() == count {
			log.SpanLog(ctx, log.DebugLevelInfo, "waitForAppInsts: count matched", "count", count)
			return nil
		}
		time.Sleep(40 * time.Millisecond)
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "Timed out waiting for cache")
	return fmt.Errorf("Timed out waiting for %d AppInsts, have %d instead", count, s.appInstCache.GetCount())
}

func (s *DummyController) CreateAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_CreateAppInstServer) error {
	if s.failCreate {
		return fmt.Errorf("Some error")
	}
	failKey := edgeproto.AppCloudletKeyPair{
		AppKey:      in.AppKey,
		CloudletKey: in.CloudletKey,
	}
	if _, found := s.failCreateInsts[failKey]; found {
		return fmt.Errorf("Some error")
	}
	s.updateAppInst(server.Context(), in)
	return nil
}

func (s *DummyController) UpdateAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_UpdateAppInstServer) error {
	s.updateAppInst(server.Context(), in)
	return nil
}

func (s *DummyController) DeleteAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_DeleteAppInstServer) error {
	if s.failDelete {
		return fmt.Errorf("Some error")
	}
	failKey := edgeproto.AppCloudletKeyPair{
		AppKey:      in.AppKey,
		CloudletKey: in.CloudletKey,
	}
	if _, found := s.failDeleteInsts[failKey]; found {
		return fmt.Errorf("Some error")
	}
	s.deleteAppInst(server.Context(), in)
	return nil
}

func (s *DummyController) RefreshAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_RefreshAppInstServer) error {
	return nil
}

func (s *DummyController) ShowAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_ShowAppInstServer) error {
	err := s.appInstCache.Show(in, func(obj *edgeproto.AppInst) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (s *DummyController) HandleFedAppInstEvent(ctx context.Context, event *edgeproto.FedAppInstEvent) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *DummyController) updateAppInst(ctx context.Context, in *edgeproto.AppInst) {
	log.SpanLog(ctx, log.DebugLevelApi, "UpdateAppInst", "inst", *in)
	if s.appInstRefsCache != nil {
		// also update refs
		s.appInstRefsCache.Mux.Lock()
		cd := s.appInstRefsCache.Objs[in.AppKey]
		cd.Obj.Insts[in.Key.GetKeyString()] = 1
		s.appInstRefsCache.Mux.Unlock()
	}
	s.appInstCache.Update(ctx, in, 0)
}

func (s *DummyController) deleteAppInst(ctx context.Context, in *edgeproto.AppInst) {
	log.SpanLog(ctx, log.DebugLevelApi, "DeleteAppInst", "inst", *in)
	if s.appInstRefsCache != nil {
		// also update refs
		s.appInstRefsCache.Mux.Lock()
		cd := s.appInstRefsCache.Objs[in.AppKey]
		delete(cd.Obj.Insts, in.Key.GetKeyString())
		s.appInstRefsCache.Mux.Unlock()
	}
	s.appInstCache.Delete(ctx, in, 0)
}

func (s *DummyController) deleteAppInstFor(ctx context.Context, appKey *edgeproto.AppKey, cloudletKey *edgeproto.CloudletKey) {
	log.SpanLog(ctx, log.DebugLevelApi, "DeleteAppInstFor", "appKey", *appKey, "cloudletKey", *cloudletKey)
	deleted := []edgeproto.AppInstKey{}
	s.appInstCache.Mux.Lock()
	for k, data := range s.appInstCache.Objs {
		if data.Obj.AppKey.Matches(appKey) && data.Obj.CloudletKey.Matches(cloudletKey) {
			delete(s.appInstCache.Objs, k)
			deleted = append(deleted, data.Obj.Key)
		}
	}
	s.appInstCache.Mux.Unlock()
	if s.appInstRefsCache != nil {
		// also update refs
		for _, key := range deleted {
			s.appInstRefsCache.Mux.Lock()
			cd := s.appInstRefsCache.Objs[*appKey]
			if cd != nil {
				delete(cd.Obj.Insts, key.GetKeyString())
			}
			s.appInstRefsCache.Mux.Unlock()
		}
	}
}

func (s *DummyController) dump() {
	s.appInstCache.Mux.Lock()
	for _, data := range s.appInstCache.Objs {
		fmt.Printf("Dump AppInst: %v\n", data.Obj)
		//log.SpanLog(ctx, log.DebugLevelApi, "Dump AppInst", "AppInst", data.Obj)
	}
	s.appInstCache.Mux.Unlock()

	s.appInstRefsCache.Mux.Lock()
	for key, data := range s.appInstRefsCache.Objs {
		//log.SpanLog(ctx, log.DebugLevelApi, "Dump AppInstRefs", "key", key, "Refs", data.Obj.Insts)
		fmt.Printf("Dump AppInstRefs: %v\n", key)
		for inst, _ := range data.Obj.Insts {
			fmt.Printf("  Ref: %v\n", inst)
		}
	}
	s.appInstRefsCache.Mux.Unlock()
}

func waitForRetryAppInsts(ctx context.Context, appKey edgeproto.AppKey, cloudletKey edgeproto.CloudletKey, checkFound bool) error {
	for i := 0; i < 50; i++ {
		found := retryTracker.hasFailure(ctx, appKey, cloudletKey)
		if checkFound == found {
			log.SpanLog(ctx, log.DebugLevelInfo, "waitForRetryAppInsts: retry appInst found", "found", checkFound)
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "Timed out waiting for retryTracker to find appInstKey", "found", checkFound)
	return fmt.Errorf("Timed out waiting for AppInst %v, %v to be found(%v) by retryTracker", appKey, cloudletKey, checkFound)
}
