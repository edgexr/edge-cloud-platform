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

// Package ccrmdummy is for unit-tests that need to call ccrm APIs
package ccrmdummy

import (
	"context"
	"fmt"
	"net"

	"github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/ccrm"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/fakecommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/fake"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type CCRMDummy struct {
	ccrm.CCRMHandler
	listener                     *bufconn.Listener
	flags                        ccrm.Flags
	caches                       ccrm.CCRMCaches
	sync                         *regiondata.Sync
	testutilCloudletInfos        map[edgeproto.CloudletKey]*edgeproto.CloudletInfo
	pause                        bool
	simulateAppCreateFailure     bool
	simulateAppDeleteFailure     bool
	simulateClusterCreateFailure bool
	simulateClusterDeleteFailure bool
}

// StartDummyCCRM starts an in-memory CCRM using grpc.bufconn.
// It uses the real CCRM handler code with a fake platform.
// Make sure to call Stop() when done to clean up the server.
// A client can be created via GRPCClient().
func StartDummyCCRM(ctx context.Context, vaultConfig *vault.Config, kvstore objstore.KVStore) *CCRMDummy {
	// ccrm apis
	dummy := &CCRMDummy{
		listener: bufconn.Listen(1024 * 1024),
		//accessAPI: &accessapi.TestHandler{},
		sync:                  regiondata.InitSync(kvstore),
		testutilCloudletInfos: make(map[edgeproto.CloudletKey]*edgeproto.CloudletInfo),
	}
	dummy.sync.SetName("ccrm")
	for _, info := range testutil.CloudletInfoData() {
		dummy.testutilCloudletInfos[info.Key] = &info
	}
	platformBuilders := map[string]platform.PlatformBuilder{
		platform.PlatformTypeFake:              dummy.NewPlatform(fake.NewPlatform),
		platform.PlatformTypeFakeSingleCluster: dummy.NewPlatform(fake.NewPlatformSingleCluster),
		platform.PlatformTypeFakeVMPool:        dummy.NewPlatform(fake.NewPlatformVMPool),
		"ccrm":                                 dummy.NewPlatform(fake.NewPlatform), // matches platformType from testutil/test_data.go
		platform.PlatformTypeFakeNodes:         dummy.NewPlatform(fake.NewPlatformNodes),
	}
	nodeMgr := svcnode.SvcNodeMgr{}
	nodeMgr.VaultConfig = vaultConfig
	nodeMgr.MyNode.Key.Type = svcnode.SvcNodeTypeCCRM
	nodeMgr.Debug.Init(&nodeMgr)
	cplookup := &svcnode.ZonePoolCache{}
	cplookup.Init()
	nodeMgr.ZonePoolLookup = cplookup
	cloudletLookup := &svcnode.CloudletCache{}
	cloudletLookup.Init()
	nodeMgr.CloudletLookup = cloudletLookup

	dummy.flags.Region = "local"
	dummy.caches.Init(ctx)
	dummy.CCRMHandler.Init(ctx, &nodeMgr, &dummy.caches, platformBuilders, &dummy.flags, &cloudcommon.DummyRegistryAuthApi{})

	serv := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(cloudcommon.AuditUnaryInterceptor)),
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(cloudcommon.AuditStreamInterceptor)),
	)
	dummy.CCRMHandler.InitConnectivity(nil, kvstore, &nodeMgr, serv, dummy.sync)

	dummy.sync.Start()

	go func() {
		if err := serv.Serve(dummy.listener); err != nil {
			fmt.Println(err)
		}
	}()
	return dummy
}

func (d *CCRMDummy) Stop() {
	d.listener.Close()
	d.sync.Done()
}

func (d *CCRMDummy) GRPCClient() (*grpc.ClientConn, error) {
	dialer := func(ctx context.Context, address string) (net.Conn, error) {
		return d.listener.Dial()
	}
	return grpc.DialContext(context.Background(), "ccrm-dummy",
		grpc.WithContextDialer(dialer),
		grpc.WithUnaryInterceptor(log.UnaryClientTraceGrpc),
		grpc.WithStreamInterceptor(log.StreamClientTraceGrpc),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}

func (d *CCRMDummy) NewPlatform(newPlatFunc func() platform.Platform) func() platform.Platform {
	return func() platform.Platform {
		p := newPlatFunc()
		f := castToFakePlatform(p)
		if f != nil {
			// For the controller's unit tests we also override the default
			// set of flavors.
			f.CustomFlavorList = UnitTestFlavors
			// Set debug states for new platforms
			if d.pause {
				f.SetPause(true)
			}
			f.SetSimulateAppCreateFailure(d.simulateAppCreateFailure)
			f.SetSimulateAppDeleteFailure(d.simulateAppDeleteFailure)
			f.SetSimulateClusterCreateFailure(d.simulateClusterCreateFailure)
			f.SetSimulateClusterDeleteFailure(d.simulateClusterDeleteFailure)
		}
		return p
	}
}

func castToFakePlatform(p platform.Platform) *fake.Platform {
	switch v := p.(type) {
	case *fake.Platform:
		return v
	case *fake.PlatformSingleCluster:
		return &v.Platform
	case *fake.PlatformVMPool:
		return &v.Platform
	case *fake.FakeNodes:
		return &v.Platform
	}
	return nil
}

type fakeSetFailure interface {
	SetSimulateAppCreateFailure(state bool)
	SetSimulateAppDeleteFailure(state bool)
	SetSimulateClusterCreateFailure(state bool)
	SetSimulateClusterDeleteFailure(state bool)
}

func (d *CCRMDummy) SetSimulateAppCreateFailure(state bool) {
	d.simulateAppCreateFailure = state
	for _, fp := range d.CCRMHandler.GetPlatformCache().GetAll() {
		if f, ok := fp.(fakeSetFailure); ok {
			f.SetSimulateAppCreateFailure(state)
		}
	}
}

func (d *CCRMDummy) SetSimulateAppDeleteFailure(state bool) {
	d.simulateAppDeleteFailure = state
	for _, fp := range d.CCRMHandler.GetPlatformCache().GetAll() {
		if f, ok := fp.(fakeSetFailure); ok {
			f.SetSimulateAppDeleteFailure(state)
		}
	}
}

func (d *CCRMDummy) SetSimulateClusterCreateFailure(state bool) {
	d.simulateClusterCreateFailure = state
	for _, fp := range d.CCRMHandler.GetPlatformCache().GetAll() {
		if f, ok := fp.(fakeSetFailure); ok {
			f.SetSimulateClusterCreateFailure(state)
		}
	}
}

func (d *CCRMDummy) SetSimulateClusterDeleteFailure(state bool) {
	d.simulateClusterDeleteFailure = state
	for _, fp := range d.CCRMHandler.GetPlatformCache().GetAll() {
		if f, ok := fp.(fakeSetFailure); ok {
			f.SetSimulateClusterDeleteFailure(state)
		}
	}
}

// SetPause blocks responder until unpaused.
// Warning: don't double-pause or double-unpause.
func (d *CCRMDummy) SetPause(enable bool) {
	d.pause = enable
	for _, fp := range d.CCRMHandler.GetPlatformCache().GetAll() {
		if f := castToFakePlatform(fp); f != nil {
			f.SetPause(enable)
		}
	}
}

func (d *CCRMDummy) GetFakePlatform(key *edgeproto.CloudletKey) (*fake.Platform, bool) {
	pf, ok := d.CCRMHandler.GetPlatformCache().Get(key)
	if !ok {
		return nil, false
	}
	f := castToFakePlatform(pf)
	if f != nil {
		return f, true
	}
	return nil, false
}

func (d *CCRMDummy) GetFakePlatformResources(key *edgeproto.CloudletKey) (*fakecommon.Resources, bool) {
	if f, ok := d.GetFakePlatform(key); ok {
		return f.GetResources(), true
	}
	return nil, false
}

func (d *CCRMDummy) SetFakePlatformFlavors(key *edgeproto.CloudletKey, flavors []*edgeproto.FlavorInfo) error {
	if f, ok := d.GetFakePlatform(key); ok {
		f.CustomFlavorList = flavors
		return nil
	}
	return fmt.Errorf("fake platform not found for %s", key.GetKeyString())
}

// RefreshCerts override real CCRM handler because it doesn't
// feed into a fake platform call, it goes a real certs function.
func (d *CCRMDummy) RefreshCerts(ctx context.Context, in *edgeproto.Cloudlet) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (d *CCRMDummy) ApplyCloudlet(in *edgeproto.Cloudlet, stream edgeproto.CloudletPlatformAPI_ApplyCloudletServer) error {
	if info := d.testutilCloudletInfos[in.Key]; info != nil {
		stream.Send(info)
	} else {
		// CCRM handles CRM bringup and set to ready
		info := &edgeproto.CloudletInfo{
			Key:   in.Key,
			State: distributed_match_engine.CloudletState_CLOUDLET_STATE_READY,
		}
		stream.Send(info)
	}
	return nil
}

var UnitTestFlavors = testutil.CloudletInfoData()[0].Flavors
