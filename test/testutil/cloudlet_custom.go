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

package testutil

// Stubs for DummyServer.
// Revisit as needed for unit tests.
import (
	"context"
	"io"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"google.golang.org/grpc"
)

func (s *DummyServer) AddCloudletResMapping(ctx context.Context, in *edgeproto.CloudletResMap) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) RemoveCloudletResMapping(ctx context.Context, in *edgeproto.CloudletResMap) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) AddCloudletAllianceOrg(ctx context.Context, in *edgeproto.CloudletAllianceOrg) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) RemoveCloudletAllianceOrg(ctx context.Context, in *edgeproto.CloudletAllianceOrg) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) FindFlavorMatch(ctx context.Context, in *edgeproto.FlavorMatch) (*edgeproto.FlavorMatch, error) {
	return in, nil
}

func (s *DummyServer) GetCloudletProps(ctx context.Context, in *edgeproto.CloudletProps) (*edgeproto.CloudletProps, error) {
	return in, nil
}

func (s *DummyServer) RevokeAccessKey(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) GenerateAccessKey(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) UpgradeAccessKey(stream edgeproto.CloudletAccessKeyApi_UpgradeAccessKeyServer) error {
	return nil
}

func (s *DummyServer) GetCloudletManifest(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.CloudletManifest, error) {
	return &edgeproto.CloudletManifest{}, nil
}

func (s *DummyServer) GetCloudletResourceUsage(ctx context.Context, usage *edgeproto.CloudletResourceUsage) (*edgeproto.CloudletResourceUsage, error) {
	return &edgeproto.CloudletResourceUsage{}, nil
}

func (s *DummyServer) GetCloudletResourceQuotaProps(ctx context.Context, in *edgeproto.CloudletResourceQuotaProps) (*edgeproto.CloudletResourceQuotaProps, error) {
	return &edgeproto.CloudletResourceQuotaProps{}, nil
}

func (s *DummyServer) GetOrganizationsOnZone(in *edgeproto.ZoneKey, cb edgeproto.CloudletApi_GetOrganizationsOnZoneServer) error {
	orgs := s.OrgsOnZone[*in]
	for _, org := range orgs {
		eorg := edgeproto.Organization{
			Name: org,
		}
		cb.Send(&eorg)
	}
	return nil
}

func (s *DummyServer) GetCloudletGPUDriverLicenseConfig(ctx context.Context, in *edgeproto.CloudletKey) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) ShowPlatformFeaturesForZone(key *edgeproto.ZoneKey, cb edgeproto.PlatformFeaturesApi_ShowPlatformFeaturesForZoneServer) error {
	return nil
}

func (s *DummyServer) ChangeCloudletDNS(key *edgeproto.CloudletKey, inCb edgeproto.CloudletApi_ChangeCloudletDNSServer) error {
	return nil
}

func (s *DummyServer) RefreshCerts(key *edgeproto.CloudletKey, inCb edgeproto.CloudletApi_RefreshCertsServer) error {
	return nil
}

// minimal bits not currently generated for flavorkey.proto to stream flavorKey objs
// for ShowFlavorsForZone cli
type ShowFlavorsForZone struct {
	Data map[string]edgeproto.FlavorKey
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowFlavorsForZone) Init() {
	x.Data = make(map[string]edgeproto.FlavorKey)
}

func (x *ShowFlavorsForZone) Send(m *edgeproto.FlavorKey) error {
	x.Data[m.Name] = *m
	return nil
}

func (x *ShowFlavorsForZone) Context() context.Context {
	return x.Ctx
}

var ShowFlavorsForCloudletExtraCount = 0

func (x *ShowFlavorsForZone) ReadStream(stream edgeproto.CloudletApi_ShowFlavorsForZoneClient, err error) {

	x.Data = make(map[string]edgeproto.FlavorKey)
	if err != nil {
		return
	}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		x.Data[obj.Name] = *obj
	}
}

func (x *CloudletCommonApi) ShowFlavorsForZone(ctx context.Context, filter *edgeproto.ZoneKey, showData *ShowFlavorsForZone) error {

	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowFlavorsForZone(filter, showData)
	} else {

		stream, err := x.client_api.ShowFlavorsForZone(ctx, filter)
		showData.ReadStream(stream, err)
		return err
	}
}

type RecvServerStream[Obj objstore.Obj] interface {
	Recv() (Obj, error)
}

type ShowServerStream[Obj objstore.Obj] struct {
	grpc.ServerStream
	Data []Obj
	Ctx  context.Context
}

func NewShowServerStream[Obj objstore.Obj](ctx context.Context) *ShowServerStream[Obj] {
	return &ShowServerStream[Obj]{
		Ctx: ctx,
	}
}

func (s *ShowServerStream[Obj]) Send(obj Obj) error {
	s.Data = append(s.Data, obj)
	return nil
}

func (s *ShowServerStream[Obj]) Context() context.Context {
	return s.Ctx
}

func (s *ShowServerStream[Obj]) ReadStream(stream RecvServerStream[Obj]) error {
	s.Data = []Obj{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		s.Data = append(s.Data, obj)
	}
	return nil
}
