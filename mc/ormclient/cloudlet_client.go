// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudlet.proto

package ormclient

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func (s *Client) CreateCloudlet(uri, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Result, int, error) {
	out := edgeproto.Result{}
	outlist := []edgeproto.Result{}
	status, err := s.PostJsonStreamOut(uri+"/auth/ctrl/CreateCloudlet", token, in, &out, func() {
		outlist = append(outlist, out)
	})
	return outlist, status, err
}

func (s *Client) DeleteCloudlet(uri, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Result, int, error) {
	out := edgeproto.Result{}
	outlist := []edgeproto.Result{}
	status, err := s.PostJsonStreamOut(uri+"/auth/ctrl/DeleteCloudlet", token, in, &out, func() {
		outlist = append(outlist, out)
	})
	return outlist, status, err
}

func (s *Client) UpdateCloudlet(uri, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Result, int, error) {
	out := edgeproto.Result{}
	outlist := []edgeproto.Result{}
	status, err := s.PostJsonStreamOut(uri+"/auth/ctrl/UpdateCloudlet", token, in, &out, func() {
		outlist = append(outlist, out)
	})
	return outlist, status, err
}

func (s *Client) ShowCloudlet(uri, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Cloudlet, int, error) {
	out := edgeproto.Cloudlet{}
	outlist := []edgeproto.Cloudlet{}
	status, err := s.PostJsonStreamOut(uri+"/auth/ctrl/ShowCloudlet", token, in, &out, func() {
		outlist = append(outlist, out)
	})
	return outlist, status, err
}

func (s *Client) GetCloudletManifest(uri, token string, in *ormapi.RegionCloudlet) (*edgeproto.CloudletManifest, int, error) {
	out := edgeproto.CloudletManifest{}
	status, err := s.PostJson(uri+"/auth/ctrl/GetCloudletManifest", token, in, &out)
	if err != nil {
		return nil, status, err
	}
	return &out, status, err
}

func (s *Client) AddCloudletResMapping(uri, token string, in *ormapi.RegionCloudletResMap) (*edgeproto.Result, int, error) {
	out := edgeproto.Result{}
	status, err := s.PostJson(uri+"/auth/ctrl/AddCloudletResMapping", token, in, &out)
	if err != nil {
		return nil, status, err
	}
	return &out, status, err
}

func (s *Client) RemoveCloudletResMapping(uri, token string, in *ormapi.RegionCloudletResMap) (*edgeproto.Result, int, error) {
	out := edgeproto.Result{}
	status, err := s.PostJson(uri+"/auth/ctrl/RemoveCloudletResMapping", token, in, &out)
	if err != nil {
		return nil, status, err
	}
	return &out, status, err
}

func (s *Client) FindFlavorMatch(uri, token string, in *ormapi.RegionFlavorMatch) (*edgeproto.FlavorMatch, int, error) {
	out := edgeproto.FlavorMatch{}
	status, err := s.PostJson(uri+"/auth/ctrl/FindFlavorMatch", token, in, &out)
	if err != nil {
		return nil, status, err
	}
	return &out, status, err
}

type CloudletApiClient interface {
	CreateCloudlet(uri, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Result, int, error)
	DeleteCloudlet(uri, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Result, int, error)
	UpdateCloudlet(uri, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Result, int, error)
	ShowCloudlet(uri, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Cloudlet, int, error)
	GetCloudletManifest(uri, token string, in *ormapi.RegionCloudlet) (*edgeproto.CloudletManifest, int, error)
	AddCloudletResMapping(uri, token string, in *ormapi.RegionCloudletResMap) (*edgeproto.Result, int, error)
	RemoveCloudletResMapping(uri, token string, in *ormapi.RegionCloudletResMap) (*edgeproto.Result, int, error)
	FindFlavorMatch(uri, token string, in *ormapi.RegionFlavorMatch) (*edgeproto.FlavorMatch, int, error)
}

func (s *Client) ShowCloudletInfo(uri, token string, in *ormapi.RegionCloudletInfo) ([]edgeproto.CloudletInfo, int, error) {
	out := edgeproto.CloudletInfo{}
	outlist := []edgeproto.CloudletInfo{}
	status, err := s.PostJsonStreamOut(uri+"/auth/ctrl/ShowCloudletInfo", token, in, &out, func() {
		outlist = append(outlist, out)
	})
	return outlist, status, err
}

type CloudletInfoApiClient interface {
	ShowCloudletInfo(uri, token string, in *ormapi.RegionCloudletInfo) ([]edgeproto.CloudletInfo, int, error)
}
