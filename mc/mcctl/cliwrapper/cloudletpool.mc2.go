// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudletpool.proto

package cliwrapper

import (
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	_ "github.com/mobiledgex/edge-cloud/protogen"
	math "math"
	"strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func (s *Client) CreateCloudletPool(uri, token string, in *ormapi.RegionCloudletPool) (*edgeproto.Result, int, error) {
	args := []string{"region", "CreateCloudletPool"}
	out := edgeproto.Result{}
	noconfig := strings.Split("Members", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) DeleteCloudletPool(uri, token string, in *ormapi.RegionCloudletPool) (*edgeproto.Result, int, error) {
	args := []string{"region", "DeleteCloudletPool"}
	out := edgeproto.Result{}
	noconfig := strings.Split("Members", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) UpdateCloudletPool(uri, token string, in *ormapi.RegionCloudletPool) (*edgeproto.Result, int, error) {
	args := []string{"region", "UpdateCloudletPool"}
	out := edgeproto.Result{}
	noconfig := strings.Split("Members", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) ShowCloudletPool(uri, token string, in *ormapi.RegionCloudletPool) ([]edgeproto.CloudletPool, int, error) {
	args := []string{"region", "ShowCloudletPool"}
	outlist := []edgeproto.CloudletPool{}
	noconfig := strings.Split("Members", ",")
	ops := []runOp{
		withIgnore(noconfig),
	}
	st, err := s.runObjs(uri, token, args, in, &outlist, ops...)
	return outlist, st, err
}

func (s *Client) AddCloudletPoolMember(uri, token string, in *ormapi.RegionCloudletPoolMember) (*edgeproto.Result, int, error) {
	args := []string{"region", "AddCloudletPoolMember"}
	out := edgeproto.Result{}
	noconfig := strings.Split("", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) RemoveCloudletPoolMember(uri, token string, in *ormapi.RegionCloudletPoolMember) (*edgeproto.Result, int, error) {
	args := []string{"region", "RemoveCloudletPoolMember"}
	out := edgeproto.Result{}
	noconfig := strings.Split("", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}
