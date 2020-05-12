// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: app.proto

package cliwrapper

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "strings"
import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func (s *Client) CreateApp(uri, token string, in *ormapi.RegionApp) (*edgeproto.Result, int, error) {
	args := []string{"region", "CreateApp"}
	out := edgeproto.Result{}
	noconfig := strings.Split("DeletePrepare", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) DeleteApp(uri, token string, in *ormapi.RegionApp) (*edgeproto.Result, int, error) {
	args := []string{"region", "DeleteApp"}
	out := edgeproto.Result{}
	noconfig := strings.Split("DeletePrepare", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) UpdateApp(uri, token string, in *ormapi.RegionApp) (*edgeproto.Result, int, error) {
	args := []string{"region", "UpdateApp"}
	out := edgeproto.Result{}
	noconfig := strings.Split("DeletePrepare", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) ShowApp(uri, token string, in *ormapi.RegionApp) ([]edgeproto.App, int, error) {
	args := []string{"region", "ShowApp"}
	outlist := []edgeproto.App{}
	noconfig := strings.Split("DeletePrepare", ",")
	ops := []runOp{
		withIgnore(noconfig),
	}
	st, err := s.runObjs(uri, token, args, in, &outlist, ops...)
	return outlist, st, err
}

func (s *Client) AddAppAutoProvPolicy(uri, token string, in *ormapi.RegionAppAutoProvPolicy) (*edgeproto.Result, int, error) {
	args := []string{"region", "AddAppAutoProvPolicy"}
	out := edgeproto.Result{}
	noconfig := strings.Split("", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) RemoveAppAutoProvPolicy(uri, token string, in *ormapi.RegionAppAutoProvPolicy) (*edgeproto.Result, int, error) {
	args := []string{"region", "RemoveAppAutoProvPolicy"}
	out := edgeproto.Result{}
	noconfig := strings.Split("", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}
