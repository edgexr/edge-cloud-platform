// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: settings.proto

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

func (s *Client) UpdateSettings(uri, token string, in *ormapi.RegionSettings) (*edgeproto.Result, int, error) {
	args := []string{"region", "UpdateSettings"}
	out := edgeproto.Result{}
	noconfig := strings.Split("", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) ResetSettings(uri, token string, in *ormapi.RegionSettings) (*edgeproto.Result, int, error) {
	args := []string{"region", "ResetSettings"}
	out := edgeproto.Result{}
	noconfig := strings.Split("", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) ShowSettings(uri, token string, in *ormapi.RegionSettings) (*edgeproto.Settings, int, error) {
	args := []string{"region", "ShowSettings"}
	out := edgeproto.Settings{}
	noconfig := strings.Split("", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}
