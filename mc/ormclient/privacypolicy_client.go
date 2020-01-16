// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: privacypolicy.proto

package ormclient

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
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

func (s *Client) CreatePrivacyPolicy(uri, token string, in *ormapi.RegionPrivacyPolicy) (edgeproto.Result, int, error) {
	out := edgeproto.Result{}
	status, err := s.PostJson(uri+"/auth/ctrl/CreatePrivacyPolicy", token, in, &out)
	return out, status, err
}

func (s *Client) DeletePrivacyPolicy(uri, token string, in *ormapi.RegionPrivacyPolicy) (edgeproto.Result, int, error) {
	out := edgeproto.Result{}
	status, err := s.PostJson(uri+"/auth/ctrl/DeletePrivacyPolicy", token, in, &out)
	return out, status, err
}

func (s *Client) UpdatePrivacyPolicy(uri, token string, in *ormapi.RegionPrivacyPolicy) (edgeproto.Result, int, error) {
	out := edgeproto.Result{}
	status, err := s.PostJson(uri+"/auth/ctrl/UpdatePrivacyPolicy", token, in, &out)
	return out, status, err
}

func (s *Client) ShowPrivacyPolicy(uri, token string, in *ormapi.RegionPrivacyPolicy) ([]edgeproto.PrivacyPolicy, int, error) {
	out := edgeproto.PrivacyPolicy{}
	outlist := []edgeproto.PrivacyPolicy{}
	status, err := s.PostJsonStreamOut(uri+"/auth/ctrl/ShowPrivacyPolicy", token, in, &out, func() {
		outlist = append(outlist, out)
	})
	return outlist, status, err
}

type PrivacyPolicyApiClient interface {
	CreatePrivacyPolicy(uri, token string, in *ormapi.RegionPrivacyPolicy) (edgeproto.Result, int, error)
	DeletePrivacyPolicy(uri, token string, in *ormapi.RegionPrivacyPolicy) (edgeproto.Result, int, error)
	UpdatePrivacyPolicy(uri, token string, in *ormapi.RegionPrivacyPolicy) (edgeproto.Result, int, error)
	ShowPrivacyPolicy(uri, token string, in *ormapi.RegionPrivacyPolicy) ([]edgeproto.PrivacyPolicy, int, error)
}
