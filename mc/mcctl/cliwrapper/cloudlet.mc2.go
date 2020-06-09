// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudlet.proto

package cliwrapper

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "strings"
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
	args := []string{"region", "CreateCloudlet"}
	outlist := []edgeproto.Result{}
	noconfig := strings.Split("Location.HorizontalAccuracy,Location.VerticalAccuracy,Location.Course,Location.Speed,Location.Timestamp,Status,Config,NotifySrvAddr,ChefClientKey", ",")
	ops := []runOp{
		withIgnore(noconfig),
		withStreamOutIncremental(),
	}
	st, err := s.runObjs(uri, token, args, in, &outlist, ops...)
	return outlist, st, err
}

func (s *Client) DeleteCloudlet(uri, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Result, int, error) {
	args := []string{"region", "DeleteCloudlet"}
	outlist := []edgeproto.Result{}
	noconfig := strings.Split("Location.HorizontalAccuracy,Location.VerticalAccuracy,Location.Course,Location.Speed,Location.Timestamp,Status,Config,NotifySrvAddr,ChefClientKey", ",")
	ops := []runOp{
		withIgnore(noconfig),
		withStreamOutIncremental(),
	}
	st, err := s.runObjs(uri, token, args, in, &outlist, ops...)
	return outlist, st, err
}

func (s *Client) UpdateCloudlet(uri, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Result, int, error) {
	args := []string{"region", "UpdateCloudlet"}
	outlist := []edgeproto.Result{}
	noconfig := strings.Split("PlatformType,Errors,Status,State,DeploymentLocal,Config,NotifySrvAddr,Flavor,PhysicalName,EnvVar,ContainerVersion,ResTagMap,VmImageVersion,Deployment,InfraApiAccess,InfraConfig,ChefClientKey", ",")
	ops := []runOp{
		withIgnore(noconfig),
		withStreamOutIncremental(),
	}
	st, err := s.runObjs(uri, token, args, in, &outlist, ops...)
	return outlist, st, err
}

func (s *Client) ShowCloudlet(uri, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Cloudlet, int, error) {
	args := []string{"region", "ShowCloudlet"}
	outlist := []edgeproto.Cloudlet{}
	noconfig := strings.Split("Location.HorizontalAccuracy,Location.VerticalAccuracy,Location.Course,Location.Speed,Location.Timestamp,Status,Config,NotifySrvAddr,ChefClientKey", ",")
	ops := []runOp{
		withIgnore(noconfig),
	}
	st, err := s.runObjs(uri, token, args, in, &outlist, ops...)
	return outlist, st, err
}

func (s *Client) GetCloudletManifest(uri, token string, in *ormapi.RegionCloudlet) (*edgeproto.CloudletManifest, int, error) {
	args := []string{"region", "GetCloudletManifest"}
	out := edgeproto.CloudletManifest{}
	noconfig := strings.Split("Location.HorizontalAccuracy,Location.VerticalAccuracy,Location.Course,Location.Speed,Location.Timestamp,Status,Config,NotifySrvAddr,ChefClientKey", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) AddCloudletResMapping(uri, token string, in *ormapi.RegionCloudletResMap) (*edgeproto.Result, int, error) {
	args := []string{"region", "AddCloudletResMapping"}
	out := edgeproto.Result{}
	noconfig := strings.Split("", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) RemoveCloudletResMapping(uri, token string, in *ormapi.RegionCloudletResMap) (*edgeproto.Result, int, error) {
	args := []string{"region", "RemoveCloudletResMapping"}
	out := edgeproto.Result{}
	noconfig := strings.Split("", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) FindFlavorMatch(uri, token string, in *ormapi.RegionFlavorMatch) (*edgeproto.FlavorMatch, int, error) {
	args := []string{"region", "FindFlavorMatch"}
	out := edgeproto.FlavorMatch{}
	noconfig := strings.Split("", ",")
	st, err := s.runObjs(uri, token, args, in, &out, withIgnore(noconfig))
	if err != nil {
		return nil, st, err
	}
	return &out, st, err
}

func (s *Client) ShowCloudletInfo(uri, token string, in *ormapi.RegionCloudletInfo) ([]edgeproto.CloudletInfo, int, error) {
	args := []string{"region", "ShowCloudletInfo"}
	outlist := []edgeproto.CloudletInfo{}
	noconfig := strings.Split("", ",")
	ops := []runOp{
		withIgnore(noconfig),
	}
	st, err := s.runObjs(uri, token, args, in, &outlist, ops...)
	return outlist, st, err
}
