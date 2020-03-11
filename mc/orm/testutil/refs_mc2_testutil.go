// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: refs.proto

package testutil

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "context"
import "github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func TestShowCloudletRefs(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.CloudletRefs) ([]edgeproto.CloudletRefs, int, error) {
	dat := &ormapi.RegionCloudletRefs{}
	dat.Region = region
	dat.CloudletRefs = *in
	return mcClient.ShowCloudletRefs(uri, token, dat)
}
func TestPermShowCloudletRefs(mcClient *ormclient.Client, uri, token, region, org string) ([]edgeproto.CloudletRefs, int, error) {
	in := &edgeproto.CloudletRefs{}
	in.Key.OperatorKey.Name = org
	return TestShowCloudletRefs(mcClient, uri, token, region, in)
}

func (s *TestClient) ShowCloudletRefs(ctx context.Context, in *edgeproto.CloudletRefs) ([]edgeproto.CloudletRefs, error) {
	inR := &ormapi.RegionCloudletRefs{
		Region:       s.Region,
		CloudletRefs: *in,
	}
	out, status, err := s.McClient.ShowCloudletRefs(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func TestShowClusterRefs(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.ClusterRefs) ([]edgeproto.ClusterRefs, int, error) {
	dat := &ormapi.RegionClusterRefs{}
	dat.Region = region
	dat.ClusterRefs = *in
	return mcClient.ShowClusterRefs(uri, token, dat)
}
func TestPermShowClusterRefs(mcClient *ormclient.Client, uri, token, region, org string) ([]edgeproto.ClusterRefs, int, error) {
	in := &edgeproto.ClusterRefs{}
	return TestShowClusterRefs(mcClient, uri, token, region, in)
}

func (s *TestClient) ShowClusterRefs(ctx context.Context, in *edgeproto.ClusterRefs) ([]edgeproto.ClusterRefs, error) {
	inR := &ormapi.RegionClusterRefs{
		Region:      s.Region,
		ClusterRefs: *in,
	}
	out, status, err := s.McClient.ShowClusterRefs(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}
