// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alert.proto

/*
Package testutil is a generated protocol buffer package.

It is generated from these files:
	alert.proto
	alldata.proto
	app.proto
	appinst.proto
	appinstclient.proto
	autoprovpolicy.proto
	autoscalepolicy.proto
	cloudlet.proto
	cloudletpool.proto
	cluster.proto
	clusterinst.proto
	common.proto
	controller.proto
	debug.proto
	exec.proto
	flavor.proto
	metric.proto
	node.proto
	notice.proto
	operatorcode.proto
	org.proto
	privacypolicy.proto
	refs.proto
	restagtable.proto
	result.proto
	settings.proto
	version.proto

It has these top-level messages:
	Alert
	AllData
	AppKey
	ConfigFile
	App
	AppInstKey
	AppInst
	AppInstRuntime
	AppInstInfo
	AppInstMetrics
	AppInstClientKey
	AppInstClient
	AutoProvPolicy
	AutoProvCloudlet
	AutoProvCount
	AutoProvCounts
	AutoProvPolicyCloudlet
	PolicyKey
	AutoScalePolicy
	CloudletKey
	OperationTimeLimits
	CloudletInfraCommon
	AzureProperties
	GcpProperties
	OpenStackProperties
	CloudletInfraProperties
	PlatformConfig
	CloudletResMap
	Cloudlet
	FlavorMatch
	FlavorInfo
	OSAZone
	OSImage
	CloudletInfo
	CloudletMetrics
	CloudletPoolKey
	CloudletPool
	CloudletPoolMember
	ClusterKey
	ClusterInstKey
	ClusterInst
	ClusterInstInfo
	StatusInfo
	ControllerKey
	Controller
	DebugRequest
	DebugReply
	DebugData
	RunCmd
	RunVMConsole
	ShowLog
	ExecRequest
	FlavorKey
	Flavor
	MetricTag
	MetricVal
	Metric
	NodeKey
	Node
	NodeData
	Notice
	OperatorCode
	Organization
	OrganizationData
	OutboundSecurityRule
	PrivacyPolicy
	CloudletRefs
	ClusterRefs
	ResTagTableKey
	ResTagTable
	Result
	Settings
*/
package testutil

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "context"
import "github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
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

func TestShowAlert(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.Alert) ([]edgeproto.Alert, int, error) {
	dat := &ormapi.RegionAlert{}
	dat.Region = region
	dat.Alert = *in
	return mcClient.ShowAlert(uri, token, dat)
}
func TestPermShowAlert(mcClient *ormclient.Client, uri, token, region, org string) ([]edgeproto.Alert, int, error) {
	in := &edgeproto.Alert{}
	return TestShowAlert(mcClient, uri, token, region, in)
}

func (s *TestClient) ShowAlert(ctx context.Context, in *edgeproto.Alert) ([]edgeproto.Alert, error) {
	inR := &ormapi.RegionAlert{
		Region: s.Region,
		Alert:  *in,
	}
	out, status, err := s.McClient.ShowAlert(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}
