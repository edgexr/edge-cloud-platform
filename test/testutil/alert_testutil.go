// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alert.proto

package testutil

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/edgectl/wrapper"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"io"
	math "math"
	"testing"
	"time"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

type ShowAlert struct {
	Data map[string]edgeproto.Alert
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowAlert) Init() {
	x.Data = make(map[string]edgeproto.Alert)
}

func (x *ShowAlert) Send(m *edgeproto.Alert) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowAlert) Context() context.Context {
	return x.Ctx
}

func (x *ShowAlert) ListData() []edgeproto.Alert {
	data := []edgeproto.Alert{}
	for _, val := range x.Data {
		data = append(data, val)
	}
	return data
}

var AlertShowExtraCount = 0

func (x *ShowAlert) ReadStream(stream edgeproto.AlertApi_ShowAlertClient, err error) {
	x.Data = make(map[string]edgeproto.Alert)
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
		x.Data[obj.GetKey().GetKeyString()] = *obj
	}
}

func (x *ShowAlert) CheckFound(obj *edgeproto.Alert) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowAlert) AssertFound(t *testing.T, obj *edgeproto.Alert) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find Alert %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "Alert are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowAlert) AssertNotFound(t *testing.T, obj *edgeproto.Alert) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find Alert %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundAlert(t *testing.T, api edgeproto.AlertApiClient, obj *edgeproto.Alert, count int, retry time.Duration) {
	show := ShowAlert{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowAlert(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundAlert(t *testing.T, api edgeproto.AlertApiClient, obj *edgeproto.Alert, count int, retry time.Duration) {
	show := ShowAlert{}
	filterNone := edgeproto.Alert{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowAlert(ctx, &filterNone)
		show.ReadStream(stream, err)
		cancel()
		if !show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertNotFound(t, obj)
}

// Wrap the api with a common interface
type AlertCommonApi struct {
	internal_api edgeproto.AlertApiServer
	client_api   edgeproto.AlertApiClient
}

func (x *AlertCommonApi) ShowAlert(ctx context.Context, filter *edgeproto.Alert, showData *ShowAlert) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowAlert(filter, showData)
	} else {
		stream, err := x.client_api.ShowAlert(ctx, filter)
		showData.ReadStream(stream, err)
		return unwrapGrpcError(err)
	}
}

func NewInternalAlertApi(api edgeproto.AlertApiServer) *AlertCommonApi {
	apiWrap := AlertCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientAlertApi(api edgeproto.AlertApiClient) *AlertCommonApi {
	apiWrap := AlertCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type AlertTestOptions struct {
	createdData []edgeproto.Alert
}

type AlertTestOp func(opts *AlertTestOptions)

func WithCreatedAlertTestData(createdData []edgeproto.Alert) AlertTestOp {
	return func(opts *AlertTestOptions) { opts.createdData = createdData }
}

func InternalAlertTest(t *testing.T, test string, api edgeproto.AlertApiServer, testData []edgeproto.Alert, ops ...AlertTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalAlertTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicAlertShowTest(t, ctx, NewInternalAlertApi(api), testData)
	}
}

func ClientAlertTest(t *testing.T, test string, api edgeproto.AlertApiClient, testData []edgeproto.Alert, ops ...AlertTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientAlertTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicAlertShowTest(t, ctx, NewClientAlertApi(api), testData)
	}
}

func basicAlertShowTest(t *testing.T, ctx context.Context, api *AlertCommonApi, testData []edgeproto.Alert) {
	var err error

	show := ShowAlert{}
	show.Init()
	filterNone := edgeproto.Alert{}
	err = api.ShowAlert(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+AlertShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetAlert(t *testing.T, ctx context.Context, api *AlertCommonApi, key *edgeproto.AlertKey, out *edgeproto.Alert) bool {
	var err error

	show := ShowAlert{}
	show.Init()
	filter := edgeproto.Alert{}
	filter.SetKey(key)
	err = api.ShowAlert(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func FindAlertData(key *edgeproto.AlertKey, testData []edgeproto.Alert) (*edgeproto.Alert, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

func (r *Run) AlertApi(data *[]edgeproto.Alert, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for Alert", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.Alert{}
		out, err := r.client.ShowAlert(r.ctx, obj)
		if err != nil {
			r.logErr("AlertApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.Alert)
			if !ok {
				panic(fmt.Sprintf("RunAlertApi expected dataOut type *[]edgeproto.Alert, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "showfiltered":
			out, err := r.client.ShowAlert(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("AlertApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Alert)
				if !ok {
					panic(fmt.Sprintf("RunAlertApi expected dataOut type *[]edgeproto.Alert, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (s *DummyServer) ShowAlert(in *edgeproto.Alert, server edgeproto.AlertApi_ShowAlertServer) error {
	var err error
	obj := &edgeproto.Alert{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Alert{})
		}
		if ch, ok := s.MidstreamFailChs["ShowAlert"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	err = s.AlertCache.Show(in, func(obj *edgeproto.Alert) error {
		err := server.Send(obj)
		return err
	})
	return err
}

type AlertStream interface {
	Recv() (*edgeproto.Alert, error)
}

func AlertReadStream(stream AlertStream) ([]edgeproto.Alert, error) {
	output := []edgeproto.Alert{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read Alert stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowAlert(ctx context.Context, in *edgeproto.Alert) ([]edgeproto.Alert, error) {
	api := edgeproto.NewAlertApiClient(s.Conn)
	stream, err := api.ShowAlert(ctx, in)
	if err != nil {
		return nil, err
	}
	return AlertReadStream(stream)
}

func (s *CliClient) ShowAlert(ctx context.Context, in *edgeproto.Alert) ([]edgeproto.Alert, error) {
	output := []edgeproto.Alert{}
	args := append(s.BaseArgs, "controller", "ShowAlert")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type AlertApiClient interface {
	ShowAlert(ctx context.Context, in *edgeproto.Alert) ([]edgeproto.Alert, error)
}

type DummyServer struct {
	CustomData
	AlertCache                    edgeproto.AlertCache
	AlertPolicyCache              edgeproto.AlertPolicyCache
	SettingsCache                 edgeproto.SettingsCache
	FlavorCache                   edgeproto.FlavorCache
	OperatorCodeCache             edgeproto.OperatorCodeCache
	ResTagTableCache              edgeproto.ResTagTableCache
	AutoScalePolicyCache          edgeproto.AutoScalePolicyCache
	TrustPolicyCache              edgeproto.TrustPolicyCache
	AppCache                      edgeproto.AppCache
	AppInstCache                  edgeproto.AppInstCache
	AppInstInfoCache              edgeproto.AppInstInfoCache
	FedAppInstCache               edgeproto.FedAppInstCache
	CloudletInternalCache         edgeproto.CloudletInternalCache
	PlatformFeaturesCache         edgeproto.PlatformFeaturesCache
	GPUDriverCache                edgeproto.GPUDriverCache
	CloudletCache                 edgeproto.CloudletCache
	CloudletInfoCache             edgeproto.CloudletInfoCache
	CloudletPoolCache             edgeproto.CloudletPoolCache
	VMPoolCache                   edgeproto.VMPoolCache
	VMPoolInfoCache               edgeproto.VMPoolInfoCache
	ClusterInstCache              edgeproto.ClusterInstCache
	ClusterInstInfoCache          edgeproto.ClusterInstInfoCache
	AutoProvPolicyCache           edgeproto.AutoProvPolicyCache
	AutoProvInfoCache             edgeproto.AutoProvInfoCache
	TrustPolicyExceptionCache     edgeproto.TrustPolicyExceptionCache
	TPEInstanceStateCache         edgeproto.TPEInstanceStateCache
	NetworkCache                  edgeproto.NetworkCache
	CloudletRefsCache             edgeproto.CloudletRefsCache
	ClusterRefsCache              edgeproto.ClusterRefsCache
	AppInstRefsCache              edgeproto.AppInstRefsCache
	FlowRateLimitSettingsCache    edgeproto.FlowRateLimitSettingsCache
	MaxReqsRateLimitSettingsCache edgeproto.MaxReqsRateLimitSettingsCache
	AppInstClientKeyCache         edgeproto.AppInstClientKeyCache
	CloudletNodeCache             edgeproto.CloudletNodeCache
	ControllerCache               edgeproto.ControllerCache
	NodeCache                     edgeproto.NodeCache
	DeviceCache                   edgeproto.DeviceCache
	ShowDummyCount                int
	CudNoop                       bool
	MidstreamFailChs              map[string]chan bool
}

func RegisterDummyServer(server *grpc.Server) *DummyServer {
	d := &DummyServer{}
	d.MidstreamFailChs = make(map[string]chan bool)
	edgeproto.InitAlertCache(&d.AlertCache)
	edgeproto.InitAlertPolicyCache(&d.AlertPolicyCache)
	edgeproto.InitSettingsCache(&d.SettingsCache)
	edgeproto.InitFlavorCache(&d.FlavorCache)
	edgeproto.InitOperatorCodeCache(&d.OperatorCodeCache)
	edgeproto.InitResTagTableCache(&d.ResTagTableCache)
	edgeproto.InitAutoScalePolicyCache(&d.AutoScalePolicyCache)
	edgeproto.InitTrustPolicyCache(&d.TrustPolicyCache)
	edgeproto.InitAppCache(&d.AppCache)
	edgeproto.InitAppInstCache(&d.AppInstCache)
	edgeproto.InitAppInstInfoCache(&d.AppInstInfoCache)
	edgeproto.InitFedAppInstCache(&d.FedAppInstCache)
	edgeproto.InitCloudletInternalCache(&d.CloudletInternalCache)
	edgeproto.InitPlatformFeaturesCache(&d.PlatformFeaturesCache)
	edgeproto.InitGPUDriverCache(&d.GPUDriverCache)
	edgeproto.InitCloudletCache(&d.CloudletCache)
	edgeproto.InitCloudletInfoCache(&d.CloudletInfoCache)
	edgeproto.InitCloudletPoolCache(&d.CloudletPoolCache)
	edgeproto.InitVMPoolCache(&d.VMPoolCache)
	edgeproto.InitVMPoolInfoCache(&d.VMPoolInfoCache)
	edgeproto.InitClusterInstCache(&d.ClusterInstCache)
	edgeproto.InitClusterInstInfoCache(&d.ClusterInstInfoCache)
	edgeproto.InitAutoProvPolicyCache(&d.AutoProvPolicyCache)
	edgeproto.InitAutoProvInfoCache(&d.AutoProvInfoCache)
	edgeproto.InitTrustPolicyExceptionCache(&d.TrustPolicyExceptionCache)
	edgeproto.InitTPEInstanceStateCache(&d.TPEInstanceStateCache)
	edgeproto.InitNetworkCache(&d.NetworkCache)
	edgeproto.InitCloudletRefsCache(&d.CloudletRefsCache)
	edgeproto.InitClusterRefsCache(&d.ClusterRefsCache)
	edgeproto.InitAppInstRefsCache(&d.AppInstRefsCache)
	edgeproto.InitFlowRateLimitSettingsCache(&d.FlowRateLimitSettingsCache)
	edgeproto.InitMaxReqsRateLimitSettingsCache(&d.MaxReqsRateLimitSettingsCache)
	edgeproto.InitAppInstClientKeyCache(&d.AppInstClientKeyCache)
	edgeproto.InitCloudletNodeCache(&d.CloudletNodeCache)
	edgeproto.InitControllerCache(&d.ControllerCache)
	edgeproto.InitNodeCache(&d.NodeCache)
	edgeproto.InitDeviceCache(&d.DeviceCache)
	edgeproto.RegisterAlertApiServer(server, d)
	edgeproto.RegisterAlertPolicyApiServer(server, d)
	edgeproto.RegisterSettingsApiServer(server, d)
	edgeproto.RegisterFlavorApiServer(server, d)
	edgeproto.RegisterOperatorCodeApiServer(server, d)
	edgeproto.RegisterAutoScalePolicyApiServer(server, d)
	edgeproto.RegisterTrustPolicyApiServer(server, d)
	edgeproto.RegisterAppApiServer(server, d)
	edgeproto.RegisterAppInstApiServer(server, d)
	edgeproto.RegisterAppInstInfoApiServer(server, d)
	edgeproto.RegisterOrganizationApiServer(server, d)
	edgeproto.RegisterPlatformFeaturesApiServer(server, d)
	edgeproto.RegisterGPUDriverApiServer(server, d)
	edgeproto.RegisterCloudletApiServer(server, d)
	edgeproto.RegisterCloudletInfoApiServer(server, d)
	edgeproto.RegisterCloudletPoolApiServer(server, d)
	edgeproto.RegisterVMPoolApiServer(server, d)
	edgeproto.RegisterClusterInstApiServer(server, d)
	edgeproto.RegisterClusterInstInfoApiServer(server, d)
	edgeproto.RegisterAutoProvPolicyApiServer(server, d)
	edgeproto.RegisterTrustPolicyExceptionApiServer(server, d)
	edgeproto.RegisterNetworkApiServer(server, d)
	edgeproto.RegisterCloudletRefsApiServer(server, d)
	edgeproto.RegisterClusterRefsApiServer(server, d)
	edgeproto.RegisterAppInstRefsApiServer(server, d)
	edgeproto.RegisterRateLimitSettingsApiServer(server, d)
	edgeproto.RegisterAppInstClientApiServer(server, d)
	edgeproto.RegisterCloudletNodeApiServer(server, d)
	edgeproto.RegisterControllerApiServer(server, d)
	edgeproto.RegisterNodeApiServer(server, d)
	edgeproto.RegisterDeviceApiServer(server, d)
	return d
}

func (s *DummyServer) EnableMidstreamFailure(api string, syncCh chan bool) {
	s.MidstreamFailChs[api] = syncCh
}

func (s *DummyServer) DisableMidstreamFailure(api string) {
	delete(s.MidstreamFailChs, api)
}

type ApiClient struct {
	Conn *grpc.ClientConn
}

type CliClient struct {
	BaseArgs []string
	RunOps   []wrapper.RunOp
}

type Client interface {
	AlertApiClient
	AlertPolicyApiClient
	SettingsApiClient
	FlavorApiClient
	OperatorCodeApiClient
	ResTagTableApiClient
	AutoScalePolicyApiClient
	TrustPolicyApiClient
	AppApiClient
	AppInstApiClient
	AppInstInfoApiClient
	AppInstMetricsApiClient
	AppInstLatencyApiClient
	OrganizationApiClient
	PlatformFeaturesApiClient
	GPUDriverApiClient
	CloudletApiClient
	CloudletInfoApiClient
	CloudletMetricsApiClient
	CloudletPoolApiClient
	VMPoolApiClient
	ClusterInstApiClient
	ClusterInstInfoApiClient
	AutoProvPolicyApiClient
	TrustPolicyExceptionApiClient
	NetworkApiClient
	CloudletRefsApiClient
	ClusterRefsApiClient
	AppInstRefsApiClient
	RateLimitSettingsApiClient
	AppInstClientApiClient
	ExecApiClient
	CloudletAccessApiClient
	CloudletNodeApiClient
	ControllerApiClient
	NodeApiClient
	DebugApiClient
	DeviceApiClient
	StreamObjApiClient
}

type InternalCUDAPIs interface {
	GetAlertPolicyApi() edgeproto.AlertPolicyApiServer
	GetFlavorApi() edgeproto.FlavorApiServer
	GetOperatorCodeApi() edgeproto.OperatorCodeApiServer
	GetResTagTableApi() edgeproto.ResTagTableApiServer
	GetAutoScalePolicyApi() edgeproto.AutoScalePolicyApiServer
	GetTrustPolicyApi() edgeproto.TrustPolicyApiServer
	GetAppApi() edgeproto.AppApiServer
	GetAppInstApi() edgeproto.AppInstApiServer
	GetGPUDriverApi() edgeproto.GPUDriverApiServer
	GetCloudletApi() edgeproto.CloudletApiServer
	GetCloudletPoolApi() edgeproto.CloudletPoolApiServer
	GetVMPoolApi() edgeproto.VMPoolApiServer
	GetClusterInstApi() edgeproto.ClusterInstApiServer
	GetAutoProvPolicyApi() edgeproto.AutoProvPolicyApiServer
	GetTrustPolicyExceptionApi() edgeproto.TrustPolicyExceptionApiServer
	GetNetworkApi() edgeproto.NetworkApiServer
	GetCloudletNodeApi() edgeproto.CloudletNodeApiServer
}
