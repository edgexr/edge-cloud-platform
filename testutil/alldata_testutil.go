// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alldata.proto

package testutil

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	_ "github.com/mobiledgex/edge-cloud/protogen"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
type AllDataOut struct {
	Flavors                    []edgeproto.Result
	Settings                   *edgeproto.Result
	OperatorCodes              []edgeproto.Result
	ResTagTables               []edgeproto.Result
	TrustPolicies              [][]edgeproto.Result
	Networks                   [][]edgeproto.Result
	Cloudlets                  [][]edgeproto.Result
	CloudletInfos              []edgeproto.Result
	CloudletPools              []edgeproto.Result
	AutoProvPolicies           []edgeproto.Result
	AutoProvPolicyCloudlets    []edgeproto.Result
	AutoScalePolicies          []edgeproto.Result
	IdleReservableClusterInsts *edgeproto.Result
	ClusterInsts               [][]edgeproto.Result
	Apps                       []edgeproto.Result
	AppInstances               [][]edgeproto.Result
	VmPools                    []edgeproto.Result
	GpuDrivers                 [][]edgeproto.Result
	AlertPolicies              []edgeproto.Result
	FlowRateLimitSettings      []edgeproto.Result
	MaxReqsRateLimitSettings   []edgeproto.Result
	TrustPolicyExceptions      []edgeproto.Result
	Errors                     []Err
}

// used to intersperse other creates/deletes/checks
// note the objs value is the previous one for create,
// but the next one for delete
type RunAllDataApiCallback func(objs string)

func RunAllDataApis(run *Run, in *edgeproto.AllData, inMap map[string]interface{}, out *AllDataOut, apicb RunAllDataApiCallback) {
	apicb("")
	run.FlavorApi(&in.Flavors, inMap["flavors"], &out.Flavors)
	apicb("flavors")
	run.SettingsApi(in.Settings, inMap["settings"], &out.Settings)
	apicb("settings")
	run.OperatorCodeApi(&in.OperatorCodes, inMap["operatorcodes"], &out.OperatorCodes)
	apicb("operatorcodes")
	run.ResTagTableApi(&in.ResTagTables, inMap["restagtables"], &out.ResTagTables)
	apicb("restagtables")
	run.TrustPolicyApi(&in.TrustPolicies, inMap["trustpolicies"], &out.TrustPolicies)
	apicb("trustpolicies")
	run.NetworkApi(&in.Networks, inMap["networks"], &out.Networks)
	apicb("networks")
	run.CloudletApi(&in.Cloudlets, inMap["cloudlets"], &out.Cloudlets)
	apicb("cloudlets")
	run.CloudletInfoApi(&in.CloudletInfos, inMap["cloudletinfos"], &out.CloudletInfos)
	apicb("cloudletinfos")
	run.CloudletPoolApi(&in.CloudletPools, inMap["cloudletpools"], &out.CloudletPools)
	apicb("cloudletpools")
	run.AutoProvPolicyApi(&in.AutoProvPolicies, inMap["autoprovpolicies"], &out.AutoProvPolicies)
	apicb("autoprovpolicies")
	run.AutoProvPolicyApi_AutoProvPolicyCloudlet(&in.AutoProvPolicyCloudlets, inMap["autoprovpolicycloudlets"], &out.AutoProvPolicyCloudlets)
	apicb("autoprovpolicycloudlets")
	run.AutoScalePolicyApi(&in.AutoScalePolicies, inMap["autoscalepolicies"], &out.AutoScalePolicies)
	apicb("autoscalepolicies")
	run.ClusterInstApi_IdleReservableClusterInsts(in.IdleReservableClusterInsts, inMap["idlereservableclusterinsts"], &out.IdleReservableClusterInsts)
	apicb("idlereservableclusterinsts")
	run.ClusterInstApi(&in.ClusterInsts, inMap["clusterinsts"], &out.ClusterInsts)
	apicb("clusterinsts")
	run.AppApi(&in.Apps, inMap["apps"], &out.Apps)
	apicb("apps")
	run.AppInstApi(&in.AppInstances, inMap["appinstances"], &out.AppInstances)
	apicb("appinstances")
	run.VMPoolApi(&in.VmPools, inMap["vmpools"], &out.VmPools)
	apicb("vmpools")
	run.GPUDriverApi(&in.GpuDrivers, inMap["gpudrivers"], &out.GpuDrivers)
	apicb("gpudrivers")
	run.AlertPolicyApi(&in.AlertPolicies, inMap["alertpolicies"], &out.AlertPolicies)
	apicb("alertpolicies")
	run.RateLimitSettingsApi_FlowRateLimitSettings(&in.FlowRateLimitSettings, inMap["flowratelimitsettings"], &out.FlowRateLimitSettings)
	apicb("flowratelimitsettings")
	run.RateLimitSettingsApi_MaxReqsRateLimitSettings(&in.MaxReqsRateLimitSettings, inMap["maxreqsratelimitsettings"], &out.MaxReqsRateLimitSettings)
	apicb("maxreqsratelimitsettings")
	run.TrustPolicyExceptionApi(&in.TrustPolicyExceptions, inMap["trustpolicyexceptions"], &out.TrustPolicyExceptions)
	apicb("trustpolicyexceptions")
	out.Errors = run.Errs
}

func RunAllDataReverseApis(run *Run, in *edgeproto.AllData, inMap map[string]interface{}, out *AllDataOut, apicb RunAllDataApiCallback) {
	apicb("trustpolicyexceptions")
	run.TrustPolicyExceptionApi(&in.TrustPolicyExceptions, inMap["trustpolicyexceptions"], &out.TrustPolicyExceptions)
	apicb("maxreqsratelimitsettings")
	run.RateLimitSettingsApi_MaxReqsRateLimitSettings(&in.MaxReqsRateLimitSettings, inMap["maxreqsratelimitsettings"], &out.MaxReqsRateLimitSettings)
	apicb("flowratelimitsettings")
	run.RateLimitSettingsApi_FlowRateLimitSettings(&in.FlowRateLimitSettings, inMap["flowratelimitsettings"], &out.FlowRateLimitSettings)
	apicb("alertpolicies")
	run.AlertPolicyApi(&in.AlertPolicies, inMap["alertpolicies"], &out.AlertPolicies)
	apicb("gpudrivers")
	run.GPUDriverApi(&in.GpuDrivers, inMap["gpudrivers"], &out.GpuDrivers)
	apicb("vmpools")
	run.VMPoolApi(&in.VmPools, inMap["vmpools"], &out.VmPools)
	apicb("appinstances")
	run.AppInstApi(&in.AppInstances, inMap["appinstances"], &out.AppInstances)
	apicb("apps")
	run.AppApi(&in.Apps, inMap["apps"], &out.Apps)
	apicb("clusterinsts")
	run.ClusterInstApi(&in.ClusterInsts, inMap["clusterinsts"], &out.ClusterInsts)
	apicb("idlereservableclusterinsts")
	run.ClusterInstApi_IdleReservableClusterInsts(in.IdleReservableClusterInsts, inMap["idlereservableclusterinsts"], &out.IdleReservableClusterInsts)
	apicb("autoscalepolicies")
	run.AutoScalePolicyApi(&in.AutoScalePolicies, inMap["autoscalepolicies"], &out.AutoScalePolicies)
	apicb("autoprovpolicycloudlets")
	run.AutoProvPolicyApi_AutoProvPolicyCloudlet(&in.AutoProvPolicyCloudlets, inMap["autoprovpolicycloudlets"], &out.AutoProvPolicyCloudlets)
	apicb("autoprovpolicies")
	run.AutoProvPolicyApi(&in.AutoProvPolicies, inMap["autoprovpolicies"], &out.AutoProvPolicies)
	apicb("cloudletpools")
	run.CloudletPoolApi(&in.CloudletPools, inMap["cloudletpools"], &out.CloudletPools)
	apicb("cloudletinfos")
	run.CloudletInfoApi(&in.CloudletInfos, inMap["cloudletinfos"], &out.CloudletInfos)
	apicb("cloudlets")
	run.CloudletApi(&in.Cloudlets, inMap["cloudlets"], &out.Cloudlets)
	apicb("networks")
	run.NetworkApi(&in.Networks, inMap["networks"], &out.Networks)
	apicb("trustpolicies")
	run.TrustPolicyApi(&in.TrustPolicies, inMap["trustpolicies"], &out.TrustPolicies)
	apicb("restagtables")
	run.ResTagTableApi(&in.ResTagTables, inMap["restagtables"], &out.ResTagTables)
	apicb("operatorcodes")
	run.OperatorCodeApi(&in.OperatorCodes, inMap["operatorcodes"], &out.OperatorCodes)
	apicb("settings")
	run.SettingsApi(in.Settings, inMap["settings"], &out.Settings)
	apicb("flavors")
	run.FlavorApi(&in.Flavors, inMap["flavors"], &out.Flavors)
	apicb("")
	out.Errors = run.Errs
}

func RunAllDataShowApis(run *Run, in *edgeproto.AllData, out *edgeproto.AllData) {
	run.FlavorApi(&in.Flavors, nil, &out.Flavors)
	run.SettingsApi(in.Settings, nil, &out.Settings)
	run.OperatorCodeApi(&in.OperatorCodes, nil, &out.OperatorCodes)
	run.ResTagTableApi(&in.ResTagTables, nil, &out.ResTagTables)
	run.TrustPolicyApi(&in.TrustPolicies, nil, &out.TrustPolicies)
	run.NetworkApi(&in.Networks, nil, &out.Networks)
	run.CloudletApi(&in.Cloudlets, nil, &out.Cloudlets)
	run.CloudletInfoApi(&in.CloudletInfos, nil, &out.CloudletInfos)
	run.CloudletPoolApi(&in.CloudletPools, nil, &out.CloudletPools)
	run.AutoProvPolicyApi(&in.AutoProvPolicies, nil, &out.AutoProvPolicies)
	run.AutoScalePolicyApi(&in.AutoScalePolicies, nil, &out.AutoScalePolicies)
	run.ClusterInstApi(&in.ClusterInsts, nil, &out.ClusterInsts)
	run.AppApi(&in.Apps, nil, &out.Apps)
	run.AppInstApi(&in.AppInstances, nil, &out.AppInstances)
	run.AppInstRefsApi(&in.AppInstRefs, nil, &out.AppInstRefs)
	run.VMPoolApi(&in.VmPools, nil, &out.VmPools)
	run.GPUDriverApi(&in.GpuDrivers, nil, &out.GpuDrivers)
	run.AlertPolicyApi(&in.AlertPolicies, nil, &out.AlertPolicies)
	run.RateLimitSettingsApi_FlowRateLimitSettings(&in.FlowRateLimitSettings, nil, &out.FlowRateLimitSettings)
	run.RateLimitSettingsApi_MaxReqsRateLimitSettings(&in.MaxReqsRateLimitSettings, nil, &out.MaxReqsRateLimitSettings)
	run.TrustPolicyExceptionApi(&in.TrustPolicyExceptions, nil, &out.TrustPolicyExceptions)
}
