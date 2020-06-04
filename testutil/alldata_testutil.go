// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alldata.proto

package testutil

import "github.com/mobiledgex/edge-cloud/edgeproto"
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
type AllDataOut struct {
	Flavors                 []edgeproto.Result
	Settings                *edgeproto.Result
	OperatorCodes           []edgeproto.Result
	ResTagTables            []edgeproto.Result
	Cloudlets               [][]edgeproto.Result
	CloudletInfos           []edgeproto.Result
	CloudletPools           []edgeproto.Result
	CloudletPoolMembers     []edgeproto.Result
	AutoProvPolicies        []edgeproto.Result
	AutoProvPolicyCloudlets []edgeproto.Result
	AutoScalePolicies       []edgeproto.Result
	PrivacyPolicies         []edgeproto.Result
	ClusterInsts            [][]edgeproto.Result
	Apps                    []edgeproto.Result
	AppInstances            [][]edgeproto.Result
	Errors                  []Err
}

func RunAllDataApis(run *Run, in *edgeproto.AllData, inMap map[string]interface{}, out *AllDataOut) {
	run.FlavorApi(&in.Flavors, inMap["flavors"], &out.Flavors)
	run.SettingsApi(in.Settings, inMap["settings"], &out.Settings)
	run.OperatorCodeApi(&in.OperatorCodes, inMap["operatorcodes"], &out.OperatorCodes)
	run.ResTagTableApi(&in.ResTagTables, inMap["restagtables"], &out.ResTagTables)
	run.CloudletApi(&in.Cloudlets, inMap["cloudlets"], &out.Cloudlets)
	run.CloudletInfoApi(&in.CloudletInfos, inMap["cloudletinfos"], &out.CloudletInfos)
	run.CloudletPoolApi(&in.CloudletPools, inMap["cloudletpools"], &out.CloudletPools)
	run.CloudletPoolMemberApi(&in.CloudletPoolMembers, inMap["cloudletpoolmembers"], &out.CloudletPoolMembers)
	run.AutoProvPolicyApi(&in.AutoProvPolicies, inMap["autoprovpolicies"], &out.AutoProvPolicies)
	run.AutoProvPolicyApi_AutoProvPolicyCloudlet(&in.AutoProvPolicyCloudlets, inMap["autoprovpolicycloudlets"], &out.AutoProvPolicyCloudlets)
	run.AutoScalePolicyApi(&in.AutoScalePolicies, inMap["autoscalepolicies"], &out.AutoScalePolicies)
	run.PrivacyPolicyApi(&in.PrivacyPolicies, inMap["privacypolicies"], &out.PrivacyPolicies)
	run.ClusterInstApi(&in.ClusterInsts, inMap["clusterinsts"], &out.ClusterInsts)
	run.AppApi(&in.Apps, inMap["apps"], &out.Apps)
	run.AppInstApi(&in.AppInstances, inMap["appinstances"], &out.AppInstances)
	out.Errors = run.Errs
}

func RunAllDataReverseApis(run *Run, in *edgeproto.AllData, inMap map[string]interface{}, out *AllDataOut) {
	run.AppInstApi(&in.AppInstances, inMap["appinstances"], &out.AppInstances)
	run.AppApi(&in.Apps, inMap["apps"], &out.Apps)
	run.ClusterInstApi(&in.ClusterInsts, inMap["clusterinsts"], &out.ClusterInsts)
	run.PrivacyPolicyApi(&in.PrivacyPolicies, inMap["privacypolicies"], &out.PrivacyPolicies)
	run.AutoScalePolicyApi(&in.AutoScalePolicies, inMap["autoscalepolicies"], &out.AutoScalePolicies)
	run.AutoProvPolicyApi_AutoProvPolicyCloudlet(&in.AutoProvPolicyCloudlets, inMap["autoprovpolicycloudlets"], &out.AutoProvPolicyCloudlets)
	run.AutoProvPolicyApi(&in.AutoProvPolicies, inMap["autoprovpolicies"], &out.AutoProvPolicies)
	run.CloudletPoolMemberApi(&in.CloudletPoolMembers, inMap["cloudletpoolmembers"], &out.CloudletPoolMembers)
	run.CloudletPoolApi(&in.CloudletPools, inMap["cloudletpools"], &out.CloudletPools)
	run.CloudletInfoApi(&in.CloudletInfos, inMap["cloudletinfos"], &out.CloudletInfos)
	run.CloudletApi(&in.Cloudlets, inMap["cloudlets"], &out.Cloudlets)
	run.ResTagTableApi(&in.ResTagTables, inMap["restagtables"], &out.ResTagTables)
	run.OperatorCodeApi(&in.OperatorCodes, inMap["operatorcodes"], &out.OperatorCodes)
	run.SettingsApi(in.Settings, inMap["settings"], &out.Settings)
	run.FlavorApi(&in.Flavors, inMap["flavors"], &out.Flavors)
	out.Errors = run.Errs
}

func RunAllDataShowApis(run *Run, in *edgeproto.AllData, out *edgeproto.AllData) {
	run.FlavorApi(&in.Flavors, nil, &out.Flavors)
	run.SettingsApi(in.Settings, nil, &out.Settings)
	run.OperatorCodeApi(&in.OperatorCodes, nil, &out.OperatorCodes)
	run.ResTagTableApi(&in.ResTagTables, nil, &out.ResTagTables)
	run.CloudletApi(&in.Cloudlets, nil, &out.Cloudlets)
	run.CloudletInfoApi(&in.CloudletInfos, nil, &out.CloudletInfos)
	run.CloudletPoolApi(&in.CloudletPools, nil, &out.CloudletPools)
	run.CloudletPoolMemberApi(&in.CloudletPoolMembers, nil, &out.CloudletPoolMembers)
	run.AutoProvPolicyApi(&in.AutoProvPolicies, nil, &out.AutoProvPolicies)
	run.AutoScalePolicyApi(&in.AutoScalePolicies, nil, &out.AutoScalePolicies)
	run.PrivacyPolicyApi(&in.PrivacyPolicies, nil, &out.PrivacyPolicies)
	run.ClusterInstApi(&in.ClusterInsts, nil, &out.ClusterInsts)
	run.AppApi(&in.Apps, nil, &out.Apps)
	run.AppInstApi(&in.AppInstances, nil, &out.AppInstances)
	run.AppInstRefsApi(&in.AppInstRefs, nil, &out.AppInstRefs)
}
