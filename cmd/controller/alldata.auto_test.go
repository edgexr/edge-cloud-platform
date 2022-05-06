// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alldata.proto

package main

import (
	"context"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/require"
	math "math"
	"testing"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

type testSupportData edgeproto.AllData

func (s *testSupportData) put(t *testing.T, ctx context.Context, all *AllApis) {
	for _, obj := range s.Flavors {
		_, err := all.flavorApi.store.Put(ctx, &obj, all.flavorApi.sync.syncWait)
		require.Nil(t, err)
	}
	if s.Settings != nil {
		_, err := all.settingsApi.store.Put(ctx, s.Settings, all.settingsApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.OperatorCodes {
		_, err := all.operatorCodeApi.store.Put(ctx, &obj, all.operatorCodeApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.ResTagTables {
		_, err := all.resTagTableApi.store.Put(ctx, &obj, all.resTagTableApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.TrustPolicies {
		_, err := all.trustPolicyApi.store.Put(ctx, &obj, all.trustPolicyApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.GpuDrivers {
		_, err := all.gpuDriverApi.store.Put(ctx, &obj, all.gpuDriverApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.Cloudlets {
		_, err := all.cloudletApi.store.Put(ctx, &obj, all.cloudletApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.CloudletInfos {
		_, err := all.cloudletInfoApi.store.Put(ctx, &obj, all.cloudletInfoApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.CloudletPools {
		_, err := all.cloudletPoolApi.store.Put(ctx, &obj, all.cloudletPoolApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.Networks {
		_, err := all.networkApi.store.Put(ctx, &obj, all.networkApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.AutoProvPolicies {
		_, err := all.autoProvPolicyApi.store.Put(ctx, &obj, all.autoProvPolicyApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.AutoScalePolicies {
		_, err := all.autoScalePolicyApi.store.Put(ctx, &obj, all.autoScalePolicyApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.ClusterInsts {
		_, err := all.clusterInstApi.store.Put(ctx, &obj, all.clusterInstApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.Apps {
		_, err := all.appApi.store.Put(ctx, &obj, all.appApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.AppInstances {
		_, err := all.appInstApi.store.Put(ctx, &obj, all.appInstApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.AppInstRefs {
		_, err := all.appInstRefsApi.store.Put(ctx, &obj, all.appInstRefsApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.ClusterRefs {
		_, err := all.clusterRefsApi.store.Put(ctx, &obj, all.clusterRefsApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.VmPools {
		_, err := all.vmPoolApi.store.Put(ctx, &obj, all.vmPoolApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.AlertPolicies {
		_, err := all.alertPolicyApi.store.Put(ctx, &obj, all.alertPolicyApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.FlowRateLimitSettings {
		_, err := all.flowRateLimitSettingsApi.store.Put(ctx, &obj, all.flowRateLimitSettingsApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.MaxReqsRateLimitSettings {
		_, err := all.maxReqsRateLimitSettingsApi.store.Put(ctx, &obj, all.maxReqsRateLimitSettingsApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.TrustPolicyExceptions {
		_, err := all.trustPolicyExceptionApi.store.Put(ctx, &obj, all.trustPolicyExceptionApi.sync.syncWait)
		require.Nil(t, err)
	}
}

func (s *testSupportData) delete(t *testing.T, ctx context.Context, all *AllApis) {
	for _, obj := range s.TrustPolicyExceptions {
		_, err := all.trustPolicyExceptionApi.store.Delete(ctx, &obj, all.trustPolicyExceptionApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.MaxReqsRateLimitSettings {
		_, err := all.maxReqsRateLimitSettingsApi.store.Delete(ctx, &obj, all.maxReqsRateLimitSettingsApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.FlowRateLimitSettings {
		_, err := all.flowRateLimitSettingsApi.store.Delete(ctx, &obj, all.flowRateLimitSettingsApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.AlertPolicies {
		_, err := all.alertPolicyApi.store.Delete(ctx, &obj, all.alertPolicyApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.VmPools {
		_, err := all.vmPoolApi.store.Delete(ctx, &obj, all.vmPoolApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.ClusterRefs {
		_, err := all.clusterRefsApi.store.Delete(ctx, &obj, all.clusterRefsApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.AppInstRefs {
		_, err := all.appInstRefsApi.store.Delete(ctx, &obj, all.appInstRefsApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.AppInstances {
		_, err := all.appInstApi.store.Delete(ctx, &obj, all.appInstApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.Apps {
		_, err := all.appApi.store.Delete(ctx, &obj, all.appApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.ClusterInsts {
		_, err := all.clusterInstApi.store.Delete(ctx, &obj, all.clusterInstApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.AutoScalePolicies {
		_, err := all.autoScalePolicyApi.store.Delete(ctx, &obj, all.autoScalePolicyApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.AutoProvPolicies {
		_, err := all.autoProvPolicyApi.store.Delete(ctx, &obj, all.autoProvPolicyApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.Networks {
		_, err := all.networkApi.store.Delete(ctx, &obj, all.networkApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.CloudletPools {
		_, err := all.cloudletPoolApi.store.Delete(ctx, &obj, all.cloudletPoolApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.CloudletInfos {
		_, err := all.cloudletInfoApi.store.Delete(ctx, &obj, all.cloudletInfoApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.Cloudlets {
		_, err := all.cloudletApi.store.Delete(ctx, &obj, all.cloudletApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.GpuDrivers {
		_, err := all.gpuDriverApi.store.Delete(ctx, &obj, all.gpuDriverApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.TrustPolicies {
		_, err := all.trustPolicyApi.store.Delete(ctx, &obj, all.trustPolicyApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.ResTagTables {
		_, err := all.resTagTableApi.store.Delete(ctx, &obj, all.resTagTableApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.OperatorCodes {
		_, err := all.operatorCodeApi.store.Delete(ctx, &obj, all.operatorCodeApi.sync.syncWait)
		require.Nil(t, err)
	}
	if s.Settings != nil {
		_, err := all.settingsApi.store.Delete(ctx, s.Settings, all.settingsApi.sync.syncWait)
		require.Nil(t, err)
	}
	for _, obj := range s.Flavors {
		_, err := all.flavorApi.store.Delete(ctx, &obj, all.flavorApi.sync.syncWait)
		require.Nil(t, err)
	}
}

func (s *testSupportData) getOneFlavor() *edgeproto.Flavor {
	if len(s.Flavors) == 0 {
		return nil
	}
	return &s.Flavors[0]
}

func (s *testSupportData) getOneSettings() *edgeproto.Settings {
	return s.Settings
}

func (s *testSupportData) getOneOperatorCode() *edgeproto.OperatorCode {
	if len(s.OperatorCodes) == 0 {
		return nil
	}
	return &s.OperatorCodes[0]
}

func (s *testSupportData) getOneResTagTable() *edgeproto.ResTagTable {
	if len(s.ResTagTables) == 0 {
		return nil
	}
	return &s.ResTagTables[0]
}

func (s *testSupportData) getOneTrustPolicy() *edgeproto.TrustPolicy {
	if len(s.TrustPolicies) == 0 {
		return nil
	}
	return &s.TrustPolicies[0]
}

func (s *testSupportData) getOneGPUDriver() *edgeproto.GPUDriver {
	if len(s.GpuDrivers) == 0 {
		return nil
	}
	return &s.GpuDrivers[0]
}

func (s *testSupportData) getOneCloudlet() *edgeproto.Cloudlet {
	if len(s.Cloudlets) == 0 {
		return nil
	}
	return &s.Cloudlets[0]
}

func (s *testSupportData) getOneCloudletInfo() *edgeproto.CloudletInfo {
	if len(s.CloudletInfos) == 0 {
		return nil
	}
	return &s.CloudletInfos[0]
}

func (s *testSupportData) getOneCloudletPool() *edgeproto.CloudletPool {
	if len(s.CloudletPools) == 0 {
		return nil
	}
	return &s.CloudletPools[0]
}

func (s *testSupportData) getOneNetwork() *edgeproto.Network {
	if len(s.Networks) == 0 {
		return nil
	}
	return &s.Networks[0]
}

func (s *testSupportData) getOneAutoProvPolicy() *edgeproto.AutoProvPolicy {
	if len(s.AutoProvPolicies) == 0 {
		return nil
	}
	return &s.AutoProvPolicies[0]
}

func (s *testSupportData) getOneAutoScalePolicy() *edgeproto.AutoScalePolicy {
	if len(s.AutoScalePolicies) == 0 {
		return nil
	}
	return &s.AutoScalePolicies[0]
}

func (s *testSupportData) getOneClusterInst() *edgeproto.ClusterInst {
	if len(s.ClusterInsts) == 0 {
		return nil
	}
	return &s.ClusterInsts[0]
}

func (s *testSupportData) getOneApp() *edgeproto.App {
	if len(s.Apps) == 0 {
		return nil
	}
	return &s.Apps[0]
}

func (s *testSupportData) getOneAppInst() *edgeproto.AppInst {
	if len(s.AppInstances) == 0 {
		return nil
	}
	return &s.AppInstances[0]
}

func (s *testSupportData) getOneAppInstRefs() *edgeproto.AppInstRefs {
	if len(s.AppInstRefs) == 0 {
		return nil
	}
	return &s.AppInstRefs[0]
}

func (s *testSupportData) getOneClusterRefs() *edgeproto.ClusterRefs {
	if len(s.ClusterRefs) == 0 {
		return nil
	}
	return &s.ClusterRefs[0]
}

func (s *testSupportData) getOneVMPool() *edgeproto.VMPool {
	if len(s.VmPools) == 0 {
		return nil
	}
	return &s.VmPools[0]
}

func (s *testSupportData) getOneAlertPolicy() *edgeproto.AlertPolicy {
	if len(s.AlertPolicies) == 0 {
		return nil
	}
	return &s.AlertPolicies[0]
}

func (s *testSupportData) getOneFlowRateLimitSettings() *edgeproto.FlowRateLimitSettings {
	if len(s.FlowRateLimitSettings) == 0 {
		return nil
	}
	return &s.FlowRateLimitSettings[0]
}

func (s *testSupportData) getOneMaxReqsRateLimitSettings() *edgeproto.MaxReqsRateLimitSettings {
	if len(s.MaxReqsRateLimitSettings) == 0 {
		return nil
	}
	return &s.MaxReqsRateLimitSettings[0]
}

func (s *testSupportData) getOneTrustPolicyException() *edgeproto.TrustPolicyException {
	if len(s.TrustPolicyExceptions) == 0 {
		return nil
	}
	return &s.TrustPolicyExceptions[0]
}
