// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"testing"

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
)

func TestDeleteChecks(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	dummy := dummyEtcd{}
	dummy.Start()

	sync := InitSync(&dummy)
	apis := NewAllApis(sync)
	sync.Start()
	defer sync.Done()

	dataGen := DeleteDataGen{}
	allDeleteChecks(t, ctx, apis, &dataGen)
}

var noSupportData = &testSupportData{}

type DeleteDataGen struct{}

// AlertPolicy
func (s *DeleteDataGen) GetAlertPolicyTestObj() (*edgeproto.AlertPolicy, *testSupportData) {
	obj := testutil.AlertPolicyData()[0]
	return &obj, noSupportData
}
func (s *DeleteDataGen) GetAppAlertPoliciesRef(key *edgeproto.AlertPolicyKey) (*edgeproto.App, *testSupportData) {
	ref := testutil.AppData()[0]
	ref.Key.Organization = key.Organization
	ref.AlertPolicies = []string{key.Name}
	return &ref, noSupportData
}

// App
func (s *DeleteDataGen) GetAppTestObj() (*edgeproto.App, *testSupportData) {
	obj := testutil.AppData()[0]
	return &obj, noSupportData
}
func (s *DeleteDataGen) GetTrustPolicyExceptionKeyAppKeyRef(key *edgeproto.AppKey) (*edgeproto.TrustPolicyException, *testSupportData) {
	ref := testutil.TrustPolicyExceptionData()[0]
	ref.Key.AppKey = *key
	return &ref, noSupportData
}
func (s *DeleteDataGen) GetAppAppInstInstsRef(key *edgeproto.AppKey) (*edgeproto.AppInstRefs, *testSupportData) {
	cloudlet := testutil.CloudletData()[0]
	inst := edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         "appAppInstRef",
			Organization: key.Organization,
			CloudletKey:  cloudlet.Key,
		},
		AppKey:   *key,
		Liveness: edgeproto.Liveness_LIVENESS_STATIC,
	}
	supportData := &testSupportData{}
	supportData.AppInstances = []edgeproto.AppInst{inst}

	ref := edgeproto.AppInstRefs{}
	ref.Key = *key
	instKeyVal, err := json.Marshal(inst.Key)
	if err != nil {
		panic(err.Error())
	}
	ref.Insts = map[string]uint32{
		string(instKeyVal): 1,
	}
	return &ref, supportData
}

// AutoProvPolicy
func (s *DeleteDataGen) GetAutoProvPolicyTestObj() (*edgeproto.AutoProvPolicy, *testSupportData) {
	obj := testutil.AutoProvPolicyData()[0]
	return &obj, noSupportData
}
func (s *DeleteDataGen) GetAppAutoProvPoliciesRef(key *edgeproto.PolicyKey) (*edgeproto.App, *testSupportData) {
	ref := testutil.AppData()[0]
	ref.Key.Organization = key.Organization
	ref.AutoProvPolicies = []string{key.Name}
	return &ref, noSupportData
}

// AutoScalePolicy
func (s *DeleteDataGen) GetAutoScalePolicyTestObj() (*edgeproto.AutoScalePolicy, *testSupportData) {
	obj := testutil.AutoScalePolicyData()[0]
	return &obj, noSupportData
}
func (s *DeleteDataGen) GetClusterInstAutoScalePolicyRef(key *edgeproto.PolicyKey) (*edgeproto.ClusterInst, *testSupportData) {
	ref := testutil.ClusterInstData()[0]
	ref.Key.ClusterKey.Organization = key.Organization
	ref.AutoScalePolicy = key.Name
	return &ref, noSupportData
}

// Cloudlet
func (s *DeleteDataGen) GetCloudletTestObj() (*edgeproto.Cloudlet, *testSupportData) {
	obj := testutil.CloudletData()[0]
	supportData := &testSupportData{}
	supportData.GpuDrivers = []edgeproto.GPUDriver{testutil.GPUDriverData()[0]}
	return &obj, supportData
}
func (s *DeleteDataGen) GetAutoProvPolicyCloudletsRef(key *edgeproto.CloudletKey) (*edgeproto.AutoProvPolicy, *testSupportData) {
	ref := testutil.AutoProvPolicyData()[0]
	ref.Cloudlets = []*edgeproto.AutoProvCloudlet{
		&edgeproto.AutoProvCloudlet{
			Key: *key,
		},
	}
	return &ref, noSupportData
}
func (s *DeleteDataGen) GetCloudletPoolCloudletsRef(key *edgeproto.CloudletKey) (*edgeproto.CloudletPool, *testSupportData) {
	ref := testutil.CloudletPoolData()[0]
	ref.Key.Organization = key.Organization
	ref.Cloudlets = []edgeproto.CloudletKey{*key}
	return &ref, noSupportData
}
func (s *DeleteDataGen) GetNetworkKeyCloudletKeyRef(key *edgeproto.CloudletKey) (*edgeproto.Network, *testSupportData) {
	ref := testutil.NetworkData()[0]
	ref.Key.CloudletKey = *key
	return &ref, noSupportData
}
func (s *DeleteDataGen) GetCloudletClusterInstClusterInstsRef(key *edgeproto.CloudletKey) (*edgeproto.CloudletRefs, *testSupportData) {
	ref := edgeproto.CloudletRefs{}
	ref.Key = *key
	clusterInst := testutil.ClusterInstData()[0]
	supportData := &testSupportData{}
	supportData.ClusterInsts = []edgeproto.ClusterInst{clusterInst}
	clusterInstRefKey := clusterInst.Key.ClusterKey
	ref.ClusterInsts = []edgeproto.ClusterKey{clusterInstRefKey}
	return &ref, supportData
}
func (s *DeleteDataGen) GetCloudletAppInstVmAppInstsRef(key *edgeproto.CloudletKey) (*edgeproto.CloudletRefs, *testSupportData) {
	ref := edgeproto.CloudletRefs{}
	ref.Key = *key
	app := testutil.AppData()[0]
	appInst := testutil.AppInstData()[0]
	appInst.AppKey = app.Key
	supportData := &testSupportData{}
	supportData.AppInstances = []edgeproto.AppInst{appInst}
	supportData.Apps = []edgeproto.App{app}
	appInstRefKey := appInst.Key.GetRefKey()
	ref.VmAppInsts = append(ref.VmAppInsts, *appInstRefKey)
	return &ref, supportData
}

// CloudletPool
func (s *DeleteDataGen) GetCloudletPoolTestObj() (*edgeproto.CloudletPool, *testSupportData) {
	obj := testutil.CloudletPoolData()[0]
	return &obj, noSupportData
}
func (s *DeleteDataGen) GetTrustPolicyExceptionKeyCloudletPoolKeyRef(key *edgeproto.CloudletPoolKey) (*edgeproto.TrustPolicyException, *testSupportData) {
	ref := testutil.TrustPolicyExceptionData()[0]
	ref.Key.CloudletPoolKey = *key
	return &ref, noSupportData
}

// ClusterInst
func (s *DeleteDataGen) GetClusterInstTestObj() (*edgeproto.ClusterInst, *testSupportData) {
	obj := testutil.ClusterInstData()[0]
	obj.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM
	cloudlet := edgeproto.Cloudlet{}
	cloudlet.Key = obj.Key.CloudletKey
	cloudletInfo := edgeproto.CloudletInfo{}
	cloudletInfo.Key = obj.Key.CloudletKey
	cloudletInfo.State = dme.CloudletState_CLOUDLET_STATE_READY
	supportData := &testSupportData{}
	supportData.Cloudlets = []edgeproto.Cloudlet{cloudlet}
	supportData.CloudletInfos = []edgeproto.CloudletInfo{cloudletInfo}
	supportData.Flavors = []edgeproto.Flavor{testutil.FlavorData()[0]}
	return &obj, supportData
}
func (s *DeleteDataGen) GetClusterInstAppInstAppsRef(key *edgeproto.ClusterInstKey) (*edgeproto.ClusterRefs, *testSupportData) {
	app := testutil.AppData()[0]
	appInst := edgeproto.AppInst{}
	appInst.Key.Name = "clusterInstAppInstRef"
	appInst.Key.Organization = app.Key.Organization
	appInst.Key.CloudletKey = key.CloudletKey
	appInst.AppKey = app.Key
	appInst.ClusterKey = key.ClusterKey
	appInst.Liveness = edgeproto.Liveness_LIVENESS_STATIC
	supportData := &testSupportData{}
	supportData.AppInstances = []edgeproto.AppInst{appInst}
	supportData.Apps = []edgeproto.App{app}

	ref := edgeproto.ClusterRefs{}
	ref.Key = *key
	instRefKey := appInst.Key.GetRefKey()
	ref.Apps = []edgeproto.AppInstRefKey{*instRefKey}
	return &ref, supportData
}

// Flavor
func (s *DeleteDataGen) GetFlavorTestObj() (*edgeproto.Flavor, *testSupportData) {
	supportData := &testSupportData{}
	supportData.Settings = edgeproto.GetDefaultSettings()

	obj := testutil.FlavorData()[0]
	return &obj, supportData
}
func (s *DeleteDataGen) GetAppDefaultFlavorRef(key *edgeproto.FlavorKey) (*edgeproto.App, *testSupportData) {
	ref := testutil.AppData()[0]
	ref.DefaultFlavor = *key
	return &ref, noSupportData
}
func (s *DeleteDataGen) GetCloudletFlavorRef(key *edgeproto.FlavorKey) (*edgeproto.Cloudlet, *testSupportData) {
	ref := testutil.CloudletData()[0]
	ref.Flavor = *key
	return &ref, noSupportData
}
func (s *DeleteDataGen) GetClusterInstFlavorRef(key *edgeproto.FlavorKey) (*edgeproto.ClusterInst, *testSupportData) {
	ref := testutil.ClusterInstData()[0]
	ref.Flavor = *key
	return &ref, noSupportData
}
func (s *DeleteDataGen) GetAppInstFlavorRef(key *edgeproto.FlavorKey) (*edgeproto.AppInst, *testSupportData) {
	ref := testutil.AppInstData()[0]
	ref.Flavor = *key
	return &ref, noSupportData
}

// GPUDriver
func (s *DeleteDataGen) GetGPUDriverTestObj() (*edgeproto.GPUDriver, *testSupportData) {
	obj := testutil.GPUDriverData()[0]
	return &obj, noSupportData
}
func (s *DeleteDataGen) GetCloudletGpuConfigDriverRef(key *edgeproto.GPUDriverKey) (*edgeproto.Cloudlet, *testSupportData) {
	ref := testutil.CloudletData()[0]
	ref.GpuConfig.Driver = *key
	return &ref, noSupportData
}

// Network
func (s *DeleteDataGen) GetNetworkTestObj() (*edgeproto.Network, *testSupportData) {
	obj := testutil.NetworkData()[0]
	return &obj, noSupportData
}
func (s *DeleteDataGen) GetClusterInstNetworksRef(key *edgeproto.NetworkKey) (*edgeproto.ClusterInst, *testSupportData) {
	ref := testutil.ClusterInstData()[0]
	ref.Key.CloudletKey = key.CloudletKey
	ref.Networks = []string{key.Name}
	return &ref, noSupportData
}

// ResTagTable
func (s *DeleteDataGen) GetResTagTableTestObj() (*edgeproto.ResTagTable, *testSupportData) {
	obj := testutil.ResTagTableData()[0]
	return &obj, noSupportData
}
func (s *DeleteDataGen) GetCloudletResTagMapRef(key *edgeproto.ResTagTableKey) (*edgeproto.Cloudlet, *testSupportData) {
	ref := testutil.CloudletData()[0]
	ref.ResTagMap = map[string]*edgeproto.ResTagTableKey{
		"gpu": key,
	}
	return &ref, noSupportData
}

// TrustPolicy
func (s *DeleteDataGen) GetTrustPolicyTestObj() (*edgeproto.TrustPolicy, *testSupportData) {
	obj := testutil.TrustPolicyData()[0]
	return &obj, noSupportData
}
func (s *DeleteDataGen) GetCloudletTrustPolicyRef(key *edgeproto.PolicyKey) (*edgeproto.Cloudlet, *testSupportData) {
	ref := testutil.CloudletData()[0]
	ref.Key.Organization = key.Organization
	ref.TrustPolicy = key.Name
	return &ref, noSupportData
}

// VMPool
func (s *DeleteDataGen) GetVMPoolTestObj() (*edgeproto.VMPool, *testSupportData) {
	obj := testutil.VMPoolData()[0]
	return &obj, noSupportData
}
func (s *DeleteDataGen) GetCloudletVmPoolRef(key *edgeproto.VMPoolKey) (*edgeproto.Cloudlet, *testSupportData) {
	ref := testutil.CloudletData()[0]
	ref.Key.Organization = key.Organization
	ref.VmPool = key.Name
	return &ref, noSupportData
}
