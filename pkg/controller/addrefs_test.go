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

package controller

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/ccrmdummy"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
)

func TestAddRefsChecks(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	dummy := regiondata.InMemoryStore{}
	dummy.Start()

	sync := regiondata.InitSync(&dummy)
	apis := NewAllApis(sync)
	sync.Start()
	defer sync.Done()
	responder := DefaultDummyInfoResponder(apis)
	responder.InitDummyInfoResponder()
	ccrm := ccrmdummy.StartDummyCCRM(ctx, testSvcs.DummyVault.Config, &dummy)
	registerDummyCCRMConn(t, ccrm)
	defer ccrm.Stop()

	reduceInfoTimeouts(t, ctx, apis)

	dataGen := AddRefsDataGen{}
	allAddRefsChecks(t, ctx, apis, &dataGen)
}

type AddRefsDataGen struct{}

func (s *AddRefsDataGen) GetAddAppAlertPolicyTestObj() (*edgeproto.AppAlertPolicy, *testSupportData) {
	app := testutil.AppData()[0]
	app.AlertPolicies = nil
	alertPolicy := testutil.AlertPolicyData()[0]

	testObj := edgeproto.AppAlertPolicy{
		AppKey:      app.Key,
		AlertPolicy: alertPolicy.Key.Name,
	}
	supportData := &testSupportData{}
	supportData.Apps = []edgeproto.App{app}
	supportData.AlertPolicies = []edgeproto.AlertPolicy{alertPolicy}
	return &testObj, supportData
}

func (s *AddRefsDataGen) GetAddAppAutoProvPolicyTestObj() (*edgeproto.AppAutoProvPolicy, *testSupportData) {
	app := testutil.AppData()[0]
	app.Deployment = cloudcommon.DeploymentTypeKubernetes
	app.AutoProvPolicies = nil
	autoProvPolicy := testutil.AutoProvPolicyData()[0]

	testObj := edgeproto.AppAutoProvPolicy{
		AppKey:         app.Key,
		AutoProvPolicy: autoProvPolicy.Key.Name,
	}
	supportData := &testSupportData{}
	supportData.Apps = []edgeproto.App{app}
	supportData.AutoProvPolicies = []edgeproto.AutoProvPolicy{autoProvPolicy}
	return &testObj, supportData
}

func (s *AddRefsDataGen) GetAddAutoProvPolicyZoneTestObj() (*edgeproto.AutoProvPolicyZone, *testSupportData) {
	zone := testutil.ZoneData()[0]
	autoProvPolicy := testutil.AutoProvPolicyData()[0]
	autoProvPolicy.Zones = nil

	testObj := edgeproto.AutoProvPolicyZone{
		Key:     autoProvPolicy.Key,
		ZoneKey: zone.Key,
	}
	supportData := &testSupportData{}
	supportData.Zones = []edgeproto.Zone{zone}
	supportData.AutoProvPolicies = []edgeproto.AutoProvPolicy{autoProvPolicy}
	return &testObj, supportData
}

func (s *AddRefsDataGen) GetAddZonePoolMemberTestObj() (*edgeproto.ZonePoolMember, *testSupportData) {
	zone := testutil.ZoneData()[0]
	zonePool := testutil.ZonePoolData()[0]
	zonePool.Key.Organization = zone.Key.Organization
	zonePool.Zones = nil

	testObj := edgeproto.ZonePoolMember{
		Key:  zonePool.Key,
		Zone: zone.Key,
	}
	supportData := &testSupportData{}
	supportData.Zones = []edgeproto.Zone{zone}
	supportData.ZonePools = []edgeproto.ZonePool{zonePool}
	return &testObj, supportData
}

func (s *AddRefsDataGen) GetAddCloudletResMappingTestObj() (*edgeproto.CloudletResMap, *testSupportData) {
	cloudlet := testutil.CloudletData()[0]
	cloudlet.ResTagMap = nil
	resTagTable := testutil.ResTagTableData()[0]

	testObj := edgeproto.CloudletResMap{
		Key: cloudlet.Key,
		Mapping: map[string]string{
			"gpu": resTagTable.Key.Name,
		},
	}
	supportData := &testSupportData{}
	supportData.Cloudlets = []edgeproto.Cloudlet{cloudlet}
	supportData.ResTagTables = []edgeproto.ResTagTable{resTagTable}
	return &testObj, supportData
}

func (s *AddRefsDataGen) GetCreateAppTestObj() (*edgeproto.App, *testSupportData) {
	flavor := testutil.FlavorData()[0]
	autoProvPolicy := testutil.AutoProvPolicyData()[0]
	alertPolicy := testutil.AlertPolicyData()[0]

	app := testutil.AppData()[0]
	app.KubernetesResources = nil
	app.NodeResources = nil
	app.DefaultFlavor = flavor.Key
	app.AutoProvPolicies = []string{autoProvPolicy.Key.Name}
	app.AlertPolicies = []string{alertPolicy.Key.Name}

	supportData := &testSupportData{}
	supportData.Flavors = []edgeproto.Flavor{flavor}
	supportData.AutoProvPolicies = []edgeproto.AutoProvPolicy{autoProvPolicy}
	supportData.AlertPolicies = []edgeproto.AlertPolicy{alertPolicy}
	return &app, supportData
}

func (s *AddRefsDataGen) GetCreateAppInstTestObj() (*edgeproto.AppInst, *testSupportData) {
	app := testutil.AppData()[0]
	app.Deployment = cloudcommon.DeploymentTypeKubernetes
	features := testutil.PlatformFeaturesData()[0]
	cloudlet := testutil.CloudletData()[0]
	cloudletInfo := testutil.CloudletInfoData()[0]
	clusterInst := testutil.ClusterInstData()[0]
	clusterInst.CloudletKey = cloudlet.Key
	clusterInst.Deployment = cloudcommon.DeploymentTypeKubernetes
	clusterInst.State = edgeproto.TrackedState_READY
	flavor := testutil.FlavorData()[0]

	appInst := testutil.AppInstData()[0]
	appInst.Key.Organization = app.Key.Organization
	appInst.CloudletKey = cloudlet.Key
	appInst.AppKey = app.Key
	appInst.ClusterKey = clusterInst.Key
	appInst.Flavor = flavor.Key
	appInst.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM

	supportData := &testSupportData{}
	supportData.Apps = []edgeproto.App{app}
	supportData.PlatformFeatures = []edgeproto.PlatformFeatures{features}
	supportData.Cloudlets = []edgeproto.Cloudlet{cloudlet}
	supportData.CloudletInfos = []edgeproto.CloudletInfo{cloudletInfo}
	supportData.ClusterInsts = []edgeproto.ClusterInst{clusterInst}
	supportData.Flavors = []edgeproto.Flavor{flavor}
	return &appInst, supportData
}

func (s *AddRefsDataGen) GetCreateAutoProvPolicyTestObj() (*edgeproto.AutoProvPolicy, *testSupportData) {
	zone := testutil.ZoneData()[0]

	autoProvPolicy := testutil.AutoProvPolicyData()[0]
	autoProvPolicy.Zones = []*edgeproto.ZoneKey{
		&zone.Key,
	}

	supportData := &testSupportData{}
	supportData.Zones = []edgeproto.Zone{zone}
	return &autoProvPolicy, supportData
}

func (s *AddRefsDataGen) GetCreateCloudletTestObj() (*edgeproto.Cloudlet, *testSupportData) {
	// must use Cloudlet[2] because TrustPolicy validation does not
	// allow special characters in org name.
	features := testutil.PlatformFeaturesData()[2]
	if features.PlatformType != platform.PlatformTypeFakeVMPool {
		panic("features must be for type " + platform.PlatformTypeFakeVMPool)
	}
	cloudlet := testutil.CloudletData()[2]

	flavor := testutil.FlavorData()[0]
	resTagTable := testutil.ResTagTableData()[0]
	resTagTable.Key.Organization = cloudlet.Key.Organization
	trustPolicy := testutil.TrustPolicyData()[0]
	trustPolicy.Key.Organization = cloudlet.Key.Organization
	gpuDriver := testutil.GPUDriverData()[0]
	gpuDriver.Key.Organization = cloudlet.Key.Organization
	zone := testutil.ZoneData()[0]
	zone.Key.Organization = cloudlet.Key.Organization
	vmpool := testutil.VMPoolData()[0]
	vmpool.Key.Organization = cloudlet.Key.Organization

	cloudlet.Flavor = flavor.Key
	cloudlet.ResTagMap = map[string]*edgeproto.ResTagTableKey{"gpu": &resTagTable.Key}
	cloudlet.TrustPolicy = trustPolicy.Key.Name
	cloudlet.GpuConfig.Driver = gpuDriver.Key
	cloudlet.Zone = zone.Key.Name
	cloudlet.VmPool = vmpool.Key.Name
	cloudlet.PlatformType = platform.PlatformTypeFakeVMPool
	cloudlet.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM

	supportData := &testSupportData{}
	supportData.Flavors = []edgeproto.Flavor{flavor}
	supportData.ResTagTables = []edgeproto.ResTagTable{resTagTable}
	supportData.TrustPolicies = []edgeproto.TrustPolicy{trustPolicy}
	supportData.GpuDrivers = []edgeproto.GPUDriver{gpuDriver}
	supportData.Zones = []edgeproto.Zone{zone}
	supportData.VmPools = []edgeproto.VMPool{vmpool}
	supportData.PlatformFeatures = []edgeproto.PlatformFeatures{features}
	return &cloudlet, supportData
}

func (s *AddRefsDataGen) GetCreateZonePoolTestObj() (*edgeproto.ZonePool, *testSupportData) {
	zone := testutil.ZoneData()[0]

	zonePool := testutil.ZonePoolData()[0]
	zonePool.Key.Organization = zone.Key.Organization
	zonePool.Zones = []*edgeproto.ZoneKey{&zone.Key}

	supportData := &testSupportData{}
	supportData.Zones = []edgeproto.Zone{zone}
	return &zonePool, supportData
}

func (s *AddRefsDataGen) GetCreateClusterInstTestObj() (*edgeproto.ClusterInst, *testSupportData) {
	features := testutil.PlatformFeaturesData()[0]
	cloudlet := testutil.CloudletData()[0]
	cloudletInfo := testutil.CloudletInfoData()[0]
	flavor := testutil.FlavorData()[0]
	autoScalePolicy := testutil.AutoScalePolicyData()[0]
	network := testutil.NetworkData()[0]
	network.Key.CloudletKey = cloudlet.Key

	clusterInst := testutil.ClusterInstData()[0]
	clusterInst.CloudletKey = cloudlet.Key
	clusterInst.Flavor = flavor.Key
	clusterInst.NodePools = nil
	clusterInst.AutoScalePolicy = autoScalePolicy.Key.Name
	clusterInst.Networks = []string{network.Key.Name}
	clusterInst.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM
	clusterInst.Deployment = cloudcommon.DeploymentTypeKubernetes
	clusterInst.State = edgeproto.TrackedState_READY

	supportData := &testSupportData{}
	supportData.Cloudlets = []edgeproto.Cloudlet{cloudlet}
	supportData.CloudletInfos = []edgeproto.CloudletInfo{cloudletInfo}
	supportData.Flavors = []edgeproto.Flavor{flavor}
	supportData.AutoScalePolicies = []edgeproto.AutoScalePolicy{autoScalePolicy}
	supportData.Networks = []edgeproto.Network{network}
	supportData.PlatformFeatures = []edgeproto.PlatformFeatures{features}
	return &clusterInst, supportData
}

func (s *AddRefsDataGen) GetCreateNetworkTestObj() (*edgeproto.Network, *testSupportData) {
	cloudlet := testutil.CloudletData()[0]

	network := testutil.NetworkData()[0]
	network.Key.CloudletKey = cloudlet.Key

	supportData := &testSupportData{}
	supportData.Cloudlets = []edgeproto.Cloudlet{cloudlet}
	return &network, supportData
}

func (s *AddRefsDataGen) GetCreateTrustPolicyExceptionTestObj() (*edgeproto.TrustPolicyException, *testSupportData) {
	zonePool := testutil.ZonePoolData()[0]
	app := testutil.AppData()[0]

	tpe := testutil.TrustPolicyExceptionData()[0]
	tpe.Key.AppKey = app.Key
	tpe.Key.ZonePoolKey = zonePool.Key

	supportData := &testSupportData{}
	supportData.ZonePools = []edgeproto.ZonePool{zonePool}
	supportData.Apps = []edgeproto.App{app}
	return &tpe, supportData
}

func (s *AddRefsDataGen) GetUpdateAppTestObj() (*edgeproto.App, *testSupportData) {
	testObj, supportData := s.GetCreateAppTestObj()
	// copy and clear refs
	updatable := *testObj
	updatable.DefaultFlavor = edgeproto.FlavorKey{}
	updatable.AutoProvPolicies = []string{}
	updatable.AlertPolicies = []string{}

	supportData.Apps = []edgeproto.App{updatable}

	testObj.Fields = []string{
		edgeproto.AppFieldDefaultFlavor,
		edgeproto.AppFieldDefaultFlavorName,
		edgeproto.AppFieldAutoProvPolicies,
		edgeproto.AppFieldAlertPolicies,
	}
	return testObj, supportData
}

func (s *AddRefsDataGen) GetUpdateAppInstTestObj() (*edgeproto.AppInst, *testSupportData) {
	testObj, supportData := s.GetCreateAppInstTestObj()
	// copy and clear refs
	updatable := *testObj
	updatable.Flavor = edgeproto.FlavorKey{}

	supportData.AppInstances = []edgeproto.AppInst{updatable}

	testObj.Fields = []string{
		edgeproto.AppInstFieldFlavor,
		edgeproto.AppInstFieldFlavorName,
	}
	return testObj, supportData
}

func (s *AddRefsDataGen) GetUpdateAutoProvPolicyTestObj() (*edgeproto.AutoProvPolicy, *testSupportData) {
	testObj, supportData := s.GetCreateAutoProvPolicyTestObj()
	// copy and clear refs
	updatable := *testObj
	updatable.Zones = nil

	supportData.AutoProvPolicies = []edgeproto.AutoProvPolicy{updatable}

	testObj.Fields = []string{
		edgeproto.AutoProvPolicyFieldZones,
	}
	return testObj, supportData
}

func (s *AddRefsDataGen) GetUpdateCloudletTestObj() (*edgeproto.Cloudlet, *testSupportData) {
	testObj, supportData := s.GetCreateCloudletTestObj()
	// copy and clear refs
	updatable := *testObj
	updatable.Flavor = edgeproto.FlavorKey{}
	updatable.ResTagMap = nil
	updatable.TrustPolicy = ""
	updatable.GpuConfig.Driver = edgeproto.GPUDriverKey{}

	supportData.Cloudlets = []edgeproto.Cloudlet{updatable}
	supportData.CloudletInfos = []edgeproto.CloudletInfo{testutil.CloudletInfoData()[2]}

	testObj.Fields = []string{
		edgeproto.CloudletFieldTrustPolicy,
		edgeproto.CloudletFieldGpuConfigDriver,
		edgeproto.CloudletFieldGpuConfigDriverName,
		edgeproto.CloudletFieldGpuConfigDriverOrganization,
	}
	return testObj, supportData
}

func (s *AddRefsDataGen) GetUpdateZonePoolTestObj() (*edgeproto.ZonePool, *testSupportData) {
	testObj, supportData := s.GetCreateZonePoolTestObj()
	// copy and clear refs
	updatable := *testObj
	updatable.Zones = nil

	supportData.ZonePools = []edgeproto.ZonePool{updatable}

	testObj.Fields = []string{edgeproto.ZonePoolFieldZones}
	return testObj, supportData
}

func (s *AddRefsDataGen) GetUpdateClusterInstTestObj() (*edgeproto.ClusterInst, *testSupportData) {
	testObj, supportData := s.GetCreateClusterInstTestObj()
	// copy and clear refs
	updatable := *testObj
	updatable.Flavor = edgeproto.FlavorKey{}
	updatable.AutoScalePolicy = ""
	updatable.Networks = nil

	supportData.ClusterInsts = []edgeproto.ClusterInst{updatable}

	testObj.Fields = []string{
		edgeproto.ClusterInstFieldAutoScalePolicy,
	}
	return testObj, supportData
}
