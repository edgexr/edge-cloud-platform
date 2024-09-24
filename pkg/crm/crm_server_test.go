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

package crm

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/platforms"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/test/testutil/testservices"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	yaml "gopkg.in/yaml.v2"
)

// Data in test_data.go is meant to go through controller, which will
// fill in certain fields (like copying Flavor from App to AppInst)
// This test data is post-copying of that data, and limited to just
// testing CRM.
var yamlData = `
trustpolicies:
-  key:
      organization: dmuus
      name: TrustPolicy1
   outboundsecurityrules:
    - protocol:  tcp
      portrangemin: 443
      remotecidr: "35.247.68.151/32"
    - protocol:  tcp
      portrangemin: 8080
      portrangemax: 8088
      remotecidr: "0.0.0.0/0"
    - protocol: udp
      portrangemin: 53
      remotecidr: "0.0.0.0/0"
    - protocol: icmp
      remotecidr: "8.0.0.0/8"
zones:
- key:
    organization: DMUUS
    name: zone2
cloudlets:
- key:
    organization: DMUUS
    name: cloud2
  vmpool: vmpool1
  zone: zone2
  trustpolicy: TrustPolicy1
  gpuconfig:
    driver:
      name: gpudriver1
      organization: DMUUS
  restagmap:
    gpu:
      name: gpudriver1
      organization: DMUUS

flavors:
- key:
    name: x1.tiny
  ram: 1024
  vcpus: 1
  disk: 1
- key:
    name: x1.small
  ram: 2048
  vcpus: 2
  disk: 2
- key:
    name: x1.medium
  ram: 4096
  vcpus: 4
  disk: 4

clusterinsts:
- key:
    name: pillimo_cluster
    organization: Untomt
  cloudletkey:
    organization: DMUUS
    name: cloud2
  flavor:
    name: x1.tiny
  numnodes: 3
  liveness: LivenessStatic
- key:
    name: Untomt_cluster
    organization: Untomt
  cloudletkey:
    organization: DMUUS
    name: cloud2
  flavor:
    name: x1.small
  numnodes: 3
  liveness: LivenessDynamic
  ipaccess: Dedicated
- key:
    name: Untomt_cluster_22
    organization: Untomt
  cloudletkey:
    organization: DMUUS
    name: cloud2
  flavor:
    name: x1.small
  numnodes: 3
  liveness: LivenessDynamic
  ipaccess: Dedicated
apps:
- key:
    organization: Atlantic
    name: Pillimo Go
    version: 1.0.0
- key:
    organization: Untomt
    name: VRmax
    version: 1.0.0
appinstances:
- key:
    organization: Atlantic
    name: Pillimo Go
  cloudletkey:
    organization: DMUUS
    name: cloud2
  appkey:
    organization: Atlantic
    name: Pillimo Go
    version: 1.0.0
  clusterkey:
    name: pillimo_cluster
    organization: Atlantic
  cloudletloc:
    latitude: 31
    longitude: -91
  liveness: LivenessStatic
  flavor:
    name: x1.tiny
- key:
    organization: Untomt
    name: VRmax
  cloudletkey:
    organization: DMUUS
    name: cloud2
  appkey:
    organization: Untomt
    name: VRmax
    version: 1.0.0
  clusterkey:
    name: Untomt_cluster
    organization: Untomt
  cloudletloc:
    latitude: 31
    longitude: -91
  liveness: LivenessDynamic
  flavor:
    name: x1.small
- key:
    organization: Untomt
    name: VRmax2
  cloudletkey:
    organization: DMUUS
    name: cloud2
  appkey:
    organization: Untomt
    name: VRmax
    version: 1.0.0
  clusterkey:
    name: Untomt_cluster_22
    organization: Untomt
  cloudletloc:
    latitude: 310
    longitude: -910
  liveness: LivenessDynamic
  flavor:
    name: x1.medium

vmpools:
- key:
    organization: DMUUS
    name: vmpool1
  vms:
  - name: vm1
    netinfo:
      externalip: 192.168.1.101
      internalip: 192.168.100.101
  - name: vm2
    netinfo:
      externalip: 192.168.1.102
      internalip: 192.168.100.102
  - name: vm3
    netinfo:
      internalip: 192.168.100.103
  - name: vm4
    netinfo:
      internalip: 192.168.100.104
- key:
    organization: DMUUS
    name: vmpool2
  vms:
  - name: vm1
    netinfo:
      externalip: 192.168.2.101
      internalip: 192.168.200.101

gpudrivers:
- key:
    organization: DMUUS
    name: gpudriver1
- key:
    organization: DMUUS
    name: gpudriver2
- key:
    name: gpudriver2

zonepools:
- key:
    organization: DMUUS
    name: zone2-pool
  zones:
  - name: zone2
    organization: DMUUS

networks:
- key:
    cloudletkey:
      organization: dmuus
      name: cloud2
    name: net1
  routes:
  - destinationcidr: 10.200.10.0/24
    nexthopip: 10.200.10.1
  - destinationcidr: 10.140.20.0/24
    nexthopip: 10.140.20.1
  connectiontype: ConnectToClusterNodes

trustpolicyexceptions:
- key:
    appkey:
      organization: Untomt
      name: VRmax
      version: 1.0.0
    zonepoolkey:
      organization: DMUUS
      name: zone2-pool
    name: tpe1
  outboundsecurityrules:
  - protocol: tcp
    remotecidr: "1.1.1.1/32"
    portrangemin: 1
    portrangemax: 111
- key:
    appkey:
      organization: Untomt
      name: VRmax
      version: 1.0.0
    zonepoolkey:
      organization: DMUUS
      name: zone2-pool
    name: tpe2
  outboundsecurityrules:
  - protocol: udp
    remotecidr: "2.2.2.2/24"
    portrangemin: 22
    portrangemax: 222
`

func TestCRM(t *testing.T) {
	var err error
	log.SetDebugLevel(log.DebugLevelApi | log.DebugLevelNotify | log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	notifyAddr := "127.0.0.1:61245"

	data := edgeproto.AllData{}
	err = yaml.UnmarshalStrict([]byte(yamlData), &data)
	require.Nil(t, err, "unmarshal yaml data")

	bytes, _ := json.Marshal(&data.Cloudlets[0].Key)

	// CRM is driven by controller
	ctrlHandler := notify.NewDummyHandler()
	ctrlMgr := notify.ServerMgr{}
	ctrlHandler.RegisterServer(&ctrlMgr)
	// handle access API
	keyServer := node.NewAccessKeyServer(&ctrlHandler.CloudletCache, "")
	accessKeyGrpcServer := node.AccessKeyGrpcServer{}
	basicUpgradeHandler := node.BasicUpgradeHandler{
		KeyServer: keyServer,
	}
	getPublicCertApi := &cloudcommon.TestPublicCertApi{}
	publicCertManager, err := node.NewPublicCertManager("localhost", "", getPublicCertApi, "", "")
	require.Nil(t, err)
	tlsConfig, err := publicCertManager.GetServerTlsConfig(ctx)
	require.Nil(t, err)
	accessKeyGrpcServer.Start("127.0.0.1:0", keyServer, tlsConfig, func(server *grpc.Server) {
		edgeproto.RegisterCloudletAccessKeyApiServer(server, &basicUpgradeHandler)
	})
	defer accessKeyGrpcServer.Stop()
	// setup access key
	accessKey, err := node.GenerateAccessKey()
	require.Nil(t, err)
	accessKeyFile := "/tmp/accesskey_crm_unittest"
	err = ioutil.WriteFile(accessKeyFile, []byte(accessKey.PrivatePEM), 0600)
	require.Nil(t, err)

	// update VMPool object before creating cloudlet
	for ii := range data.VmPools {
		ctrlHandler.VMPoolCache.Update(ctx, &data.VmPools[ii], 0)
	}

	// update GPUDriver object before creating cloudlet
	for ii := range data.GpuDrivers {
		ctrlHandler.GPUDriverCache.Update(ctx, &data.GpuDrivers[ii], 0)
	}

	// set Cloudlet state to CRM_INIT to allow crm notify exchange to proceed
	cdata := data.Cloudlets[0]
	cdata.State = edgeproto.TrackedState_CRM_INITOK
	cdata.CrmAccessPublicKey = accessKey.PublicPEM
	ctrlHandler.CloudletCache.Update(ctx, &cdata, 0)
	ctrlMgr.Start("ctrl", notifyAddr, nil)

	*cloudletKeyStr = string(bytes)
	*notifyAddrs = notifyAddr
	*platformName = "PLATFORM_TYPE_FAKE"
	nodeMgr.AccessKeyClient.AccessApiAddr = accessKeyGrpcServer.ApiAddr()
	nodeMgr.AccessKeyClient.AccessKeyFile = accessKeyFile
	highAvailabilityManager.HARole = string(process.HARolePrimary)
	nodeMgr.AccessKeyClient.TestSkipTlsVerify = true
	err = Start(platforms.All.GetBuilders())
	require.Nil(t, err)
	defer Stop()

	require.Nil(t, notifyClient.WaitForConnect(1))
	stats := notify.Stats{}
	notifyClient.GetStats(&stats)
	require.Equal(t, uint64(1), stats.Connects)

	// Add data to controller
	for ii := range data.Flavors {
		ctrlHandler.FlavorCache.Update(ctx, &data.Flavors[ii], 0)
	}
	for ii := range data.ClusterInsts {
		ctrlHandler.ClusterInstCache.Update(ctx, &data.ClusterInsts[ii], 0)
	}
	for ii := range data.Apps {
		ctrlHandler.AppCache.Update(ctx, &data.Apps[ii], 0)
	}
	for ii := range data.AppInstances {
		data.AppInstances[ii].State = edgeproto.TrackedState_READY
		log.SpanLog(ctx, log.DebugLevelApi, "update AppInst", "ai", data.AppInstances[ii])
		ctrlHandler.AppInstCache.Update(ctx, &data.AppInstances[ii], 0)
	}
	for ii := range data.ZonePools {
		ctrlHandler.ZonePoolCache.Update(ctx, &data.ZonePools[ii], 0)
	}

	for ii := range data.Networks {
		ctrlHandler.NetworkCache.Update(ctx, &data.Networks[ii], 0)
	}

	for ii := range data.TrustPolicyExceptions {
		ctrlHandler.TrustPolicyExceptionCache.Update(ctx, &data.TrustPolicyExceptions[ii], 0)
	}

	require.Nil(t, notify.WaitFor(&crmdata.FlavorCache, 3))
	// Note for ClusterInsts and AppInsts, only those that match
	// myCloudlet Key will be sent.
	log.SpanLog(ctx, log.DebugLevelApi, "wait for instances")
	require.Nil(t, notify.WaitFor(&crmdata.ClusterInstCache, 3))
	require.Nil(t, notify.WaitFor(&crmdata.AppCache, 2))
	require.Nil(t, notify.WaitFor(&crmdata.AppInstCache, 3))
	// ensure that only vmpool object associated with cloudlet is received
	require.Nil(t, notify.WaitFor(&crmdata.VMPoolCache, 1))

	// ensure that only gpudriver object associated with cloudlet is received
	require.Nil(t, notify.WaitFor(&crmdata.GPUDriverCache, 1))
	require.Nil(t, notify.WaitFor(&crmdata.NetworkCache, 1))

	require.Nil(t, notify.WaitFor(&crmdata.TrustPolicyExceptionCache, 2))

	// TODO: check that the above changes triggered cloudlet cluster/app creates
	// for now just check stats
	log.SpanLog(ctx, log.DebugLevelApi, "check counts")
	require.Equal(t, 3, len(crmdata.FlavorCache.Objs))
	require.Equal(t, 3, len(crmdata.ClusterInstCache.Objs))
	require.Equal(t, 2, len(crmdata.AppCache.Objs))
	require.Equal(t, 3, len(crmdata.AppInstCache.Objs))
	require.Equal(t, 1, len(crmdata.VMPoolCache.Objs))
	require.Equal(t, 1, len(crmdata.GPUDriverCache.Objs))
	require.Equal(t, 1, len(crmdata.NetworkCache.Objs))
	require.Equal(t, 2, len(crmdata.TrustPolicyExceptionCache.Objs))

	testVMPoolUpdates(t, ctx, &data.VmPools[0], ctrlHandler)

	// delete
	for ii := range data.VmPools {
		ctrlHandler.VMPoolCache.Delete(ctx, &data.VmPools[ii], 0)
	}
	for ii := range data.GpuDrivers {
		ctrlHandler.GPUDriverCache.Delete(ctx, &data.GpuDrivers[ii], 0)
	}
	for ii := range data.AppInstances {
		ctrlHandler.AppInstCache.Delete(ctx, &data.AppInstances[ii], 0)
	}
	for ii := range data.Apps {
		ctrlHandler.AppCache.Delete(ctx, &data.Apps[ii], 0)
	}
	for ii := range data.ClusterInsts {
		ctrlHandler.ClusterInstCache.Delete(ctx, &data.ClusterInsts[ii], 0)
	}
	for ii := range data.Flavors {
		ctrlHandler.FlavorCache.Delete(ctx, &data.Flavors[ii], 0)
	}
	for ii := range data.ZonePools {
		ctrlHandler.ZonePoolCache.Delete(ctx, &data.ZonePools[ii], 0)
	}

	for ii := range data.Networks {
		ctrlHandler.NetworkCache.Delete(ctx, &data.Networks[ii], 0)
	}

	require.Nil(t, notify.WaitFor(&crmdata.FlavorCache, 0))
	require.Nil(t, notify.WaitFor(&crmdata.ClusterInstCache, 0))
	require.Nil(t, notify.WaitFor(&crmdata.AppInstCache, 0))
	require.Nil(t, notify.WaitFor(&crmdata.AppCache, 0))
	require.Nil(t, notify.WaitFor(&crmdata.VMPoolCache, 0))
	require.Nil(t, notify.WaitFor(&crmdata.GPUDriverCache, 0))
	require.Nil(t, notify.WaitFor(&crmdata.NetworkCache, 0))

	// TODO: check that deletes triggered cloudlet cluster/app deletes.
	require.Equal(t, 0, len(crmdata.FlavorCache.Objs))
	require.Equal(t, 0, len(crmdata.ClusterInstCache.Objs))
	require.Equal(t, 0, len(crmdata.AppInstCache.Objs))
	require.Equal(t, 0, len(crmdata.AppCache.Objs))
	require.Equal(t, 0, len(crmdata.VMPoolCache.Objs))
	require.Equal(t, 0, len(crmdata.GPUDriverCache.Objs))
	require.Equal(t, 0, len(crmdata.NetworkCache.Objs))

}

func TestNotifyOrder(t *testing.T) {
	_, _, err := nodeMgr.Init(node.NodeTypeCRM, node.NoTlsClientIssuer)
	require.Nil(t, err)
	defer nodeMgr.Finish()
	crmdata = NewCRMData(nil, &edgeproto.CloudletKey{}, &nodeMgr, &highAvailabilityManager)
	mgr := notify.ServerMgr{}
	InitSrvNotify(&mgr, &nodeMgr, crmdata.CRMHandler)
	testservices.CheckNotifySendOrder(t, mgr.GetSendOrder())
}

func WaitForInfoState(key *edgeproto.VMPoolKey, state edgeproto.TrackedState) (*edgeproto.VMPoolInfo, error) {
	lastState := edgeproto.TrackedState_TRACKED_STATE_UNKNOWN
	info := edgeproto.VMPoolInfo{}
	for i := 0; i < 100; i++ {
		if crmdata.VMPoolInfoCache.Get(key, &info) {
			if info.State == state {
				return &info, nil
			}
			lastState = info.State
		}
		time.Sleep(10 * time.Millisecond)
	}

	return &info, fmt.Errorf("Unable to get desired vmPool state, actual state %s, desired state %s", lastState, state)
}

func WaitForVMPoolState(key *edgeproto.VMPoolKey, state edgeproto.TrackedState) (*edgeproto.VMPool, error) {
	lastState := edgeproto.TrackedState_TRACKED_STATE_UNKNOWN
	pool := edgeproto.VMPool{}
	for i := 0; i < 100; i++ {
		if crmdata.VMPoolCache.Get(key, &pool) {
			if pool.State == state {
				return &pool, nil
			}
			lastState = pool.State
		}
		time.Sleep(10 * time.Millisecond)
	}

	return &pool, fmt.Errorf("Unable to get desired vmPool state, actual state %s, desired state %s", lastState, state)
}

var (
	Pass = true
	Fail = false
)

func verifyVMPoolUpdate(t *testing.T, ctx context.Context, vmPool *edgeproto.VMPool, ctrlHandler *notify.DummyHandler, pass bool) {
	key := &vmPool.Key

	ctrlHandler.VMPoolCache.Update(ctx, vmPool, 0)

	state := edgeproto.TrackedState_READY
	if !pass {
		state = edgeproto.TrackedState_UPDATE_ERROR
	}
	info, err := WaitForInfoState(key, state)
	require.Nil(t, err)

	// clear vmpoolinfo for next run
	crmdata.VMPoolInfoCache.Delete(ctx, info, 0)

	vmPool.State = edgeproto.TrackedState_READY
	ctrlHandler.VMPoolCache.Update(ctx, vmPool, 0)
	WaitForVMPoolState(key, edgeproto.TrackedState_READY)

	if !pass {
		return
	}

	count := 0
	addVMs := make(map[string]struct{})
	deleteVMs := make(map[string]struct{})
	updateVMs := make(map[string]edgeproto.VM)
	for _, vm := range vmPool.Vms {
		if vm.State == edgeproto.VMState_VM_UPDATE || vm.State == edgeproto.VMState_VM_FORCE_FREE {
			updateVMs[vm.Name] = vm
			count++
		} else {
			if vm.State == edgeproto.VMState_VM_ADD {
				addVMs[vm.Name] = struct{}{}
			} else if vm.State == edgeproto.VMState_VM_REMOVE {
				deleteVMs[vm.Name] = struct{}{}
				continue
			}
			count++
		}
	}
	require.Equal(t, count, len(info.Vms), "info has expected vms")

	added := false
	for _, vm := range info.Vms {
		if _, ok := addVMs[vm.Name]; ok {
			require.Equal(t, edgeproto.VMState_VM_FREE, vm.State, "vm state matches")
			added = true
		}
		if _, ok := deleteVMs[vm.Name]; ok {
			require.False(t, ok, "vm should be removed")
		}
		if len(updateVMs) > 0 {
			updatedVM, ok := updateVMs[vm.Name]
			if updatedVM.State == edgeproto.VMState_VM_FORCE_FREE {
				require.Equal(t, edgeproto.VMState_VM_FREE, vm.State, "vm is forcefully freed")
				require.Empty(t, vm.InternalName)
				require.Empty(t, vm.GroupName)
			}
			require.True(t, ok, "vm should be updated")
			require.Equal(t, updatedVM.NetInfo.InternalIp, vm.NetInfo.InternalIp, "vm internal ip matches")
			require.Equal(t, updatedVM.NetInfo.ExternalIp, vm.NetInfo.ExternalIp, "vm external ip matches")
		}

	}
	if len(addVMs) > 0 {
		require.True(t, added, "vm found")
	}
}

func copyCrmVMPool() *edgeproto.VMPool {
	vmPool := edgeproto.VMPool{}
	vmPool.DeepCopyIn(&crmdata.VMPool)
	return &vmPool
}

func testVMPoolUpdates(t *testing.T, ctx context.Context, vmPool *edgeproto.VMPool, ctrlHandler *notify.DummyHandler) {
	crmdata.VMPool = *vmPool

	// Add new VM
	vmPoolUpdate1 := copyCrmVMPool()
	vmPoolUpdate1.Vms = append(vmPoolUpdate1.Vms, edgeproto.VM{
		Name: "vm5",
		NetInfo: edgeproto.VMNetInfo{
			InternalIp: "192.168.100.105",
		},
		State: edgeproto.VMState_VM_ADD,
	})
	vmPoolUpdate1.Vms = append(vmPoolUpdate1.Vms, edgeproto.VM{
		Name: "vm6",
		NetInfo: edgeproto.VMNetInfo{
			InternalIp: "192.168.100.106",
		},
		State: edgeproto.VMState_VM_ADD,
	})
	vmPoolUpdate1.State = edgeproto.TrackedState_UPDATE_REQUESTED
	verifyVMPoolUpdate(t, ctx, vmPoolUpdate1, ctrlHandler, Pass)
	require.Equal(t, 6, len(crmdata.VMPool.Vms), "matches crm global vmpool")

	// Add another VM which will fail verification
	vmPoolAddMember := copyCrmVMPool()
	vmPoolAddMember.Vms = append(vmPoolAddMember.Vms, edgeproto.VM{
		Name: "vmFailVerification",
		NetInfo: edgeproto.VMNetInfo{
			InternalIp: "192.168.100.106",
		},
		State: edgeproto.VMState_VM_ADD,
	})
	vmPoolAddMember.State = edgeproto.TrackedState_UPDATE_REQUESTED
	verifyVMPoolUpdate(t, ctx, vmPoolAddMember, ctrlHandler, Fail)
	require.Equal(t, 6, len(crmdata.VMPool.Vms), "matches crm global vmpool")

	// Remove VM
	vmPoolUpdate2 := copyCrmVMPool()
	vmPoolUpdate2.Vms[5].State = edgeproto.VMState_VM_REMOVE
	vmPoolUpdate2.State = edgeproto.TrackedState_UPDATE_REQUESTED
	verifyVMPoolUpdate(t, ctx, vmPoolUpdate2, ctrlHandler, Pass)
	require.Equal(t, 5, len(crmdata.VMPool.Vms), "matches crm global vmpool")

	// Update VM
	vmPoolUpdate3 := copyCrmVMPool()
	crmdata.VMPool.Vms[0].State = edgeproto.VMState_VM_IN_USE
	crmdata.VMPool.Vms[0].InternalName = "testname"
	crmdata.VMPool.Vms[0].GroupName = "testgroup"
	vmPoolUpdate3.Vms[3].NetInfo.ExternalIp = "1.1.1.1"
	// As part of Update, remove a VM as well
	vmPoolUpdate3.Vms = vmPoolUpdate3.Vms[:len(vmPoolUpdate3.Vms)-1]
	// As part of Update, add a VM as well
	vmPoolUpdate3.Vms = append(vmPoolUpdate3.Vms, edgeproto.VM{
		Name: "vm6",
		NetInfo: edgeproto.VMNetInfo{
			InternalIp: "192.168.100.106",
		},
	})
	for ii, _ := range vmPoolUpdate3.Vms {
		vmPoolUpdate3.Vms[ii].State = edgeproto.VMState_VM_UPDATE
	}
	vmPoolUpdate3.State = edgeproto.TrackedState_UPDATE_REQUESTED
	verifyVMPoolUpdate(t, ctx, vmPoolUpdate3, ctrlHandler, Pass)
	require.Equal(t, 5, len(crmdata.VMPool.Vms), "matches crm global vmpool")
	// Make sure existing VM details didnt change as part of update
	require.Equal(t, edgeproto.VMState_VM_IN_USE, crmdata.VMPool.Vms[0].State, "matches old entry")
	require.Equal(t, "testname", crmdata.VMPool.Vms[0].InternalName, "matches old entry")
	require.Equal(t, "testgroup", crmdata.VMPool.Vms[0].GroupName, "matches old entry")

	// Add already existing VM, should fail
	vmPoolUpdate4 := copyCrmVMPool()
	vmPoolUpdate4.Vms = append(vmPoolUpdate4.Vms, edgeproto.VM{
		Name: "vm6",
		NetInfo: edgeproto.VMNetInfo{
			InternalIp: "192.168.100.106",
		},
		State: edgeproto.VMState_VM_ADD,
	})
	vmPoolUpdate4.State = edgeproto.TrackedState_UPDATE_REQUESTED
	verifyVMPoolUpdate(t, ctx, vmPoolUpdate4, ctrlHandler, Fail)
	require.Equal(t, 5, len(crmdata.VMPool.Vms), "matches crm global vmpool")

	// Remove a VM which is busy
	vmPoolUpdate5 := copyCrmVMPool()
	vmPoolUpdate5.Vms[0].State = edgeproto.VMState_VM_REMOVE
	vmPoolUpdate5.State = edgeproto.TrackedState_UPDATE_REQUESTED
	verifyVMPoolUpdate(t, ctx, vmPoolUpdate5, ctrlHandler, Fail)
	require.Equal(t, 5, len(crmdata.VMPool.Vms), "matches crm global vmpool")

	// Update a VM which is busy
	vmPoolUpdate6 := copyCrmVMPool()
	vmPoolUpdate6.Vms[0].NetInfo.ExternalIp = "1.1.1.1"
	vmPoolUpdate6.Vms = append(vmPoolUpdate6.Vms, edgeproto.VM{
		Name: "vm6",
		NetInfo: edgeproto.VMNetInfo{
			InternalIp: "192.168.100.105",
		},
	})
	for ii, _ := range vmPoolUpdate6.Vms {
		vmPoolUpdate6.Vms[ii].State = edgeproto.VMState_VM_UPDATE
	}
	vmPoolUpdate6.State = edgeproto.TrackedState_UPDATE_REQUESTED
	verifyVMPoolUpdate(t, ctx, vmPoolUpdate6, ctrlHandler, Fail)
	require.Equal(t, 5, len(crmdata.VMPool.Vms), "matches crm global vmpool")

	// Forcefully free a VM which is busy
	vmPoolUpdate7 := copyCrmVMPool()
	vmPoolUpdate7.Vms[0].State = edgeproto.VMState_VM_FORCE_FREE
	for ii, _ := range vmPoolUpdate7.Vms {
		if vmPoolUpdate7.Vms[ii].State != edgeproto.VMState_VM_FORCE_FREE {
			vmPoolUpdate7.Vms[ii].State = edgeproto.VMState_VM_UPDATE
		}
	}
	vmPoolUpdate7.State = edgeproto.TrackedState_UPDATE_REQUESTED
	verifyVMPoolUpdate(t, ctx, vmPoolUpdate7, ctrlHandler, Pass)
	require.Equal(t, 5, len(crmdata.VMPool.Vms), "matches crm global vmpool")
}
