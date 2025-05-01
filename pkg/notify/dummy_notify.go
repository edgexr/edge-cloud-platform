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

// Dummy Sender/Receiver for unit testing.
// These are exported because the notify package is meant to be included
// in other processes, so to include these structs in other package's
// unit tests, these test structures must be exported.
package notify

import (
	"fmt"
	"runtime"
	"time"

	dmeproto "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

type DummyHandler struct {
	AppCache                  edgeproto.AppCache
	AppInstCache              edgeproto.AppInstCache
	CloudletCache             edgeproto.CloudletCache
	VMPoolCache               edgeproto.VMPoolCache
	GPUDriverCache            edgeproto.GPUDriverCache
	FlavorCache               edgeproto.FlavorCache
	ClusterInstCache          edgeproto.ClusterInstCache
	AppInstInfoCache          edgeproto.AppInstInfoCache
	ClusterInstInfoCache      edgeproto.ClusterInstInfoCache
	CloudletInfoCache         edgeproto.CloudletInfoCache
	VMPoolInfoCache           edgeproto.VMPoolInfoCache
	AlertCache                edgeproto.AlertCache
	SvcNodeCache              edgeproto.SvcNodeCache
	AutoScalePolicyCache      edgeproto.AutoScalePolicyCache
	AutoProvPolicyCache       edgeproto.AutoProvPolicyCache
	TrustPolicyCache          edgeproto.TrustPolicyCache
	TrustPolicyExceptionCache edgeproto.TrustPolicyExceptionCache
	ZoneCache                 edgeproto.ZoneCache
	ZonePoolCache             edgeproto.ZonePoolCache
	DeviceCache               edgeproto.DeviceCache
	frClusterInsts            edgeproto.FreeReservableClusterInstCache
	SettingsCache             edgeproto.SettingsCache
	NetworkCache              edgeproto.NetworkCache
}

func NewDummyHandler() *DummyHandler {
	h := &DummyHandler{}
	edgeproto.InitSettingsCache(&h.SettingsCache)
	edgeproto.InitAppCache(&h.AppCache)
	edgeproto.InitAppInstCache(&h.AppInstCache)
	edgeproto.InitCloudletCache(&h.CloudletCache)
	edgeproto.InitVMPoolCache(&h.VMPoolCache)
	edgeproto.InitGPUDriverCache(&h.GPUDriverCache)
	edgeproto.InitAppInstInfoCache(&h.AppInstInfoCache)
	edgeproto.InitClusterInstInfoCache(&h.ClusterInstInfoCache)
	edgeproto.InitCloudletInfoCache(&h.CloudletInfoCache)
	edgeproto.InitVMPoolInfoCache(&h.VMPoolInfoCache)
	edgeproto.InitFlavorCache(&h.FlavorCache)
	edgeproto.InitClusterInstCache(&h.ClusterInstCache)
	edgeproto.InitAlertCache(&h.AlertCache)
	edgeproto.InitSvcNodeCache(&h.SvcNodeCache)
	edgeproto.InitAutoScalePolicyCache(&h.AutoScalePolicyCache)
	edgeproto.InitAutoProvPolicyCache(&h.AutoProvPolicyCache)
	edgeproto.InitTrustPolicyCache(&h.TrustPolicyCache)
	edgeproto.InitTrustPolicyExceptionCache(&h.TrustPolicyExceptionCache)
	edgeproto.InitZoneCache(&h.ZoneCache)
	edgeproto.InitZonePoolCache(&h.ZonePoolCache)
	edgeproto.InitDeviceCache(&h.DeviceCache)
	edgeproto.InitNetworkCache(&h.NetworkCache)
	h.frClusterInsts.Init()
	return h
}

func (s *DummyHandler) RegisterServer(mgr *ServerMgr) {
	mgr.RegisterSendSettingsCache(&s.SettingsCache)
	mgr.RegisterSendFlavorCache(&s.FlavorCache)
	mgr.RegisterSendVMPoolCache(&s.VMPoolCache)
	mgr.RegisterSendGPUDriverCache(&s.GPUDriverCache)
	mgr.RegisterSendTrustPolicyCache(&s.TrustPolicyCache)
	mgr.RegisterSendZoneCache(&s.ZoneCache)
	mgr.RegisterSendCloudletCache(&s.CloudletCache)
	mgr.RegisterSendCloudletInfoCache(&s.CloudletInfoCache)
	mgr.RegisterSendZonePoolCache(&s.ZonePoolCache)
	mgr.RegisterSendAutoScalePolicyCache(&s.AutoScalePolicyCache)
	mgr.RegisterSendAutoProvPolicyCache(&s.AutoProvPolicyCache)
	mgr.RegisterSendNetworkCache(&s.NetworkCache)
	mgr.RegisterSendClusterInstCache(&s.ClusterInstCache)
	mgr.RegisterSendAppCache(&s.AppCache)
	mgr.RegisterSendAppInstCache(&s.AppInstCache)
	mgr.RegisterSendTrustPolicyExceptionCache(&s.TrustPolicyExceptionCache)
	mgr.RegisterSendAlertCache(&s.AlertCache)

	mgr.RegisterRecvAppInstInfoCache(&s.AppInstInfoCache)
	mgr.RegisterRecvClusterInstInfoCache(&s.ClusterInstInfoCache)
	mgr.RegisterRecvCloudletInfoCache(&s.CloudletInfoCache)
	mgr.RegisterRecvVMPoolInfoCache(&s.VMPoolInfoCache)
	mgr.RegisterRecvAlertCache(&s.AlertCache)
	mgr.RegisterRecvSvcNodeCache(&s.SvcNodeCache)
	mgr.RegisterRecvDeviceCache(&s.DeviceCache)
	mgr.RegisterRecvTrustPolicyExceptionCache(&s.TrustPolicyExceptionCache)
}

func (s *DummyHandler) RegisterCRMClient(cl *Client) {
	cl.SetFilterByCloudletKey()
	cl.RegisterSendAppInstInfoCache(&s.AppInstInfoCache)
	cl.RegisterSendClusterInstInfoCache(&s.ClusterInstInfoCache)
	cl.RegisterSendCloudletInfoCache(&s.CloudletInfoCache)
	cl.RegisterSendVMPoolInfoCache(&s.VMPoolInfoCache)
	cl.RegisterSendAlertCache(&s.AlertCache)
	cl.RegisterSendSvcNodeCache(&s.SvcNodeCache)
	cl.RegisterSendTrustPolicyExceptionCache(&s.TrustPolicyExceptionCache)

	cl.RegisterRecvSettingsCache(&s.SettingsCache)
	cl.RegisterRecvAppCache(&s.AppCache)
	cl.RegisterRecvAppInstCache(&s.AppInstCache)
	cl.RegisterRecvCloudletCache(&s.CloudletCache)
	cl.RegisterRecvVMPoolCache(&s.VMPoolCache)
	cl.RegisterRecvGPUDriverCache(&s.GPUDriverCache)
	cl.RegisterRecvFlavorCache(&s.FlavorCache)
	cl.RegisterRecvClusterInstCache(&s.ClusterInstCache)
	cl.RegisterRecvAutoProvPolicyCache(&s.AutoProvPolicyCache)
	cl.RegisterRecvNetworkCache(&s.NetworkCache)
	cl.RegisterRecvTrustPolicyExceptionCache(&s.TrustPolicyExceptionCache)
}

func (s *DummyHandler) RegisterDMEClient(cl *Client) {
	cl.RegisterRecvAppCache(&s.AppCache)
	cl.RegisterRecvAppInstCache(&s.AppInstCache)
	cl.RegisterSendDeviceCache(&s.DeviceCache)
	cl.RegisterRecv(NewClusterInstRecv(&s.frClusterInsts))
}

type CacheType int

const (
	AppType     CacheType = iota
	AppInstType           = iota
	CloudletType
	FlavorType
	ClusterInstType
	AppInstInfoType
	ClusterInstInfoType
	CloudletInfoType
	AlertType
	NodeType
	FreeReservableClusterInstType
	VMPoolType
	VMPoolInfoType
	GPUDriverType
	NetworkType
	TrustPolicyExceptionType
)

type WaitForCache interface {
	GetCount() int
	GetTypeString() string
}

func (s *DummyHandler) WaitFor(typ CacheType, count int) error {
	log.DebugLog(log.DebugLevelInfo, "WaitFor", "cache", typ.String(), "count", count)
	cache := s.GetCache(typ)
	return WaitFor(cache, count)
}

func (s *DummyHandler) GetCache(typ CacheType) WaitForCache {
	var cache WaitForCache
	switch typ {
	case AppType:
		cache = &s.AppCache
	case AppInstType:
		cache = &s.AppInstCache
	case CloudletType:
		cache = &s.CloudletCache
	case VMPoolType:
		cache = &s.VMPoolCache
	case GPUDriverType:
		cache = &s.GPUDriverCache
	case FlavorType:
		cache = &s.FlavorCache
	case ClusterInstType:
		cache = &s.ClusterInstCache
	case AppInstInfoType:
		cache = &s.AppInstInfoCache
	case ClusterInstInfoType:
		cache = &s.ClusterInstInfoCache
	case CloudletInfoType:
		cache = &s.CloudletInfoCache
	case VMPoolInfoType:
		cache = &s.VMPoolInfoCache
	case AlertType:
		cache = &s.AlertCache
	case NodeType:
		cache = &s.SvcNodeCache
	case FreeReservableClusterInstType:
		cache = &s.frClusterInsts
	case NetworkType:
		cache = &s.NetworkCache
	case TrustPolicyExceptionType:
		cache = &s.TrustPolicyExceptionCache
	}

	return cache
}

func (c CacheType) String() string {
	switch c {
	case AppType:
		return "AppCache"
	case AppInstType:
		return "AppInstCache"
	case CloudletType:
		return "CloudletCache"
	case VMPoolType:
		return "VMPoolCache"
	case GPUDriverType:
		return "GPUDriverCache"
	case FlavorType:
		return "FlavorCache"
	case ClusterInstType:
		return "ClusterInstCache"
	case AppInstInfoType:
		return "AppInstCache"
	case ClusterInstInfoType:
		return "ClusterInstCache"
	case CloudletInfoType:
		return "CloudletInfoCache"
	case VMPoolInfoType:
		return "VMPoolInfoCache"
	case AlertType:
		return "AlertCache"
	case NodeType:
		return "NodeCache"
	case FreeReservableClusterInstType:
		return "FreeReservableClusterInstCache"
	case NetworkType:
		return "NetworkCache"
	case TrustPolicyExceptionType:
		return "TrustPolicyExceptionType"
	}
	return "unknown cache type"
}

func WaitFor(cache WaitForCache, count int) error {
	if cache == nil {
		return nil
	}
	for i := 0; i < 100; i++ {
		if cache.GetCount() == count {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	log.DebugLog(log.DebugLevelInfo, "Timed out waiting for cache", "type", cache.GetTypeString(), "expected", count, "actual", cache.GetCount())
	DumpStacks()
	return fmt.Errorf("Timed out waiting for %s count %d, was %d", cache.GetTypeString(), count, cache.GetCount())
}

func (s *DummyHandler) WaitForAppInstInfo(count int) error {
	return WaitFor(&s.AppInstInfoCache, count)
}

func (s *DummyHandler) WaitForClusterInstInfo(count int) error {
	return WaitFor(&s.ClusterInstInfoCache, count)
}

func (s *DummyHandler) WaitForCloudletInfo(count int) error {
	return WaitFor(&s.CloudletInfoCache, count)
}

func (s *DummyHandler) WaitForVMPoolInfo(count int) error {
	return WaitFor(&s.VMPoolInfoCache, count)
}

func (s *DummyHandler) WaitForApps(count int) error {
	return WaitFor(&s.AppCache, count)
}

func (s *DummyHandler) WaitForAppInsts(count int) error {
	return WaitFor(&s.AppInstCache, count)
}

func (s *DummyHandler) WaitForCloudlets(count int) error {
	return WaitFor(&s.CloudletCache, count)
}

func (s *DummyHandler) WaitForVMPools(count int) error {
	return WaitFor(&s.VMPoolCache, count)
}

func (s *DummyHandler) WaitForGPUDrivers(count int) error {
	return WaitFor(&s.GPUDriverCache, count)
}

func (s *DummyHandler) WaitForFlavors(count int) error {
	return WaitFor(&s.FlavorCache, count)
}

func (s *DummyHandler) WaitForClusterInsts(count int) error {
	return WaitFor(&s.ClusterInstCache, count)
}

func (s *DummyHandler) WaitForAlerts(count int) error {
	return s.WaitFor(AlertType, count)
}

func (s *DummyHandler) WaitForNetworks(count int) error {
	return s.WaitFor(NetworkType, count)
}

func (s *DummyHandler) WaitForTrustPolicyException(count int) error {
	return s.WaitFor(TrustPolicyExceptionType, count)
}

func (s *DummyHandler) WaitForCloudletState(key *edgeproto.CloudletKey, state dmeproto.CloudletState) error {
	lastState := dmeproto.CloudletState_CLOUDLET_STATE_UNKNOWN
	for i := 0; i < 100; i++ {
		cloudletInfo := edgeproto.CloudletInfo{}
		if s.CloudletInfoCache.Get(key, &cloudletInfo) {
			if cloudletInfo.State == state {
				return nil
			}
			lastState = cloudletInfo.State
		}
		time.Sleep(30 * time.Millisecond)
	}

	return fmt.Errorf("Unable to get desired cloudletInfo state, actual state %s, desired state %s", lastState, state)
}

func (s *DummyHandler) GetCloudletDetails(key *edgeproto.CloudletKey) (string, int64, error) {
	for _, data := range s.SvcNodeCache.Objs {
		obj := data.Obj
		if obj.Key.Type != "crm" {
			continue
		}
		if obj.Key.CloudletKey != *key {
			continue
		}
		return obj.ContainerVersion, obj.NotifyId, nil
	}
	return "", -1, fmt.Errorf("Unable to find cloudlet in node list")
}

func (s *DummyHandler) WaitForDevices(count int) error {
	return WaitFor(&s.DeviceCache, count)
}

func (s *Client) WaitForConnect(connect uint64) error {
	var cnt uint64
	for i := 0; i < 10; i++ {
		cnt = s.sendrecv.stats.Connects
		if cnt == connect {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	DumpStacks()
	return fmt.Errorf("Timed out waiting for client %s connect count %d, was %d", s.name, connect, cnt)
}

func (s *Client) WaitForSendAllEnd(count uint64) error {
	var cnt uint64
	for i := 0; i < 10; i++ {
		cnt = s.sendrecv.stats.SendAllEnd
		if cnt == cnt {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	DumpStacks()
	return fmt.Errorf("Timed out waiting for client %s sendAllEnd count %d, was %d", s.name, count, cnt)
}

func (mgr *ServerMgr) WaitServerCount(count int) error {
	cnt := 0
	for i := 0; i < 50; i++ {
		mgr.mux.Lock()
		cnt = len(mgr.table)
		mgr.mux.Unlock()
		if cnt == count {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	DumpStacks()
	return fmt.Errorf("Timed out waiting for mgr %s server count %d, was %d", mgr.name, count, cnt)
}

func DumpStacks() {
	buf := make([]byte, 200*1024)
	len := runtime.Stack(buf, true)
	fmt.Println(string(buf[:len]))
}
