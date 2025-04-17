// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crm

import (
	"context"
	"sync"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/crmutil"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	pf "github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	"github.com/edgexr/edge-cloud-platform/pkg/util/tasks"
)

// CRMData is a wrapper around crmutil.CRMHandler and uses
// it in the context of the on-edge-site CRM.
// CRMData is updated via notify, and changes are sent back via notify.
type CRMData struct {
	*crmutil.CRMHandler
	platform                         pf.Platform
	cloudletKey                      *edgeproto.CloudletKey
	ControllerWait                   chan bool
	ControllerSyncInProgress         bool
	ControllerSyncDone               chan bool
	WaitPlatformActive               chan bool
	PlatformCommonInitDone           bool
	highAvailabilityManager          *redundancy.HighAvailabilityManager
	UpdateHACompatibilityVersion     bool
	ExecReqHandler                   *ExecReqHandler
	ExecReqSend                      *notify.ExecRequestSend
	waitForCRMINITOK                 bool
	AppInstInfoCache                 edgeproto.AppInstInfoCache
	CloudletInfoCache                edgeproto.CloudletInfoCache
	ClusterInstInfoCache             edgeproto.ClusterInstInfoCache
	VMPool                           edgeproto.VMPool
	VMPoolMux                        sync.Mutex
	VMPoolUpdateMux                  sync.Mutex
	updateVMPoolWorkers              tasks.KeyWorkers
	vmResourceSnapshotWorker         tasks.KeyWorkers
	vmResourceSnapshotPeriodicTask   *tasks.PeriodicTask
	updateCloudletInfoHAPeriodicTask *tasks.PeriodicTask
}

const CloudletInfoCacheKey = "cloudletInfo"
const InitCompatibilityVersionKey = "initCompatVersion"
const CloudletInfoUpdateExpireMultiple = 20 // relative to PlatformHaInstanceActiveExpireTime how long cloudletInfo cache is valid
const CloudletInfoUpdateRefreshMultiple = 9 // relative to PlatformHaInstanceActiveExpireTime how often to refresh cloudlet info

func NewCRMData(platform pf.Platform, key *edgeproto.CloudletKey, nodeMgr *svcnode.SvcNodeMgr, haMgr *redundancy.HighAvailabilityManager) *CRMData {
	s := &CRMData{}
	s.cloudletKey = key
	s.platform = platform
	s.ControllerWait = make(chan bool, 1)
	s.ControllerSyncDone = make(chan bool, 1)
	s.WaitPlatformActive = make(chan bool, 1)
	s.highAvailabilityManager = haMgr
	s.CRMHandler = crmutil.NewCRMHandler(getPlatform, nodeMgr)

	edgeproto.InitAppInstInfoCache(&s.AppInstInfoCache)
	edgeproto.InitClusterInstInfoCache(&s.ClusterInstInfoCache)
	edgeproto.InitCloudletInfoCache(&s.CloudletInfoCache)

	// set callbacks to trigger changes
	s.ClusterInstCache.SetUpdatedCb(s.clusterInstChanged)
	s.ClusterInstCache.SetDeletedCb(s.clusterInstDeleted)
	s.AppInstCache.SetUpdatedCb(s.appInstChanged)
	s.AppInstCache.SetDeletedCb(s.appInstDeleted)
	s.CloudletCache.SetUpdatedCb(s.cloudletChanged)
	s.CloudletCache.SetDeletedCb(s.cloudletDeleted)
	s.VMPoolCache.SetUpdatedCb(s.VMPoolChanged)
	s.SettingsCache.SetUpdatedCb(s.SettingsChanged)
	s.TPEInstanceStateCache.AddUpdatedCb(s.tpeInstanceStateChanged)

	s.ExecReqHandler = NewExecReqHandler(s)
	s.ExecReqSend = notify.NewExecRequestSend()

	s.updateVMPoolWorkers.Init("vmpool-updatevm", s.UpdateVMPool)
	s.vmResourceSnapshotWorker.Init("vmResourceSnapshot", s.vmResourceSnapshotWork)

	// debug functions
	nodeMgr.Debug.AddDebugFunc("show-ha-status", haMgr.DumpHAManager)
	nodeMgr.Debug.AddDebugFunc(GetEnvoyVersionCmd, s.GetClusterEnvoyVersion)
	return s
}

func (s *CRMData) RecvAllEnd(ctx context.Context) {
	if s.ControllerSyncInProgress {
		s.ControllerSyncDone <- true
	}
	s.ControllerSyncInProgress = false
}

func (s *CRMData) RecvAllStart() {
}

func (s *CRMData) notifyControllerConnect() {
	// Notify controller connect only if:
	// * started manually and not by controller
	// * if started by controller, then notify on INITOK
	select {
	case s.ControllerWait <- true:
		// Controller - CRM communication started on Notify channel
	default:
	}
}
