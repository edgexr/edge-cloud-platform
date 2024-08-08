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
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

type CrmHAProcess struct {
	crmData     *CRMData
	cloudletKey *edgeproto.CloudletKey
}

func (s *CrmHAProcess) ActiveChangedPreSwitch(ctx context.Context, haRole string, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChangedPreSwitch", "role", haRole, "platformActive", platformActive)
	if !platformActive {
		// not supported, CRM should have been killed within HA manager
		log.SpanFromContext(ctx).Finish()
		log.FatalLog("Error: Unexpected CRM transition to inactive", "cloudletKey", s.cloudletKey)
	}
	return nil
}

func (s *CrmHAProcess) ActiveChangedPostSwitch(ctx context.Context, haRole string, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChangedPostSwitch", "role", haRole, "platformActive", platformActive)
	var cloudletInfo edgeproto.CloudletInfo
	if !s.crmData.CloudletInfoCache.Get(s.cloudletKey, &cloudletInfo) {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to find cloudlet info in cache", "cloudletKey", s.cloudletKey)
		return fmt.Errorf("cannot find in cloudlet info in cache for key %s", s.cloudletKey.String())
	}
	if platformActive {
		cloudletInfo.ActiveCrmInstance = haRole
		cloudletInfo.StandbyCrm = false
	} else {
		cloudletInfo.StandbyCrm = true
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChangedPostSwitch", "PlatformCommonInitDone", s.crmData.PlatformCommonInitDone)

	s.crmData.CloudletInfoCache.Update(ctx, &cloudletInfo, 0)

	select {
	case s.crmData.WaitPlatformActive <- true:
	default:
		// this is not expected because the channel should be filled either by transitioning from
		// standby to active, or starting out active. But as there is no transition for the CRM to go
		// active to standby without restarting, the channel should never be filled more than once
		log.SpanFromContext(ctx).Finish()
		log.FatalLog("WaitPlatformActive channel already full")
	}

	if platformActive {
		err := s.crmData.UpdateCloudletInfoAndVersionHACache(ctx, &cloudletInfo)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "UpdateCloudletInfoCache fail", "err", err)
		}
	}
	return nil
}

func (s *CrmHAProcess) PlatformActiveOnStartup(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelInfra, "PlatformActiveOnStartup")
	select {
	case s.crmData.WaitPlatformActive <- true:
	default:
		// this is not expected because the channel should be filled either by transitioning from
		// standby to active, or starting out active. But as there is no transition for the CRM to go
		// active to standby without restarting, the channel should never be filled more than once
		log.SpanFromContext(ctx).Finish()
		log.FatalLog("WaitPlatformActive channel already full")
	}
}

func (s *CrmHAProcess) DumpWatcherFields(ctx context.Context) map[string]interface{} {
	watcherStatus := make(map[string]interface{})
	watcherStatus["Type"] = "CrmHAProcess"
	watcherStatus["PlatformCommonInitDone"] = s.crmData.PlatformCommonInitDone
	watcherStatus["UpdateHACompatibilityVersion"] = s.crmData.UpdateHACompatibilityVersion
	watcherStatus["ControllerSyncInProgress"] = s.crmData.ControllerSyncInProgress
	return watcherStatus
}
