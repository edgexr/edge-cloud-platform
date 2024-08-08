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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	"github.com/edgexr/edge-cloud-platform/pkg/util/tasks"
	opentracing "github.com/opentracing/opentracing-go"
)

// InitHAManager returns haEnabled, error
func (s *CRMData) InitHAManager(ctx context.Context, haMgr *redundancy.HighAvailabilityManager, haKey string, cloudletKey *edgeproto.CloudletKey) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitHAManager", "haKey", haKey)
	haEnabled := false
	haCrm := CrmHAProcess{
		crmData:     s,
		cloudletKey: cloudletKey,
	}
	err := haMgr.Init(ctx, haKey, s.NodeMgr, s.Settings.PlatformHaInstanceActiveExpireTime, s.Settings.PlatformHaInstancePollInterval, &haCrm)
	if err == nil {
		haEnabled = true
	} else if strings.Contains(err.Error(), redundancy.HighAvailabilityManagerDisabled) {
		log.SpanLog(ctx, log.DebugLevelInfo, "high availability disabled", "err", err)
	} else {
		return false, err
	}
	return haEnabled, nil
}

func (s *CRMData) StartHAManagerActiveCheck(ctx context.Context, haMgr *redundancy.HighAvailabilityManager) {
	log.SpanLog(ctx, log.DebugLevelInfra, "StartHAManagerActiveCheck")
	go haMgr.CheckActiveLoop(ctx)
}

func (cd *CRMData) GetCloudletInfoFromHACache(ctx context.Context, cloudletInfo *edgeproto.CloudletInfo) error {
	ciVal, err := cd.highAvailabilityManager.GetValue(ctx, CloudletInfoCacheKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "unexpected error getting cloudletinfo from haMgr", "err", err)
		return err
	}
	if ciVal == "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "no existing cloudlet info found")
	} else {
		err = json.Unmarshal([]byte(ciVal), &cloudletInfo)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "cloudletInfo unmarshal error", "err", err)
			return err
		}
		cloudletInfo.ActiveCrmInstance = cd.highAvailabilityManager.HARole
		log.SpanLog(ctx, log.DebugLevelInfra, "got cloudletinfo from HA cache", "state", cloudletInfo.State)
	}
	return nil
}

func (s *CRMData) StartUpdateCloudletInfoHAThread(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelInfra, "StartUpdateCloudletInfoHAThread", "interval", s.Settings.PlatformHaInstanceActiveExpireTime.TimeDuration()*CloudletInfoUpdateRefreshMultiple)
	s.updateCloudletInfoHAPeriodicTask = tasks.NewPeriodicTask(&updateCloudletInfoHATaskable{s})
}

func (s *CRMData) FinishUpdateCloudletInfoHAThread() {
	if s.updateCloudletInfoHAPeriodicTask != nil {
		s.updateCloudletInfoHAPeriodicTask.Stop()
	}
}

// configuration for HA periodic thread
type updateCloudletInfoHATaskable struct {
	cd *CRMData
}

func (s *updateCloudletInfoHATaskable) Run(ctx context.Context) {
	if !s.cd.highAvailabilityManager.PlatformInstanceActive || !s.cd.PlatformCommonInitDone {
		return
	}
	var cloudletInfo edgeproto.CloudletInfo
	if !s.cd.CloudletInfoCache.Get(s.cd.cloudletKey, &cloudletInfo) {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to find cloudlet info in cache", "cloudletKey", s.cd.cloudletKey)
		return
	}
	s.cd.UpdateCloudletInfoAndVersionHACache(ctx, &cloudletInfo)
}

func (s *updateCloudletInfoHATaskable) GetInterval() time.Duration {
	return s.cd.Settings.PlatformHaInstanceActiveExpireTime.TimeDuration() * CloudletInfoUpdateRefreshMultiple
}

func (s *updateCloudletInfoHATaskable) StartSpan() opentracing.Span {
	return log.StartSpan(log.DebugLevelApi, "CloudletResourceRefresh thread", log.WithNoLogStartFinish{})
}

// UpdateCloudletInfoAndVersionHACache updates the value for cloudletInfo and init version that HA Manager has cached in redis
func (s *CRMData) UpdateCloudletInfoAndVersionHACache(ctx context.Context, cloudletInfo *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateCloudletInfoAndVersionHACache", "cloudletInfo state", cloudletInfo.State.String())

	expiration := s.Settings.PlatformHaInstanceActiveExpireTime.TimeDuration() * CloudletInfoUpdateExpireMultiple
	ciJson, err := json.Marshal(cloudletInfo)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cloudletinfo marshal fail", "cloudletInfo", cloudletInfo, "err", err)
		return fmt.Errorf("cloudletinfo marshal fail - %s", err)
	}
	err = s.highAvailabilityManager.SetValue(ctx, CloudletInfoCacheKey, string(ciJson), expiration)
	if err != nil {
		return err
	}
	if s.UpdateHACompatibilityVersion {
		err = s.highAvailabilityManager.SetValue(ctx, InitCompatibilityVersionKey, s.platform.GetInitHAConditionalCompatibilityVersion(ctx), expiration)
	}
	return err
}
