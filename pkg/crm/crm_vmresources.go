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
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/util/tasks"
	opentracing "github.com/opentracing/opentracing-go"
)

// This is the code that used to be vmResourceActionBegin()
// and vmResourceActionEnd()

func (s *CRMData) vmResourceActionEnd(ctx context.Context) {
	// only one worker thread used
	s.vmResourceSnapshotWorker.NeedsWork(ctx, "singleton")
}

func (s *CRMData) vmResourceSnapshotWork(ctx context.Context, k any) {
	resources, err := s.CRMHandler.CaptureResourcesSnapshot(ctx, s.platform, s.cloudletKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to capture resource snapshot", "err", err)
		return
	}
	if resources == nil {
		return
	}

	cloudletInfo := edgeproto.CloudletInfo{}
	found := s.CloudletInfoCache.Get(s.cloudletKey, &cloudletInfo)
	if !found {
		log.SpanLog(ctx, log.DebugLevelInfra, "CloudletInfo not found for cloudlet", "key", s.cloudletKey)
		return
	}
	cloudletInfo.ResourcesSnapshot = *resources
	s.CloudletInfoCache.Update(ctx, &cloudletInfo, 0)
}

func (s *CRMData) StartInfraResourceRefreshThread() {
	s.vmResourceSnapshotPeriodicTask = tasks.NewPeriodicTask(&infraResourceThreadTaskable{s})
	s.vmResourceSnapshotPeriodicTask.Start()
}

func (s *CRMData) FinishInfraResourceRefreshThread() {
	if s.vmResourceSnapshotPeriodicTask != nil {
		s.vmResourceSnapshotPeriodicTask.Stop()
	}
}

// configuration for the periodic infra resource thread
type infraResourceThreadTaskable struct {
	cd *CRMData
}

func (s *infraResourceThreadTaskable) Run(ctx context.Context) {
	s.cd.vmResourceSnapshotWorker.NeedsWork(ctx, "singleton")
}

func (s *infraResourceThreadTaskable) GetInterval() time.Duration {
	return s.cd.Settings.ResourceSnapshotThreadInterval.TimeDuration()
}

func (s *infraResourceThreadTaskable) StartSpan() opentracing.Span {
	return log.StartSpan(log.DebugLevelApi, "CloudletResourceRefresh thread", log.WithNoLogStartFinish{})
}
