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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/opentracing/opentracing-go"
	"go.etcd.io/etcd/client/v3/concurrency"
	"google.golang.org/grpc"
)

// This runs periodic tasks that compete with other Controllers
// running the same threads. The controller that wins spawns
// some API calls that trigger the CCRMs to do work. Those API
// calls get load balanced over all CCRMs. The Controller is
// not doing any work here.

const (
	CloudletCertRefreshTaskKey     = "CloudletCertRefreshTask"
	CloudletResourceRefreshTaskKey = "CloudletResourceRefreshTask"
)

type PeriodicData struct {
	LastTime time.Time
}

type CloudletCertRefreshTaskable struct {
	CloudletTaskableHelper
}

// NewCloudletCertRefreshTaskable returns a PeriodicTaskable for refreshing
// cloudlet certificates
func NewCloudletCertRefreshTaskable(all *AllApis) *CloudletCertRefreshTaskable {
	s := CloudletCertRefreshTaskable{}
	s.all = all
	s.taskName = CloudletCertRefreshTaskKey
	s.getInterval = s.GetInterval
	s.shouldRunFunc = s.shouldRun
	s.runAPIFunc = s.runAPI
	return &s
}

func (s *CloudletCertRefreshTaskable) GetInterval() time.Duration {
	return 24 * time.Hour
}

func (s *CloudletCertRefreshTaskable) StartSpan() opentracing.Span {
	return log.StartSpan(log.DebugLevelApi, "ccrm cert refresh trigger")
}

func (s *CloudletCertRefreshTaskable) shouldRun(ctx context.Context, cloudlet *edgeproto.Cloudlet, features *edgeproto.PlatformFeatures) bool {
	return canRunRefreshCerts(cloudlet, features)
}

func (s *CloudletCertRefreshTaskable) runAPI(ctx context.Context, cloudlet *edgeproto.Cloudlet, conn *grpc.ClientConn) error {
	api := edgeproto.NewCloudletPlatformAPIClient(conn)
	_, err := api.RefreshCerts(ctx, cloudlet)
	return err
}

// CloudletTaskableHelper provides common code for any periodic cloudlet task
type CloudletTaskableHelper struct {
	all           *AllApis
	taskName      string
	shouldRunFunc func(context.Context, *edgeproto.Cloudlet, *edgeproto.PlatformFeatures) bool
	getInterval   func() time.Duration
	runAPIFunc    func(ctx context.Context, cloudlet *edgeproto.Cloudlet, conn *grpc.ClientConn) error
}

func (s *CloudletTaskableHelper) Run(ctx context.Context) {
	run, err := s.periodicTaskShouldRun(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "check if periodic task should run failed", "err", err)
		return
	}
	if !run {
		return
	}

	ptof := s.all.platformFeaturesApi.FeaturesByPlatform()

	s.all.cloudletApi.cache.Show(&edgeproto.Cloudlet{}, func(cloudlet *edgeproto.Cloudlet) error {
		features, ok := ptof[cloudlet.PlatformType]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelApi, "cloudlet missing features", "task", s.taskName, "platformType", cloudlet.PlatformType, "cloudlet", cloudlet.Key)
			return nil
		}
		if !s.shouldRunFunc(ctx, cloudlet, &features) {
			return nil
		}
		cloudletCopy := &edgeproto.Cloudlet{}
		cloudletCopy.DeepCopyIn(cloudlet)
		log.SpanLog(ctx, log.DebugLevelApi, "spawn ccrm periodic task", "name", s.taskName, "cloudlet", cloudlet.Key)

		conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "ccrm periodic task no connection for nodeType", "nodeType", features.NodeType, "task", s.taskName, "cloudlet", cloudlet.Key)
			return nil
		}

		go func(cloudlet *edgeproto.Cloudlet, conn *grpc.ClientConn) {
			span, ctx := log.ChildSpan(ctx, log.DebugLevelApi, "ccrm periodic task for cloudlet")
			defer span.Finish()
			log.SetTags(span, cloudlet.Key.GetTags())
			err := s.runAPIFunc(ctx, cloudlet, conn)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "cloudlet periodic task failed", "task", s.taskName, "cloudlet", cloudlet.Key, "err", err)
			} else {
				log.SpanLog(ctx, log.DebugLevelApi, "cloudlet periodic task succeeded", "task", s.taskName, "cloudlet", cloudlet.Key)
			}
		}(cloudletCopy, conn)
		return nil
	})
}

func (s *CloudletTaskableHelper) periodicTaskShouldRun(ctx context.Context) (bool, error) {
	run := false
	err := s.all.cloudletApi.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		run = false
		key := getPeriodicTaskKey(s.taskName)
		val := stm.Get(key)
		pdata := PeriodicData{}
		err := json.Unmarshal([]byte(val), &pdata)
		if err != nil {
			return fmt.Errorf("failed to unmarshal data, %s, %s", err, val)
		}
		if pdata.LastTime.Add(s.getInterval()).After(time.Now()) {
			// not time yet
			return nil
		}
		run = true
		pdata.LastTime = time.Now()
		bval, err := json.Marshal(&pdata)
		if err != nil {
			return fmt.Errorf("failed to marshal data, %s, %v", err, pdata)
		}
		stm.Put(key, string(bval))
		return nil
	})
	return run, err
}

func getPeriodicTaskKey(name string) string {
	return fmt.Sprintf("%d/PeriodicTaskKey/%s", objstore.GetRegion(), name)
}
