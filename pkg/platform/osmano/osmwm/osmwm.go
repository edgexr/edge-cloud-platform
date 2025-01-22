// Copyright 2025 EdgeXR, Inc
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

// Package osmwm provides OpenSourceMano APIs for workload management.
package osmwm

import (
	"context"
	"errors"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/osmano/osmclient"
	"github.com/edgexr/edge-cloud-platform/pkg/workloadmgrs"
)

type OSMWorkloadMgr struct {
	clusterAccess workloadmgrs.ClusterAccess
	osmClient     osmclient.OSMClient
}

func (s *OSMWorkloadMgr) Init(clusterAccess workloadmgrs.ClusterAccess, accessVars map[string]string, properties *infracommon.InfraProperties) error {
	s.clusterAccess = clusterAccess
	if err := s.osmClient.Init(accessVars, properties); err != nil {
		return err
	}
	return nil
}

func (s *OSMWorkloadMgr) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateSender edgeproto.AppInstInfoSender) error {
	// make sure app has been registered
	_, err := s.osmClient.CreateApp(ctx, app)
	if err != nil {
		return err
	}
	clusterName := s.clusterAccess.GetClusterName(clusterInst)

	_, err = s.osmClient.CreateAppInst(ctx, clusterName, app, appInst)
	if err != nil {
		return err
	}

	return nil
}

func (s *OSMWorkloadMgr) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return s.osmClient.DeleteAppInst(ctx, appInst)
}

func (s *OSMWorkloadMgr) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	return errors.New("unsupported")
}
