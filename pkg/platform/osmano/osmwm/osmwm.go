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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/k8spm"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/osmano/osmclient"
	ssh "github.com/edgexr/golang-ssh"
)

type OSMWorkloadMgr struct {
	clusterAccess k8spm.ClusterAccess
	osmClient     osmclient.OSMClient
}

func (s *OSMWorkloadMgr) Init(clusterAccess k8spm.ClusterAccess, accessVars map[string]string, properties *infracommon.InfraProperties) error {
	s.clusterAccess = clusterAccess
	if err := s.osmClient.Init(accessVars, properties); err != nil {
		return err
	}
	return nil
}

func (s *OSMWorkloadMgr) ApplyAppInstWorkload(ctx context.Context, accessAPI platform.AccessApi, client ssh.Client, names *k8smgmt.KubeNames, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, ops ...k8smgmt.AppInstOp) error {
	// make sure app has been registered
	_, err := s.osmClient.CreateApp(ctx, app)
	if err != nil {
		return err
	}
	clusterName := s.clusterAccess.GetClusterName(clusterInst)

	_, err = s.osmClient.CreateAppInst(ctx, names, clusterName, app, appInst)
	if err != nil {
		return err
	}
	return nil
}

func (s *OSMWorkloadMgr) DeleteAppInstWorkload(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *k8smgmt.KubeNames, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, ops ...k8smgmt.AppInstOp) error {
	err := s.osmClient.DeleteAppInst(ctx, appInst)
	if err != nil {
		return err
	}
	return nil
}
