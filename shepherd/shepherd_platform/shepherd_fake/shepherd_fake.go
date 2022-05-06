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

package shepherd_fake

import (
	"context"
	"time"

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/edgeproto"
	ssh "github.com/mobiledgex/golang-ssh"
)

type Platform struct {
	promStarted bool
}

func (s *Platform) Init(ctx context.Context, pfConfig *platform.PlatformConfig, caches *platform.Caches) error {
	return nil
}

func (s *Platform) SetVMPool(ctx context.Context, vmPool *edgeproto.VMPool) {
}

func (s *Platform) GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	return "localhost", nil
}

func (s *Platform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) GetVmAppRootLbClient(ctx context.Context, appInst *edgeproto.AppInst) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error) {
	return shepherd_common.CloudletMetrics{}, nil
}

func (s *Platform) GetVmStats(ctx context.Context, key *edgeproto.AppInstKey) (shepherd_common.AppMetrics, error) {
	return shepherd_common.AppMetrics{}, nil
}

func (s *Platform) VmAppChangedCallback(ctx context.Context, appInst *edgeproto.AppInst, newState edgeproto.TrackedState) {
}

func (s *Platform) GetMetricsCollectInterval() time.Duration {
	return 0
}

func (s *Platform) SetUsageAccessArgs(ctx context.Context, addr string, client ssh.Client) error {
	return nil
}

func (s *Platform) IsPlatformLocal(ctx context.Context) bool {
	return true
}
