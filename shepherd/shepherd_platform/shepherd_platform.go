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

package shepherd_platform

import (
	"context"
	"time"

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
	ssh "github.com/mobiledgex/golang-ssh"
)

// Platform abstracts the underlying cloudlet platform.
type Platform interface {
	// Init is called once during shepherd startup.
	Init(ctx context.Context, pc *platform.PlatformConfig, caches *platform.Caches) error
	// Set VMPool in cache
	SetVMPool(ctx context.Context, vmPool *edgeproto.VMPool)
	// Gets the IP for a cluster
	GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error)
	// Gets a platform client to be able to run commands against (mainly for curling the prometheuses)
	GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error)
	// Gets a rootLb ssh client for VM apps
	GetVmAppRootLbClient(ctx context.Context, appInst *edgeproto.AppInst) (ssh.Client, error)
	// Gets cloudlet-level metrics. This is platform-dependent, hence the common interfcae
	GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error)
	// Get VM metrics - this is really a set of AppMetrics
	GetVmStats(ctx context.Context, key *edgeproto.AppInstKey) (shepherd_common.AppMetrics, error)
	// Get Platform Specific collection time. If the platform doesn't have periodic collection, it will return 0
	GetMetricsCollectInterval() time.Duration
	// Inform the platform that a VM App was added or deleted
	VmAppChangedCallback(ctx context.Context, appInst *edgeproto.AppInst, newState edgeproto.TrackedState)
	// Set Prometheus address. For platforms that rely on prometheus to gather cloudlet stats
	SetUsageAccessArgs(ctx context.Context, addr string, client ssh.Client) error
	// Check if the platform is running locally
	IsPlatformLocal(ctx context.Context) bool
}
