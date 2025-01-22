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

package workloadmgrs

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	ssh "github.com/edgexr/golang-ssh"
)

// ClusterAccess interface defines APIs for gaining access to a cluster
type ClusterAccess interface {
	// GetClusterPlatformClient gets an ssh client to access the
	// node that will have the local kubeconfig and manifest files.
	GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error)
	// GetClusterCredentials retrieves kubeconfig credentials from the cluster
	GetClusterCredentials(ctx context.Context, clusterInst *edgeproto.ClusterInst) ([]byte, error)
	// GetClusterName gets the name used for the cluster
	GetClusterName(clusterInst *edgeproto.ClusterInst) string
}

// WorkloadMgr handles deploying instances. It should be provided
// a TLS certificate if needed (TODO), and it should return the IP
// addresses that were assigned so the caller can create DNS entries.
type WorkloadMgr interface {
	// Create an AppInst on a Cluster
	CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateSender edgeproto.AppInstInfoSender) error
	// Delete an AppInst on a Cluster
	DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error
	// Update an AppInst
	UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error
}
