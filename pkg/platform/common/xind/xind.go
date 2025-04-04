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

package xind

import (
	"context"
	"fmt"
	"sort"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	certscache "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs-cache"
	ssh "github.com/edgexr/golang-ssh"
)

// Common code for DIND and KIND
type Xind struct {
	Caches         *platform.Caches
	remotePassword string
	clusterManager ClusterManager
	PlatformType   string
	platformConfig *platform.PlatformConfig
}

func (s *Xind) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, clusterManager ClusterManager, updateCallback edgeproto.CacheUpdateCallback) error {
	s.Caches = caches
	s.clusterManager = clusterManager
	s.platformConfig = platformConfig
	return nil
}
func (s *Xind) InitHAConditional(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *Xind) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "xind-1.0"
}

func (s *Xind) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:            s.PlatformType,
		CloudletServicesLocal:   true,
		ResourceQuotaProperties: cloudcommon.CommonResourceQuotaProps,
	}
}

func (s *Xind) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	client, err := s.GetClient(ctx)
	if err != nil {
		return err
	}
	err = GetLimits(ctx, client, info)
	if err != nil {
		return err
	}
	// Use flavors from controller as platform flavor
	var flavors []*edgeproto.FlavorInfo
	if s.Caches == nil {
		return fmt.Errorf("Flavor cache is nil")
	}
	flavorkeys := make(map[edgeproto.FlavorKey]struct{})
	s.Caches.FlavorCache.GetAllKeys(ctx, func(k *edgeproto.FlavorKey, modRev int64) {
		flavorkeys[*k] = struct{}{}
	})
	for k := range flavorkeys {
		var flav edgeproto.Flavor
		if s.Caches.FlavorCache.Get(&k, &flav) {
			var flavInfo edgeproto.FlavorInfo
			flavInfo.Name = flav.Key.Name
			flavInfo.Ram = flav.Ram
			flavInfo.Vcpus = flav.Vcpus
			flavInfo.Disk = flav.Disk
			flavors = append(flavors, &flavInfo)
		} else {
			return fmt.Errorf("fail to fetch flavor %s", k)
		}
	}
	sort.Slice(flavors[:], func(i, j int) bool {
		return flavors[i].Name < flavors[j].Name
	})
	info.Flavors = flavors
	return nil
}

func (s *Xind) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return s.GetClient(ctx)
}

func (s *Xind) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return s.GetClient(ctx)
}

func (s *Xind) GetClient(ctx context.Context) (ssh.Client, error) {
	// TODO: add support for remote infra
	return &pc.LocalClient{
		WorkingDir: "/tmp",
	}, nil
}

func (s *Xind) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

func (s *Xind) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return nil, nil
}

func (s *Xind) GetVersionProperties(ctx context.Context) map[string]string {
	return map[string]string{}
}

func (s *Xind) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &edgeproto.Flavor{
		Vcpus: uint64(0),
		Ram:   uint64(0),
		Disk:  uint64(0),
	}, nil
}

func (s *Xind) NameSanitize(name string) string {
	return name
}

func (s *Xind) RefreshCerts(ctx context.Context, certsCache *certscache.ProxyCertsCache) error {
	return nil
}
