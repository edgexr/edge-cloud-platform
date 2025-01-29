// Copyright 2024 EdgeXR, Inc
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

// Package osmano provides the translation layer for using the
// Open Source Mano platform as a Kubernetes cluster provider
// (https://osm.etsi.org/).
package osmk8s

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/managedk8s"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/osmano/osmapi"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/osmano/osmclient"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
)

type Platform struct {
	properties *infracommon.InfraProperties
	accessVars map[string]string
	osmClient  osmclient.OSMClient
}

func NewPlatform() platform.Platform {
	return &managedk8s.ManagedK8sPlatform{
		Provider: &Platform{},
	}
}

func (s *Platform) Init(accessVars map[string]string, properties *infracommon.InfraProperties) error {
	s.accessVars = accessVars
	s.properties = properties
	if err := s.osmClient.Init(accessVars, properties); err != nil {
		return err
	}
	return nil
}

func (s *Platform) GetFeatures() *edgeproto.PlatformFeatures {
	props := make(map[string]*edgeproto.PropertyInfo)
	for k, v := range osmclient.Props {
		props[k] = v
	}
	for k, v := range Props {
		props[k] = v
	}
	return &edgeproto.PlatformFeatures{
		PlatformType:                  platform.PlatformTypeOSMK8S,
		SupportsMultiTenantCluster:    true,
		SupportsKubernetesOnly:        true,
		KubernetesRequiresWorkerNodes: true,
		IpAllocatedPerService:         true,
		AccessVars:                    osmclient.AccessVarProps,
		Properties:                    props,
		ResourceQuotaProperties:       cloudcommon.CommonResourceQuotaProps,
		RequiresCrmOffEdge:            true,
	}
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	// OSM has no way to list resource limits
	// OSM has no way to list flavors
	flavorsJSON, ok := s.properties.GetValue(OSM_FLAVORS)
	if ok && flavorsJSON != "" {
		flavors := []*edgeproto.FlavorInfo{}
		if err := json.Unmarshal([]byte(flavorsJSON), &flavors); err != nil {
			return fmt.Errorf("failed to unmarshal %s: %s, %s", OSM_FLAVORS, flavorsJSON, err)
		}
		info.Flavors = flavors
	}
	return nil
}

func (s *Platform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

func (s *Platform) Login(ctx context.Context) error {
	_, err := s.getClient(ctx)
	return err
}

func (s *Platform) NameSanitize(clusterName string) string {
	return osmclient.NameSanitize(clusterName)
}

func (s *Platform) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return nil, nil
}

func (s *Platform) getClient(ctx context.Context) (*osmapi.ClientWithResponses, error) {
	return s.osmClient.GetClient(ctx)
}
