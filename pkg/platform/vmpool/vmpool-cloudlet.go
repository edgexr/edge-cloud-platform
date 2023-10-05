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

package vmpool

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/vmlayer"
)

func (o *VMPoolPlatform) GetApiEndpointAddr(ctx context.Context) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetApiEndpointAddr not supported")
	return "", nil
}

func (o *VMPoolPlatform) GetCloudletManifest(ctx context.Context, name string, cloudletImagePath string, vmgp *vmlayer.VMGroupOrchestrationParams) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletManifest", "name", name)
	var manifest infracommon.CloudletManifest

	if vmgp == nil {
		return "", nil
	}
	if len(vmgp.VMs) != 1 {
		return "", fmt.Errorf("invalid number of VMs")
	}
	cloudConfigParams := vmgp.VMs[0].CloudConfigParams
	if cloudConfigParams.ConfigureNodeVars == nil {
		return "", fmt.Errorf("missing cloudlet node params for %s", name)
	}
	if cloudConfigParams.ConfigureNodeVars.Password == "" {
		return "", fmt.Errorf("missing cloudlet node key for %s", cloudConfigParams.ConfigureNodeVars.Key.Name)
	}

	// TODO: Support for ansible based configuration management
	return manifest.ToString()
}

func (o *VMPoolPlatform) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	return []edgeproto.InfraResource{}, nil
}

func (o *VMPoolPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	resInfo := make(map[string]edgeproto.InfraResource)
	return resInfo
}

func (o *VMPoolPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

func (o *VMPoolPlatform) InternalCloudletUpdatedCallback(ctx context.Context, old *edgeproto.CloudletInternal, new *edgeproto.CloudletInternal) {
	log.SpanLog(ctx, log.DebugLevelInfra, "InternalCloudletUpdatedCallback")
}

func (o *VMPoolPlatform) GetGPUSetupStage(ctx context.Context) vmlayer.GPUSetupStage {
	return vmlayer.ClusterInstStage
}
