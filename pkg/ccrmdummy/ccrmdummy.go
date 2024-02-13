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

// Package ccrmdummy is for unit-tests that need to call ccrm APIs
package ccrmdummy

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/fake"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/go-redis/redis/v8"
)

type CCRMDummy struct {
	plat platform.Platform
}

func StartDummyCCRM(ctx context.Context, redisClient *redis.Client, optionalPlatform platform.Platform) func() {
	// ccrm apis
	if optionalPlatform == nil {
		optionalPlatform = fake.NewPlatform()
	}
	dummy := &CCRMDummy{
		plat: optionalPlatform,
	}
	hctx, cancel := context.WithCancel(ctx)
	server := rediscache.GetCCRMAPIServer(redisClient, node.NodeTypeCCRM, dummy)
	server.Start(hctx)
	return cancel
}

func (d *CCRMDummy) GetCloudletManifest(ctx context.Context, in *edgeproto.CloudletKey) (*edgeproto.CloudletManifest, error) {
	return d.plat.GetCloudletManifest(ctx, &edgeproto.Cloudlet{
		Key: *in,
	}, &edgeproto.PlatformConfig{}, nil, nil, nil)
}

func (d *CCRMDummy) GetClusterAdditionalResources(ctx context.Context, in *edgeproto.ClusterResourcesReq) (*edgeproto.InfraResourceMap, error) {
	resMapIn := make(map[string]edgeproto.InfraResource)
	for k, v := range in.InfraResources {
		resMapIn[k] = *v
	}
	resMap := d.plat.GetClusterAdditionalResources(ctx,
		&edgeproto.Cloudlet{
			Key: *in.CloudletKey,
		},
		in.VmResources, resMapIn,
	)
	out := &edgeproto.InfraResourceMap{
		InfraResources: make(map[string]*edgeproto.InfraResource),
	}
	for k, v := range resMap {
		out.InfraResources[k] = &v
	}
	return out, nil
}

func (d *CCRMDummy) GetClusterAdditionalResourceMetric(ctx context.Context, in *edgeproto.ClusterResourceMetricReq) (*edgeproto.Metric, error) {
	err := d.plat.GetClusterAdditionalResourceMetric(ctx,
		&edgeproto.Cloudlet{
			Key: *in.CloudletKey,
		}, in.ResMetric, in.VmResources,
	)
	return in.ResMetric, err
}

func (d *CCRMDummy) GetRestrictedCloudletStatus(ctx context.Context, in *edgeproto.CloudletKey, send func(*edgeproto.StreamStatus) error) error {
	return d.plat.GetRestrictedCloudletStatus(ctx,
		&edgeproto.Cloudlet{
			Key: *in,
		},
		&edgeproto.PlatformConfig{}, nil,
		func(updateType edgeproto.CacheUpdateType, value string) {
			ss := edgeproto.StreamStatus{
				CacheUpdateType: int32(updateType),
				Status:          value,
			}
			send(&ss)
		},
	)
}

func (d *CCRMDummy) GetRootLbFlavor(ctx context.Context, in *edgeproto.CloudletKey) (*edgeproto.Flavor, error) {
	return d.plat.GetRootLBFlavor(ctx)
}

func (d *CCRMDummy) NameSanitize(ctx context.Context, in *edgeproto.NameSanitizeReq) (*edgeproto.Result, error) {
	msg := d.plat.NameSanitize(in.Message)
	return &edgeproto.Result{
		Message: msg,
	}, nil
}
