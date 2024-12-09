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

package ccrm

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessvars"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/proxy/certs"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

// Functions here implement GRPC CloudletPlatform server APIs.

func (s *CCRMHandler) GetCloudletManifest(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.CloudletManifest, error) {
	cloudlet, cloudletPlatform, err := s.getCloudletPlatform(ctx, key)
	if err != nil {
		return nil, err
	}
	features := cloudletPlatform.GetFeatures()

	pfFlavor := edgeproto.Flavor{}
	if !features.IsVmPool {
		if cloudlet.Flavor.Name == "" && cloudlet.Flavor.Name != cloudcommon.DefaultPlatformFlavorKey.Name {
			if !s.crmHandler.FlavorCache.Get(&cloudlet.Flavor, &pfFlavor) {
				return nil, cloudlet.Flavor.NotFoundError()
			}
		}
	}
	accessKeys, err := accessvars.GetCRMAccessKeys(ctx, s.flags.Region, cloudlet, s.nodeMgr.VaultConfig)
	if err != nil {
		return nil, err
	}
	pfConfig, err := s.getPlatformConfig(ctx, cloudlet, accessKeys)
	if err != nil {
		return nil, err
	}
	caches := s.crmHandler.GetCaches()
	pfInitConfig := s.getPlatformInitConfig(cloudlet)
	accessApi := s.vaultClient.CloudletContext(cloudlet)

	manifest, err := cloudletPlatform.GetCloudletManifest(ctx, cloudlet, pfConfig, pfInitConfig, accessApi, &pfFlavor, caches)
	if err != nil {
		return nil, err
	}

	reply := edgeproto.CloudletManifest{
		Manifest: manifest.Manifest,
	}
	return &reply, nil
}

func (s *CCRMHandler) GetClusterAdditionalResources(ctx context.Context, in *edgeproto.ClusterResourcesReq) (*edgeproto.InfraResourceMap, error) {
	cloudlet, cloudletPlatform, err := s.getCloudletPlatform(ctx, in.CloudletKey)
	if err != nil {
		return nil, err
	}
	resMap := cloudletPlatform.GetClusterAdditionalResources(ctx, cloudlet, in.VmResources)
	res := edgeproto.InfraResourceMap{
		InfraResources: resMap,
	}
	return &res, nil
}

func (s *CCRMHandler) GetClusterAdditionalResourceMetric(ctx context.Context, in *edgeproto.ClusterResourceMetricReq) (*edgeproto.Metric, error) {
	cloudlet, cloudletPlatform, err := s.getCloudletPlatform(ctx, in.CloudletKey)
	if err != nil {
		return nil, err
	}

	err = cloudletPlatform.GetClusterAdditionalResourceMetric(ctx, cloudlet, in.ResMetric, in.VmResources)
	if err != nil {
		return nil, err
	}
	return in.ResMetric, nil
}

func (s *CCRMHandler) GetRestrictedCloudletStatus(key *edgeproto.CloudletKey, stream edgeproto.CloudletPlatformAPI_GetRestrictedCloudletStatusServer) error {
	ctx := stream.Context()
	cloudlet, cloudletPlatform, err := s.getCloudletPlatform(ctx, key)
	if err != nil {
		return err
	}

	accessKeys, err := accessvars.GetCRMAccessKeys(ctx, s.flags.Region, cloudlet, s.nodeMgr.VaultConfig)
	if err != nil && vault.IsErrNoSecretsAtPath(err) {
		// cloudlet may not have access keys, i.e. fake platform
		err = nil
	}
	if err != nil {
		return err
	}
	pfConfig, err := s.getPlatformConfig(ctx, cloudlet, accessKeys)
	if err != nil {
		return err
	}
	accessApi := s.vaultClient.CloudletContext(cloudlet)
	err = cloudletPlatform.GetRestrictedCloudletStatus(ctx, cloudlet, pfConfig, accessApi, func(updateType edgeproto.CacheUpdateType, value string) {
		reply := &edgeproto.StreamStatus{
			CacheUpdateType: int32(updateType),
			Status:          value,
		}
		err := stream.Send(reply)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "GetRestrictedCloudletStatus failed to send reply", "reply", reply, "err", err)
		}
	})
	return err
}

func (s *CCRMHandler) GetRootLbFlavor(ctx context.Context, in *edgeproto.CloudletKey) (*edgeproto.Flavor, error) {
	_, cloudletPlatform, err := s.getCloudletPlatform(ctx, in)
	if err != nil {
		return nil, err
	}
	return cloudletPlatform.GetRootLBFlavor(ctx)
}

func (s *CCRMHandler) NameSanitize(ctx context.Context, in *edgeproto.NameSanitizeReq) (*edgeproto.Result, error) {
	_, cloudletPlatform, err := s.getCloudletPlatform(ctx, in.CloudletKey)
	if err != nil {
		return nil, err
	}
	res := cloudletPlatform.NameSanitize(in.Message)
	return &edgeproto.Result{
		Message: res,
	}, nil
}

func (s *CCRMHandler) RefreshCerts(ctx context.Context, in *edgeproto.Cloudlet) (*edgeproto.Result, error) {
	pf, err := s.getCRMCloudletPlatform(ctx, &in.Key)
	if err != nil {
		return nil, err
	}
	features := pf.GetFeatures()

	// There are now two possible ways that certs can be updated
	// below.
	// 1. proxyCerts.RefreshCerts assumes VM-based platforms with
	// a load-balancer VM to ssh to, that is running envoy instances
	// which hold the certificates. This depends on the platform
	// returning ssh clients via GetRootLBClients().
	// 2. Platform.RefreshCerts is a more general way which leaves
	// how to apply new certificates up to the platform code, and
	// just supplies the certs cache.
	proxyCerts := certs.NewProxyCerts(ctx, &in.Key, pf, s.nodeMgr, nil, features, s.flags.CommercialCerts, s.flags.EnvoyWithCurlImage, s.proxyCertsCache)
	err = proxyCerts.RefreshCerts(ctx)
	if err != nil {
		return nil, err
	}
	err = pf.RefreshCerts(ctx, s.proxyCertsCache)
	if err != nil {
		return nil, err
	}
	return &edgeproto.Result{}, err
}

func (s *CCRMHandler) GetCloudletResources(ctx context.Context, in *edgeproto.Cloudlet) (*edgeproto.InfraResourceMap, error) {
	pf, err := s.getCRMCloudletPlatform(ctx, &in.Key)
	if err != nil {
		return nil, err
	}
	snapshot, err := s.crmHandler.CaptureResourcesSnapshot(ctx, pf, &in.Key)
	if err != nil {
		return nil, err
	}
	res := &edgeproto.InfraResourceMap{
		InfraResources: make(map[string]edgeproto.InfraResource),
	}
	for _, infraRes := range snapshot.Info {
		res.InfraResources[infraRes.Name] = infraRes
	}
	return res, nil
}
