package ccrm

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessvars"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

func (s *CCRMHandler) GetCloudletManifest(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.CloudletManifest, error) {
	cloudlet := edgeproto.Cloudlet{}
	if !s.caches.CloudletCache.Get(key, &cloudlet) {
		return nil, key.NotFoundError()
	}
	cloudletPlatform, found := s.caches.getPlatform(cloudlet.PlatformType)
	if !found {
		// ignore, some other CCRM should handle it
		log.SpanLog(ctx, log.DebugLevelApi, "cloudletManifest ignoring unknown platform", "platform", cloudlet.PlatformType)
		return nil, nil
	}
	features := cloudletPlatform.GetFeatures()

	pfFlavor := edgeproto.Flavor{}
	if !features.IsVmPool {
		if cloudlet.Flavor.Name == "" && cloudlet.Flavor.Name != cloudcommon.DefaultPlatformFlavorKey.Name {
			if !s.caches.FlavorCache.Get(&cloudlet.Flavor, &pfFlavor) {
				return nil, cloudlet.Flavor.NotFoundError()
			}
		}
	}
	accessKeys, err := accessvars.GetCRMAccessKeys(ctx, s.flags.Region, &cloudlet, s.nodeMgr.VaultConfig)
	if err != nil {
		return nil, err
	}
	pfConfig, err := s.getPlatformConfig(ctx, &cloudlet, accessKeys)
	if err != nil {
		return nil, err
	}
	caches := s.caches.getPlatformCaches()
	accessApi := s.vaultClient.CloudletContext(&cloudlet)

	manifest, err := cloudletPlatform.GetCloudletManifest(ctx, &cloudlet, pfConfig, accessApi, &pfFlavor, caches)
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
	infraRes := make(map[string]edgeproto.InfraResource)
	for k, v := range in.InfraResources {
		if v == nil {
			continue
		}
		infraRes[k] = *v
	}
	resMap := cloudletPlatform.GetClusterAdditionalResources(ctx, cloudlet, in.VmResources, infraRes)
	res := edgeproto.InfraResourceMap{
		InfraResources: map[string]*edgeproto.InfraResource{},
	}
	for k, v := range resMap {
		res.InfraResources[k] = &v
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

func (s *CCRMHandler) GetRestrictedCloudletStatus(ctx context.Context, key *edgeproto.CloudletKey, send func(*edgeproto.StreamStatus) error) error {
	cloudlet := edgeproto.Cloudlet{}
	if !s.caches.CloudletCache.Get(key, &cloudlet) {
		return key.NotFoundError()
	}

	cloudletPlatform, found := s.caches.getPlatform(cloudlet.PlatformType)
	if !found {
		// ignore, some other CCRM should handle it
		log.SpanLog(ctx, log.DebugLevelApi, "cloudletManifest ignoring unknown platform", "platform", cloudlet.PlatformType)
		return nil
	}

	accessKeys, err := accessvars.GetCRMAccessKeys(ctx, s.flags.Region, &cloudlet, s.nodeMgr.VaultConfig)
	if err != nil {
		return err
	}
	pfConfig, err := s.getPlatformConfig(ctx, &cloudlet, accessKeys)
	if err != nil {
		return err
	}
	accessApi := s.vaultClient.CloudletContext(&cloudlet)
	err = cloudletPlatform.GetRestrictedCloudletStatus(ctx, &cloudlet, pfConfig, accessApi, func(updateType edgeproto.CacheUpdateType, value string) {
		reply := &edgeproto.StreamStatus{
			CacheUpdateType: int32(updateType),
			Status:          value,
		}
		err := send(reply)
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

func (s *CCRMHandler) getCloudletPlatform(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.Cloudlet, platform.Platform, error) {
	if key == nil {
		return nil, nil, fmt.Errorf("CloudletKey not specified")
	}
	cloudlet := edgeproto.Cloudlet{}
	if !s.caches.CloudletCache.Get(key, &cloudlet) {
		return nil, nil, key.NotFoundError()
	}
	cloudletPlatform, found := s.caches.getPlatform(cloudlet.PlatformType)
	if !found {
		// Redis APIs should be directed to the correct CCRM
		// for the platform.
		return nil, nil, fmt.Errorf("platform %s not found for cloudlet %s", cloudlet.PlatformType, key.GetKeyString())
	}
	return &cloudlet, cloudletPlatform, nil
}
