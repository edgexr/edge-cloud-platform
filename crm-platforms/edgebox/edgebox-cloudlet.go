package edgebox

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/fakeinfra"
	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (e *EdgeboxPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *pf.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "create cloudlet for edgebox")
	err := e.generic.CreateCloudlet(ctx, cloudlet, pfConfig, flavor, nil, updateCallback)
	if err != nil {
		return err
	}
	if err = fakeinfra.ShepherdStartup(ctx, cloudlet, pfConfig, updateCallback); err != nil {
		return err
	}

	return fakeinfra.CloudletPrometheusStartup(ctx, cloudlet, pfConfig, caches, updateCallback)
}

func (e *EdgeboxPlatform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "delete cloudlet for edgebox")
	err := e.generic.DeleteCloudlet(ctx, cloudlet, pfConfig, updateCallback)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Stopping Cloudlet Monitoring")
	intprocess.StartCloudletPrometheus(ctx, cloudlet, edgeproto.GetDefaultSettings())
	updateCallback(edgeproto.UpdateTask, "Stopping Shepherd")
	return intprocess.StopShepherdService(ctx, cloudlet)
}

func (e *EdgeboxPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Saving cloudlet access vars", "cloudletName", cloudlet.Key.Name)
	return nil
}

func (e *EdgeboxPlatform) DeleteCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Deleting cloudlet access vars", "cloudletName", cloudlet.Key.Name)
	return nil
}

func (e *EdgeboxPlatform) SyncControllerCache(ctx context.Context, caches *pf.Caches, cloudletState edgeproto.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SyncControllerCache", "cloudletState", cloudletState)
	return nil
}

func (e *EdgeboxPlatform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest", "cloudletName", cloudlet.Key.Name)
	return e.generic.GetCloudletManifest(ctx, cloudlet, pfConfig, flavor)
}
