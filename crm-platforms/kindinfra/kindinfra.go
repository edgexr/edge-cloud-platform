package kindinfra

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/fakeinfra"
	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/kind"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

// Kind platform with multi-tenant cluster support.
// We may also want to add shepherd/envoy to test metrics.
type Platform struct {
	kind.Platform
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	err := s.Platform.GatherCloudletInfo(ctx, info)
	if err != nil {
		return err
	}
	if info.Properties == nil {
		info.Properties = make(map[string]string)
	}
	info.OsMaxRam = 81920
	info.OsMaxVcores = 100
	info.OsMaxVolGb = 500
	return nil
}

func (s *Platform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *pf.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	cloudletResourcesCreated, err := s.Platform.CreateCloudlet(ctx, cloudlet, pfConfig, flavor, caches, accessApi, updateCallback)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	if err = fakeinfra.ShepherdStartup(ctx, cloudlet, pfConfig, updateCallback); err != nil {
		return cloudletResourcesCreated, err
	}
	return cloudletResourcesCreated, fakeinfra.CloudletPrometheusStartup(ctx, cloudlet, pfConfig, caches, updateCallback)
}

func (s *Platform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *pf.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	err := s.Platform.DeleteCloudlet(ctx, cloudlet, pfConfig, caches, accessApi, updateCallback)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Stopping Shepherd")
	return intprocess.StopShepherdService(ctx, cloudlet)
}
