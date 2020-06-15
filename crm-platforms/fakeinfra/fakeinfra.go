package fakeinfra

import (
	"context"
	"errors"
	"fmt"
	"time"

	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/fake"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type Platform struct {
	fake.Platform
}

func (s *Platform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *pf.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	err := s.Platform.CreateCloudlet(ctx, cloudlet, pfConfig, flavor, nil, updateCallback)
	if err != nil {
		return err
	}
	if err = ShepherdStartup(ctx, cloudlet, pfConfig, updateCallback); err != nil {
		return err
	}
	return CloudletPrometheusStartup(ctx, cloudlet, pfConfig, updateCallback)
}

func (s *Platform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	err := s.Platform.DeleteCloudlet(ctx, cloudlet, pfConfig, updateCallback)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Stopping Shepherd")
	return intprocess.StopShepherdService(ctx, cloudlet)
}

// Start prometheus container
func CloudletPrometheusStartup(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	// for fakeinfra we only start the first cloudlet prometheus, since it's going to run on the same port as
	// other cloudlet prometheus
	if intprocess.CloudletPrometheusExists(ctx) {
		updateCallback(edgeproto.UpdateTask, "Skipping Cloudlet Monitoring for fakeinfra platform")
		return nil
	}

	updateCallback(edgeproto.UpdateTask, "Starting Cloudlet Monitoring")
	return intprocess.StartCloudletPrometheus(ctx, cloudlet)
}

func ShepherdStartup(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "Starting Shepherd")
	shProc, err := intprocess.StartShepherdService(ctx, cloudlet, pfConfig)
	if err != nil {
		return err
	}
	fatal := make(chan bool, 1)

	go func() {
		shProc.Wait()
		fatal <- true
	}()
	select {
	case <-fatal:
		out := ""
		out, err = cloudcommon.GetCloudletLog(ctx, &cloudlet.Key)
		if err != nil || out == "" {
			out = fmt.Sprintf("Please look at %s for more details", cloudcommon.GetCloudletLogFile(cloudlet.Key.Name+".shepherd"))
		} else {
			out = fmt.Sprintf("Failure: %s", out)
		}
		return errors.New(out)
	case <-time.After(2 * time.Second):
		// Small timeout should be enough for Shepherd to connect to CRM as both will be present locally
		return nil
	}
}
