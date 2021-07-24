package fakeinfra

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"

	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud-infra/version"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/fake"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/integration/process"
	"github.com/mobiledgex/edge-cloud/log"
)

type Platform struct {
	fake.Platform
	envoys map[edgeproto.AppInstKey]*exec.Cmd
	mux    sync.Mutex
}

func (s *Platform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	s.envoys = make(map[edgeproto.AppInstKey]*exec.Cmd)
	return s.Platform.Init(ctx, platformConfig, caches, updateCallback)
}

func (s *Platform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *pf.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	err := s.Platform.CreateCloudlet(ctx, cloudlet, pfConfig, flavor, caches, accessApi, updateCallback)
	if err != nil {
		return err
	}
	if err = ShepherdStartup(ctx, cloudlet, pfConfig, updateCallback); err != nil {
		return err
	}
	return CloudletPrometheusStartup(ctx, cloudlet, pfConfig, caches, updateCallback)
}

func (s *Platform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *pf.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	err := s.Platform.DeleteCloudlet(ctx, cloudlet, pfConfig, caches, accessApi, updateCallback)
	if err != nil {
		return err
	}
	// Cloudlet prometheus needs to be stopped when Shepherd is stopped,
	// otherwise it can erroneously trigger alerts during e2e-tests, when
	// it is unable to scrape Shepherd.
	log.SpanLog(ctx, log.DebugLevelApi, "Stopping Cloudlet Prometheus")
	if err := intprocess.StopCloudletPrometheus(ctx); err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Stopping Shepherd")
	return intprocess.StopShepherdService(ctx, cloudlet)
}

// Start prometheus container
func CloudletPrometheusStartup(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *pf.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	// for fakeinfra we only start the first cloudlet prometheus, since it's going to run on the same port as
	// other cloudlet prometheus
	if intprocess.CloudletPrometheusExists(ctx) {
		updateCallback(edgeproto.UpdateTask, "Skipping Cloudlet Monitoring for fakeinfra platform")
		return nil
	}

	updateCallback(edgeproto.UpdateTask, "Starting Cloudlet Monitoring")
	return intprocess.StartCloudletPrometheus(ctx, cloudlet, caches.SettingsCache.Singular())
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

func (s *Platform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "Creating App Inst")
	if shepherd_common.ShouldRunEnvoy(app, appInst) {
		name := shepherd_common.GetProxyKey(&appInst.Key)
		envoySock := "/tmp/envoy_" + name + ".sock"
		envoyLog := "/tmp/envoy_" + name + ".log"

		args := []string{
			"--sockfile", envoySock,
			"--cluster", clusterInst.Key.ClusterKey.Name,
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "start fake_envoy_exporter", "AppInst", appInst.Key)
		cmd, err := process.StartLocal(name, "fake_envoy_exporter", args, nil, envoyLog)
		if err != nil {
			return err
		}
		s.mux.Lock()
		s.envoys[appInst.Key] = cmd
		s.mux.Unlock()
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "fake AppInst ready")
	return nil
}

func (s *Platform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	s.mux.Lock()
	cmd, ok := s.envoys[appInst.Key]
	delete(s.envoys, appInst.Key)
	s.mux.Unlock()

	if ok {
		cmd.Process.Kill()
		cmd.Process.Wait()
	}
	updateCallback(edgeproto.UpdateTask, "First Delete Task")
	updateCallback(edgeproto.UpdateTask, "Second Delete Task")
	log.SpanLog(ctx, log.DebugLevelInfra, "fake AppInst deleted")
	return nil
}

func (s *Platform) GetCloudletProps(ctx context.Context) (*edgeproto.CloudletProps, error) {
	return s.Platform.GetCloudletProps(ctx)
}

func (s *Platform) GetVersionProperties() map[string]string {
	return version.InfraBuildProps("FakeInfra")
}
