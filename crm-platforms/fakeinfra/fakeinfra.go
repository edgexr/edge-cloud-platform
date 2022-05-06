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

package fakeinfra

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"

	intprocess "github.com/edgexr/edge-cloud-infra/e2e-tests/int-process"
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud-infra/version"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	pf "github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/fake"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/redundancy"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/integration/process"
	"github.com/edgexr/edge-cloud/log"
)

type Platform struct {
	fake.Platform
	envoys map[edgeproto.AppInstKey]*exec.Cmd
	mux    sync.Mutex
}

func (s *Platform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	s.envoys = make(map[edgeproto.AppInstKey]*exec.Cmd)
	return s.Platform.InitCommon(ctx, platformConfig, caches, haMgr, updateCallback)
}

func (s *Platform) InitHAConditional(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	return s.Platform.InitHAConditional(ctx, platformConfig, updateCallback)
}

func (s *Platform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "fakeinfra-1.0"
}

func (s *Platform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *pf.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	cloudletResourcesCreated, err := s.Platform.CreateCloudlet(ctx, cloudlet, pfConfig, flavor, caches, accessApi, updateCallback)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	if err = ShepherdStartup(ctx, cloudlet, pfConfig, updateCallback); err != nil {
		return cloudletResourcesCreated, err
	}
	if err = CloudletPrometheusStartup(ctx, cloudlet, pfConfig, caches, updateCallback); err != nil {
		return cloudletResourcesCreated, err
	}
	return cloudletResourcesCreated, nil
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
	return intprocess.StartCloudletPrometheus(ctx, pfConfig.ThanosRecvAddr, cloudlet, caches.SettingsCache.Singular())
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
		}
		for _, port := range appInst.MappedPorts {
			args = append(args, "--port")
			args = append(args, fmt.Sprintf("%d", port.InternalPort))
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
