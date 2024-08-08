package localhost

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/dockermgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/mock"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	ssh "github.com/edgexr/golang-ssh"
)

// Run docker and kubernetes App Instances on the localhost
// For code testing and development only.

type Platform struct {
	mock.Platform
	platformConfig *platform.PlatformConfig
	caches         *platform.Caches
}

func NewPlatform() platform.Platform {
	return &Platform{}
}

func (s *Platform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	s.platformConfig = platformConfig
	s.caches = caches
	return s.Platform.InitCommon(ctx, platformConfig, caches, haMgr, updateCallback)
}

func (s *Platform) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:          platform.PlatformTypeLocalhost,
		CloudletServicesLocal: true,
	}
}

func getWorkingDir(key *edgeproto.CloudletKey) string {
	return "/tmp/" + key.Name
}

func (s *Platform) getClient() *pc.LocalClient {
	return &pc.LocalClient{
		WorkingDir: getWorkingDir(s.platformConfig.CloudletKey),
	}
}

func (s *Platform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, flavor *edgeproto.Flavor, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	err := os.MkdirAll(getWorkingDir(&cloudlet.Key), 0755)
	if err != nil {
		return false, err
	}
	var redisCfg rediscache.RedisConfig
	err = process.StartCRMService(ctx, cloudlet, pfConfig, process.HARolePrimary, &redisCfg)
	return true, err
}

func (s *Platform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *Platform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	return process.StopCRMService(ctx, cloudlet, process.HARoleAll)
}

func (s *Platform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	client := s.getClient()
	switch clusterInst.Deployment {
	case cloudcommon.DeploymentTypeDocker:
		// just going to use localhost
		return nil
	case cloudcommon.DeploymentTypeKubernetes:
		// create local k3d cluster
		name := clusterInst.Key.ClusterKey.Name
		cmd := "k3d cluster create " + name + " --kubeconfig-switch-context=false --kubeconfig-update-default=false"
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("%s failed: %s, %s", cmd, out, err)
		}
		kconf := k8smgmt.GetKconfName(clusterInst)
		cmd = "k3d kubeconfig get " + name + " > " + kconf
		out, err = client.Output(cmd)
		if err != nil {
			return fmt.Errorf("%s failed: %s, %s", cmd, out, err)
		}
		err = k8smgmt.WaitNodesReady(ctx, client, clusterInst, 1, time.Second, 30)
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("unsupported deployment")
}

func (s *Platform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *Platform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	client := s.getClient()
	switch clusterInst.Deployment {
	case cloudcommon.DeploymentTypeDocker:
		// just going to use localhost
		return nil
	case cloudcommon.DeploymentTypeKubernetes:
		// create local k3d cluster
		name := clusterInst.Key.ClusterKey.Name
		cmd := "k3d cluster delete " + name
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("%s failed: %s, %s", cmd, out, err)
		}
		kconf := k8smgmt.GetKconfName(clusterInst)
		err = pc.DeleteFile(client, kconf, pc.NoSudo)
		if err != nil {
			return fmt.Errorf("delete %s failed, %s", kconf, err)
		}
		return nil
	}
	return fmt.Errorf("unsupported deployment")
}

func (s *Platform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateSender edgeproto.AppInstInfoSender) (reterr error) {
	client := s.getClient()
	switch app.Deployment {
	case cloudcommon.DeploymentTypeDocker:
		// just going to use localhost
		return dockermgmt.CreateAppInst(ctx, s.platformConfig.AccessApi, client, app, appInst, dockermgmt.WithExposePorts(), dockermgmt.WithNoHostNetwork())
	case cloudcommon.DeploymentTypeKubernetes:
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return err
		}
		// create proxy for localhost access
		proxy := s.getAppInstProxy(clusterInst, appInst)
		logFile := client.WorkingDir + "/" + proxy.Name + ".log"
		err = proxy.StartLocal(logFile)
		if err != nil {
			return err
		}
		defer func() {
			if reterr != nil {
				proxy.StopLocal()
			}
		}()
		/*
			err = proxy.WaitStatus("running", 3*time.Second)
			if err != nil {
				return err
			}*/
		err = k8smgmt.CreateAppInst(ctx, s.platformConfig.AccessApi, client, names, app, appInst, &edgeproto.Flavor{})
		if err != nil {
			return err
		}
		defer func() {
			if reterr != nil {
				k8smgmt.DeleteAppInst(ctx, client, names, app, appInst)
			}
		}()
		return k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
	case cloudcommon.DeploymentTypeHelm:
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return err
		}
		return k8smgmt.CreateHelmAppInst(ctx, client, names, clusterInst, app, appInst)
	}
	return fmt.Errorf("unsupported deployment")
}

func (s *Platform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *Platform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	client := s.getClient()
	switch app.Deployment {
	case cloudcommon.DeploymentTypeDocker:
		// just going to use localhost
		return dockermgmt.DeleteAppInst(ctx, s.platformConfig.AccessApi, client, app, appInst, dockermgmt.WithStopTimeoutSecs(1))
	case cloudcommon.DeploymentTypeKubernetes:
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return err
		}
		proxy := s.getAppInstProxy(clusterInst, appInst)
		proxy.StopLocal()
		return k8smgmt.DeleteAppInst(ctx, client, names, app, appInst)
	case cloudcommon.DeploymentTypeHelm:
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return err
		}
		return k8smgmt.DeleteHelmAppInst(ctx, client, names, clusterInst)
	}
	return fmt.Errorf("unsupported deployment")
}

func (s *Platform) getAppInstProxy(clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst) *process.NginxProxy {
	// create proxy for localhost access
	clustName := clusterInst.Key.ClusterKey.Name
	proxy := &process.NginxProxy{
		DockerGeneric: process.DockerGeneric{
			Common: process.Common{
				Name: appInst.Key.Name + "-proxy",
			},
			DockerNetwork: "k3d-" + clustName,
		},
	}
	for _, port := range appInst.MappedPorts {
		proxy.Servers = append(proxy.Servers, process.NginxServerConfig{
			ServerName: fmt.Sprintf("%s-%d", appInst.Key.Name, port.InternalPort),
			Port:       fmt.Sprintf("%d", port.PublicPort),
			Target:     fmt.Sprintf("http://k3d-%s-server-0:%d", clustName, port.InternalPort),
		})
	}
	return proxy
}

func (s *Platform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	client := s.getClient()
	switch clusterInst.Deployment {
	case cloudcommon.DeploymentTypeDocker:
		// just going to use localhost
		return dockermgmt.GetAppInstRuntime(ctx, client, app, appInst)
	case cloudcommon.DeploymentTypeKubernetes:
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return nil, err
		}
		return k8smgmt.GetAppInstRuntime(ctx, client, names, app, appInst)
	}
	return nil, fmt.Errorf("unsupported deployment")
}

func (s *Platform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *Platform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *Platform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.DeploymentTypeHelm:
		return k8smgmt.GetContainerCommand(ctx, clusterInst, app, appInst, req)
	case cloudcommon.DeploymentTypeDocker:
		return dockermgmt.GetContainerCommand(clusterInst, app, appInst, req)
	case cloudcommon.DeploymentTypeVM:
		fallthrough
	default:
		return "", fmt.Errorf("unsupported deployment type %s", deployment)
	}
}
