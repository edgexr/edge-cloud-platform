package azure

import (
	"context"
	"fmt"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	v1 "k8s.io/api/core/v1"
)

func (a *AzurePlatform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "Creating AppInst")

	var err error
	// regenerate kconf if missing because CRM in container was restarted
	if err = a.SetupKconf(ctx, clusterInst); err != nil {
		return fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := a.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Creating Registry Secret")

	for _, imagePath := range names.ImagePaths {
		err = infracommon.CreateDockerRegistrySecret(ctx, client, clusterInst, imagePath, a.commonPf.VaultConfig, names)
		if err != nil {
			return err
		}
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		err = k8smgmt.CreateAppInst(ctx, a.commonPf.VaultConfig, client, names, app, appInst)
		if err == nil {
			updateCallback(edgeproto.UpdateTask, "Waiting for AppInst to Start")

			err = k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
		}
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Waiting for Load Balancer External IP")

	// set up dns
	getDnsAction := func(svc v1.Service) (*infracommon.DnsSvcAction, error) {
		action := infracommon.DnsSvcAction{}
		externalIP, err := infracommon.GetSvcExternalIP(ctx, client, names, svc.ObjectMeta.Name)
		if err != nil {
			return nil, err
		}
		action.ExternalIP = externalIP
		// no patching needed since Azure already does it.
		// Should only add DNS for external ports
		action.AddDNS = !app.InternalPorts
		return &action, nil
	}
	err = a.commonPf.CreateAppDNSAndPatchKubeSvc(ctx, client, names, infracommon.NoDnsOverride, getDnsAction)
	if err != nil {
		return nil
	}
	return nil
}

func (a *AzurePlatform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	var err error
	// regenerate kconf if missing because CRM in container was restarted
	if err = a.SetupKconf(ctx, clusterInst); err != nil {
		return fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := a.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		err = k8smgmt.DeleteAppInst(ctx, client, names, app, appInst)
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	if err != nil {
		return err
	}
	// No DNS entry if ports are internal
	if app.InternalPorts {
		return nil
	}
	return a.commonPf.DeleteAppDNS(ctx, client, names, infracommon.NoDnsOverride)
}

func (a *AzurePlatform) SetupKconf(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	targetFile := infracommon.GetLocalKconfName(clusterInst)
	if _, err := os.Stat(targetFile); err == nil {
		// already exists
		return nil
	}
	if err := a.AzureLogin(ctx); err != nil {
		return err
	}
	clusterName := AzureSanitize(clusterInst.Key.ClusterKey.Name)
	rg := GetResourceGroupForCluster(clusterInst)
	if err := GetAKSCredentials(rg, clusterName); err != nil {
		return fmt.Errorf("unable to get AKS credentials %v", err)
	}
	src := infracommon.DefaultKubeconfig()
	if err := infracommon.CopyFile(src, targetFile); err != nil {
		return fmt.Errorf("can't copy %s, %v", src, err)
	}
	return nil
}

func (s *AzurePlatform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	// regenerate kconf if missing because CRM in container was restarted
	if err := s.SetupKconf(ctx, clusterInst); err != nil {
		return nil, fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := s.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return nil, err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return nil, err
	}
	return k8smgmt.GetAppInstRuntime(ctx, client, names, app, appInst)
}

func (a *AzurePlatform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "Updating Azure AppInst")
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	client, err := a.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}

	err = k8smgmt.UpdateAppInst(ctx, a.commonPf.VaultConfig, client, names, app, appInst)
	if err == nil {
		updateCallback(edgeproto.UpdateTask, "Waiting for AppInst to Start")
		err = k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
	}
	return err
}

func (a *AzurePlatform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return k8smgmt.GetContainerCommand(ctx, clusterInst, app, appInst, req)
}

func (a *AzurePlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App) (string, error) {
	return "", fmt.Errorf("Unsupported command for platform")
}

func (a *AzurePlatform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Unsupported command for platform")
}
