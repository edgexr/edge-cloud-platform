package azure

import (
	"context"
	"fmt"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	v1 "k8s.io/api/core/v1"
)

func (s *Platform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "Creating AppInst")

	var err error
	// regenerate kconf if missing because CRM in container was restarted
	if err = s.SetupKconf(ctx, clusterInst); err != nil {
		return fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := s.GetPlatformClient(ctx, clusterInst)
	if err != nil {
		return err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Creating Registry Secret")

	err = mexos.CreateDockerRegistrySecret(ctx, client, clusterInst, app, s.vaultConfig, names)
	if err != nil {
		return err
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
		err = k8smgmt.CreateAppInst(ctx, client, names, app, appInst)
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
	getDnsAction := func(svc v1.Service) (*mexos.DnsSvcAction, error) {
		action := mexos.DnsSvcAction{}
		externalIP, err := mexos.GetSvcExternalIP(ctx, client, names, svc.ObjectMeta.Name)
		if err != nil {
			return nil, err
		}
		action.ExternalIP = externalIP
		// no patching needed since Azure already does it.
		// Should only add DNS for external ports
		action.AddDNS = !app.InternalPorts
		return &action, nil
	}
	err = mexos.CreateAppDNS(ctx, client, names, mexos.NoDnsOverride, getDnsAction)
	if err != nil {
		return nil
	}
	return nil
}

func (s *Platform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	var err error
	// regenerate kconf if missing because CRM in container was restarted
	if err = s.SetupKconf(ctx, clusterInst); err != nil {
		return fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := s.GetPlatformClient(ctx, clusterInst)
	if err != nil {
		return err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
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
	return mexos.DeleteAppDNS(ctx, client, names, mexos.NoDnsOverride)
}

func (s *Platform) SetupKconf(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	targetFile := mexos.GetLocalKconfName(clusterInst)
	if _, err := os.Stat(targetFile); err == nil {
		// already exists
		return nil
	}
	if err := s.AzureLogin(ctx); err != nil {
		return err
	}
	clusterName := AzureSanitize(clusterInst.Key.ClusterKey.Name)
	rg := GetResourceGroupForCluster(clusterInst)
	if err := GetAKSCredentials(rg, clusterName); err != nil {
		return fmt.Errorf("unable to get AKS credentials %v", err)
	}
	src := mexos.DefaultKubeconfig()
	if err := mexos.CopyFile(src, targetFile); err != nil {
		return fmt.Errorf("can't copy %s, %v", src, err)
	}
	return nil
}

func (s *Platform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	// regenerate kconf if missing because CRM in container was restarted
	if err := s.SetupKconf(ctx, clusterInst); err != nil {
		return nil, fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := s.GetPlatformClient(ctx, clusterInst)
	if err != nil {
		return nil, err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return nil, err
	}
	return k8smgmt.GetAppInstRuntime(ctx, client, names, app, appInst)
}

func (s *Platform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "Updating Azure AppInst")
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	client, err := s.GetPlatformClient(ctx, clusterInst)
	if err != nil {
		return err
	}

	err = k8smgmt.UpdateAppInst(ctx, client, names, app, appInst)
	if err == nil {
		updateCallback(edgeproto.UpdateTask, "Waiting for AppInst to Start")
		err = k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
	}
	return err
}

func (s *Platform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return k8smgmt.GetContainerCommand(ctx, clusterInst, app, appInst, req)
}

func (s *Platform) GetConsoleUrl(ctx context.Context, app *edgeproto.App) (string, error) {
	return "", fmt.Errorf("Unsupported command for platform")
}
