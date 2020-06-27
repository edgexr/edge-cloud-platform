package gcp

import (
	"context"
	"fmt"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"

	v1 "k8s.io/api/core/v1"
)

func (g *GCPPlatform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	var err error
	// regenerate kconf if missing because CRM in container was restarted
	if err = SetupKconf(ctx, clusterInst); err != nil {
		return fmt.Errorf("can't set up kconf, %s", err.Error())
	}

	client, err := g.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	for _, imagePath := range names.ImagePaths {
		err = infracommon.CreateDockerRegistrySecret(ctx, client, clusterInst, imagePath, g.commonPf.VaultConfig, names)
		if err != nil {
			return err
		}
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		err = k8smgmt.CreateAppInst(ctx, g.commonPf.VaultConfig, client, names, app, appInst)
		if err == nil {
			err = k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
		}
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	if err != nil {
		return err
	}

	// set up dns
	getDnsAction := func(svc v1.Service) (*infracommon.DnsSvcAction, error) {
		action := infracommon.DnsSvcAction{}
		externalIP, err := infracommon.GetSvcExternalIP(ctx, client, names, svc.ObjectMeta.Name)
		if err != nil {
			return nil, err
		}
		action.ExternalIP = externalIP
		// no patching needed since GCP already does it.
		// Should only add DNS for external ports
		action.AddDNS = !app.InternalPorts
		return &action, nil
	}
	if err = g.commonPf.CreateAppDNSAndPatchKubeSvc(ctx, client, names, infracommon.NoDnsOverride, getDnsAction); err != nil {
		return err
	}
	return nil
}

func (g *GCPPlatform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	// regenerate kconf if missing because CRM in container was restarted
	if err := SetupKconf(ctx, clusterInst); err != nil {
		return fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := g.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
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
	return g.commonPf.DeleteAppDNS(ctx, client, names, infracommon.NoDnsOverride)
}

func SetupKconf(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	targetFile := k8smgmt.GetKconfName(clusterInst)
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupKconf", "targetFile", targetFile)

	if _, err := os.Stat(targetFile); err == nil {
		// already exists
		return nil
	}
	clusterName := clusterInst.Key.ClusterKey.Name
	if err := GetGKECredentials(clusterName); err != nil {
		return fmt.Errorf("unable to get GKE credentials %v", err)
	}
	src := infracommon.DefaultKubeconfig()
	if err := infracommon.CopyFile(src, targetFile); err != nil {
		return fmt.Errorf("can't copy %s, %v", src, err)
	}
	return nil
}

func (g *GCPPlatform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "Updating GCP AppInst")
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	client, err := g.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}

	err = k8smgmt.UpdateAppInst(ctx, g.commonPf.VaultConfig, client, names, app, appInst)
	if err == nil {
		updateCallback(edgeproto.UpdateTask, "Waiting for AppInst to Start")
		err = k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
	}
	return err
}

func (g *GCPPlatform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	// regenerate kconf if missing because CRM in container was restarted
	if err := SetupKconf(ctx, clusterInst); err != nil {
		return nil, fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := g.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return nil, err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return nil, err
	}
	return k8smgmt.GetAppInstRuntime(ctx, client, names, app, appInst)
}

func (g *GCPPlatform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return k8smgmt.GetContainerCommand(ctx, clusterInst, app, appInst, req)
}

func (g *GCPPlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App) (string, error) {
	return "", fmt.Errorf("Unsupported command for platform")
}

func (g *GCPPlatform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Unsupported command for platform")
}
