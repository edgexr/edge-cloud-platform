package edgebox

import (
	"context"
	"fmt"
	"net"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/dind"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	v1 "k8s.io/api/core/v1"
)

func (e *EdgeboxPlatform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	client, err := e.generic.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}

	externalIP, err := e.GetDINDServiceIP(ctx)
	if err != nil {
		return fmt.Errorf("init cannot get service ip, %s", err.Error())
	}
	// Should only add DNS for external ports
	mappedAddr := e.commonPf.GetMappedExternalIP(externalIP)
	// Use IP address as AppInst URI, so that we can avoid using Cloudflare for Edgebox
	appInst.Uri = mappedAddr

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	names.IsUriIPAddr = true
	// Setup secrets only for K8s app. For docker, we already do it as part of edgebox script
	// Use secrets from env-var as we already have console creds, which limits user to access its own org images
	dockerUser, dockerPass := e.GetEdgeboxDockerCreds()
	existingCreds := cloudcommon.RegistryAuth{}
	existingCreds.AuthType = cloudcommon.BasicAuth
	existingCreds.Username = dockerUser
	existingCreds.Password = dockerPass
	if app.Deployment != cloudcommon.DeploymentTypeDocker {
		for _, imagePath := range names.ImagePaths {
			err = infracommon.CreateDockerRegistrySecret(ctx, client, k8smgmt.GetKconfName(clusterInst), imagePath, e.commonPf.PlatformConfig.AccessApi, names, &existingCreds)
			if err != nil {
				return err
			}
		}
	}

	// Use generic DIND to create the AppInst
	err = e.generic.CreateAppInstNoPatch(ctx, clusterInst, app, appInst, flavor, updateCallback)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot create app", "error", err)
		return err
	}

	// The rest is k8s specific
	if clusterInst.Deployment != cloudcommon.DeploymentTypeKubernetes {
		return nil
	}

	// set up DNS
	cluster, err := dind.FindCluster(names.ClusterName)
	if err != nil {
		e.generic.DeleteAppInst(ctx, clusterInst, app, appInst, updateCallback)
		return err
	}
	masterIP := cluster.MasterAddr
	getDnsAction := func(svc v1.Service) (*infracommon.DnsSvcAction, error) {
		action := infracommon.DnsSvcAction{}

		if len(svc.Spec.ExternalIPs) > 0 && svc.Spec.ExternalIPs[0] == masterIP {
			log.SpanLog(ctx, log.DebugLevelInfra, "external IP already present in DIND, no patch required", "addr", masterIP)
		} else {
			action.PatchKube = true
			action.PatchIP = masterIP
		}
		if err != nil {
			return nil, err
		}
		action.ExternalIP = externalIP
		// use custom DNS mapping, and hence not create cloudflare entries
		action.AddDNS = false
		return &action, nil
	}
	if err = e.commonPf.CreateAppDNSAndPatchKubeSvc(ctx, client, names, infracommon.NoDnsOverride, getDnsAction); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot add DNS entries", "error", err)
		e.generic.DeleteAppInst(ctx, clusterInst, app, appInst, updateCallback)
		return err
	}
	return nil
}

func (e *EdgeboxPlatform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	if err := e.generic.DeleteAppInst(ctx, clusterInst, app, appInst, updateCallback); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "warning, cannot delete AppInst", "error", err)
		return err
	}
	return nil
}

func (e *EdgeboxPlatform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateAppInst", "appInst", appInst)

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	client, err := e.generic.GetClient(ctx)
	if err != nil {
		return err
	}
	if app.Deployment == cloudcommon.DeploymentTypeKubernetes || app.Deployment == cloudcommon.DeploymentTypeHelm {
		// Use secrets from env-var as we already have console creds, which limits user to access its own org images
		dockerUser, dockerPass := e.GetEdgeboxDockerCreds()
		existingCreds := cloudcommon.RegistryAuth{}
		existingCreds.Username = dockerUser
		existingCreds.Password = dockerPass
		kconf := k8smgmt.GetKconfName(clusterInst)
		for _, imagePath := range names.ImagePaths {
			// secret may have changed, so delete and re-create
			err = infracommon.DeleteDockerRegistrySecret(ctx, client, kconf, imagePath, e.commonPf.PlatformConfig.AccessApi, names, &existingCreds)
			if err != nil {
				return err
			}
			err = infracommon.CreateDockerRegistrySecret(ctx, client, kconf, imagePath, e.commonPf.PlatformConfig.AccessApi, names, &existingCreds)
			if err != nil {
				return err
			}
		}
	}

	err = e.generic.UpdateAppInst(ctx, clusterInst, app, appInst, updateCallback)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error updating appinst", "error", err)
		return err
	}
	return nil
}

func (e *EdgeboxPlatform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	return e.generic.GetAppInstRuntime(ctx, clusterInst, app, appInst)
}

func (e *EdgeboxPlatform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return e.generic.GetContainerCommand(ctx, clusterInst, app, appInst, req)
}

func (e *EdgeboxPlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App) (string, error) {
	return e.generic.GetConsoleUrl(ctx, app)
}

func (e *EdgeboxPlatform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return e.generic.SetPowerState(ctx, app, appInst, updateCallback)
}

// GetDINDServiceIP depending on the type of DIND cluster will return either the interface or external address
func (e *EdgeboxPlatform) GetDINDServiceIP(ctx context.Context) (string, error) {
	if e.NetworkScheme == cloudcommon.NetworkSchemePrivateIP {
		return GetLocalAddr()
	}
	return infracommon.GetExternalPublicAddr(ctx)
}

// GetLocalAddr gets the IP address the machine uses for outbound comms
func GetLocalAddr() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}
