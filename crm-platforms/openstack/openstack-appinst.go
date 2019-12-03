package openstack

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/dockermgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/nginx"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vmspec"
	v1 "k8s.io/api/core/v1"
)

func (s *Platform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, appFlavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	var err error

	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.AppDeploymentTypeHelm:
		rootLBName := s.rootLBName
		appWaitChan := make(chan string)

		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			rootLBName = cloudcommon.GetDedicatedLBFQDN(s.cloudletKey, &clusterInst.Key.ClusterKey)
			log.SpanLog(ctx, log.DebugLevelMexos, "using dedicated RootLB to create app", "rootLBName", rootLBName)
		}
		client, err := s.GetPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return err
		}
		updateCallback(edgeproto.UpdateTask, "Setting up registry secret")
		err = mexos.CreateDockerRegistrySecret(ctx, client, clusterInst, app, s.vaultConfig, names)
		if err != nil {
			return err
		}

		if deployment == cloudcommon.AppDeploymentTypeKubernetes {
			updateCallback(edgeproto.UpdateTask, "Creating Kubernetes App")
			err = k8smgmt.CreateAppInst(client, names, app, appInst)
		} else {
			updateCallback(edgeproto.UpdateTask, "Creating Helm App")

			err = k8smgmt.CreateHelmAppInst(client, names, clusterInst, app, appInst)
		}
		if err != nil {
			return err
		}

		// wait for the appinst in parallel with other tasks
		go func() {
			if deployment == cloudcommon.AppDeploymentTypeKubernetes {
				waitErr := k8smgmt.WaitForAppInst(client, names, app, k8smgmt.WaitRunning)
				if waitErr == nil {
					appWaitChan <- ""
				} else {
					appWaitChan <- waitErr.Error()
				}
			} else { // no waiting for the helm apps currently, to be revisited
				appWaitChan <- ""
			}
		}()

		// set up DNS
		var rootLBIPaddr string
		_, masterIP, err := mexos.GetMasterNameAndIP(ctx, clusterInst)
		if err == nil {
			rootLBIPaddr, err = mexos.GetServerIPAddr(ctx, mexos.GetCloudletExternalNetwork(), rootLBName, mexos.ExternalIPType)
			if err == nil {
				getDnsAction := func(svc v1.Service) (*mexos.DnsSvcAction, error) {
					action := mexos.DnsSvcAction{}
					action.PatchKube = true
					action.PatchIP = masterIP
					action.ExternalIP = rootLBIPaddr
					// Should only add DNS for external ports
					action.AddDNS = !app.InternalPorts
					return &action, nil
				}
				// If this is an internal ports, all we need is patch of kube service
				if app.InternalPorts {
					err = mexos.CreateAppDNS(ctx, client, names, getDnsAction)
				} else {
					updateCallback(edgeproto.UpdateTask, "Configuring Service: LB, Firewall Rules and DNS")
					err = mexos.AddProxySecurityRulesAndPatchDNS(ctx, client, names, appInst, getDnsAction, rootLBName, masterIP, true, nginx.WithDockerPublishPorts(), nginx.WithDockerNetwork(""))
				}
			}
		}
		appWaitErr := <-appWaitChan
		if appWaitErr != "" {
			return fmt.Errorf("app wait error, %v", appWaitErr)
		}
		if err != nil {
			return err
		}
	case cloudcommon.AppDeploymentTypeVM:
		imageName, err := cloudcommon.GetFileName(app.ImagePath)
		if err != nil {
			return err
		}
		sourceImageTime, md5Sum, err := mexos.GetUrlInfo(ctx, app.ImagePath)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMexos, "failed to fetch source image info, skip image validity checks")
		}
		imageDetail, err := mexos.GetImageDetail(ctx, imageName)
		createImage := false
		if err != nil {
			if strings.Contains(err.Error(), "Could not find resource") {
				// Add image to Glance
				log.SpanLog(ctx, log.DebugLevelMexos, "image is not present in glance, add image")
				createImage = true
			} else {
				return err
			}
		} else {
			if imageDetail.Status != "active" {
				return fmt.Errorf("image in store %s is not active", imageName)
			}
			if imageDetail.Checksum != md5Sum {
				return fmt.Errorf("mismatch in md5sum")
			}
			glanceImageTime, err := time.Parse(time.RFC3339, imageDetail.UpdatedAt)
			if err != nil {
				return err
			}
			if !sourceImageTime.IsZero() {
				if sourceImageTime.Sub(glanceImageTime) > 0 {
					// Update the image in Glance
					updateCallback(edgeproto.UpdateTask, "Image in store is outdated, deleting old image")
					err = mexos.DeleteImage(ctx, imageName)
					if err != nil {
						return err
					}
					createImage = true
				}
			}
		}
		if createImage {
			updateCallback(edgeproto.UpdateTask, "Creating VM Image from URL")
			err = mexos.CreateImageFromUrl(ctx, imageName, app.ImagePath, md5Sum)
			if err != nil {
				return err
			}
		}

		finfo, _, _, err := mexos.GetFlavorInfo(ctx)
		if err != nil {
			return err
		}
		vmspec, err := vmspec.GetVMSpec(finfo, *appFlavor)
		if err != nil {
			return fmt.Errorf("unable to find closest flavor for app: %v", err)
		}
		objName := cloudcommon.GetAppFQN(&app.Key)
		vmp, err := mexos.GetVMParams(ctx,
			mexos.UserVMDeployment,
			objName,
			vmspec.FlavorName,
			vmspec.ExternalVolumeSize,
			imageName,
			mexos.GetSecurityGroupName(ctx, objName),
			&clusterInst.Key.CloudletKey,
			mexos.WithPublicKey(app.AuthPublicKey),
			mexos.WithAccessPorts(app.AccessPorts),
			mexos.WithDeploymentManifest(app.DeploymentManifest),
			mexos.WithCommand(app.Command),
		)

		if err != nil {
			return fmt.Errorf("unable to get vm params: %v", err)
		}
		updateCallback(edgeproto.UpdateTask, "Deploying VM")
		log.SpanLog(ctx, log.DebugLevelMexos, "Deploying VM", "stackName", objName, "vmspec", vmspec)
		err = mexos.CreateHeatStackFromTemplate(ctx, vmp, objName, mexos.VmTemplate, updateCallback)
		if err != nil {
			return err
		}
		external_ip, err := mexos.GetServerIPAddr(ctx, mexos.GetCloudletExternalNetwork(), objName, mexos.ExternalIPType)
		if err != nil {
			return err
		}
		if appInst.Uri != "" && external_ip != "" {
			fqdn := appInst.Uri
			if err = mexos.ActivateFQDNA(ctx, fqdn, external_ip); err != nil {
				return err
			}
			log.SpanLog(ctx, log.DebugLevelMexos, "DNS A record activated",
				"name", objName,
				"fqdn", fqdn,
				"IP", external_ip)
		}
		return nil
	case cloudcommon.AppDeploymentTypeDocker:
		rootLBName := s.rootLBName
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			rootLBName = cloudcommon.GetDedicatedLBFQDN(s.cloudletKey, &clusterInst.Key.ClusterKey)
			log.SpanLog(ctx, log.DebugLevelMexos, "using dedicated RootLB to create app", "rootLBName", rootLBName)
		}
		client, err := s.GetPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		rootLBIPaddr, err := mexos.GetServerIPAddr(ctx, mexos.GetCloudletExternalNetwork(), rootLBName, mexos.ExternalIPType)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return fmt.Errorf("get kube names failed, %v", err)
		}
		updateCallback(edgeproto.UpdateTask, "Seeding docker secret")
		err = mexos.SeedDockerSecret(ctx, client, clusterInst, app, s.vaultConfig)
		if err != nil {
			return fmt.Errorf("seeding docker secret failed, %v", err)
		}
		updateCallback(edgeproto.UpdateTask, "Deploying Docker App")
		err = dockermgmt.CreateAppInst(ctx, client, app, appInst)
		if err != nil {
			return err
		}
		getDnsAction := func(svc v1.Service) (*mexos.DnsSvcAction, error) {
			action := mexos.DnsSvcAction{}
			action.PatchKube = false
			action.ExternalIP = rootLBIPaddr
			return &action, nil
		}
		updateCallback(edgeproto.UpdateTask, "Configuring Firewall Rules and DNS")
		err = mexos.AddProxySecurityRulesAndPatchDNS(ctx, client, names, appInst, getDnsAction, rootLBName, rootLBIPaddr, false)
		if err != nil {
			return fmt.Errorf("AddProxySecurityRulesAndPatchDNS error: %v", err)
		}
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	return err
}

func (s *Platform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) error {

	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.AppDeploymentTypeHelm:
		rootLBName := s.rootLBName
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			rootLBName = cloudcommon.GetDedicatedLBFQDN(s.cloudletKey, &clusterInst.Key.ClusterKey)
			log.SpanLog(ctx, log.DebugLevelMexos, "using dedicated RootLB to delete app", "rootLBName", rootLBName)
			_, err := mexos.GetServerDetails(ctx, rootLBName)
			if err != nil {
				if strings.Contains(err.Error(), "No server with a name or ID") {
					log.SpanLog(ctx, log.DebugLevelMexos, "Dedicated RootLB is gone, allow app deletion")
					return nil
				}
				return err
			}
		}
		client, err := s.GetPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return fmt.Errorf("get kube names failed: %s", err)
		}
		_, _, err = mexos.GetMasterNameAndIP(ctx, clusterInst)
		if err != nil {
			if strings.Contains(err.Error(), mexos.ClusterNotFoundErr) {
				log.SpanLog(ctx, log.DebugLevelMexos, "cluster is gone, allow app deletion")
				return nil
			}
			return err
		} // Clean up security rules and nginx proxy if app is external
		secGrp := mexos.GetSecurityGroupName(ctx, rootLBName)
		if !app.InternalPorts {
			if err := mexos.DeleteProxySecurityGroupRules(ctx, client, names.AppName, secGrp, appInst.MappedPorts, rootLBName); err != nil {
				log.SpanLog(ctx, log.DebugLevelMexos, "cannot delete security rules", "name", names.AppName, "rootlb", rootLBName, "error", err)
			}
			// Clean up DNS entries
			if err := mexos.DeleteAppDNS(ctx, client, names); err != nil {
				log.SpanLog(ctx, log.DebugLevelMexos, "cannot clean up DNS entries", "name", names.AppName, "rootlb", rootLBName, "error", err)
			}
		}

		if deployment == cloudcommon.AppDeploymentTypeKubernetes {
			return k8smgmt.DeleteAppInst(client, names, app, appInst)
		} else {
			return k8smgmt.DeleteHelmAppInst(client, names, clusterInst)
		}

	case cloudcommon.AppDeploymentTypeVM:
		objName := cloudcommon.GetAppFQN(&app.Key)
		log.SpanLog(ctx, log.DebugLevelMexos, "Deleting VM", "stackName", objName)
		err := mexos.HeatDeleteStack(ctx, objName)
		if err != nil {
			return fmt.Errorf("DeleteVMAppInst error: %v", err)
		}
		return nil
	case cloudcommon.AppDeploymentTypeDocker:
		rootLBName := cloudcommon.GetDedicatedLBFQDN(s.cloudletKey, &clusterInst.Key.ClusterKey)
		_, err := mexos.GetServerDetails(ctx, rootLBName)
		if err != nil {
			if strings.Contains(err.Error(), "No server with a name or ID") {
				log.SpanLog(ctx, log.DebugLevelMexos, "Dedicated RootLB is gone, allow app deletion")
				return nil
			}
			return err
		}
		client, err := s.GetPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		appName := k8smgmt.NormalizeName(app.Key.Name)
		if !app.InternalPorts {
			secGrp := mexos.GetSecurityGroupName(ctx, rootLBName)
			//  the proxy does not yet exist for docker, but it eventually will.  Secgrp rules should be deleted in either case
			if err := mexos.DeleteProxySecurityGroupRules(ctx, client, appName, secGrp, appInst.MappedPorts, rootLBName); err != nil {
				log.SpanLog(ctx, log.DebugLevelMexos, "cannot delete security rules", "name", appName, "rootlb", rootLBName, "error", err)
			}
		}
		return dockermgmt.DeleteAppInst(ctx, client, app, appInst)
	default:
		return fmt.Errorf("unsupported deployment type %s", deployment)
	}
}

func (s *Platform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
		client, err := s.GetPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return fmt.Errorf("get kube names failed: %s", err)
		}
		return k8smgmt.UpdateAppInst(client, names, app, appInst)
	case cloudcommon.AppDeploymentTypeDocker:
		client, err := s.GetPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		return dockermgmt.UpdateAppInst(ctx, client, app, appInst)
	case cloudcommon.AppDeploymentTypeHelm:
		client, err := s.GetPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return fmt.Errorf("get kube names failed: %s", err)
		}
		return k8smgmt.UpdateHelmAppInst(client, names, app, appInst)

	default:
		return fmt.Errorf("UpdateAppInst not supported for deployment: %s", app.Deployment)
	}
}

func (s *Platform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {

	client, err := s.GetPlatformClient(ctx, clusterInst)
	if err != nil {
		return nil, err
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.AppDeploymentTypeHelm:
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return nil, err
		}
		return k8smgmt.GetAppInstRuntime(client, names, app, appInst)
	case cloudcommon.AppDeploymentTypeDocker:
		return dockermgmt.GetAppInstRuntime(client, app, appInst)
	case cloudcommon.AppDeploymentTypeVM:
		fallthrough
	default:
		return nil, fmt.Errorf("unsupported deployment type %s", deployment)
	}
}

func (s *Platform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.AppDeploymentTypeHelm:
		return k8smgmt.GetContainerCommand(clusterInst, app, appInst, req)
	case cloudcommon.AppDeploymentTypeDocker:
		return dockermgmt.GetContainerCommand(clusterInst, app, appInst, req)
	case cloudcommon.AppDeploymentTypeVM:
		fallthrough
	default:
		return "", fmt.Errorf("unsupported deployment type %s", deployment)
	}
}

func (s *Platform) GetConsoleUrl(ctx context.Context, app *edgeproto.App) (string, error) {
	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeVM:
		objName := cloudcommon.GetAppFQN(&app.Key)
		consoleUrl, err := mexos.OSGetConsoleUrl(ctx, objName)
		if err != nil {
			return "", err
		}
		return consoleUrl.Url, nil
	default:
		return "", fmt.Errorf("unsupported deployment type %s", deployment)
	}
}
