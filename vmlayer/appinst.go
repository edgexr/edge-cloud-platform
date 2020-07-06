package vmlayer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"

	"github.com/mobiledgex/edge-cloud-infra/chefmgmt"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/access"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/crmutil"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/dockermgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	"github.com/mobiledgex/edge-cloud/vault"

	v1 "k8s.io/api/core/v1"
)

var MaxDockerSeedWait = 1 * time.Minute

type ProxyDnsSecOpts struct {
	AddProxy              bool
	AddDnsAndPatchKubeSvc bool
	AddSecurityRules      bool
}

type vmAppOrchValues struct {
	lbName             string
	externalServerName string
	vmgp               *VMGroupOrchestrationParams
	newSubnetName      string
}

func (v *VMPlatform) PerformOrchestrationForVMApp(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, privacyPolicy *edgeproto.PrivacyPolicy, action ActionType, updateCallback edgeproto.CacheUpdateCallback) (*vmAppOrchValues, error) {
	var orchVals vmAppOrchValues

	imageName, err := cloudcommon.GetFileName(app.ImagePath)
	if err != nil {
		return &orchVals, err
	}

	if action == ActionCreate {
		err = v.VMProvider.AddAppImageIfNotPresent(ctx, app, appInst.Flavor.Name, updateCallback)
		if err != nil {
			return &orchVals, err
		}
	}

	objName := cloudcommon.GetAppFQN(&app.Key)
	usesLb := app.AccessType == edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER

	deploymentVars := crmutil.DeploymentReplaceVars{
		Deployment: crmutil.CrmReplaceVars{
			CloudletName: k8smgmt.NormalizeName(appInst.Key.ClusterInstKey.CloudletKey.Name),
			CloudletOrg:  k8smgmt.NormalizeName(appInst.Key.ClusterInstKey.CloudletKey.Organization),
			AppOrg:       k8smgmt.NormalizeName(app.Key.Organization),
			DnsZone:      v.VMProperties.CommonPf.GetCloudletDNSZone(),
		},
	}
	ctx = context.WithValue(ctx, crmutil.DeploymentReplaceVarsKey, &deploymentVars)

	// whether the app vm needs to connect to internal or external networks
	// depends on whether it has an LB
	appConnectsExternal := !usesLb
	var vms []*VMRequestSpec
	orchVals.externalServerName = objName

	if usesLb {
		orchVals.lbName = cloudcommon.GetVMAppFQDN(&appInst.Key, &appInst.Key.ClusterInstKey.CloudletKey, v.VMProperties.CommonPf.PlatformConfig.AppDNSRoot)
		orchVals.externalServerName = orchVals.lbName
		orchVals.newSubnetName = objName + "-subnet"
		tags := v.GetChefClusterTags(&appInst.Key.ClusterInstKey, VMTypeRootLB)
		lbVm, err := v.GetVMSpecForRootLB(ctx, orchVals.lbName, orchVals.newSubnetName, tags, updateCallback)
		if err != nil {
			return &orchVals, err
		}
		vms = append(vms, lbVm)
	}

	appVm, err := v.GetVMRequestSpec(
		ctx,
		VMTypeAppVM,
		objName,
		appInst.VmFlavor,
		imageName,
		appConnectsExternal,
		WithComputeAvailabilityZone(appInst.AvailabilityZone),
		WithExternalVolume(appInst.ExternalVolumeSize),
		WithSubnetConnection(orchVals.newSubnetName),
		WithDeploymentManifest(app.DeploymentManifest),
		WithCommand(app.Command),
		WithImageFolder(cloudcommon.GetAppFQN(&app.Key)),
	)
	if err != nil {
		return &orchVals, err
	}
	vms = append(vms, appVm)
	updateCallback(edgeproto.UpdateTask, "Deploying App")
	vmgp, err := v.OrchestrateVMsFromVMSpec(ctx, objName, vms, action, updateCallback, WithNewSubnet(orchVals.newSubnetName),
		WithPrivacyPolicy(privacyPolicy),
		WithAccessPorts(app.AccessPorts),
		WithNewSecurityGroup(v.GetServerSecurityGroupName(orchVals.externalServerName)),
	)
	if err != nil {
		return &orchVals, err
	}
	orchVals.vmgp = vmgp
	return &orchVals, nil
}

func (v *VMPlatform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, appFlavor *edgeproto.Flavor, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback) error {

	var err error
	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.DeploymentTypeHelm:
		rootLBName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
		appWaitChan := make(chan string)

		client, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return err
		}
		updateCallback(edgeproto.UpdateTask, "Setting up registry secret")
		for _, imagePath := range names.ImagePaths {
			err = infracommon.CreateDockerRegistrySecret(ctx, client, clusterInst, imagePath, v.VMProperties.CommonPf.VaultConfig, names)
			if err != nil {
				return err
			}
		}
		masterIP, masterIpErr := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
		// Add crm local replace variables
		if masterIpErr != nil {
			return masterIpErr
		}
		deploymentVars := crmutil.DeploymentReplaceVars{
			Deployment: crmutil.CrmReplaceVars{
				ClusterIp:    masterIP.ExternalAddr,
				CloudletName: k8smgmt.NormalizeName(clusterInst.Key.CloudletKey.Name),
				ClusterName:  k8smgmt.NormalizeName(clusterInst.Key.ClusterKey.Name),
				CloudletOrg:  k8smgmt.NormalizeName(clusterInst.Key.CloudletKey.Organization),
				AppOrg:       k8smgmt.NormalizeName(app.Key.Organization),
				DnsZone:      v.VMProperties.CommonPf.GetCloudletDNSZone(),
			},
		}
		ctx = context.WithValue(ctx, crmutil.DeploymentReplaceVarsKey, &deploymentVars)

		if deployment == cloudcommon.DeploymentTypeKubernetes {
			updateCallback(edgeproto.UpdateTask, "Creating Kubernetes App")
			err = k8smgmt.CreateAppInst(ctx, v.VMProperties.CommonPf.VaultConfig, client, names, app, appInst)
		} else {
			updateCallback(edgeproto.UpdateTask, "Creating Helm App")

			err = k8smgmt.CreateHelmAppInst(ctx, client, names, clusterInst, app, appInst)
		}
		if err != nil {
			return err
		}

		// wait for the appinst in parallel with other tasks
		go func() {
			if deployment == cloudcommon.DeploymentTypeKubernetes {
				waitErr := k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
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
		var rootLBIPaddr *ServerIP
		rootLBIPaddr, err = v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletExternalNetwork(), "", rootLBName)
		if err == nil {
			getDnsAction := func(svc v1.Service) (*infracommon.DnsSvcAction, error) {
				action := infracommon.DnsSvcAction{}
				action.PatchKube = true
				action.PatchIP = masterIP.ExternalAddr
				action.ExternalIP = rootLBIPaddr.ExternalAddr
				// Should only add DNS for external ports
				action.AddDNS = !app.InternalPorts
				return &action, nil
			}
			// If this is an internal ports, all we need is patch of kube service
			if app.InternalPorts {
				err = v.VMProperties.CommonPf.CreateAppDNSAndPatchKubeSvc(ctx, client, names, infracommon.NoDnsOverride, getDnsAction)
			} else {
				updateCallback(edgeproto.UpdateTask, "Configuring Service: LB, Firewall Rules and DNS")
				ops := ProxyDnsSecOpts{AddProxy: true, AddDnsAndPatchKubeSvc: true, AddSecurityRules: true}
				err = v.AddProxySecurityRulesAndPatchDNS(ctx, client, names, app, appInst, getDnsAction, rootLBName, cloudcommon.IPAddrAllInterfaces, masterIP.ExternalAddr, ops, proxy.WithDockerPublishPorts(), proxy.WithDockerNetwork(""))
			}
		}

		appWaitErr := <-appWaitChan
		if appWaitErr != "" {
			return fmt.Errorf("app wait error, %v", appWaitErr)
		}
		if err != nil {
			return err
		}
	case cloudcommon.DeploymentTypeVM:
		objName := cloudcommon.GetAppFQN(&app.Key)
		orchVals, err := v.PerformOrchestrationForVMApp(ctx, app, appInst, privacyPolicy, ActionCreate, updateCallback)
		if err != nil {
			return err
		}
		ip, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletExternalNetwork(), "", orchVals.externalServerName)
		if err != nil {
			return err
		}
		if app.AccessType == edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
			updateCallback(edgeproto.UpdateTask, "Setting Up Load Balancer")
			_, err := v.NewRootLB(ctx, orchVals.lbName)
			if err != nil {
				// likely already exists which means something went really wrong
				return err
			}
			err = v.SetupRootLB(ctx, orchVals.lbName, &clusterInst.Key.CloudletKey, updateCallback)
			if err != nil {
				return err
			}
			var proxyOps []proxy.Op
			client, err := v.GetSSHClientForServer(ctx, orchVals.externalServerName, v.VMProperties.GetCloudletExternalNetwork())
			if err != nil {
				return err
			}
			// clusterInst is empty but that is ok here
			names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
			if err != nil {
				return fmt.Errorf("get kube names failed: %s", err)
			}
			proxyOps = append(proxyOps, proxy.WithDockerPublishPorts(), proxy.WithDockerNetwork(""))
			getDnsAction := func(svc v1.Service) (*infracommon.DnsSvcAction, error) {
				action := infracommon.DnsSvcAction{}
				action.PatchKube = false
				action.ExternalIP = ip.ExternalAddr
				return &action, nil
			}
			vmIP, err := v.GetIPFromServerName(ctx, "", orchVals.newSubnetName, objName)
			if err != nil {
				return err
			}
			updateCallback(edgeproto.UpdateTask, "Configuring Firewall Rules")
			ops := ProxyDnsSecOpts{AddProxy: true, AddDnsAndPatchKubeSvc: false, AddSecurityRules: false}
			err = v.AddProxySecurityRulesAndPatchDNS(ctx, client, names, app, appInst, getDnsAction, orchVals.externalServerName, cloudcommon.IPAddrAllInterfaces, vmIP.ExternalAddr, ops, proxyOps...)
			if err != nil {
				return fmt.Errorf("AddProxySecurityRulesAndPatchDNS error: %v", err)
			}

			if v.VMProperties.GetCloudletExternalRouter() == NoExternalRouter {
				log.SpanLog(ctx, log.DebugLevelInfra, "Need to attach internal interface on rootlb")

				// after vm creation, the orchestrator will update some fields in the group params including gateway IP.
				// this IP is used on the rootLB to server as the GW for this new subnet
				gw, err := v.GetSubnetGatewayFromVMGroupParms(ctx, orchVals.newSubnetName, orchVals.vmgp)
				if err != nil {
					return err
				}
				attachPort := v.VMProvider.GetInternalPortPolicy() == AttachPortAfterCreate
				err = v.AttachAndEnableRootLBInterface(ctx, client, orchVals.lbName, attachPort, orchVals.newSubnetName, GetPortName(orchVals.lbName, orchVals.newSubnetName), gw)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "AttachAndEnableRootLBInterface failed", "err", err)
					return err
				}
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "External router in use, no internal interface for rootlb")
			}
			// DNS entry is already added while setting up RootLB
			return nil
		}
		updateCallback(edgeproto.UpdateTask, "Adding DNS Entry")
		if appInst.Uri != "" && ip.ExternalAddr != "" {
			fqdn := appInst.Uri
			configs := append(app.Configs, appInst.Configs...)
			aac, err := access.GetAppAccessConfig(ctx, configs, app.TemplateDelimiter)
			if err != nil {
				return err
			}
			if aac.DnsOverride != "" {
				fqdn = aac.DnsOverride
			}
			if err = v.VMProperties.CommonPf.ActivateFQDNA(ctx, fqdn, ip.ExternalAddr); err != nil {
				return err
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "DNS A record activated",
				"name", objName,
				"fqdn", fqdn,
				"IP", ip.ExternalAddr)
		}
		return nil

	case cloudcommon.DeploymentTypeDocker:
		rootLBName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
		rootLBClient, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
		if err != nil {
			return err
		}
		clientType := cloudcommon.GetAppClientType(app)
		appClient, err := v.GetClusterPlatformClient(ctx, clusterInst, clientType)
		if err != nil {
			return err
		}
		backendIP := cloudcommon.RemoteServerNone
		if app.AccessType == edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
			sip, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
			if err != nil {
				return err
			}
			backendIP = sip.ExternalAddr
		}

		rootLBIPaddr, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletExternalNetwork(), "", rootLBName)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return fmt.Errorf("get kube names failed, %v", err)
		}
		// Fetch image paths from zip file
		if app.DeploymentManifest != "" && strings.HasSuffix(app.DeploymentManifest, ".zip") {
			filename := util.DockerSanitize(app.Key.Name + app.Key.Organization + app.Key.Version)
			zipfile := "/tmp/" + filename + ".zip"
			zipContainers, err := cloudcommon.GetRemoteZipDockerManifests(ctx, v.VMProperties.CommonPf.VaultConfig, app.DeploymentManifest, zipfile, cloudcommon.Download)
			if err != nil {
				return err
			}
			for _, containers := range zipContainers {
				for _, container := range containers {
					names.ImagePaths = append(names.ImagePaths, container.Image)
				}
			}
		}

		updateCallback(edgeproto.UpdateTask, "Seeding docker secret")

		start := time.Now()
		for _, imagePath := range names.ImagePaths {
			for {
				err = infracommon.SeedDockerSecret(ctx, appClient, clusterInst, imagePath, v.VMProperties.CommonPf.VaultConfig)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "seeding docker secret failed", "err", err)
					elapsed := time.Since(start)
					if elapsed > MaxDockerSeedWait {
						return fmt.Errorf("can't seed docker secret - %v", err)
					}
					log.SpanLog(ctx, log.DebugLevelInfra, "retrying in 10 seconds")
					time.Sleep(10 * time.Second)
				} else {
					break
				}
			}
		}

		updateCallback(edgeproto.UpdateTask, "Deploying Docker App")

		err = dockermgmt.CreateAppInst(ctx, v.VMProperties.CommonPf.VaultConfig, appClient, app, appInst)
		if err != nil {
			return err
		}
		getDnsAction := func(svc v1.Service) (*infracommon.DnsSvcAction, error) {
			action := infracommon.DnsSvcAction{}
			action.PatchKube = false
			action.ExternalIP = rootLBIPaddr.ExternalAddr
			return &action, nil
		}
		updateCallback(edgeproto.UpdateTask, "Configuring Firewall Rules and DNS")
		var proxyOps []proxy.Op
		addproxy := false
		listenIP := "NONE" // only applicable for proxy case
		if app.AccessType == edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
			proxyOps = append(proxyOps, proxy.WithDockerPublishPorts(), proxy.WithDockerNetwork(""))
			addproxy = true
			listenIP = rootLBIPaddr.InternalAddr
		}
		ops := ProxyDnsSecOpts{AddProxy: addproxy, AddDnsAndPatchKubeSvc: true, AddSecurityRules: true}
		err = v.AddProxySecurityRulesAndPatchDNS(ctx, rootLBClient, names, app, appInst, getDnsAction, rootLBName, listenIP, backendIP, ops, proxyOps...)
		if err != nil {
			return fmt.Errorf("AddProxySecurityRulesAndPatchDNS error: %v", err)
		}
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	return err
}

func (v *VMPlatform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	chefClient := v.VMProperties.GetChefClient()
	if chefClient == nil {
		return fmt.Errorf("Chef client is not initialzied")
	}
	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.DeploymentTypeHelm:
		rootLBName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			log.SpanLog(ctx, log.DebugLevelInfra, "using dedicated RootLB to delete app", "rootLBName", rootLBName)
			_, err := v.VMProvider.GetServerDetail(ctx, rootLBName)
			if err != nil {
				if strings.Contains(err.Error(), ServerDoesNotExistError) {
					log.SpanLog(ctx, log.DebugLevelInfra, "Dedicated RootLB is gone, allow app deletion")
					return nil
				}
				return err
			}
		}
		client, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return fmt.Errorf("get kube names failed: %s", err)
		}
		masterIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
		if err != nil {
			if strings.Contains(err.Error(), ServerDoesNotExistError) {
				log.SpanLog(ctx, log.DebugLevelInfra, "cluster is gone, allow app deletion")
				secGrp := v.GetServerSecurityGroupName(rootLBName)
				v.DeleteProxySecurityGroupRules(ctx, client, dockermgmt.GetContainerName(&app.Key), secGrp, appInst.MappedPorts, app, rootLBName)
				return nil
			}
			return err
		}
		// Add crm local replace variables
		deploymentVars := crmutil.DeploymentReplaceVars{
			Deployment: crmutil.CrmReplaceVars{
				ClusterIp:    masterIP.ExternalAddr,
				CloudletName: k8smgmt.NormalizeName(clusterInst.Key.CloudletKey.Name),
				ClusterName:  k8smgmt.NormalizeName(clusterInst.Key.ClusterKey.Name),
				CloudletOrg:  k8smgmt.NormalizeName(clusterInst.Key.CloudletKey.Organization),
				AppOrg:       k8smgmt.NormalizeName(app.Key.Organization),
				DnsZone:      v.VMProperties.CommonPf.GetCloudletDNSZone(),
			},
		}
		ctx = context.WithValue(ctx, crmutil.DeploymentReplaceVarsKey, &deploymentVars)

		// Clean up security rules and proxy if app is external
		secGrp := v.GetServerSecurityGroupName(rootLBName)
		if err := v.DeleteProxySecurityGroupRules(ctx, client, dockermgmt.GetContainerName(&app.Key), secGrp, appInst.MappedPorts, app, rootLBName); err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "cannot delete security rules", "name", names.AppName, "rootlb", rootLBName, "error", err)
		}
		if !app.InternalPorts {
			// Clean up DNS entries
			configs := append(app.Configs, appInst.Configs...)
			aac, err := access.GetAppAccessConfig(ctx, configs, app.TemplateDelimiter)
			if err != nil {
				return err
			}
			if err := v.VMProperties.CommonPf.DeleteAppDNS(ctx, client, names, aac.DnsOverride); err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cannot clean up DNS entries", "name", names.AppName, "rootlb", rootLBName, "error", err)
			}
		}

		if deployment == cloudcommon.DeploymentTypeKubernetes {
			return k8smgmt.DeleteAppInst(ctx, client, names, app, appInst)
		} else {
			return k8smgmt.DeleteHelmAppInst(ctx, client, names, clusterInst)
		}

	case cloudcommon.DeploymentTypeVM:
		objName := cloudcommon.GetAppFQN(&app.Key)
		log.SpanLog(ctx, log.DebugLevelInfra, "Deleting VM", "stackName", objName)
		err := v.VMProvider.DeleteVMs(ctx, objName)
		if err != nil {
			return fmt.Errorf("DeleteVMAppInst error: %v", err)
		}
		if app.AccessType == edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
			lbName := cloudcommon.GetVMAppFQDN(&appInst.Key, &appInst.Key.ClusterInstKey.CloudletKey, v.VMProperties.CommonPf.PlatformConfig.AppDNSRoot)
			clientName := v.GetChefClientName(lbName)
			err = chefmgmt.ChefClientDelete(ctx, chefClient, clientName)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete client from Chef Server", "clientName", clientName, "err", err)
			}
			DeleteRootLB(lbName)
		}
		imgName, err := cloudcommon.GetFileName(app.ImagePath)
		if err != nil {
			return err
		}
		err = v.VMProvider.DeleteImage(ctx, cloudcommon.GetAppFQN(&app.Key), imgName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "cannot delete image", "imgName", imgName)
		}
		if appInst.Uri != "" {
			fqdn := appInst.Uri
			configs := append(app.Configs, appInst.Configs...)
			aac, err := access.GetAppAccessConfig(ctx, configs, app.TemplateDelimiter)
			if err != nil {
				return err
			}
			if aac.DnsOverride != "" {
				fqdn = aac.DnsOverride
			}
			if err = v.VMProperties.CommonPf.DeleteDNSRecords(ctx, fqdn); err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cannot delete DNS entries", "fqdn", fqdn)
			}
		}
		return nil

	case cloudcommon.DeploymentTypeDocker:
		rootLBName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
		rootLBClient, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
		if err != nil {
			return err
		}
		clientType := cloudcommon.GetAppClientType(app)
		appClient, err := v.GetClusterPlatformClient(ctx, clusterInst, clientType)
		if err != nil {
			if strings.Contains(err.Error(), ServerDoesNotExistError) {
				log.SpanLog(ctx, log.DebugLevelInfra, "cluster is gone, allow app deletion")
				secGrp := v.GetServerSecurityGroupName(rootLBName)
				v.DeleteProxySecurityGroupRules(ctx, rootLBClient, dockermgmt.GetContainerName(&app.Key), secGrp, appInst.MappedPorts, app, rootLBName)
				return nil
			}
			return err
		}
		_, err = v.VMProvider.GetServerDetail(ctx, rootLBName)
		if err != nil {
			if strings.Contains(err.Error(), ServerDoesNotExistError) {
				log.SpanLog(ctx, log.DebugLevelInfra, "Dedicated RootLB is gone, allow app deletion")
				return nil
			}
			return err
		}
		name := dockermgmt.GetContainerName(&app.Key)
		if !app.InternalPorts {
			secGrp := v.GetServerSecurityGroupName(rootLBName)
			//  the proxy does not yet exist for docker, but it eventually will.  Secgrp rules should be deleted in either case
			if err := v.DeleteProxySecurityGroupRules(ctx, rootLBClient, name, secGrp, appInst.MappedPorts, app, rootLBName); err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cannot delete security rules", "name", name, "rootlb", rootLBName, "error", err)
			}
		}

		return dockermgmt.DeleteAppInst(ctx, v.VMProperties.CommonPf.VaultConfig, appClient, app, appInst)
	default:
		return fmt.Errorf("unsupported deployment type %s", deployment)
	}

}

func (v *VMPlatform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	masterIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
	if err != nil {
		return err
	}

	// Add crm local replace variables
	deploymentVars := crmutil.DeploymentReplaceVars{
		Deployment: crmutil.CrmReplaceVars{
			ClusterIp:    masterIP.ExternalAddr,
			ClusterName:  k8smgmt.NormalizeName(clusterInst.Key.ClusterKey.Name),
			CloudletName: k8smgmt.NormalizeName(clusterInst.Key.CloudletKey.Organization),
			AppOrg:       k8smgmt.NormalizeName(app.Key.Organization),
			DnsZone:      v.VMProperties.CommonPf.GetCloudletDNSZone(),
		},
	}
	ctx = context.WithValue(ctx, crmutil.DeploymentReplaceVarsKey, &deploymentVars)
	clientType := cloudcommon.GetAppClientType(app)
	client, err := v.GetClusterPlatformClient(ctx, clusterInst, clientType)
	if err != nil {
		return err
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return fmt.Errorf("get kube names failed: %s", err)
		}
		return k8smgmt.UpdateAppInst(ctx, v.VMProperties.CommonPf.VaultConfig, client, names, app, appInst)
	case cloudcommon.DeploymentTypeDocker:
		return dockermgmt.UpdateAppInst(ctx, v.VMProperties.CommonPf.VaultConfig, client, app, appInst)
	case cloudcommon.DeploymentTypeHelm:
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return fmt.Errorf("get kube names failed: %s", err)
		}
		return k8smgmt.UpdateHelmAppInst(ctx, client, names, app, appInst)

	default:
		return fmt.Errorf("UpdateAppInst not supported for deployment: %s", app.Deployment)
	}
}

func (v *VMPlatform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	clientType := cloudcommon.GetAppClientType(app)
	client, err := v.GetClusterPlatformClient(ctx, clusterInst, clientType)
	if err != nil {
		return nil, err
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.DeploymentTypeHelm:
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return nil, err
		}
		return k8smgmt.GetAppInstRuntime(ctx, client, names, app, appInst)
	case cloudcommon.DeploymentTypeDocker:
		return dockermgmt.GetAppInstRuntime(ctx, client, app, appInst)
	case cloudcommon.DeploymentTypeVM:
		fallthrough
	default:
		return nil, fmt.Errorf("unsupported deployment type %s", deployment)
	}
}

func (v *VMPlatform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
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

func DownloadVMImage(ctx context.Context, vaultConfig *vault.Config, imageName, imageUrl, md5Sum string) (string, error) {
	fileExt, err := cloudcommon.GetFileNameWithExt(imageUrl)
	if err != nil {
		return "", err
	}
	filePath := "/tmp/" + fileExt

	err = cloudcommon.DownloadFile(ctx, vaultConfig, imageUrl, filePath, nil)
	if err != nil {
		return "", fmt.Errorf("error downloading image from %s, %v", imageUrl, err)
	}
	// Verify checksum
	if md5Sum != "" {
		fileMd5Sum, err := infracommon.Md5SumFile(filePath)
		if err != nil {
			return "", err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "verify md5sum", "downloaded-md5sum", fileMd5Sum, "actual-md5sum", md5Sum)
		if fileMd5Sum != md5Sum {
			return "", fmt.Errorf("mismatch in md5sum for downloaded image: %s", imageName)
		}
	}
	return filePath, nil
}

func (v *VMPlatform) syncAppInst(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	_, err := v.PerformOrchestrationForVMApp(ctx, app, appInst, nil, ActionSync, updateCallback)
	return err
}

func (v *VMPlatform) SyncAppInsts(ctx context.Context, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SyncAppInsts")
	appInstKeys := make(map[edgeproto.AppInstKey]struct{})
	caches.AppInstCache.GetAllKeys(ctx, func(k *edgeproto.AppInstKey, modRev int64) {
		appInstKeys[*k] = struct{}{}
	})

	for k := range appInstKeys {
		log.SpanLog(ctx, log.DebugLevelInfra, "SyncAppInsts found appinst", "key", k)
		var appinst edgeproto.AppInst
		var app edgeproto.App
		if !caches.AppCache.Get(&k.AppKey, &app) {
			return fmt.Errorf("Failed to get app from cache: %s", k.AppKey.String())
		}
		if app.Deployment != cloudcommon.DeploymentTypeVM {
			// only vm apps need sync
			continue
		}
		if !caches.AppInstCache.Get(&k, &appinst) {
			return fmt.Errorf("Failed to get appinst from cache: %s", k.String())
		}

		err := v.syncAppInst(ctx, &app, &appinst, updateCallback)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "syncAppInst failed", "err", err)
			appinst.State = edgeproto.TrackedState_CREATE_ERROR
			caches.AppInstCache.Update(ctx, &appinst, 0)
		}

	}
	log.SpanLog(ctx, log.DebugLevelInfra, "SyncClusterInsts done")
	return nil
}
