package vmlayer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/access"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/crmutil"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/dockermgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"

	v1 "k8s.io/api/core/v1"
)

var MaxDockerSeedWait = 1 * time.Minute

type ProxyDnsSecOpts struct {
	AddProxy              bool
	AddDnsAndPatchKubeSvc bool
	AddSecurityRules      bool
}

func (v *VMPlatform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, appFlavor *edgeproto.Flavor, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback) error {

	var err error
	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.AppDeploymentTypeHelm:
		rootLBName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
		appWaitChan := make(chan string)

		client, err := v.GetClusterPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return err
		}
		updateCallback(edgeproto.UpdateTask, "Setting up registry secret")
		err = infracommon.CreateDockerRegistrySecret(ctx, client, clusterInst, app, v.VMProperties.CommonPf.VaultConfig, names)
		if err != nil {
			return err
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

		if deployment == cloudcommon.AppDeploymentTypeKubernetes {
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
			if deployment == cloudcommon.AppDeploymentTypeKubernetes {
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
		rootLBIPaddr, err = v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletExternalNetwork(), GetClusterSubnetName(ctx, clusterInst), rootLBName)
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
	case cloudcommon.AppDeploymentTypeVM:
		imageName, err := cloudcommon.GetFileName(app.ImagePath)
		if err != nil {
			return err
		}

		err = v.VMProvider.AddAppImageIfNotPresent(ctx, app, updateCallback)
		if err != nil {
			return err
		}

		objName := cloudcommon.GetAppFQN(&app.Key)
		usesLb := app.AccessType == edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER
		newSubnetName := ""

		deploymentVars := crmutil.DeploymentReplaceVars{
			Deployment: crmutil.CrmReplaceVars{
				CloudletName: k8smgmt.NormalizeName(appInst.Key.ClusterInstKey.CloudletKey.Name),
				CloudletOrg:  k8smgmt.NormalizeName(clusterInst.Key.CloudletKey.Organization),
				AppOrg:       k8smgmt.NormalizeName(app.Key.Organization),
				DnsZone:      v.VMProperties.CommonPf.GetCloudletDNSZone(),
			},
		}
		ctx = context.WithValue(ctx, crmutil.DeploymentReplaceVarsKey, &deploymentVars)

		// whether the app vm needs to connect to internal or external networks
		// depends on whether it has an LB
		appConnectsExternal := !usesLb
		var vms []*VMRequestSpec
		externalServerName := objName
		var lbName string
		var vmgp *VMGroupOrchestrationParams

		if usesLb {
			lbName = objName + "-lb"
			externalServerName = lbName
			newSubnetName = objName + "-subnet"
			lbVm, err := v.GetVMSpecForRootLB(ctx, lbName, newSubnetName, updateCallback)
			if err != nil {
				return err
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
			WithSubnetConnection(newSubnetName),
			WithDeploymentManifest(app.DeploymentManifest),
			WithCommand(app.Command),
		)
		if err != nil {
			return err
		}
		vms = append(vms, appVm)

		updateCallback(edgeproto.UpdateTask, "Deploying App")
		vmgp, err = v.OrchestrateVMsFromVMSpec(ctx, objName, vms, ActionCreate, updateCallback, WithNewSubnet(newSubnetName),
			WithPrivacyPolicy(privacyPolicy),
			WithAccessPorts(app.AccessPorts),
			WithNewSecurityGroup(v.GetServerSecurityGroupName(objName)),
		)

		if err != nil {
			return err
		}

		ip, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletExternalNetwork(), "", externalServerName)
		if err != nil {
			return err
		}
		if usesLb {
			updateCallback(edgeproto.UpdateTask, "Setting Up Load Balancer")
			_, err := v.NewRootLB(ctx, lbName)
			if err != nil {
				// likely already exists which means something went really wrong
				return err
			}
			err = v.SetupRootLB(ctx, lbName, &clusterInst.Key.CloudletKey, updateCallback)
			if err != nil {
				return err
			}
			var proxyOps []proxy.Op
			client, err := v.GetSSHClientForServer(ctx, externalServerName, v.VMProperties.GetCloudletExternalNetwork())
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
			vmIP, err := v.GetIPFromServerName(ctx, "", newSubnetName, objName)
			if err != nil {
				return err
			}
			updateCallback(edgeproto.UpdateTask, "Configuring Firewall Rules")
			ops := ProxyDnsSecOpts{AddProxy: true, AddDnsAndPatchKubeSvc: false, AddSecurityRules: false}
			err = v.AddProxySecurityRulesAndPatchDNS(ctx, client, names, app, appInst, getDnsAction, externalServerName, cloudcommon.IPAddrAllInterfaces, vmIP.ExternalAddr, ops, proxyOps...)
			if err != nil {
				return fmt.Errorf("AddProxySecurityRulesAndPatchDNS error: %v", err)
			}

			if v.VMProperties.GetCloudletExternalRouter() == NoExternalRouter {
				log.SpanLog(ctx, log.DebugLevelInfra, "Need to attach internal interface on rootlb")

				// after vm creation, the orchestrator will update some fields in the group params including gateway IP.
				// this IP is used on the rootLB to server as the GW for this new subnet
				gw, err := v.GetSubnetGatewayFromVMGroupParms(ctx, newSubnetName, vmgp)
				if err != nil {
					return err
				}
				attachPort := v.VMProvider.GetInternalPortPolicy() == AttachPortAfterCreate
				err = v.AttachAndEnableRootLBInterface(ctx, client, lbName, attachPort, newSubnetName, GetPortName(lbName, newSubnetName), gw)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "AttachAndEnableRootLBInterface failed", "err", err)
					return err
				}
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "External router in use, no internal interface for rootlb")
			}

		}
		updateCallback(edgeproto.UpdateTask, "Adding DNS Entry")
		if appInst.Uri != "" && ip.ExternalAddr != "" {
			fqdn := appInst.Uri
			configs := append(app.Configs, appInst.Configs...)
			aac, err := access.GetAppAccessConfig(ctx, configs)
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

	case cloudcommon.AppDeploymentTypeDocker:
		rootLBName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
		backendIP := cloudcommon.RemoteServerNone
		dockerNetworkMode := dockermgmt.DockerBridgeMode
		rootLBClient, err := v.GetClusterPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		// docker commands can be run on either the rootlb or on the docker
		// vm.  The default is to run on the rootlb client
		dockerCommandTarget := rootLBClient

		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			log.SpanLog(ctx, log.DebugLevelInfra, "using dedicated RootLB to create app", "rootLBName", rootLBName)
			if app.AccessType == edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
				backendIP = cloudcommon.IPAddrDockerHost
			} else {
				dockerNetworkMode = dockermgmt.DockerHostMode
			}
		} else {
			// Shared access uses a separate VM for docker.  This is used both for running the docker commands
			// and as the backend ip for the proxy
			backendIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
			if err != nil {
				return err
			}
			// docker command will run on the docker vm
			dockerCommandTarget, err = rootLBClient.AddHop(backendIP.ExternalAddr, 22)
			if err != nil {
				return err
			}
			dockerNetworkMode = dockermgmt.DockerHostMode
		}

		rootLBIPaddr, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletExternalNetwork(), "", rootLBName)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return fmt.Errorf("get kube names failed, %v", err)
		}
		updateCallback(edgeproto.UpdateTask, "Seeding docker secret")

		start := time.Now()
		for {
			err = infracommon.SeedDockerSecret(ctx, dockerCommandTarget, clusterInst, app, v.VMProperties.CommonPf.VaultConfig)
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

		updateCallback(edgeproto.UpdateTask, "Deploying Docker App")

		err = dockermgmt.CreateAppInst(ctx, v.VMProperties.CommonPf.VaultConfig, dockerCommandTarget, app, appInst, dockerNetworkMode)
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
	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.AppDeploymentTypeHelm:
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
		client, err := v.GetClusterPlatformClient(ctx, clusterInst)
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
			aac, err := access.GetAppAccessConfig(ctx, configs)
			if err != nil {
				return err
			}
			if err := v.VMProperties.CommonPf.DeleteAppDNS(ctx, client, names, aac.DnsOverride); err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cannot clean up DNS entries", "name", names.AppName, "rootlb", rootLBName, "error", err)
			}
		}

		if deployment == cloudcommon.AppDeploymentTypeKubernetes {
			return k8smgmt.DeleteAppInst(ctx, client, names, app, appInst)
		} else {
			return k8smgmt.DeleteHelmAppInst(ctx, client, names, clusterInst)
		}

	case cloudcommon.AppDeploymentTypeVM:
		objName := cloudcommon.GetAppFQN(&app.Key)
		log.SpanLog(ctx, log.DebugLevelInfra, "Deleting VM", "stackName", objName)
		err := v.VMProvider.DeleteVMs(ctx, objName)
		if err != nil {
			return fmt.Errorf("DeleteVMAppInst error: %v", err)
		}
		if appInst.Uri != "" {
			fqdn := appInst.Uri
			configs := append(app.Configs, appInst.Configs...)
			aac, err := access.GetAppAccessConfig(ctx, configs)
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

	case cloudcommon.AppDeploymentTypeDocker:
		rootLBName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
		rootLBClient, err := v.GetClusterPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		// docker commands can be run on either the rootlb or on the docker
		// vm.  The default is to run on the rootlb client
		dockerCommandTarget := rootLBClient

		if clusterInst.IpAccess != edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			backendIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
			if err != nil {
				if strings.Contains(err.Error(), ServerDoesNotExistError) {
					log.SpanLog(ctx, log.DebugLevelInfra, "cluster is gone, allow app deletion")
					secGrp := v.GetServerSecurityGroupName(rootLBName)
					v.DeleteProxySecurityGroupRules(ctx, rootLBClient, dockermgmt.GetContainerName(&app.Key), secGrp, appInst.MappedPorts, app, rootLBName)
					return nil
				}
				return err
			}
			// docker command will run on the docker vm
			dockerCommandTarget, err = rootLBClient.AddHop(backendIP.ExternalAddr, 22)
			if err != nil {
				return err
			}
		}
		_, err = v.VMProvider.GetServerDetail(ctx, rootLBName)
		if err != nil {
			if strings.Contains(err.Error(), ServerDoesNotExistError) {
				log.SpanLog(ctx, log.DebugLevelInfra, "Dedicated RootLB is gone, allow app deletion")
				return nil
			}
			return err
		}
		client, err := v.GetClusterPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		name := dockermgmt.GetContainerName(&app.Key)
		if !app.InternalPorts {
			secGrp := v.GetServerSecurityGroupName(rootLBName)
			//  the proxy does not yet exist for docker, but it eventually will.  Secgrp rules should be deleted in either case
			if err := v.DeleteProxySecurityGroupRules(ctx, client, name, secGrp, appInst.MappedPorts, app, rootLBName); err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cannot delete security rules", "name", name, "rootlb", rootLBName, "error", err)
			}
		}

		return dockermgmt.DeleteAppInst(ctx, v.VMProperties.CommonPf.VaultConfig, dockerCommandTarget, app, appInst)
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

	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
		client, err := v.GetClusterPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return fmt.Errorf("get kube names failed: %s", err)
		}
		return k8smgmt.UpdateAppInst(ctx, v.VMProperties.CommonPf.VaultConfig, client, names, app, appInst)
	case cloudcommon.AppDeploymentTypeDocker:
		dockerNetworkMode := dockermgmt.DockerBridgeMode
		rootLBClient, err := v.GetClusterPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
		// docker commands can be run on either the rootlb or on the docker
		// vm.  The default is to run on the rootlb client
		dockerCommandTarget := rootLBClient

		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_SHARED {
			masterIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
			if err != nil {
				return err
			}
			// docker command will run on the docker vm
			dockerCommandTarget, err = rootLBClient.AddHop(masterIP.ExternalAddr, 22)
			if err != nil {
				return err
			}
		}
		return dockermgmt.UpdateAppInst(ctx, v.VMProperties.CommonPf.VaultConfig, dockerCommandTarget, app, appInst, dockerNetworkMode)
	case cloudcommon.AppDeploymentTypeHelm:
		client, err := v.GetClusterPlatformClient(ctx, clusterInst)
		if err != nil {
			return err
		}
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
	client, err := v.GetClusterPlatformClient(ctx, clusterInst)
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
		return k8smgmt.GetAppInstRuntime(ctx, client, names, app, appInst)
	case cloudcommon.AppDeploymentTypeDocker:
		return dockermgmt.GetAppInstRuntime(ctx, client, app, appInst)
	case cloudcommon.AppDeploymentTypeVM:
		fallthrough
	default:
		return nil, fmt.Errorf("unsupported deployment type %s", deployment)
	}
}

func (v *VMPlatform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.AppDeploymentTypeHelm:
		return k8smgmt.GetContainerCommand(ctx, clusterInst, app, appInst, req)
	case cloudcommon.AppDeploymentTypeDocker:
		return dockermgmt.GetContainerCommand(clusterInst, app, appInst, req)
	case cloudcommon.AppDeploymentTypeVM:
		fallthrough
	default:
		return "", fmt.Errorf("unsupported deployment type %s", deployment)
	}
}
