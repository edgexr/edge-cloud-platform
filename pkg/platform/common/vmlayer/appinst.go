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

package vmlayer

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/codeskyblue/go-sh"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/access"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/deployvars"
	"github.com/edgexr/edge-cloud-platform/pkg/dockermgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/proxy"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	ssh "github.com/edgexr/golang-ssh"
	v1 "k8s.io/api/core/v1"
)

const (
	MaxDockerSeedWait                   = 1 * time.Minute
	qcowConvertTimeout                  = 15 * time.Minute
	FileDownloadDir                     = "/var/tmp/"
	cleanupNonVMAppinstRetryWaitSeconds = 10
	cleanupVMAppinstRetryWaitSeconds    = 60
	maxWaitImageDownloadInProgress      = 60 * time.Minute // this timeout is very long because it should never happen
)

type ProxyDnsSecOpts struct {
	AddProxy              bool
	AddDnsAndPatchKubeSvc bool
	AddSecurityRules      bool
}

type vmAppOrchValues struct {
	lbName             string
	externalServerName string
	vmgp               *VMGroupOrchestrationParams
	newSubnetNames     SubnetNames
}

var imageLock sync.Mutex // serializes changes to local disk
var imageDownloadsInProgress map[string]bool

func init() {
	imageDownloadsInProgress = make(map[string]bool)
}

func (v *VMPlatform) GetVMAppSubnetNames(appVmName string) SubnetNames {
	subnetNames := SubnetNames{}
	subnetNames[infracommon.IndexIPV4] = appVmName + "-subnet"
	subnetNames[infracommon.IndexIPV6] = appVmName + "-subnet-ipv6"
	return subnetNames
}

func (v *VMPlatform) PerformOrchestrationForVMApp(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, action ActionType, updateCallback edgeproto.CacheUpdateCallback) (*vmAppOrchValues, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "PerformOrchestrationForVMApp", "appInst", appInst, "action", action)
	var orchVals vmAppOrchValues

	imageName, err := cloudcommon.GetFileName(app.ImagePath)
	if err != nil {
		return &orchVals, err
	}
	if appInst.UniqueId == "" {
		return nil, fmt.Errorf("appInst uniqueID not set")
	}
	appVmName := appInst.UniqueId
	groupName := appInst.UniqueId
	var imageInfo infracommon.ImageInfo
	sourceImageTime, md5Sum, err := infracommon.GetUrlInfo(ctx, v.VMProperties.CommonPf.PlatformConfig.AccessApi, app.ImagePath)
	imageInfo.LocalImageName = imageName + "-" + md5Sum
	if v.VMProperties.AppendFlavorToVmAppImage {
		imageInfo.LocalImageName = imageInfo.LocalImageName + "-" + appInst.Flavor.Name
	}
	imageInfo.Md5sum = md5Sum
	imageInfo.SourceImageTime = sourceImageTime
	imageInfo.OsType = app.VmAppOsType
	imageInfo.ImagePath = app.ImagePath
	imageInfo.ImageType = app.ImageType
	imageInfo.VmName = appVmName
	imageInfo.Flavor = appInst.Flavor.Name
	imageInfo.ImageCategory = infracommon.ImageCategoryVmApp
	if err != nil {
		return &orchVals, err
	}
	// only one thread should be downloading any given image at once.
	reserved := reserveImageDownloadInProgress(ctx, imageInfo.LocalImageName)
	if reserved {
		err = v.VMProvider.AddImageIfNotPresent(ctx, &imageInfo, updateCallback)
		clearImageDownloadInProgress(ctx, imageInfo.LocalImageName)
	} else {
		// download already in progress by another thread, wait for it to finish
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Waiting for download of %s", imageInfo.LocalImageName))
		err = waitForImageDownloadInProgress(ctx, imageInfo.LocalImageName)
	}
	if err != nil {
		return &orchVals, err
	}
	deploymentVars := deployvars.DeploymentReplaceVars{
		Deployment: deployvars.CrmReplaceVars{
			CloudletName: k8smgmt.NormalizeName(appInst.CloudletKey.Name),
			CloudletOrg:  k8smgmt.NormalizeName(appInst.CloudletKey.Organization),
			AppOrg:       k8smgmt.NormalizeName(app.Key.Organization),
			DnsZone:      v.VMProperties.CommonPf.GetCloudletDNSZone(),
		},
	}
	ctx = context.WithValue(ctx, deployvars.DeploymentReplaceVarsKey, &deploymentVars)

	var vms []*VMRequestSpec
	orchVals.externalServerName = appVmName

	orchVals.lbName = appInst.Uri
	orchVals.externalServerName = orchVals.lbName
	orchVals.newSubnetNames = v.GetVMAppSubnetNames(appVmName)
	nets := make(map[string]NetworkType)
	routes := make(map[string][]edgeproto.Route)
	lbVm, err := v.GetVMSpecForRootLB(ctx, orchVals.lbName, orchVals.newSubnetNames, &appInst.Key, nets, routes, NoAccessKey, cloudcommon.NodeRoleBase, updateCallback)
	if err != nil {
		return &orchVals, err
	}
	vms = append(vms, lbVm)

	appVm, err := v.GetVMRequestSpec(
		ctx,
		cloudcommon.NodeTypeAppVM,
		appVmName,
		appInst.VmFlavor,
		imageInfo.LocalImageName,
		false,
		WithComputeAvailabilityZone(appInst.AvailabilityZone),
		WithExternalVolume(appInst.ExternalVolumeSize),
		WithSubnetConnection(orchVals.newSubnetNames),
		WithDeploymentManifest(app.DeploymentManifest),
		WithCommand(app.Command),
		WithImageFolder(appVmName),
		WithVmAppOsType(app.VmAppOsType),
	)
	if err != nil {
		return &orchVals, err
	}
	vms = append(vms, appVm)
	updateCallback(edgeproto.UpdateTask, "Deploying App")
	vmgp, err := v.OrchestrateVMsFromVMSpec(ctx,
		groupName,
		appInst.ObjId,
		vms,
		action,
		updateCallback,
		WithNewSubnet(orchVals.newSubnetNames),
		WithAccessPorts(app.AccessPorts),
		WithNewSecurityGroup(infracommon.GetServerSecurityGroupName(orchVals.externalServerName)),
		WithEnableIPV6(appInst.EnableIpv6),
	)
	if err != nil {
		return &orchVals, err
	}
	orchVals.vmgp = vmgp
	return &orchVals, nil
}

func (v *VMPlatform) setupVMAppRootLBAndNode(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, orchVals *vmAppOrchValues, action ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "setupVMAppRootLBAndNode", "orchVals", orchVals)

	if action == ActionUpdate {
		// attach any missing external ports to the dedicated rootLB
		// TODO: remove ports that shouldn't be there anymore.
		err := v.attachRootLBExternalPorts(ctx, orchVals.lbName, orchVals.vmgp, action)
		if err != nil {
			return err
		}
	}

	rootLBDetail, err := v.VMProvider.GetServerDetail(ctx, orchVals.lbName)
	if err != nil {
		return fmt.Errorf("failed to get server detail for VMApp rootLB %s, %s", orchVals.lbName, err)
	}

	vmName := appInst.UniqueId
	getIPOps := []GetIPOp{}
	if orchVals.externalServerName == orchVals.lbName {
		getIPOps = []GetIPOp{WithServerDetail(rootLBDetail)}
	}
	ips, err := v.GetExternalIPFromServerName(ctx, orchVals.externalServerName, getIPOps...)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Setting Up Load Balancer")
	pp := edgeproto.TrustPolicy{}
	err = v.SetupRootLB(ctx, orchVals.lbName, orchVals.lbName, &clusterInst.CloudletKey, &pp, rootLBDetail, appInst.EnableIpv6, updateCallback)
	if err != nil {
		return err
	}
	var proxyOps []proxy.Op
	client, err := v.GetSSHClientForServer(ctx, orchVals.externalServerName, v.VMProperties.GetCloudletExternalNetwork())
	if err != nil {
		return err
	}
	err = v.proxyCerts.SetupTLSCerts(ctx, orchVals.lbName, orchVals.lbName, client)
	if err != nil {
		return err
	}
	// clusterInst is empty but that is ok here
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return fmt.Errorf("get kube names failed: %s", err)
	}
	proxyOps = append(proxyOps, proxy.WithDockerNetwork("host"))
	proxyOps = append(proxyOps, proxy.WithMetricEndpoint(infracommon.GetUniqueLoopbackIp(ctx, appInst.MappedPorts)))

	getDnsAction := func(svc v1.Service) (*infracommon.DnsSvcAction, error) {
		action := infracommon.DnsSvcAction{}
		action.PatchKube = false
		action.ExternalIP = ips.IPV4ExternalAddr()
		action.ExternalIPV6 = ips.IPV6ExternalAddr()
		return &action, nil
	}
	vmAppDetail, err := v.VMProvider.GetServerDetail(ctx, vmName)
	if err != nil {
		return fmt.Errorf("failed to get server detail for VMApp %s, %s", vmName, err)
	}
	vmIPs, err := v.GetIPFromServerName(ctx, "", orchVals.newSubnetNames, vmName, WithServerDetail(vmAppDetail))
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Configuring Firewall Rules")
	addSecRules := v.VMProperties.IptablesBasedFirewall // need to do the rules here for iptables based providers
	ops := infracommon.ProxyDnsSecOpts{AddProxy: true, AddDnsAndPatchKubeSvc: false, AddSecurityRules: addSecRules}
	wlParams := infracommon.WhiteListParams{
		SecGrpName:  infracommon.GetServerSecurityGroupName(orchVals.externalServerName),
		ServerName:  orchVals.externalServerName,
		Label:       infracommon.GetAppWhitelistRulesLabel(app),
		AllowedCIDR: infracommon.GetAllowedClientCIDR(),
		Ports:       appInst.MappedPorts,
		DestIP:      infracommon.DestIPUnspecified,
	}
	proxyConfig := NewProxyConfig(ListenAllIPs, vmIPs, appInst.EnableIpv6)
	err = v.VMProperties.CommonPf.AddProxySecurityRulesAndPatchDNS(ctx, client, names, app, appInst, getDnsAction, v.VMProvider.WhitelistSecurityRules, &wlParams, proxyConfig, ops, proxyOps...)
	if err != nil {
		return fmt.Errorf("AddProxySecurityRulesAndPatchDNS error: %v", err)
	}
	if appInst.EnableIpv6 {
		if err := setupDockerIPV6(ctx, client); err != nil {
			return err
		}
	}

	var internalIfName string
	if v.VMProperties.GetCloudletExternalRouter() == NoExternalRouter {
		log.SpanLog(ctx, log.DebugLevelInfra, "Need to attach internal interface on rootlb")

		// after vm creation, the orchestrator will update some fields in the group params including gateway IP.
		// this IP is used on the rootLB to server as the GW for this new subnet
		gws, err := v.GetSubnetGatewayFromVMGroupParms(ctx, orchVals.newSubnetNames, orchVals.vmgp)
		if err != nil {
			return err
		}
		// Attach rootLB internal interface
		attachPort := v.VMProvider.GetInternalPortPolicy() == AttachPortAfterCreate
		rootLBDetail, internalIfName, err = v.AttachAndEnableRootLBInterface(ctx, client, orchVals.lbName, attachPort, orchVals.newSubnetNames, GetPortNameFromSubnet(orchVals.lbName, orchVals.newSubnetNames), gws, action)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AttachAndEnableRootLBInterface failed", "err", err)
			return err
		}
		if v.VMProperties.RunLbDhcpServerForVmApps {
			updateCallback(edgeproto.UpdateTask, "Enabling DHCP on RootLB for VM App")
			err = v.StartDHCPServerForVMApp(ctx, client, rootLBDetail, internalIfName, vmIPs, vmName)
			if err != nil {
				return err
			}
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "External router in use, no internal interface for rootlb")
	}
	return nil
}

func seedDockerSecrets(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst, names *k8smgmt.KubeNames, accessApi platform.AccessApi) error {
	start := time.Now()
	for _, imagePath := range names.ImagePaths {
		for {
			err := dockermgmt.SeedDockerSecret(ctx, client, imagePath, accessApi)
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
	return nil
}

func (v *VMPlatform) setupDnsForAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, client ssh.Client, deployment string) error {
	var proxyOps []proxy.Op
	var getDnsAction func(svc v1.Service) (*infracommon.DnsSvcAction, error)

	rootLBName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
	rootLBIPs, err := v.GetExternalIPFromServerName(ctx, rootLBName, WithCachedIP(true))
	if err != nil {
		return err
	}
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	sips, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), v.GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
	if err != nil {
		return err
	}
	ops := infracommon.ProxyDnsSecOpts{AddProxy: true, AddDnsAndPatchKubeSvc: true, AddSecurityRules: true}
	wlParams := infracommon.WhiteListParams{
		SecGrpName:  infracommon.GetServerSecurityGroupName(rootLBName),
		ServerName:  rootLBName,
		Label:       infracommon.GetAppWhitelistRulesLabel(app),
		AllowedCIDR: infracommon.GetAllowedClientCIDR(),
		Ports:       appInst.MappedPorts,
		DestIP:      infracommon.DestIPUnspecified,
	}
	proxyConfig := NewProxyConfig(ListenAllIPs, sips, appInst.EnableIpv6)

	// setup common proxy options
	loopbackIp := infracommon.GetUniqueLoopbackIp(ctx, appInst.MappedPorts)
	proxyOps = append(proxyOps, proxy.WithDockerNetwork("host"))
	proxyOps = append(proxyOps, proxy.WithMetricEndpoint(loopbackIp))

	switch deployment {
	case cloudcommon.DeploymentTypeHelm:
		fallthrough
	case cloudcommon.DeploymentTypeKubernetes:
		patchIPV4 := ""
		patchIPV6 := ""
		useMetalLb := v.VMProperties.GetUsesMetalLb()
		if useMetalLb {
			// generally MetalLB should already be installed, but if the cluster is pre-existing it is
			// possible that the install was not yet done
			lbIpRange, err := v.VMProperties.GetMetalLBAddresses(ctx, sips)
			if err != nil {
				return err
			}
			if err := infracommon.InstallAndConfigMetalLbIfNotInstalled(ctx, client, clusterInst, lbIpRange); err != nil {
				return err
			}
			err = k8smgmt.PopulateAppInstLoadBalancerIps(ctx, client, names, appInst)
			if err != nil {
				return err
			}
		} else {
			patchIPV4 = sips.IPV4ExternalAddr()
			patchIPV6 = sips.IPV6ExternalAddr()
		}
		features := v.GetFeatures()
		getDnsAction = func(svc v1.Service) (*infracommon.DnsSvcAction, error) {
			action := infracommon.DnsSvcAction{}
			action.PatchKube = !v.VMProperties.GetUsesMetalLb()
			action.PatchIP = patchIPV4
			action.PatchIPV6 = patchIPV6
			action.ExternalIP = rootLBIPs.IPV4ExternalAddr()
			action.ExternalIPV6 = rootLBIPs.IPV6ExternalAddr()
			// Should only add DNS for external ports
			// and if ips are per service.
			action.AddDNS = !app.InternalPorts && features.IpAllocatedPerService
			return &action, nil
		}
		// If this is an internal ports, all we need is patch of kube service
		if app.InternalPorts {
			return v.VMProperties.CommonPf.CreateAppDNSAndPatchKubeSvc(ctx, client, names, infracommon.NoDnsOverride, getDnsAction)
		}

	case cloudcommon.DeploymentTypeDocker:
		getDnsAction = func(svc v1.Service) (*infracommon.DnsSvcAction, error) {
			action := infracommon.DnsSvcAction{}
			action.PatchKube = false
			action.ExternalIP = rootLBIPs.IPV4ExternalAddr()
			action.ExternalIPV6 = rootLBIPs.IPV6ExternalAddr()
			return &action, nil
		}
	case cloudcommon.DeploymentTypeVM:
		// TODO - we only support shared load balancer updates for now
		fallthrough
	default:
		return fmt.Errorf("unsupported deployment type %s", deployment)
	}
	return v.VMProperties.CommonPf.AddProxySecurityRulesAndPatchDNS(ctx, client, names, app, appInst, getDnsAction, v.VMProvider.WhitelistSecurityRules, &wlParams, proxyConfig, ops, proxyOps...)
}

func (v *VMPlatform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, appFlavor *edgeproto.Flavor, updateSender edgeproto.AppInstInfoSender) error {
	updateCallback := updateSender.SendStatusIgnoreErr
	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	if app.Deployment != cloudcommon.DeploymentTypeVM {
		// Platforms like VCD needs an additional step to setup GPU driver.
		// Hence, GPU drivers should only be setup as part of AppInst bringup.
		client, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
		if err != nil {
			return err
		}
		setupStage := v.VMProvider.GetGPUSetupStage(ctx)
		if appInst.OptRes == "gpu" && !cloudcommon.IsSideCarApp(app) && setupStage == AppInstStage {
			// setup GPU drivers
			err = v.setupGPUDrivers(ctx, client, clusterInst, updateCallback, ActionCreate)
			if err != nil {
				return fmt.Errorf("failed to install GPU drivers on appInst cluster VMs: %v", err)
			}
			if clusterInst.Deployment == cloudcommon.DeploymentTypeKubernetes {
				// setup GPU operator helm repo
				v.manageGPUOperator(ctx, client, clusterInst, updateCallback, ActionCreate)
			}
		}
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.DeploymentTypeHelm:
		appWaitChan := make(chan string)

		client, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return err
		}
		err = k8smgmt.CreateAllNamespaces(ctx, client, names)
		if err != nil {
			return err
		}
		updateCallback(edgeproto.UpdateTask, "Setting up registry secret")
		kconf := k8smgmt.GetKconfName(clusterInst)
		for _, imagePath := range names.ImagePaths {
			err = infracommon.CreateDockerRegistrySecret(ctx, client, kconf, imagePath, v.VMProperties.CommonPf.PlatformConfig.AccessApi, names, nil)
			if err != nil {
				return err
			}
		}
		masterIPs, masterIpErr := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), v.GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
		// Add crm local replace variables
		if masterIpErr != nil {
			return masterIpErr
		}
		deploymentVars := deployvars.DeploymentReplaceVars{
			Deployment: deployvars.CrmReplaceVars{
				ClusterIp:    masterIPs.IPV4ExternalAddr(),
				ClusterIPV6:  masterIPs.IPV6ExternalAddr(),
				CloudletName: k8smgmt.NormalizeName(clusterInst.CloudletKey.Name),
				ClusterName:  k8smgmt.NormalizeName(clusterInst.Key.Name),
				CloudletOrg:  k8smgmt.NormalizeName(clusterInst.CloudletKey.Organization),
				AppOrg:       k8smgmt.NormalizeName(app.Key.Organization),
				DnsZone:      v.VMProperties.CommonPf.GetCloudletDNSZone(),
			},
		}
		ctx = context.WithValue(ctx, deployvars.DeploymentReplaceVarsKey, &deploymentVars)

		if deployment == cloudcommon.DeploymentTypeKubernetes {
			updateCallback(edgeproto.UpdateTask, "Creating Kubernetes App")
			err = k8smgmt.CreateAppInst(ctx, v.VMProperties.CommonPf.PlatformConfig.AccessApi, client, names, app, appInst, appFlavor)
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
		updateCallback(edgeproto.UpdateTask, "Configuring Service: LB, Firewall Rules and DNS")
		err = v.setupDnsForAppInst(ctx, clusterInst, app, appInst, client, app.Deployment)

		appWaitErr := <-appWaitChan
		if appWaitErr != "" {
			return fmt.Errorf("app wait error, %v", appWaitErr)
		}
		if err != nil {
			return err
		}
	case cloudcommon.DeploymentTypeVM:
		if v.VMProvider.NameSanitize(appInst.UniqueId) != appInst.UniqueId {
			// id must be sanitized by controller first
			return fmt.Errorf("non sanitized app unique id provided: %s", appInst.UniqueId)
		}
		orchVals, err := v.PerformOrchestrationForVMApp(ctx, app, appInst, ActionCreate, updateCallback)
		if err != nil {
			return err
		}
		return v.setupVMAppRootLBAndNode(ctx, clusterInst, app, appInst, orchVals, ActionCreate, updateCallback)

	case cloudcommon.DeploymentTypeDocker:
		return v.setupDockerAppInst(ctx, clusterInst, app, appInst, ActionCreate, updateCallback)
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	return err
}

func (v *VMPlatform) setupDockerAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, action ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	rootLBClient, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	clientType := cloudcommon.GetAppClientType(app)
	appClient, err := v.GetClusterPlatformClient(ctx, clusterInst, clientType)
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
		zipfile := FileDownloadDir + filename + ".zip"
		zipContainers, err := cloudcommon.GetRemoteZipDockerManifests(ctx, v.VMProperties.CommonPf.PlatformConfig.AccessApi, app.DeploymentManifest, zipfile, cloudcommon.Download)
		if err != nil {
			return err
		}
		for _, containers := range zipContainers {
			for _, container := range containers {
				names.ImagePaths = append(names.ImagePaths, container.Image)
			}
		}
	}

	updateCallback(edgeproto.UpdateTask, "Seeding docker secrets")
	err = seedDockerSecrets(ctx, appClient, clusterInst, names, v.VMProperties.CommonPf.PlatformConfig.AccessApi)
	if err != nil {
		return err
	}

	updateCallback(edgeproto.UpdateTask, "Deploying Docker App")

	if action == ActionCreate {
		err = dockermgmt.CreateAppInst(ctx, v.VMProperties.CommonPf.PlatformConfig.AccessApi, appClient, app, appInst, dockermgmt.WithForceImagePull(true))
		if err != nil {
			return err
		}
	} else if action == ActionUpdate {
		err = dockermgmt.UpdateAppInst(ctx, v.VMProperties.CommonPf.PlatformConfig.AccessApi, appClient, app, appInst)
		if err != nil {
			return err
		}
	}

	updateCallback(edgeproto.UpdateTask, "Configuring Firewall Rules and DNS")
	err = v.setupDnsForAppInst(ctx, clusterInst, app, appInst, rootLBClient, app.Deployment)
	if err != nil {
		return fmt.Errorf("AddProxySecurityRulesAndPatchDNS error: %v", err)
	}
	return nil
}

func (v *VMPlatform) cleanupAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "cleanupAppInst", "appinst", appInst)

	var err error
	retryTimeout := cleanupNonVMAppinstRetryWaitSeconds
	if app.Deployment == cloudcommon.DeploymentTypeVM {
		retryTimeout = cleanupVMAppinstRetryWaitSeconds
	}
	for tryNum := 0; tryNum <= v.VMProperties.NumCleanupRetries; tryNum++ {
		err = v.cleanupAppInstInternal(ctx, clusterInst, app, appInst, updateCallback)
		if err == nil {
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to cleanup appinst", "appInst", appInst, "tryNum", tryNum, "retries", v.VMProperties.NumCleanupRetries, "err", err)
		if tryNum < v.VMProperties.NumCleanupRetries {
			log.SpanLog(ctx, log.DebugLevelInfra, "sleeping and retrying cleanup", "retryTimeout", retryTimeout)
			time.Sleep(time.Second * time.Duration(retryTimeout))
			updateCallback(edgeproto.UpdateTask, "Retrying cleanup")
		}
	}
	v.VMProperties.CommonPf.PlatformConfig.NodeMgr.Event(ctx, "Failed to clean up appInst", app.Key.Organization, appInst.GetTags(), err)
	return fmt.Errorf("Failed to cleanup appinst - %v", err)
}

func (v *VMPlatform) cleanupAppInstInternal(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "cleanupAppInstInternal", "appinst", appInst)

	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
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
		masterIPs, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), v.GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
		if err != nil {
			if strings.Contains(err.Error(), ServerDoesNotExistError) {
				log.SpanLog(ctx, log.DebugLevelInfra, "cluster is gone, allow app deletion")
				wlParams := infracommon.WhiteListParams{
					SecGrpName:  infracommon.GetServerSecurityGroupName(rootLBName),
					ServerName:  rootLBName,
					Label:       infracommon.GetAppWhitelistRulesLabel(app),
					AllowedCIDR: infracommon.GetAllowedClientCIDR(),
					Ports:       appInst.MappedPorts,
					DestIP:      infracommon.DestIPUnspecified,
				}
				v.VMProperties.CommonPf.DeleteProxySecurityGroupRules(ctx, client, dockermgmt.GetContainerName(appInst), v.VMProvider.RemoveWhitelistSecurityRules, &wlParams)
				return nil
			}
			return err
		}
		// Add crm local replace variables
		deploymentVars := deployvars.DeploymentReplaceVars{
			Deployment: deployvars.CrmReplaceVars{
				ClusterIp:    masterIPs.IPV4ExternalAddr(),
				ClusterIPV6:  masterIPs.IPV6ExternalAddr(),
				CloudletName: k8smgmt.NormalizeName(clusterInst.CloudletKey.Name),
				ClusterName:  k8smgmt.NormalizeName(clusterInst.Key.Name),
				CloudletOrg:  k8smgmt.NormalizeName(clusterInst.CloudletKey.Organization),
				AppOrg:       k8smgmt.NormalizeName(app.Key.Organization),
				DnsZone:      v.VMProperties.CommonPf.GetCloudletDNSZone(),
			},
		}
		ctx = context.WithValue(ctx, deployvars.DeploymentReplaceVarsKey, &deploymentVars)

		// Clean up security rules and proxy if app is external
		wlParams := infracommon.WhiteListParams{
			SecGrpName:  infracommon.GetServerSecurityGroupName(rootLBName),
			ServerName:  rootLBName,
			Label:       infracommon.GetAppWhitelistRulesLabel(app),
			AllowedCIDR: infracommon.GetAllowedClientCIDR(),
			Ports:       appInst.MappedPorts,
			DestIP:      infracommon.DestIPUnspecified,
		}
		if err := v.VMProperties.CommonPf.DeleteProxySecurityGroupRules(ctx, client, dockermgmt.GetContainerName(appInst), v.VMProvider.RemoveWhitelistSecurityRules, &wlParams); err != nil {
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
		objName := appInst.UniqueId
		log.SpanLog(ctx, log.DebugLevelInfra, "Deleting VM", "stackName", objName)
		err := v.VMProvider.DeleteVMs(ctx, objName, clusterInst.ObjId)
		if err != nil && err.Error() != ServerDoesNotExistError {
			return fmt.Errorf("DeleteVMAppInst error: %v", err)
		}
		accessApi := v.VMProperties.CommonPf.PlatformConfig.AccessApi
		lbName := appInst.Uri
		nodeKey := edgeproto.CloudletNodeKey{
			Name:        lbName,
			CloudletKey: clusterInst.CloudletKey,
		}
		err = accessApi.DeleteCloudletNode(ctx, &nodeKey)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete cloudlet node registration", "lbName", lbName, "err", err)
		}
		DeleteServerIpFromCache(ctx, lbName)

		imgName, err := cloudcommon.GetFileName(app.ImagePath)
		if err != nil {
			return err
		}

		_, md5Sum, err := infracommon.GetUrlInfo(ctx, v.VMProperties.CommonPf.PlatformConfig.AccessApi, app.ImagePath)
		localImageName := imgName + "-" + md5Sum
		if v.VMProperties.AppendFlavorToVmAppImage {
			localImageName = localImageName + "-" + appInst.Flavor.Name
		}
		imageName := appInst.UniqueId
		if v.VMProperties.GetVMAppCleanupImageOnDelete() {
			err = v.VMProvider.DeleteImage(ctx, imageName, localImageName)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cannot delete image", "folder", imageName, "localImageName", localImageName)
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "skipping image cleanup due to MEX_VM_APP_IMAGE_CLEANUP_ON_DELETE setting")
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
				wlParams := infracommon.WhiteListParams{
					SecGrpName:  infracommon.GetServerSecurityGroupName(rootLBName),
					ServerName:  rootLBName,
					Label:       infracommon.GetAppWhitelistRulesLabel(app),
					AllowedCIDR: infracommon.GetAllowedClientCIDR(),
					Ports:       appInst.MappedPorts,
					DestIP:      infracommon.DestIPUnspecified,
				}
				v.VMProperties.CommonPf.DeleteProxySecurityGroupRules(ctx, rootLBClient, dockermgmt.GetContainerName(appInst), v.VMProvider.RemoveWhitelistSecurityRules, &wlParams)
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
		name := dockermgmt.GetContainerName(appInst)
		if !app.InternalPorts {
			//  the proxy does not yet exist for docker, but it eventually will.  Secgrp rules should be deleted in either case
			wlParams := infracommon.WhiteListParams{
				SecGrpName:  infracommon.GetServerSecurityGroupName(rootLBName),
				ServerName:  rootLBName,
				Label:       infracommon.GetAppWhitelistRulesLabel(app),
				AllowedCIDR: infracommon.GetAllowedClientCIDR(),
				Ports:       appInst.MappedPorts,
				DestIP:      infracommon.DestIPUnspecified,
			}
			if err := v.VMProperties.CommonPf.DeleteProxySecurityGroupRules(ctx, rootLBClient, name, v.VMProvider.RemoveWhitelistSecurityRules, &wlParams); err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cannot delete security rules", "name", name, "rootlb", rootLBName, "error", err)
			}
		}

		return dockermgmt.DeleteAppInst(ctx, v.VMProperties.CommonPf.PlatformConfig.AccessApi, appClient, app, appInst)
	default:
		return fmt.Errorf("unsupported deployment type %s", deployment)
	}

}

func (v *VMPlatform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteAppInst", "appInst", appInst)
	return v.cleanupAppInst(ctx, clusterInst, app, appInst, updateCallback)
}

func (v *VMPlatform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {

	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	if app.Deployment == cloudcommon.DeploymentTypeVM {
		orchVals, err := v.PerformOrchestrationForVMApp(ctx, app, appInst, ActionUpdate, updateCallback)
		if err != nil {
			return err
		}
		return v.setupVMAppRootLBAndNode(ctx, clusterInst, app, appInst, orchVals, ActionUpdate, updateCallback)
	} else if app.Deployment == cloudcommon.DeploymentTypeDocker {
		return v.setupDockerAppInst(ctx, clusterInst, app, appInst, ActionUpdate, updateCallback)
	}

	masterIPs, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), v.GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
	if err != nil {
		return err
	}

	// Add crm local replace variables
	deploymentVars := deployvars.DeploymentReplaceVars{
		Deployment: deployvars.CrmReplaceVars{
			ClusterIp:    masterIPs.IPV4ExternalAddr(),
			ClusterIPV6:  masterIPs.IPV6ExternalAddr(),
			ClusterName:  k8smgmt.NormalizeName(clusterInst.Key.Name),
			CloudletName: k8smgmt.NormalizeName(clusterInst.CloudletKey.Name),
			CloudletOrg:  k8smgmt.NormalizeName(clusterInst.CloudletKey.Organization),
			AppOrg:       k8smgmt.NormalizeName(app.Key.Organization),
			DnsZone:      v.VMProperties.CommonPf.GetCloudletDNSZone(),
		},
	}
	ctx = context.WithValue(ctx, deployvars.DeploymentReplaceVarsKey, &deploymentVars)
	clientType := cloudcommon.GetAppClientType(app)
	client, err := v.GetClusterPlatformClient(ctx, clusterInst, clientType)
	if err != nil {
		return err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return fmt.Errorf("get kube names failed: %s", err)
	}

	if app.Deployment == cloudcommon.DeploymentTypeKubernetes || app.Deployment == cloudcommon.DeploymentTypeHelm {
		kconf := k8smgmt.GetKconfName(clusterInst)
		for _, imagePath := range names.ImagePaths {
			// secret may have changed, so delete and re-create
			err = infracommon.DeleteDockerRegistrySecret(ctx, client, kconf, imagePath, v.VMProperties.CommonPf.PlatformConfig.AccessApi, names, nil)
			if err != nil {
				return err
			}
			err = k8smgmt.CreateAllNamespaces(ctx, client, names)
			if err != nil {
				return err
			}
			err = infracommon.CreateDockerRegistrySecret(ctx, client, kconf, imagePath, v.VMProperties.CommonPf.PlatformConfig.AccessApi, names, nil)
			if err != nil {
				return err
			}
		}
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		return k8smgmt.UpdateAppInst(ctx, v.VMProperties.CommonPf.PlatformConfig.AccessApi, client, names, app, appInst, flavor)
	case cloudcommon.DeploymentTypeHelm:
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

func DownloadVMImage(ctx context.Context, accessApi platform.AccessApi, imageName, imageUrl, md5Sum string) (outPath string, reterr error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "DownloadVMImage", "imageName", imageName, "imageUrl", imageUrl)

	fileExt, err := cloudcommon.GetFileNameWithExt(imageUrl)
	if err != nil {
		return "", err
	}
	filePath := FileDownloadDir + fileExt

	defer func() {
		if reterr != nil {
			// Stale file might be present if download fails/succeeds, deleting it
			cloudcommon.DeleteFile(filePath)
		}
	}()

	err = cloudcommon.DownloadFile(ctx, accessApi, imageUrl, cloudcommon.NoCreds, filePath, nil)
	if err != nil {
		return "", fmt.Errorf("error downloading image from %s, %v", imageUrl, err)
	}
	// Verify checksum
	if md5Sum != "" {
		fileMd5Sum, err := cloudcommon.Md5SumFile(filePath)
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

func ConvertQcowToVmdk(ctx context.Context, sourceFile string, size uint64) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ConvertQcowToVmdk", "sourceFile", sourceFile, "size", size, "timeout", qcowConvertTimeout)
	destFile := strings.TrimSuffix(sourceFile, filepath.Ext(sourceFile))
	destFile = destFile + ".vmdk"

	convertChan := make(chan string, 1)
	var convertErr string
	go func() {
		//resize to the correct size
		sizeInGB := fmt.Sprintf("%dG", size)
		log.SpanLog(ctx, log.DebugLevelInfra, "Resizing to", "size", sizeInGB)
		out, err := sh.Command("qemu-img", "resize", sourceFile, "--shrink", sizeInGB).CombinedOutput()

		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "qemu-img resize failed", "out", string(out), "err", err)
			convertChan <- fmt.Sprintf("qemu-img resize failed: %s %v", out, err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "doing qemu-img convert", "destFile", destFile)
		out, err = sh.Command("qemu-img", "convert", "-O", "vmdk", "-o", "subformat=streamOptimized", sourceFile, destFile).CombinedOutput()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "qemu-img convert failed", "out", string(out), "err", err)
			convertChan <- fmt.Sprintf("qemu-img convert failed: %s %v", out, err)
		} else {
			convertChan <- ""

		}
	}()
	select {
	case convertErr = <-convertChan:
	case <-time.After(qcowConvertTimeout):
		return "", fmt.Errorf("ConvertQcowToVmdk timed out")
	}
	if convertErr != "" {
		return "", errors.New(convertErr)
	}
	return destFile, nil
}

// reserveImageDownloadInProgress returns true if there was not already a download happening. If so
// the caller must call clearImageDownloadInProgress when done
func reserveImageDownloadInProgress(ctx context.Context, imageName string) bool {
	log.SpanLog(ctx, log.DebugLevelInfra, "reserveImageDownloadInProgress", "imageName", imageName)
	imageLock.Lock()
	defer imageLock.Unlock()
	if imageDownloadsInProgress[imageName] {
		log.SpanLog(ctx, log.DebugLevelInfra, "download already in progress", "imageName", imageName)
		return false
	}
	imageDownloadsInProgress[imageName] = true
	return true
}

func isImageDownloadInProgress(ctx context.Context, imageName string) bool {
	imageLock.Lock()
	defer imageLock.Unlock()
	return imageDownloadsInProgress[imageName]
}

func clearImageDownloadInProgress(ctx context.Context, imageName string) {
	log.SpanLog(ctx, log.DebugLevelInfra, "clearImageDownloadInProgress", "imageName", imageName)
	imageLock.Lock()
	defer imageLock.Unlock()
	delete(imageDownloadsInProgress, imageName)
}

func waitForImageDownloadInProgress(ctx context.Context, imageName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "waitForImageDownloadInProgress", "imageName", imageName)
	startTime := time.Now()
	for {
		log.SpanLog(ctx, log.DebugLevelInfra, "waiting to recheck isImageDownloadInProgress")
		time.Sleep(time.Second * 10)
		if !isImageDownloadInProgress(ctx, imageName) {
			return nil
		}
		elapsed := time.Since(startTime)
		log.SpanLog(ctx, log.DebugLevelInfra, "waiting for download", "imageName", imageName, "elapsed", elapsed, "timeout", maxWaitImageDownloadInProgress)
		if elapsed > maxWaitImageDownloadInProgress {
			log.SpanLog(ctx, log.DebugLevelInfra, "Error: waitForImageDownloadInProgress timed out", "imageName", imageName)
			return fmt.Errorf("waiting for downloading in progress timed out")
		}
	}
}

func (*VMPlatform) HandleFedAppInstCb(ctx context.Context, msg *edgeproto.FedAppInstEvent) {}
