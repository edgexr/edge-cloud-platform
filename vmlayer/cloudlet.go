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
	"fmt"

	"github.com/edgexr/edge-cloud-infra/chefmgmt"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	pf "github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
	"github.com/edgexr/edge-cloud/vmspec"

	ssh "github.com/mobiledgex/golang-ssh"
)

// VMDomain is to differentiate platform vs computing VMs and associated resources
type VMDomain string

const (
	VMDomainCompute  VMDomain = "compute"
	VMDomainPlatform VMDomain = "platform"
	VMDomainAny      VMDomain = "any" // used for matching only
)

var CloudletAccessToken = "CloudletAccessToken"
var CloudletNetworkNamesMap = "CloudletNetworkNamesMap"

func (v *VMPlatform) IsCloudletServicesLocal() bool {
	return false
}

func (v *VMPlatform) GetSanitizedCloudletName(key *edgeproto.CloudletKey) string {
	// Form platform VM name based on cloudletKey
	return v.VMProvider.NameSanitize(key.Name + "-" + key.Organization)
}

func (v *VMPlatform) GetPlatformVMName(key *edgeproto.CloudletKey) string {
	// Form platform VM name based on cloudletKey
	return v.GetSanitizedCloudletName(key) + "-pf"
}

func (v *VMPlatform) GetChefClientNameForCloudlet(cloudlet *edgeproto.Cloudlet) string {
	pfName := v.GetPlatformVMName(&cloudlet.Key)
	if cloudlet.Deployment == cloudcommon.DeploymentTypeKubernetes {
		pfName = pfName + "-master"
	}
	clientName := v.GetChefClientName(pfName)
	return clientName
}

func (v *VMPlatform) GetPlatformSubnetName(key *edgeproto.CloudletKey) string {
	return "mex-k8s-subnet-" + v.GetPlatformVMName(key)
}

func (v *VMPlatform) GetPlatformNodes(cloudlet *edgeproto.Cloudlet) []chefmgmt.ChefNodeInfo {
	nodes := []chefmgmt.ChefNodeInfo{}
	platformVMName := v.GetPlatformVMName(&cloudlet.Key)
	if cloudlet.Deployment == cloudcommon.DeploymentTypeDocker {
		nodes = append(nodes, chefmgmt.ChefNodeInfo{NodeName: platformVMName, NodeType: cloudcommon.NodeTypePlatformVM})
	} else {
		masterNode := platformVMName + "-master"
		nodes = append(nodes, chefmgmt.ChefNodeInfo{NodeName: masterNode, NodeType: cloudcommon.NodeTypePlatformK8sClusterMaster, Policy: chefmgmt.ChefPolicyK8s})
		for nn := uint32(1); nn <= chefmgmt.K8sWorkerNodeCount; nn++ {
			workerNode := fmt.Sprintf("%s-node-%d", platformVMName, nn)
			if nn == 1 {
				nodes = append(nodes, chefmgmt.ChefNodeInfo{NodeName: workerNode, NodeType: cloudcommon.NodeTypePlatformK8sClusterPrimaryNode, Policy: chefmgmt.ChefPolicyK8sWorker})
			} else {
				nodes = append(nodes, chefmgmt.ChefNodeInfo{NodeName: workerNode, NodeType: cloudcommon.NodeTypePlatformK8sClusterSecondaryNode, Policy: chefmgmt.ChefPolicyK8sWorker})
			}
		}
	}
	return nodes
}

// GetCloudletImageToUse decides what image to use based on
// 1) if MEX_OS_IMAGE is specified in properties and not default, use that
// 2) Use image specified on startup based on cloudlet config
func (v *VMPlatform) GetCloudletImageToUse(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) (string, error) {
	imgFromProps := v.VMProperties.GetCloudletOSImage()
	if imgFromProps != DefaultOSImageName {
		log.SpanLog(ctx, log.DebugLevelInfra, "using image from MEX_OS_IMAGE property", "imgFromProps", imgFromProps)
		return imgFromProps, nil
	}

	// imageBasePath is the path minus the file
	imageBasePath := v.VMProperties.CommonPf.PlatformConfig.CloudletVMImagePath
	if imageBasePath != "" {
		imageBasePath = DefaultCloudletVMImagePath
	}
	imageVersion := v.VMProperties.CommonPf.PlatformConfig.VMImageVersion
	if imageVersion == "" {
		imageVersion = MEXInfraVersion
	}
	imageName := GetCloudletVMImageName(imageVersion)
	cloudletImagePath := GetCloudletVMImagePath(imageBasePath, imageVersion, v.VMProvider.GetCloudletImageSuffix(ctx))
	log.SpanLog(ctx, log.DebugLevelInfra, "Getting cloudlet image from platform config", "cloudletImagePath", cloudletImagePath, "imageName", imageName, "imageVersion", imageVersion)
	sourceImageTime, md5Sum, err := infracommon.GetUrlInfo(ctx, v.VMProperties.CommonPf.PlatformConfig.AccessApi, cloudletImagePath)
	if err != nil {
		return "", fmt.Errorf("unable to get URL info for cloudlet image: %s - %v", v.VMProperties.CommonPf.PlatformConfig.CloudletVMImagePath, err)
	}
	var imageInfo infracommon.ImageInfo
	imageInfo.Md5sum = md5Sum
	imageInfo.SourceImageTime = sourceImageTime
	imageInfo.OsType = edgeproto.VmAppOsType_VM_APP_OS_LINUX
	imageInfo.ImagePath = cloudletImagePath
	imageInfo.ImageType = edgeproto.ImageType_IMAGE_TYPE_QCOW
	imageInfo.LocalImageName = imageName
	imageInfo.ImageCategory = infracommon.ImageCategoryPlatform
	return imageName, v.VMProvider.AddImageIfNotPresent(ctx, &imageInfo, updateCallback)
}

// setupPlatformVM:
//   * Downloads Cloudlet VM base image (if not-present)
//   * Brings up Platform VM (using vm provider stack)
//   * Sets up Security Group for access to Cloudlet
// Returns ssh client
func (v *VMPlatform) SetupPlatformVM(ctx context.Context, accessApi platform.AccessApi, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfFlavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupPlatformVM", "cloudlet", cloudlet)

	platformVmGroupName := v.GetPlatformVMName(&cloudlet.Key)
	_, err := v.GetCloudletImageToUse(ctx, updateCallback)
	if err != nil {
		return err
	}

	vms, err := v.getCloudletVMsSpec(ctx, accessApi, cloudlet, pfConfig, pfFlavor, updateCallback)
	if err != nil {
		return err
	}

	if cloudlet.Deployment == cloudcommon.DeploymentTypeDocker {
		updateCallback(edgeproto.UpdateTask, "Deploying Platform VM")

		_, err = v.OrchestrateVMsFromVMSpec(
			ctx,
			platformVmGroupName,
			vms,
			ActionCreate,
			updateCallback,
			WithNewSecurityGroup(infracommon.GetServerSecurityGroupName(platformVmGroupName)),
			WithAccessPorts("tcp:22", infracommon.RemoteCidrAll),
			WithSkipDefaultSecGrp(true),
			WithInitOrchestrator(true),
		)
	} else {
		updateCallback(edgeproto.UpdateTask, "Deploying Platform Cluster")

		subnetName := v.GetPlatformSubnetName(&cloudlet.Key)
		skipInfraSpecificCheck := false
		if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
			// It'll be end-users responsibility to make sure subnet range
			// is not confliciting with existing subnets
			skipInfraSpecificCheck = true
		}
		_, err = v.OrchestrateVMsFromVMSpec(
			ctx,
			platformVmGroupName,
			vms,
			ActionCreate,
			updateCallback,
			WithNewSecurityGroup(infracommon.GetServerSecurityGroupName(platformVmGroupName)),
			WithAccessPorts("tcp:22", infracommon.RemoteCidrAll),
			WithSkipDefaultSecGrp(true),
			WithNewSubnet(subnetName),
			WithSkipSubnetGateway(true),
			WithSkipInfraSpecificCheck(skipInfraSpecificCheck),
			WithInitOrchestrator(true),
			WithAntiAffinity(cloudlet.PlatformHighAvailability),
		)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error while creating platform VM", "vms request spec", vms)
		return err
	}

	// Copy client keys from vms so that it can be used to generate
	// cloudlet manifest
	for _, vm := range vms {
		if vm.ChefParams == nil {
			continue
		}
		cloudlet.ChefClientKey[vm.ChefParams.NodeName] = vm.ChefParams.ClientKey
	}

	updateCallback(edgeproto.UpdateTask, "Successfully Deployed Platform VM")

	return nil
}

func (v *VMPlatform) GetChefPlatformApiAccess(ctx context.Context, cloudlet *edgeproto.Cloudlet) (*chefmgmt.ChefApiAccess, error) {
	var chefApi chefmgmt.ChefApiAccess
	apiAddr, err := v.VMProvider.GetApiEndpointAddr(ctx)
	if err != nil {
		return nil, err
	}
	chefApi.ApiEndpoint = apiAddr
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_DIRECT_ACCESS && apiAddr != "" {
		gatewayAddr, err := v.VMProvider.GetExternalGateway(ctx, v.VMProperties.GetCloudletExternalNetwork())
		if err != nil {
			return nil, fmt.Errorf("unable to fetch gateway IP for external network: %s, %v",
				v.VMProperties.GetCloudletExternalNetwork(), err)
		}
		chefApi.ApiGateway = gatewayAddr
	}

	return &chefApi, nil
}

func (v *VMPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfFlavor *edgeproto.Flavor, caches *pf.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	var err error
	cloudletResourcesCreated := false
	log.SpanLog(ctx, log.DebugLevelInfra, "Creating cloudlet", "cloudletName", cloudlet.Key.Name)

	if !pfConfig.TestMode {
		err = v.VMProperties.CommonPf.InitCloudletSSHKeys(ctx, accessApi)
		if err != nil {
			return cloudletResourcesCreated, err
		}
	}
	v.VMProperties.Domain = VMDomainPlatform
	pc := infracommon.GetPlatformConfig(cloudlet, pfConfig, accessApi)
	err = v.InitProps(ctx, pc)
	if err != nil {
		return cloudletResourcesCreated, err
	}

	v.VMProvider.InitData(ctx, caches)

	stage := ProviderInitCreateCloudletDirect
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		stage = ProviderInitCreateCloudletRestricted
	}

	// Source OpenRC file to access openstack API endpoint
	updateCallback(edgeproto.UpdateTask, "Sourcing access variables")
	log.SpanLog(ctx, log.DebugLevelInfra, "Sourcing access variables", "region", pfConfig.Region, "cloudletKey", cloudlet.Key, "PhysicalName", cloudlet.PhysicalName)
	err = v.VMProvider.InitApiAccessProperties(ctx, accessApi, cloudlet.EnvVar)
	if err != nil {
		return cloudletResourcesCreated, err
	}

	// edge-cloud image already contains the certs
	if pfConfig.TlsCertFile != "" {
		crtFile, err := infracommon.GetDockerCrtFile(pfConfig.TlsCertFile)
		if err != nil {
			return cloudletResourcesCreated, err
		}
		pfConfig.TlsCertFile = crtFile
	}

	if pfConfig.ChefServerPath == "" {
		pfConfig.ChefServerPath = chefmgmt.DefaultChefServerPath
	}

	if cloudlet.InfraConfig.ExternalNetworkName != "" {
		v.VMProperties.SetCloudletExternalNetwork(cloudlet.InfraConfig.ExternalNetworkName)
	}

	// For real setups, ansible will always specify the correct
	// cloudlet container and vm image paths to the controller.
	// But for local testing convenience, we default to the hard-coded
	// ones if not specified.
	if pfConfig.ContainerRegistryPath == "" {
		pfConfig.ContainerRegistryPath = infracommon.DefaultContainerRegistryPath
	}

	// save caches needed for flavors
	v.Caches = caches
	v.GPUConfig = cloudlet.GpuConfig

	err = v.VMProvider.InitProvider(ctx, caches, stage, updateCallback)
	if err != nil {
		return cloudletResourcesCreated, err
	}

	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	chefApi, err := v.GetChefPlatformApiAccess(ctx, cloudlet)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	nodes := v.GetPlatformNodes(cloudlet)

	chefClient := v.VMProperties.GetChefClient()
	if chefClient == nil {
		return cloudletResourcesCreated, fmt.Errorf("Chef client is not initialized")
	}

	// once we get this far we should ensure delete succeeds on a failure
	cloudletResourcesCreated = true

	cloudlet.ChefClientKey = make(map[string]string)
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		for nn, node := range nodes {
			chefAttributes, err := chefmgmt.GetChefPlatformAttributes(ctx, cloudlet, pfConfig, &nodes[nn], chefApi, nodes)
			if err != nil {
				return cloudletResourcesCreated, err
			}
			clientName := v.GetChefClientName(node.NodeName)
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Creating chef client %s with cloudlet attributes", clientName))
			chefParams := v.GetServerChefParams(clientName, "", node.Policy, chefAttributes)
			clientKey, err := chefmgmt.ChefClientCreate(ctx, chefClient, chefParams)
			if err != nil {
				return cloudletResourcesCreated, err
			}
			// Store client key in cloudlet obj
			cloudlet.ChefClientKey[clientName] = clientKey
		}
		// Return, as end-user will setup the platform VM
		return cloudletResourcesCreated, nil
	}

	err = v.SetupPlatformVM(ctx, accessApi, cloudlet, pfConfig, pfFlavor, updateCallback)
	if err != nil {
		return cloudletResourcesCreated, err
	}

	return cloudletResourcesCreated, chefmgmt.GetChefRunStatus(ctx, chefClient, v.GetChefClientNameForCloudlet(cloudlet), cloudlet, pfConfig, accessApi, updateCallback)
}

func (v *VMPlatform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	var err error
	v.VMProperties.Domain = VMDomainPlatform
	pc := infracommon.GetPlatformConfig(cloudlet, pfConfig, accessApi)
	err = v.InitProps(ctx, pc)
	if err != nil {
		return err
	}
	chefAuth, err := accessApi.GetChefAuthKey(ctx)
	if err != nil {
		return err
	}

	chefServerPath := pfConfig.ChefServerPath
	if chefServerPath == "" {
		chefServerPath = chefmgmt.DefaultChefServerPath
	}

	chefClient, err := chefmgmt.GetChefClient(ctx, chefAuth.ApiKey, chefServerPath)
	if err != nil {
		return err
	}
	return chefmgmt.GetChefRunStatus(ctx, chefClient, v.GetChefClientNameForCloudlet(cloudlet), cloudlet, pfConfig, accessApi, updateCallback)
}

func (v *VMPlatform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	// Update envvars
	v.VMProperties.CommonPf.Properties.UpdatePropsFromVars(ctx, cloudlet.EnvVar)
	// Update GPU config
	v.GPUConfig = cloudlet.GpuConfig
	return nil
}

func (v *VMPlatform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	log.DebugLog(log.DebugLevelInfra, "update VMPlatform TrustPolicy", "policy", TrustPolicy)
	egressRestricted := TrustPolicy.Key.Name != ""
	var result OperationInitResult
	ctx, result, err := v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}
	rootlbClients, err := v.GetAllRootLBClients(ctx)
	if err != nil {
		return fmt.Errorf("Unable to get rootlb clients - %v", err)
	}
	return v.VMProvider.ConfigureCloudletSecurityRules(ctx, egressRestricted, TrustPolicy, rootlbClients, ActionUpdate, edgeproto.DummyUpdateCallback)
}

func (v *VMPlatform) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterInstKey *edgeproto.ClusterInstKey) error {
	log.DebugLog(log.DebugLevelInfra, "update VMPlatform TrustPolicyException", "policy", TrustPolicyException)

	rootlbClients, err := v.GetRootLBClientForClusterInstKey(ctx, clusterInstKey)
	if err != nil {
		return fmt.Errorf("Unable to get rootlb clients - %v", err)
	}
	// Only create supported, update not allowed.
	return v.VMProvider.ConfigureTrustPolicyExceptionSecurityRules(ctx, TrustPolicyException, rootlbClients, ActionCreate, edgeproto.DummyUpdateCallback)
}

func (v *VMPlatform) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterInstKey *edgeproto.ClusterInstKey) error {
	log.DebugLog(log.DebugLevelInfra, "Delete VMPlatform TrustPolicyException", "policyKey", TrustPolicyExceptionKey)

	rootlbClients, err := v.GetRootLBClientForClusterInstKey(ctx, clusterInstKey)
	if err != nil {
		return fmt.Errorf("Unable to get rootlb clients - %v", err)
	}
	// Note when Delete gets called using a task-worker approach, we don't actually have the TrustPolicyException object that was deleted, we only have the key.
	TrustPolicyException := edgeproto.TrustPolicyException{
		Key: *TrustPolicyExceptionKey,
	}
	return v.VMProvider.ConfigureTrustPolicyExceptionSecurityRules(ctx, &TrustPolicyException, rootlbClients, ActionDelete, edgeproto.DummyUpdateCallback)
}

func (v *VMPlatform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *pf.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Deleting cloudlet", "cloudletName", cloudlet.Key.Name)

	updateCallback(edgeproto.UpdateTask, "Deleting cloudlet")

	if !pfConfig.TestMode {
		err := v.VMProperties.CommonPf.InitCloudletSSHKeys(ctx, accessApi)
		if err != nil {
			return err
		}
	}

	v.VMProperties.Domain = VMDomainPlatform
	pc := infracommon.GetPlatformConfig(cloudlet, pfConfig, accessApi)
	err := v.InitProps(ctx, pc)
	if err != nil {
		// ignore this error, as no creation would've happened on infra, so nothing to delete
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to init props", "cloudletName", cloudlet.Key.Name, "err", err)
		return nil
	}

	v.VMProvider.InitData(ctx, caches)

	// Source OpenRC file to access openstack API endpoint
	err = v.VMProvider.InitApiAccessProperties(ctx, accessApi, cloudlet.EnvVar)
	if err != nil {
		// ignore this error, as no creation would've happened on infra, so nothing to delete
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to source platform variables", "cloudletName", cloudlet.Key.Name, "err", err)
		return nil
	}

	if pfConfig.ChefServerPath == "" {
		pfConfig.ChefServerPath = chefmgmt.DefaultChefServerPath
	}

	v.Caches = caches
	v.VMProvider.InitProvider(ctx, caches, ProviderInitDeleteCloudlet, updateCallback)

	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	chefClient := v.VMProperties.GetChefClient()
	if chefClient == nil {
		return fmt.Errorf("Chef client is not initialzied")
	}

	rootLBName := v.GetRootLBName(&cloudlet.Key)
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_DIRECT_ACCESS {
		vmGroupName := v.GetPlatformVMName(&cloudlet.Key)
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Deleting RootLB %s", rootLBName))
		err = v.VMProvider.DeleteVMs(ctx, rootLBName)
		if err != nil && err.Error() != ServerDoesNotExistError {
			return fmt.Errorf("DeleteCloudlet error: %v", err)
		}
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Deleting Platform VMs %s", vmGroupName))
		err = v.VMProvider.DeleteVMs(ctx, vmGroupName)
		if err != nil && err.Error() != ServerDoesNotExistError {
			return fmt.Errorf("DeleteCloudlet error: %v", err)
		}
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Deleting Cloudlet Security Rules %s", rootLBName))

		// as delete cloudlet is called from the controller only, there is no need for
		// rootlb ssh clients so just pass an empty map.  We have deleted all rootLB VMs anyway.
		rootlbClients := make(map[string]ssh.Client)
		err = v.VMProvider.ConfigureCloudletSecurityRules(ctx, false, &edgeproto.TrustPolicy{}, rootlbClients, ActionDelete, edgeproto.DummyUpdateCallback)
		if err != nil {
			if v.VMProperties.IptablesBasedFirewall {
				// iptables based security rules can fail on one clusterInst LB or other VM not responding
				log.SpanLog(ctx, log.DebugLevelInfra, "Warning: error in ConfigureCloudletSecurityRules", "err", err)
			} else {
				return err
			}
		}
	}

	nodes := v.GetPlatformNodes(cloudlet)
	for _, node := range nodes {
		clientName := v.GetChefClientName(node.NodeName)
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Deleting %s client from Chef Server", clientName))
		err = chefmgmt.ChefClientDelete(ctx, chefClient, clientName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete client from Chef Server", "clientName", clientName, "err", err)
		}
	}

	// Delete rootLB object from Chef Server
	clientName := v.GetChefClientName(rootLBName)
	updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Deleting %s client from Chef Server", clientName))
	err = chefmgmt.ChefClientDelete(ctx, chefClient, clientName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete client from Chef Server", "clientName", clientName, "err", err)
	}

	// Delete FQDN of shared RootLB
	rootLbFqdn := rootLBName
	if cloudlet.RootLbFqdn != "" {
		rootLbFqdn = cloudlet.RootLbFqdn
	}
	if err = v.VMProperties.CommonPf.DeleteDNSRecords(ctx, rootLbFqdn); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete sharedRootLB DNS record", "fqdn", rootLbFqdn, "err", err)
	}

	// Not sure if it's safe to remove vars from Vault due to testing/virtual cloudlets,
	// so leaving them in Vault for the time being. We can always delete them manually

	return nil
}

func (v *VMPlatform) DeleteCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Deleting access vars from vault", "cloudletName", cloudlet.Key.Name)

	updateCallback(edgeproto.UpdateTask, "Deleting access vars from secure secrets storage")

	path := v.VMProvider.GetVaultCloudletAccessPath(&cloudlet.Key, pfConfig.Region, cloudlet.PhysicalName)
	if path != "" {
		err := infracommon.DeleteDataFromVault(vaultConfig, path)
		if err != nil {
			return fmt.Errorf("Failed to delete access vars from vault: %v", err)
		}
	}
	return nil
}

func (v *VMPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	return v.VMProvider.SaveCloudletAccessVars(ctx, cloudlet, accessVarsIn, pfConfig, vaultConfig, updateCallback)
}

func (v *VMPlatform) GetFeatures() *platform.Features {
	return v.VMProvider.GetFeatures()
}

func (v *VMPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}
	return v.VMProvider.GatherCloudletInfo(ctx, info)
}

func (v *VMPlatform) getCloudletVMsSpec(ctx context.Context, accessApi platform.AccessApi, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfFlavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) ([]*VMRequestSpec, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletVMsSpec", "region", pfConfig.Region, "cloudletKey", cloudlet.Key, "pfFlavor", pfFlavor)

	var err error
	// edge-cloud image already contains the certs
	if pfConfig.TlsCertFile != "" {
		crtFile, err := infracommon.GetDockerCrtFile(pfConfig.TlsCertFile)
		if err != nil {
			return nil, err
		}
		pfConfig.TlsCertFile = crtFile
	}

	if pfConfig.ContainerRegistryPath == "" {
		pfConfig.ContainerRegistryPath = infracommon.DefaultContainerRegistryPath
	}

	if cloudlet.InfraConfig.ExternalNetworkName != "" {
		v.VMProperties.SetCloudletExternalNetwork(cloudlet.InfraConfig.ExternalNetworkName)
	}

	flavorName := cloudlet.InfraConfig.FlavorName
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_DIRECT_ACCESS {
		// Validate infra external network provided by user
		if cloudlet.InfraConfig.ExternalNetworkName != "" {
			nets, err := v.VMProvider.GetNetworkList(ctx)
			if err != nil {
				return nil, err
			}

			found := false
			for _, n := range nets {
				if n == cloudlet.InfraConfig.ExternalNetworkName {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("cannot find infra external network %s", cloudlet.InfraConfig.ExternalNetworkName)
			}
		}
		additionalNets := v.VMProperties.GetNetworksByType(ctx, []NetworkType{NetworkTypeExternalAdditionalPlatform})
		if len(additionalNets) > 0 {
			err = v.VMProvider.ValidateAdditionalNetworks(ctx, additionalNets)
			if err != nil {
				return nil, err
			}
		}

		flavorList, err := v.VMProvider.GetFlavorList(ctx)
		if err != nil {
			return nil, err
		}
		if cloudlet.InfraConfig.FlavorName == "" {
			var spec *vmspec.VMCreationSpec = &vmspec.VMCreationSpec{}
			cli := edgeproto.CloudletInfo{}
			cli.Flavors = flavorList
			cli.Key = cloudlet.Key
			if len(flavorList) == 0 {
				flavInfo, err := v.GetDefaultRootLBFlavor(ctx)
				if err != nil {
					return nil, fmt.Errorf("unable to find DefaultShared RootLB flavor: %v", err)
				}
				spec.FlavorName = flavInfo.Name
			} else {
				restbls := v.GetResTablesForCloudlet(ctx, &cli.Key)
				spec, err = vmspec.GetVMSpec(ctx, *pfFlavor, cli, restbls)
				if err != nil {
					return nil, fmt.Errorf("unable to find VM spec for Shared RootLB: %v", err)
				}
			}
			flavorName = spec.FlavorName
		} else {
			// Validate infra flavor name provided by user
			for _, finfo := range flavorList {
				if finfo.Name == cloudlet.InfraConfig.FlavorName {
					flavorName = cloudlet.InfraConfig.FlavorName
					break
				}
			}
			if flavorName == "" {
				return nil, fmt.Errorf("invalid InfraConfig.FlavorName, does not exist")
			}
		}

	}
	if flavorName == "" {
		// give some default flavor name, user can fix this later
		flavorName = "<ADD_FLAVOR_HERE>"
	}

	platformVmName := v.GetPlatformVMName(&cloudlet.Key)
	pfImageName := v.VMProperties.GetCloudletOSImage()
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_DIRECT_ACCESS {
		pfImageName, err = v.GetCloudletImageToUse(ctx, updateCallback)
		if err != nil {
			return nil, err
		}
	}

	// Setup Chef parameters
	chefApi, err := v.GetChefPlatformApiAccess(ctx, cloudlet)
	if err != nil {
		return nil, err
	}
	nodes := v.GetPlatformNodes(cloudlet)
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no platform nodes")
	}
	chefAttributes, err := chefmgmt.GetChefPlatformAttributes(ctx, cloudlet, pfConfig, &nodes[0], chefApi, nodes)
	if err != nil {
		return nil, err
	}
	if cloudlet.ChefClientKey == nil {
		return nil, fmt.Errorf("missing chef client key")
	}
	for _, node := range nodes {
		clientName := v.GetChefClientName(node.NodeName)
		if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_DIRECT_ACCESS {
			cloudlet.ChefClientKey[clientName] = ""
		}
		if _, ok := cloudlet.ChefClientKey[clientName]; !ok {
			return nil, fmt.Errorf("missing chef client key for %s", clientName)
		}
	}
	clientName := v.GetChefClientName(platformVmName)
	var vms []*VMRequestSpec
	subnetName := v.GetPlatformSubnetName(&cloudlet.Key)
	netTypes := []NetworkType{NetworkTypeExternalAdditionalPlatform}
	addNets := v.VMProperties.GetNetworksByType(ctx, netTypes)
	if cloudlet.Deployment == cloudcommon.DeploymentTypeDocker {
		chefParams := v.GetServerChefParams(clientName, cloudlet.ChefClientKey[clientName], chefmgmt.ChefPolicyDocker, chefAttributes)
		platvm, err := v.GetVMRequestSpec(
			ctx,
			cloudcommon.NodeTypePlatformVM,
			platformVmName,
			flavorName,
			pfImageName,
			true, //connect external
			WithChefParams(chefParams),
			WithAccessKey(pfConfig.CrmAccessPrivateKey),
			WithAdditionalNetworks(addNets),
		)
		if err != nil {
			return nil, err
		}
		vms = append(vms, platvm)
	} else {
		for _, node := range nodes {
			clientName := v.GetChefClientName(node.NodeName)
			masterAttributes := chefAttributes
			masterAttributes["tags"] = chefmgmt.GetChefCloudletTags(cloudlet, pfConfig, node.NodeType)
			chefParams := v.GetServerChefParams(clientName, cloudlet.ChefClientKey[clientName], node.Policy, chefAttributes)
			ak := pfConfig.CrmAccessPrivateKey
			if node.NodeType == cloudcommon.NodeTypePlatformK8sClusterSecondaryNode {
				ak = pfConfig.SecondaryCrmAccessPrivateKey
			}
			vmSpec, err := v.GetVMRequestSpec(
				ctx,
				node.NodeType,
				node.NodeName,
				flavorName,
				pfImageName,
				true, //connect external
				WithSubnetConnection(subnetName),
				WithChefParams(chefParams),
				WithAccessKey(ak),
			)
			if err != nil {
				return nil, err
			}
			vms = append(vms, vmSpec)
		}
	}

	return vms, nil
}

func (v *VMPlatform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, pfFlavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest", "cloudletName", cloudlet.Key.Name)

	if cloudlet.ChefClientKey == nil {
		return nil, fmt.Errorf("unable to find chef client key")
	}

	v.VMProperties.Domain = VMDomainPlatform
	pc := infracommon.GetPlatformConfig(cloudlet, pfConfig, accessApi)
	err := v.InitProps(ctx, pc)
	if err != nil {
		return nil, err
	}

	v.VMProvider.InitData(ctx, caches)

	err = v.VMProvider.InitApiAccessProperties(ctx, accessApi, cloudlet.EnvVar)
	if err != nil {
		return nil, err
	}
	platvms, err := v.getCloudletVMsSpec(ctx, accessApi, cloudlet, pfConfig, pfFlavor, edgeproto.DummyUpdateCallback)
	if err != nil {
		return nil, err
	}

	platformVmName := v.GetPlatformVMName(&cloudlet.Key)

	skipInfraSpecificCheck := false
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		// It'll be end-users responsibility to make sure subnet range
		// is not confliciting with existing subnets
		skipInfraSpecificCheck = true
	}

	var gp *VMGroupOrchestrationParams
	if cloudlet.Deployment == cloudcommon.DeploymentTypeDocker {
		gp, err = v.GetVMGroupOrchestrationParamsFromVMSpec(
			ctx,
			platformVmName,
			platvms,
			WithNewSecurityGroup(infracommon.GetServerSecurityGroupName(platformVmName)),
			WithAccessPorts("tcp:22", infracommon.RemoteCidrAll),
			WithSkipDefaultSecGrp(true),
			WithSkipInfraSpecificCheck(skipInfraSpecificCheck),
		)
	} else {
		subnetName := v.GetPlatformSubnetName(&cloudlet.Key)
		gp, err = v.GetVMGroupOrchestrationParamsFromVMSpec(
			ctx,
			platformVmName,
			platvms,
			WithNewSecurityGroup(infracommon.GetServerSecurityGroupName(platformVmName)),
			WithAccessPorts("tcp:22", infracommon.RemoteCidrAll),
			WithNewSubnet(subnetName),
			WithSkipDefaultSecGrp(true),
			WithSkipSubnetGateway(true),
			WithSkipInfraSpecificCheck(skipInfraSpecificCheck),
		)
	}
	if err != nil {
		return nil, err
	}
	imgPath := GetCloudletVMImagePath(pfConfig.CloudletVmImagePath, cloudlet.VmImageVersion, v.VMProvider.GetCloudletImageSuffix(ctx))
	manifest, err := v.VMProvider.GetCloudletManifest(ctx, platformVmName, imgPath, gp)
	if err != nil {
		return nil, err
	}
	return &edgeproto.CloudletManifest{
		Manifest: manifest,
	}, nil
}

func (v *VMPlatform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	return v.VMProvider.VerifyVMs(ctx, vms)
}

func (v *VMPlatform) GetCloudletProps(ctx context.Context) (*edgeproto.CloudletProps, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletProps")

	props := edgeproto.CloudletProps{}
	props.Properties = make(map[string]*edgeproto.PropertyInfo)
	for k, v := range VMProviderProps {
		val := *v
		props.Properties[k] = &val
	}
	for k, v := range infracommon.InfraCommonProps {
		val := *v
		props.Properties[k] = &val
	}
	providerProps, err := v.VMProvider.GetProviderSpecificProps(ctx)
	if err != nil {
		return nil, err
	}
	for k, v := range providerProps {
		val := *v
		props.Properties[k] = &val
	}
	return &props, nil
}

func (v *VMPlatform) ActiveChanged(ctx context.Context, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChanged", "platformActive", platformActive)
	if !platformActive {
		// unexpected as this is not currently supported
		log.SpanLog(ctx, log.DebugLevelInfra, "platform unexpectedly transitioned to inactive")
		return fmt.Errorf("platform unexpectedly transitioned to inactive")
	}
	var err error
	err = v.VMProvider.ActiveChanged(ctx, platformActive)
	if err != nil {
		log.FatalLog("Error in provider ActiveChanged - %v", err)
	}
	ctx, _, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to init context for cleanup", "err", err)
		return err
	}
	infracommon.HandlePlatformSwitchToActive(ctx, v.VMProperties.CommonPf.PlatformConfig.CloudletKey, v.Caches, v.cleanupClusterInst, v.cleanupAppInst)
	return nil
}

func (v *VMPlatform) NameSanitize(name string) string {
	return v.VMProvider.NameSanitize(name)
}
