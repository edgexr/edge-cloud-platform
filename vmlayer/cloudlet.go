package vmlayer

import (
	"context"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/chefmgmt"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	"github.com/mobiledgex/edge-cloud/vmspec"
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

func (v *VMPlatform) GetPlatformNodes(cloudlet *edgeproto.Cloudlet) []string {
	nodes := []string{}
	platformVMName := v.GetPlatformVMName(&cloudlet.Key)
	if cloudlet.Deployment == cloudcommon.DeploymentTypeDocker {
		nodes = append(nodes, platformVMName)
	} else {
		masterNode := platformVMName + "-master"
		nodes = append(nodes, masterNode)
		for nn := uint32(1); nn <= chefmgmt.K8sWorkerNodeCount; nn++ {
			workerNode := fmt.Sprintf("%s-node-%d", platformVMName, nn)
			nodes = append(nodes, workerNode)
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

	platformVmName := v.GetPlatformVMName(&cloudlet.Key)
	_, err := v.GetCloudletImageToUse(ctx, updateCallback)
	if err != nil {
		return err
	}

	updateCallback(edgeproto.UpdateTask, "Deploying Platform VM")

	vms, err := v.getCloudletVMsSpec(ctx, accessApi, cloudlet, pfConfig, pfFlavor, updateCallback)
	if err != nil {
		return err
	}

	if cloudlet.Deployment == cloudcommon.DeploymentTypeDocker {
		_, err = v.OrchestrateVMsFromVMSpec(
			ctx,
			platformVmName,
			vms,
			ActionCreate,
			updateCallback,
			WithNewSecurityGroup(infracommon.GetServerSecurityGroupName(platformVmName)),
			WithAccessPorts("tcp:22", infracommon.RemoteCidrAll),
			WithSkipDefaultSecGrp(true),
			WithInitOrchestrator(true),
		)
	} else {
		subnetName := v.GetPlatformSubnetName(&cloudlet.Key)
		skipInfraSpecificCheck := false
		if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
			// It'll be end-users responsibility to make sure subnet range
			// is not confliciting with existing subnets
			skipInfraSpecificCheck = true
		}
		_, err = v.OrchestrateVMsFromVMSpec(
			ctx,
			platformVmName,
			vms,
			ActionCreate,
			updateCallback,
			WithNewSecurityGroup(infracommon.GetServerSecurityGroupName(platformVmName)),
			WithAccessPorts("tcp:22", infracommon.RemoteCidrAll),
			WithSkipDefaultSecGrp(true),
			WithNewSubnet(subnetName),
			WithSkipSubnetGateway(true),
			WithSkipInfraSpecificCheck(skipInfraSpecificCheck),
			WithInitOrchestrator(true),
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

func (v *VMPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfFlavor *edgeproto.Flavor, caches *pf.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	var err error

	log.SpanLog(ctx, log.DebugLevelInfra, "Creating cloudlet", "cloudletName", cloudlet.Key.Name)

	if !pfConfig.TestMode {
		err = v.VMProperties.CommonPf.InitCloudletSSHKeys(ctx, accessApi)
		if err != nil {
			return err
		}
	}
	v.VMProperties.Domain = VMDomainPlatform
	pc := infracommon.GetPlatformConfig(cloudlet, pfConfig, accessApi)
	err = v.InitProps(ctx, pc)
	if err != nil {
		return err
	}

	v.VMProvider.InitData(ctx, caches)

	stage := ProviderInitCreateCloudletDirect
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		stage = ProviderInitCreateCloudletRestricted
	}

	// Source OpenRC file to access openstack API endpoint
	updateCallback(edgeproto.UpdateTask, "Sourcing access variables")
	log.SpanLog(ctx, log.DebugLevelInfra, "Sourcing access variables", "region", pfConfig.Region, "cloudletKey", cloudlet.Key, "PhysicalName", cloudlet.PhysicalName)
	err = v.VMProvider.InitApiAccessProperties(ctx, accessApi, cloudlet.EnvVar, stage)
	if err != nil {
		return err
	}

	// edge-cloud image already contains the certs
	if pfConfig.TlsCertFile != "" {
		crtFile, err := infracommon.GetDockerCrtFile(pfConfig.TlsCertFile)
		if err != nil {
			return err
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
		return err
	}
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}
	chefApi, err := v.GetChefPlatformApiAccess(ctx, cloudlet)
	if err != nil {
		return err
	}
	chefAttributes, err := chefmgmt.GetChefPlatformAttributes(ctx, cloudlet, pfConfig, cloudcommon.VMTypePlatform, chefApi)
	if err != nil {
		return err
	}

	chefClient := v.VMProperties.GetChefClient()
	if chefClient == nil {
		return fmt.Errorf("Chef client is not initialized")
	}

	chefPolicy := chefmgmt.ChefPolicyDocker
	if cloudlet.Deployment == cloudcommon.DeploymentTypeKubernetes {
		chefPolicy = chefmgmt.ChefPolicyK8s
	}
	cloudlet.ChefClientKey = make(map[string]string)
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		nodes := v.GetPlatformNodes(cloudlet)
		for _, nodeName := range nodes {
			clientName := v.GetChefClientName(nodeName)
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Creating chef client %s with cloudlet attributes", clientName))
			chefParams := v.GetServerChefParams(clientName, "", chefPolicy, chefAttributes)
			clientKey, err := chefmgmt.ChefClientCreate(ctx, chefClient, chefParams)
			if err != nil {
				return err
			}
			// Store client key in cloudlet obj
			cloudlet.ChefClientKey[clientName] = clientKey
		}
		// Return, as end-user will setup the platform VM
		return nil
	}

	err = v.SetupPlatformVM(ctx, accessApi, cloudlet, pfConfig, pfFlavor, updateCallback)
	if err != nil {
		return err
	}

	return chefmgmt.GetChefRunStatus(ctx, chefClient, v.GetChefClientNameForCloudlet(cloudlet), cloudlet, pfConfig, accessApi, updateCallback)
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
	err = v.VMProvider.InitApiAccessProperties(ctx, accessApi, cloudlet.EnvVar, ProviderInitDeleteCloudlet)
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
		nodes := v.GetPlatformNodes(cloudlet)
		for _, nodeName := range nodes {
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Deleting PlatformVM %s", nodeName))
			err = v.VMProvider.DeleteVMs(ctx, nodeName)
			if err != nil {
				return fmt.Errorf("DeleteCloudlet error: %v", err)
			}
		}
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Deleting RootLB %s", rootLBName))
		err = v.VMProvider.DeleteVMs(ctx, rootLBName)
		if err != nil {
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
	for _, nodeName := range nodes {
		clientName := v.GetChefClientName(nodeName)
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
	if err = v.VMProperties.CommonPf.DeleteDNSRecords(ctx, rootLBName); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete sharedRootLB DNS record", "fqdn", rootLBName, "err", err)
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
	chefAttributes, err := chefmgmt.GetChefPlatformAttributes(ctx, cloudlet, pfConfig, cloudcommon.VMTypePlatform, chefApi)
	if err != nil {
		return nil, err
	}
	if cloudlet.ChefClientKey == nil {
		return nil, fmt.Errorf("missing chef client key")
	}

	nodes := v.GetPlatformNodes(cloudlet)
	for _, nodeName := range nodes {
		clientName := v.GetChefClientName(nodeName)
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
			cloudcommon.VMTypePlatform,
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
		for _, nodeName := range nodes {
			clientName := v.GetChefClientName(nodeName)
			var vmSpec *VMRequestSpec
			if strings.HasSuffix(nodeName, "-master") {
				masterAttributes := chefAttributes
				masterAttributes["tags"] = chefmgmt.GetChefCloudletTags(cloudlet, pfConfig, cloudcommon.VMTypePlatformClusterMaster)
				chefParams := v.GetServerChefParams(clientName, cloudlet.ChefClientKey[clientName], chefmgmt.ChefPolicyK8s, chefAttributes)
				vmSpec, err = v.GetVMRequestSpec(
					ctx,
					cloudcommon.VMTypeClusterMaster,
					nodeName,
					flavorName,
					pfImageName,
					true, //connect external
					WithSubnetConnection(subnetName),
					WithChefParams(chefParams),
					WithAccessKey(pfConfig.CrmAccessPrivateKey),
				)
			} else {
				nodeAttributes := make(map[string]interface{})
				nodeAttributes["tags"] = chefmgmt.GetChefCloudletTags(cloudlet, pfConfig, cloudcommon.VMTypePlatformClusterNode)
				chefParams := v.GetServerChefParams(clientName, cloudlet.ChefClientKey[clientName], chefmgmt.ChefPolicyK8s, nodeAttributes)
				vmSpec, err = v.GetVMRequestSpec(ctx,
					cloudcommon.VMTypeClusterK8sNode,
					nodeName,
					flavorName,
					pfImageName,
					true, //connect external
					WithSubnetConnection(subnetName),
					WithChefParams(chefParams),
					WithAccessKey(pfConfig.CrmAccessPrivateKey),
				)
			}
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

	err = v.VMProvider.InitApiAccessProperties(ctx, accessApi, cloudlet.EnvVar, ProviderInitGetVmSpec)
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
