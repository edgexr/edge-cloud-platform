package vmlayer

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/chefmgmt"
	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	"github.com/mobiledgex/edge-cloud/vault"
	"github.com/mobiledgex/edge-cloud/vmspec"
)

const (
	// Platform services
	ServiceTypeCRM                = "crmserver"
	ServiceTypeShepherd           = "shepherd"
	ServiceTypeCloudletPrometheus = intprocess.PrometheusContainer
	K8sMasterNodeCount            = 1
	K8sWorkerNodeCount            = 2
)

var PlatformServices = []string{
	ServiceTypeCRM,
	ServiceTypeShepherd,
	ServiceTypeCloudletPrometheus,
}

// VMDomain is to differentiate platform vs computing VMs and associated resources
type VMDomain string

const (
	VMDomainCompute  VMDomain = "compute"
	VMDomainPlatform VMDomain = "platform"
	VMDomainAny      VMDomain = "any" // used for matching only
)

func (v *VMPlatform) GetPlatformVMName(key *edgeproto.CloudletKey) string {
	// Form platform VM name based on cloudletKey
	return v.VMProvider.NameSanitize(key.Name + "-" + key.Organization + "-pf")
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
		for nn := uint32(1); nn <= K8sWorkerNodeCount; nn++ {
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
	log.SpanLog(ctx, log.DebugLevelInfra, "Getting cloudlet image from platform config", "CloudletVMImagePath", v.VMProperties.CommonPf.PlatformConfig.CloudletVMImagePath, "version", v.VMProperties.CommonPf.PlatformConfig.VMImageVersion)
	return v.VMProvider.AddCloudletImageIfNotPresent(ctx, v.VMProperties.CommonPf.PlatformConfig.CloudletVMImagePath, v.VMProperties.CommonPf.PlatformConfig.VMImageVersion, updateCallback)
}

// setupPlatformVM:
//   * Downloads Cloudlet VM base image (if not-present)
//   * Brings up Platform VM (using vm provider stack)
//   * Sets up Security Group for access to Cloudlet
// Returns ssh client
func (v *VMPlatform) SetupPlatformVM(ctx context.Context, vaultConfig *vault.Config, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfFlavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupPlatformVM", "cloudlet", cloudlet)

	platformVmName := v.GetPlatformVMName(&cloudlet.Key)
	_, err := v.GetCloudletImageToUse(ctx, updateCallback)
	if err != nil {
		return err
	}

	updateCallback(edgeproto.UpdateTask, "Deploying Platform VM")

	vms, err := v.GetCloudletVMsSpec(ctx, vaultConfig, cloudlet, pfConfig, pfFlavor, updateCallback)
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
			WithNewSecurityGroup(GetServerSecurityGroupName(platformVmName)),
			WithAccessPorts("tcp:22"),
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
			WithNewSecurityGroup(GetServerSecurityGroupName(platformVmName)),
			WithAccessPorts("tcp:22"),
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

func (v *VMPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfFlavor *edgeproto.Flavor, caches *pf.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	var err error

	log.SpanLog(ctx, log.DebugLevelInfra, "Creating cloudlet", "cloudletName", cloudlet.Key.Name)

	v.VMProperties.CommonPf = &infracommon.CommonPlatform{}
	vaultConfig, err := vault.BestConfig(pfConfig.VaultAddr, vault.WithEnvMap(pfConfig.EnvVar))
	if err != nil {
		return err
	}

	if !pfConfig.TestMode {
		err = v.InitCloudletSSHKeys(ctx, vaultConfig)
		if err != nil {
			return err
		}
	}

	v.VMProperties.Domain = VMDomainPlatform
	pc := infracommon.GetPlatformConfig(cloudlet, pfConfig)
	err = v.InitProps(ctx, pc, vaultConfig)
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
	err = v.VMProvider.InitApiAccessProperties(ctx, &cloudlet.Key, pfConfig.Region, cloudlet.PhysicalName, vaultConfig, cloudlet.EnvVar, stage)
	if err != nil {
		return err
	}

	// edge-cloud image already contains the certs
	if pfConfig.TlsCertFile != "" {
		crtFile, err := GetDockerCrtFile(pfConfig.TlsCertFile)
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

	err = v.VMProvider.InitProvider(ctx, caches, stage, updateCallback)
	if err != nil {
		return err
	}

	chefAttributes, err := v.GetChefPlatformAttributes(ctx, cloudlet, pfConfig)
	if err != nil {
		return err
	}

	chefClient := v.VMProperties.GetChefClient()
	if chefClient == nil {
		return fmt.Errorf("Chef client is not initialzied")
	}

	chefPolicy := chefmgmt.ChefPolicyDocker
	if cloudlet.Deployment == cloudcommon.DeploymentTypeKubernetes {
		chefPolicy = chefmgmt.ChefPolicyK8s
	}
	cloudlet.ChefClientKey = make(map[string]string)
	platformVMName := v.GetPlatformVMName(&cloudlet.Key)
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		nodes := v.GetPlatformNodes(cloudlet)
		for _, nodeName := range nodes {
			clientName := v.GetChefClientName(nodeName)
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Creating chef client %s with cloudlet attributes", clientName))
			chefParams := v.GetVMChefParams(clientName, "", chefPolicy, chefAttributes)
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

	startTime := time.Now()

	err = v.SetupPlatformVM(ctx, vaultConfig, cloudlet, pfConfig, pfFlavor, updateCallback)
	if err != nil {
		return err
	}

	// Fetch chef run list status
	pfName := platformVMName
	if cloudlet.Deployment == cloudcommon.DeploymentTypeKubernetes {
		pfName = pfName + "-master"
	}
	clientName := v.GetChefClientName(pfName)
	updateCallback(edgeproto.UpdateTask, "Waiting for run lists to be executed on Platform VM")
	timeout := time.After(20 * time.Minute)
	tick := time.Tick(5 * time.Second)
	for {
		var statusInfo []chefmgmt.ChefStatusInfo
		select {
		case <-timeout:
			return fmt.Errorf("timed out waiting for platform VM to connect to Chef Server")
		case <-tick:
			statusInfo, err = chefmgmt.ChefClientRunStatus(ctx, chefClient, clientName, startTime)
			if err != nil {
				return err
			}
		}
		if len(statusInfo) > 0 {
			updateCallback(edgeproto.UpdateTask, "Performed following actions:")
			for _, info := range statusInfo {
				if info.Failed {
					return fmt.Errorf(info.Message)
				}
				updateCallback(edgeproto.UpdateStep, info.Message)
			}
			break
		}
	}

	return nil
}

func (v *VMPlatform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	// Update envvars
	v.VMProperties.CommonPf.Properties.UpdatePropsFromVars(ctx, cloudlet.EnvVar)
	return nil
}

func (v *VMPlatform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *pf.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Deleting cloudlet", "cloudletName", cloudlet.Key.Name)

	updateCallback(edgeproto.UpdateTask, "Deleting cloudlet")

	vaultConfig, err := vault.BestConfig(pfConfig.VaultAddr, vault.WithEnvMap(pfConfig.EnvVar))
	if err != nil {
		return err
	}

	if !pfConfig.TestMode {
		err = v.InitCloudletSSHKeys(ctx, vaultConfig)
		if err != nil {
			return err
		}
	}

	v.VMProperties.Domain = VMDomainPlatform
	cpf := infracommon.CommonPlatform{}
	v.VMProperties.CommonPf = &cpf
	pc := infracommon.GetPlatformConfig(cloudlet, pfConfig)
	err = v.InitProps(ctx, pc, vaultConfig)
	if err != nil {
		// ignore this error, as no creation would've happened on infra, so nothing to delete
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to init props", "cloudletName", cloudlet.Key.Name, "err", err)
		return nil
	}

	v.VMProvider.InitData(ctx, caches)

	// Source OpenRC file to access openstack API endpoint
	err = v.VMProvider.InitApiAccessProperties(ctx, &cloudlet.Key, pfConfig.Region, cloudlet.PhysicalName, vaultConfig, cloudlet.EnvVar, ProviderInitDeleteCloudlet)
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
	}

	if err == nil {
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
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to fetch chef auth keys", "err", err)
	}

	// Not sure if it's safe to remove vars from Vault due to testing/virtual cloudlets,
	// so leaving them in Vault for the time being. We can always delete them manually

	return nil
}

func (v *VMPlatform) DeleteCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Deleting access vars from vault", "cloudletName", cloudlet.Key.Name)

	updateCallback(edgeproto.UpdateTask, "Deleting access vars from secure secrets storage")

	vaultConfig, err := vault.BestConfig(pfConfig.VaultAddr, vault.WithEnvMap(pfConfig.EnvVar))
	if err != nil {
		return err
	}
	path := GetVaultCloudletAccessPath(&cloudlet.Key, pfConfig.Region, v.Type, cloudlet.PhysicalName, v.VMProvider.GetApiAccessFilename())
	err = infracommon.DeleteDataFromVault(vaultConfig, path)
	if err != nil {
		return fmt.Errorf("Failed to delete access vars from vault: %v", err)
	}
	return nil
}

func (v *VMPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	return v.VMProvider.SaveCloudletAccessVars(ctx, cloudlet, accessVarsIn, pfConfig, updateCallback)
}

func (v *VMPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return v.VMProvider.GatherCloudletInfo(ctx, info)
}

func GetChefCloudletTags(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, vmType VMType) []string {
	return []string{
		"deploytag/" + pfConfig.DeploymentTag,
		"region/" + pfConfig.Region,
		"cloudlet/" + cloudlet.Key.Name,
		"cloudletorg/" + cloudlet.Key.Organization,
		"vmtype/" + string(vmType),
	}
}

func GetChefCloudletAttributes(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) (map[string]interface{}, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetChefCloudletAttributes", "region", pfConfig.Region, "cloudletKey", cloudlet.Key)

	chefAttributes := make(map[string]interface{})

	if cloudlet.Deployment == cloudcommon.DeploymentTypeKubernetes {
		chefAttributes["k8sNodeCount"] = K8sMasterNodeCount + K8sWorkerNodeCount
	}
	chefAttributes["edgeCloudImage"] = pfConfig.ContainerRegistryPath
	chefAttributes["edgeCloudVersion"] = cloudlet.ContainerVersion
	if cloudlet.OverridePolicyContainerVersion {
		chefAttributes["edgeCloudVersionOverride"] = cloudlet.ContainerVersion
	}
	chefAttributes["notifyAddrs"] = pfConfig.NotifyCtrlAddrs

	chefAttributes["tags"] = GetChefCloudletTags(cloudlet, pfConfig, VMTypePlatform)

	// Use default address if port is 0, as we'll have single
	// CRM instance here, hence there will be no port conflict
	if cloudlet.NotifySrvAddr == "127.0.0.1:0" {
		cloudlet.NotifySrvAddr = ""
	}

	for _, serviceType := range PlatformServices {
		serviceObj := make(map[string]interface{})
		var serviceCmdArgs []string
		var dockerArgs []string
		var envVars *map[string]string
		var err error
		switch serviceType {
		case ServiceTypeShepherd:
			serviceCmdArgs, envVars, err = intprocess.GetShepherdCmdArgs(cloudlet, pfConfig)
			if err != nil {
				return nil, err
			}
		case ServiceTypeCRM:
			// Set container version to be empty, as it will be
			// present in edge-cloud image itself
			containerVersion := cloudlet.ContainerVersion
			cloudlet.ContainerVersion = ""
			serviceCmdArgs, envVars, err = cloudcommon.GetCRMCmdArgs(cloudlet, pfConfig)
			if err != nil {
				return nil, err
			}
			cloudlet.ContainerVersion = containerVersion
		case ServiceTypeCloudletPrometheus:
			// set image path for Promtheus
			serviceCmdArgs = intprocess.GetCloudletPrometheusCmdArgs()
			// docker args for prometheus
			dockerArgs = intprocess.GetCloudletPrometheusDockerArgs(cloudlet, intprocess.GetCloudletPrometheusConfigHostFilePath())
			// env vars for promtheeus is empty for now
			envVars = &map[string]string{}

			chefAttributes["prometheusImage"] = intprocess.PrometheusImagePath
			chefAttributes["prometheusVersion"] = intprocess.PrometheusImageVersion
		default:
			return nil, fmt.Errorf("invalid service type: %s, valid service types are [%v]", serviceType, PlatformServices)
		}
		chefArgs := chefmgmt.GetChefArgs(serviceCmdArgs)
		serviceObj["args"] = chefArgs
		chefDockerArgs := chefmgmt.GetChefDockerArgs(dockerArgs)
		for k, v := range chefDockerArgs {
			serviceObj[k] = v
		}
		if envVars != nil {
			envVarArr := []string{}
			for k, v := range *envVars {
				envVar := fmt.Sprintf("%s=%s", k, v)
				envVarArr = append(envVarArr, envVar)
			}
			serviceObj["env"] = envVarArr
		}
		chefAttributes[serviceType] = serviceObj
	}
	return chefAttributes, nil
}

func (v *VMPlatform) GetChefPlatformAttributes(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) (map[string]interface{}, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetChefPlatformAttributes", "region", pfConfig.Region, "cloudletKey", cloudlet.Key, "PhysicalName", cloudlet.PhysicalName)

	chefAttributes, err := GetChefCloudletAttributes(ctx, cloudlet, pfConfig)
	if err != nil {
		return nil, err
	}

	apiAddr, err := v.VMProvider.GetApiEndpointAddr(ctx)
	if err != nil {
		return nil, err
	}
	if apiAddr != "" {
		urlObj, err := util.ImagePathParse(apiAddr)
		if err != nil {
			return nil, err
		}
		hostname := strings.Split(urlObj.Host, ":")
		if len(hostname) != 2 {
			return nil, fmt.Errorf("invalid api endpoint addr: %s", apiAddr)
		}
		// API Endpoint address might have hostname in it, hence resolve the addr
		endpointIp, err := infracommon.LookupDNS(hostname[0])
		if err != nil {
			return nil, err
		}
		chefAttributes["infraApiAddr"] = endpointIp
		chefAttributes["infraApiPort"] = hostname[1]
		if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_DIRECT_ACCESS {
			// Fetch gateway IP of external network
			gatewayAddr, err := v.VMProvider.GetExternalGateway(ctx, v.VMProperties.GetCloudletExternalNetwork())
			if err != nil {
				return nil, fmt.Errorf("unable to fetch gateway IP for external network: %s, %v",
					v.VMProperties.GetCloudletExternalNetwork(), err)
			}
			chefAttributes["infraApiGw"] = gatewayAddr
		}
	}
	return chefAttributes, nil
}

func GetDockerCrtFile(crtFilePath string) (string, error) {
	_, crtFile := filepath.Split(crtFilePath)
	ext := filepath.Ext(crtFile)
	if ext == "" {
		return "", fmt.Errorf("invalid tls cert file name: %s", crtFile)
	}
	return "/root/tls/" + crtFile, nil
}

func (v *VMPlatform) GetCloudletVMsSpec(ctx context.Context, vaultConfig *vault.Config, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfFlavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) ([]*VMRequestSpec, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletVMsSpec", "region", pfConfig.Region, "cloudletKey", cloudlet.Key, "pfFlavor", pfFlavor)
	err := v.VMProvider.InitApiAccessProperties(ctx, &cloudlet.Key, pfConfig.Region, cloudlet.PhysicalName, vaultConfig, cloudlet.EnvVar, ProviderInitGetVmSpec)
	if err != nil {
		return nil, err
	}
	// edge-cloud image already contains the certs
	if pfConfig.TlsCertFile != "" {
		crtFile, err := GetDockerCrtFile(pfConfig.TlsCertFile)
		if err != nil {
			return nil, err
		}
		pfConfig.TlsCertFile = crtFile
	}

	pc := infracommon.GetPlatformConfig(cloudlet, pfConfig)
	err = v.InitProps(ctx, pc, vaultConfig)
	if err != nil {
		return nil, err
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
		flavorList, err := v.VMProvider.GetFlavorList(ctx)
		if err != nil {
			return nil, err
		}
		if cloudlet.InfraConfig.FlavorName == "" {
			cli := edgeproto.CloudletInfo{}
			cli.Flavors = flavorList
			cli.Key = cloudlet.Key
			restbls := v.GetResTablesForCloudlet(ctx, &cli.Key)
			vmspec, err := vmspec.GetVMSpec(ctx, *pfFlavor, cli, restbls)

			if err != nil {
				return nil, fmt.Errorf("unable to find VM spec for Shared RootLB: %v", err)
			}
			flavorName = vmspec.FlavorName
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
	chefAttributes, err := v.GetChefPlatformAttributes(ctx, cloudlet, pfConfig)
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
	if cloudlet.Deployment == cloudcommon.DeploymentTypeDocker {
		chefParams := v.GetVMChefParams(clientName, cloudlet.ChefClientKey[clientName], chefmgmt.ChefPolicyDocker, chefAttributes)
		platvm, err := v.GetVMRequestSpec(
			ctx,
			VMTypePlatform,
			platformVmName,
			flavorName,
			pfImageName,
			true, //connect external
			WithChefParams(chefParams),
			WithAccessKey(pfConfig.CrmAccessPrivateKey),
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
				masterAttributes["tags"] = GetChefCloudletTags(cloudlet, pfConfig, VMTypePlatformClusterMaster)
				chefParams := v.GetVMChefParams(clientName, cloudlet.ChefClientKey[clientName], chefmgmt.ChefPolicyK8s, chefAttributes)
				vmSpec, err = v.GetVMRequestSpec(
					ctx,
					VMTypeClusterMaster,
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
				nodeAttributes["tags"] = GetChefCloudletTags(cloudlet, pfConfig, VMTypePlatformClusterNode)
				chefParams := v.GetVMChefParams(clientName, cloudlet.ChefClientKey[clientName], chefmgmt.ChefPolicyK8s, nodeAttributes)
				vmSpec, err = v.GetVMRequestSpec(ctx,
					VMTypeClusterNode,
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

func (v *VMPlatform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfFlavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest", "cloudletName", cloudlet.Key.Name)
	v.VMProperties.Domain = VMDomainPlatform
	v.VMProperties.CommonPf = &infracommon.CommonPlatform{}

	if cloudlet.ChefClientKey == nil {
		return nil, fmt.Errorf("unable to find chef client key")
	}

	vaultConfig, err := vault.BestConfig(pfConfig.VaultAddr, vault.WithEnvMap(pfConfig.EnvVar))
	if err != nil {
		return nil, err
	}

	v.VMProvider.InitData(ctx, caches)

	platvms, err := v.GetCloudletVMsSpec(ctx, vaultConfig, cloudlet, pfConfig, pfFlavor, edgeproto.DummyUpdateCallback)
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
			WithNewSecurityGroup(GetServerSecurityGroupName(platformVmName)),
			WithAccessPorts("tcp:22"),
			WithSkipDefaultSecGrp(true),
			WithSkipInfraSpecificCheck(skipInfraSpecificCheck),
		)
	} else {
		subnetName := v.GetPlatformSubnetName(&cloudlet.Key)
		gp, err = v.GetVMGroupOrchestrationParamsFromVMSpec(
			ctx,
			platformVmName,
			platvms,
			WithNewSecurityGroup(GetServerSecurityGroupName(platformVmName)),
			WithAccessPorts("tcp:22"),
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
	props.Properties = VMProviderProps

	for k, v := range infracommon.InfraCommonProps {
		props.Properties[k] = v
	}

	providerProps, err := v.VMProvider.GetProviderSpecificProps(ctx, v.VMProperties.CommonPf.PlatformConfig, v.VMProperties.CommonPf.VaultConfig)
	if err != nil {
		return nil, err
	}
	for k, v := range providerProps {
		props.Properties[k] = v
	}

	return &props, nil
}
