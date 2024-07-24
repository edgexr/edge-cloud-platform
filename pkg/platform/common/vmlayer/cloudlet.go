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
	"path/filepath"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	pf "github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/confignode"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/edgexr/edge-cloud-platform/pkg/vmspec"
)

// VMDomain is to differentiate platform vs computing VMs and associated resources
type VMDomain string

const (
	VMDomainCompute  VMDomain = "compute"
	VMDomainPlatform VMDomain = "platform"
	VMDomainAny      VMDomain = "any" // used for matching only
)

type NodeInfo struct {
	NodeName string
	NodeRole cloudcommon.NodeRole
	NodeType cloudcommon.NodeType
}

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

func (v *VMPlatform) GetPlatformSubnetName(key *edgeproto.CloudletKey) SubnetNames {
	names := SubnetNames{}
	names[infracommon.IndexIPV4] = "mex-k8s-subnet-" + v.GetPlatformVMName(key)
	names[infracommon.IndexIPV6] = "mex-k8s-subnet-" + v.GetPlatformVMName(key) + "-ipv6"
	return names
}

func (v *VMPlatform) GetPlatformNodes(cloudlet *edgeproto.Cloudlet) []NodeInfo {
	nodes := []NodeInfo{}
	platformVMName := v.GetPlatformVMName(&cloudlet.Key)
	if cloudlet.Deployment == cloudcommon.DeploymentTypeDocker {
		nodes = append(nodes, NodeInfo{NodeName: platformVMName, NodeType: cloudcommon.NodeTypePlatformVM, NodeRole: cloudcommon.NodeRoleDockerCrm})
	} else {
		masterNode := platformVMName + "-master"
		nodes = append(nodes, NodeInfo{NodeName: masterNode, NodeType: cloudcommon.NodeTypePlatformK8sClusterMaster, NodeRole: cloudcommon.NodeRoleK8sCrm})
		for nn := uint32(1); nn <= confignode.K8sWorkerNodeCount; nn++ {
			workerNode := fmt.Sprintf("%s-node-%d", platformVMName, nn)
			if nn == 1 {
				nodes = append(nodes, NodeInfo{NodeName: workerNode, NodeType: cloudcommon.NodeTypePlatformK8sClusterPrimaryNode, NodeRole: cloudcommon.NodeRoleK8sCrmWorker})
			} else {
				nodes = append(nodes, NodeInfo{NodeName: workerNode, NodeType: cloudcommon.NodeTypePlatformK8sClusterSecondaryNode, NodeRole: cloudcommon.NodeRoleK8sCrmWorker})
			}
		}
	}
	return nodes
}

// GetCloudletImageName decides what image to use based on
// 1) if MEX_OS_IMAGE is specified in properties and not default, use that
// 2) Use image specified on startup based on cloudlet config
func (v *VMPlatform) GetCloudletImageName(ctx context.Context) (string, string, error) {
	imgFromProps := v.VMProperties.GetCloudletOSImage()
	if imgFromProps != "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "using image from MEX_OS_IMAGE property", "imgFromProps", imgFromProps)
		return imgFromProps, "", nil
	}

	imagePath := v.VMProperties.CommonPf.PlatformConfig.CloudletVMImagePath
	if imagePath == "" {
		return "", "", fmt.Errorf("Get cloudlet image failed, cloudletVMImagePath not set")
	}
	imageNameWithoutExt := util.RemoveExtension(filepath.Base(imagePath))
	return imageNameWithoutExt, imagePath, nil
}

// GetCloudletImageToUse decides what image to use based on
// 1) if MEX_OS_IMAGE is specified in properties and not default, use that
// 2) Use image specified on startup based on cloudlet config
// 3) Add image to cloudlet image storage if not
func (v *VMPlatform) GetCloudletImageToUse(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) (string, error) {
	imageNameWithoutExt, imagePath, err := v.GetCloudletImageName(ctx)
	if err != nil {
		return "", err
	}

	// if no image path, nothing to download, so just return the image name
	if imagePath == "" {
		return imageNameWithoutExt, nil
	}
	cloudletImagePath := util.SetExtension(imagePath, v.VMProvider.GetCloudletImageSuffix(ctx))
	log.SpanLog(ctx, log.DebugLevelInfra, "Getting cloudlet image from platform config", "cloudletImagePath", cloudletImagePath, "imageNameWithoutExt", imageNameWithoutExt)
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
	imageInfo.LocalImageName = imageNameWithoutExt
	imageInfo.ImageCategory = infracommon.ImageCategoryPlatform
	return imageNameWithoutExt, v.VMProvider.AddImageIfNotPresent(ctx, &imageInfo, updateCallback)
}

// setupPlatformVM:
//   - Downloads Cloudlet VM base image (if not-present)
//   - Brings up Platform VM (using vm provider stack)
//   - Sets up Security Group for access to Cloudlet
//
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
			WithAccessPorts("tcp:22"),
			WithSkipDefaultSecGrp(true),
			WithInitOrchestrator(true),
			WithEnableIPV6(v.VMProperties.CloudletEnableIPV6),
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
			WithAccessPorts("tcp:22"),
			WithSkipDefaultSecGrp(true),
			WithNewSubnet(subnetName),
			WithSkipSubnetGateway(true),
			WithSkipInfraSpecificCheck(skipInfraSpecificCheck),
			WithInitOrchestrator(true),
			WithAntiAffinity(cloudlet.PlatformHighAvailability),
			WithEnableIPV6(v.VMProperties.CloudletEnableIPV6),
		)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error while creating platform VM", "vms request spec", vms)
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Successfully Deployed Platform VM")

	return nil
}

func (v *VMPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfFlavor *edgeproto.Flavor, caches *pf.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	var err error
	cloudletResourcesCreated := false
	log.SpanLog(ctx, log.DebugLevelInfra, "Creating cloudlet", "cloudletName", cloudlet.Key.Name)

	if pfConfig.ContainerRegistryPath == "" {
		return false, fmt.Errorf("container registry path not specified")
	}

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

	if cloudlet.InfraConfig.ExternalNetworkName != "" {
		v.VMProperties.SetCloudletExternalNetwork(cloudlet.InfraConfig.ExternalNetworkName)
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

	// once we get this far we should ensure delete succeeds on a failure
	cloudletResourcesCreated = true
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		return cloudletResourcesCreated, nil
	}

	err = v.SetupPlatformVM(ctx, accessApi, cloudlet, pfConfig, pfFlavor, updateCallback)
	if err != nil {
		return cloudletResourcesCreated, err
	}

	return cloudletResourcesCreated, nil
}

func (v *VMPlatform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	// This used be where we would query chef's cookbook
	// run status, but our ansible-based node management
	// doesn't support that. TODO: May be we add that feature
	// later by having the ansible scripts push status
	// updates to the Controller.
	return nil
}

func (v *VMPlatform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	// Update envvars
	v.VMProperties.CommonPf.Properties.UpdatePropsFromVars(ctx, cloudlet.EnvVar)
	// Update GPU config
	v.GPUConfig = cloudlet.GpuConfig
	return nil
}

func (v *VMPlatform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "update VMPlatform TrustPolicy", "policy", TrustPolicy)
	egressRestricted := TrustPolicy.Key.Name != ""
	var result OperationInitResult
	ctx, result, err := v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}
	rootlbClients, err := v.GetRootLBClients(ctx)
	if err != nil {
		return fmt.Errorf("Unable to get rootlb clients - %v", err)
	}
	return v.VMProvider.ConfigureCloudletSecurityRules(ctx, egressRestricted, TrustPolicy, rootlbClients, ActionUpdate, edgeproto.DummyUpdateCallback)
}

func (v *VMPlatform) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterInstKey *edgeproto.ClusterInstKey) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "update VMPlatform TrustPolicyException", "policy", TrustPolicyException)

	rootlbClients, err := v.GetRootLBClientForClusterInstKey(ctx, clusterInstKey)
	if err != nil {
		return fmt.Errorf("Unable to get rootlb clients - %v", err)
	}
	// Only create supported, update not allowed.
	return v.VMProvider.ConfigureTrustPolicyExceptionSecurityRules(ctx, TrustPolicyException, rootlbClients, ActionCreate, edgeproto.DummyUpdateCallback)
}

func (v *VMPlatform) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterInstKey *edgeproto.ClusterInstKey) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Delete VMPlatform TrustPolicyException", "policyKey", TrustPolicyExceptionKey)

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
		rootlbClients := make(map[string]platform.RootLBClient)
		err = v.VMProvider.ConfigureCloudletSecurityRules(ctx, false, &edgeproto.TrustPolicy{}, rootlbClients, ActionDelete, edgeproto.DummyUpdateCallback)
		if err != nil {
			if v.VMProperties.IptablesBasedFirewall {
				// iptables based security rules can fail on one clusterInst LB or other VM not responding
				log.SpanLog(ctx, log.DebugLevelInfra, "Warning: error in ConfigureCloudletSecurityRules", "err", err)
			} else if err.Error() != ServerDoesNotExistError {
				return err
			}
		}
	}

	nodes := v.GetPlatformNodes(cloudlet)
	for _, node := range nodes {
		nodeKey := &edgeproto.CloudletNodeKey{
			Name:        node.NodeName,
			CloudletKey: cloudlet.Key,
		}
		err = accessApi.DeleteCloudletNode(ctx, nodeKey)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete CloudletNode registration", "cloudlet", cloudlet.Key, "name", node.NodeName, "err", err)
		}
	}

	// Delete rootLB object from CloudletNode entries
	nodeKey := &edgeproto.CloudletNodeKey{
		Name:        rootLBName,
		CloudletKey: cloudlet.Key,
	}
	err = accessApi.DeleteCloudletNode(ctx, nodeKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete CloudletNode registration", "cloudlet", cloudlet.Key, "rootLBName", rootLBName, "err", err)
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

func (v *VMPlatform) GetFeatures() *edgeproto.PlatformFeatures {
	features := v.VMProvider.GetFeatures()
	// add in vmprovider common properties
	for k, v := range VMProviderProps {
		features.Properties[k] = v
	}
	for k, v := range infracommon.InfraCommonProps {
		features.Properties[k] = v
	}
	return features
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
		return nil, fmt.Errorf("container registry path not specified")
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
	pfImageName, _, _ := v.GetCloudletImageName(ctx)
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_DIRECT_ACCESS {
		pfImageName, err = v.GetCloudletImageToUse(ctx, updateCallback)
		if err != nil {
			return nil, err
		}
	}

	nodes := v.GetPlatformNodes(cloudlet)
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no platform nodes")
	}

	var vms []*VMRequestSpec
	subnetName := v.GetPlatformSubnetName(&cloudlet.Key)
	netTypes := []NetworkType{NetworkTypeExternalAdditionalPlatform}
	addNets := v.VMProperties.GetNetworksByType(ctx, netTypes)
	if cloudlet.Deployment == cloudcommon.DeploymentTypeDocker {
		platvm, err := v.GetVMRequestSpec(
			ctx,
			cloudcommon.NodeTypePlatformVM,
			platformVmName,
			flavorName,
			pfImageName,
			true, //connect external
			WithConfigureNodeVars(v, cloudcommon.NodeRoleDockerCrm, &cloudlet.Key, &cloudlet.Key),
			WithAccessKey(pfConfig.CrmAccessPrivateKey),
			WithAdditionalNetworks(addNets),
		)
		if err != nil {
			return nil, err
		}
		vms = append(vms, platvm)
	} else {
		for _, node := range nodes {
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
				WithConfigureNodeVars(v, node.NodeRole, &cloudlet.Key, &cloudlet.Key),
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
			WithAccessPorts("tcp:22"),
			WithSkipDefaultSecGrp(true),
			WithSkipInfraSpecificCheck(skipInfraSpecificCheck),
			WithEnableIPV6(v.VMProperties.CloudletEnableIPV6),
		)
	} else {
		subnetName := v.GetPlatformSubnetName(&cloudlet.Key)
		gp, err = v.GetVMGroupOrchestrationParamsFromVMSpec(
			ctx,
			platformVmName,
			platvms,
			WithNewSecurityGroup(infracommon.GetServerSecurityGroupName(platformVmName)),
			WithAccessPorts("tcp:22"),
			WithNewSubnet(subnetName),
			WithSkipDefaultSecGrp(true),
			WithSkipSubnetGateway(true),
			WithSkipInfraSpecificCheck(skipInfraSpecificCheck),
			WithEnableIPV6(v.VMProperties.CloudletEnableIPV6),
		)
	}
	if err != nil {
		return nil, err
	}

	// set auth for the config-node script
	for _, vm := range gp.VMs {
		if err = infracommon.CreateCloudletNode(ctx, vm.CloudConfigParams.ConfigureNodeVars, accessApi); err != nil {
			return nil, err
		}
	}

	imgPath := util.SetExtension(pfConfig.CloudletVmImagePath, v.VMProvider.GetCloudletImageSuffix(ctx))
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
