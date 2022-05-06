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

package awsec2

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

func (a *AwsEc2Platform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("SaveCloudletAccessVars not implemented")
}

func (a *AwsEc2Platform) GetCloudletImageSuffix(ctx context.Context) string {
	return ""
}

//CreateImageFromUrl downloads image from URL and then imports to the datastore
func (a *AwsEc2Platform) CreateImageFromUrl(ctx context.Context, imageName, imageUrl, md5Sum string) error {
	return fmt.Errorf("CreateImageFromUrl not implemented")
}

func (a *AwsEc2Platform) DeleteImage(ctx context.Context, folder, imageName string) error {
	return fmt.Errorf("DeleteImage not implemented")
}

func (a *AwsEc2Platform) GetApiEndpointAddr(ctx context.Context) (string, error) {
	return fmt.Sprintf("https://ec2.%s.amazonaws.com:443", a.awsGenPf.GetAwsRegion()), nil
}

// GetCloudletManifest follows the standard practice for vSphere to use OVF for this purpose.  We store the OVF
// in artifactory along with with the vmdk formatted disk.  No customization is needed per cloudlet as the OVF
// import tool will prompt for datastore and portgroup.
func (a *AwsEc2Platform) GetCloudletManifest(ctx context.Context, name string, cloudletImagePath string, vmgp *vmlayer.VMGroupOrchestrationParams) (string, error) {
	return "", fmt.Errorf("GetCloudletManifest not implemented")
}

func (a *AwsEc2Platform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	return nil
}

func (a *AwsEc2Platform) GetExternalGateway(ctx context.Context, extNetName string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "GetExternalGateway", "extNetName", extNetName)

	subnet, err := a.GetSubnet(ctx, extNetName)
	if err != nil {
		return "", nil
	}
	ip, _, err := net.ParseCIDR(subnet.CidrBlock)
	if err != nil {
		return "", fmt.Errorf("cannot parse start cidr: %s - %v", subnet.CidrBlock, err)
	}
	// GW is the first IP on the subnet
	infracommon.IncrIP(ip)
	return ip.String(), nil
}

func (a *AwsEc2Platform) GetNetworkList(ctx context.Context) ([]string, error) {
	subMap, err := a.GetSubnets(ctx)
	subnetList := []string{}
	if err != nil {
		return nil, err
	}
	for sn, _ := range subMap {
		subnetList = append(subnetList, sn)
	}
	return subnetList, nil
}

func (a *AwsEc2Platform) GetPlatformResourceInfo(ctx context.Context) (*vmlayer.PlatformResources, error) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "GetPlatformResourceInfo not supported")
	return &vmlayer.PlatformResources{}, nil
}

func (a *AwsEc2Platform) GetResourceID(ctx context.Context, resourceType vmlayer.ResourceType, resourceName string) (string, error) {
	switch resourceType {
	case vmlayer.ResourceTypeSecurityGroup:
		return resourceName, nil
	}
	return "", fmt.Errorf("GetResourceID not implemented for resource type: %s ", resourceType)
}
func (a *AwsEc2Platform) GetRouterDetail(ctx context.Context, routerName string) (*vmlayer.RouterDetail, error) {
	return nil, fmt.Errorf("GetRouterDetail not supported")
}

func (a *AwsEc2Platform) InitProvider(ctx context.Context, caches *platform.Caches, stage vmlayer.ProviderInitStage, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider", "stage", stage)
	vpcName := a.GetVpcName()

	// for common init, do nothing here. Shepherd has not been integrated for EC2 and requires work
	switch stage {
	case vmlayer.ProviderInitPlatformStartCrmCommon:
		// will be called again as init conditional
		return nil
	case vmlayer.ProviderInitPlatformStartShepherd:
		fallthrough
	case vmlayer.ProviderInitPlatformStartCrmConditional:
		fallthrough
	case vmlayer.ProviderInitCreateCloudletDirect:
		fallthrough
	case vmlayer.ProviderInitDeleteCloudlet:
		err := a.awsGenPf.GetAwsSessionToken(ctx, a.VMProperties.CommonPf.PlatformConfig.AccessApi)
		if err != nil {
			return err
		}
		if stage == vmlayer.ProviderInitPlatformStartCrmConditional {
			go a.awsGenPf.RefreshAwsSessionToken(a.VMProperties.CommonPf.PlatformConfig)
		}
		if stage == vmlayer.ProviderInitPlatformStartShepherd {
			return nil
		}
	}

	acct, err := a.GetIamAccountForImage(ctx)
	if err != nil {
		return err
	}
	a.AmiIamAccountId = acct

	ns := a.VMProperties.GetCloudletNetworkScheme()
	nspec, err := vmlayer.ParseNetSpec(ctx, ns)
	if err != nil {
		return nil
	}
	nspecCidr := strings.ToUpper(nspec.CIDR)
	// Use the last subnet as the internally facing side of the external network
	extCidr := strings.Replace(nspecCidr, "X", "255", 1)
	// vpc cidr is a network which encompasses all subnets
	vpcCidr, err := a.VMProperties.GetInternalNetworkRoute(ctx, false)
	vpcId, err := a.CreateVPC(ctx, vpcName, vpcCidr)
	if err != nil {
		return err
	}
	a.VpcCidr = vpcCidr

	if stage == vmlayer.ProviderInitDeleteCloudlet {
		return nil
	}
	updateCallback(edgeproto.UpdateTask, "Creating Internet Gateway")
	igw, err := a.CreateInternetGateway(ctx, vpcName)
	if err != nil {
		return err
	}
	if len(igw.Attachments) == 0 {
		err = a.CreateInternetGatewayDefaultRoute(ctx, vpcName, vpcId)
		if err != nil {
			return err
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "Internet GW already exists")
	}

	secGrpName := a.VMProperties.CloudletSecgrpName
	sg, err := a.GetSecurityGroup(ctx, secGrpName, vpcId)
	if err != nil {
		if strings.Contains(err.Error(), SecGrpDoesNotExistError) {
			updateCallback(edgeproto.UpdateTask, "Creating Security Group")
			sg, err = a.CreateSecurityGroup(ctx, secGrpName, vpcId, "default security group for cloudlet "+vpcName)
			if err != nil {
				return err
			}
		}
	}
	err = a.AllowIntraVpcTraffic(ctx, sg.GroupId)
	if err != nil {
		return err
	}
	extSubnetName := a.VMProperties.GetCloudletExternalNetwork()
	if a.awsGenPf.IsAwsOutpost() {
		updateCallback(edgeproto.UpdateTask, "Assigning Subnet")
		subnets, err := a.GetSubnets(ctx)
		if err != nil {
			return err
		}
		err = a.GetFreePrecreatedSubnet(ctx, extSubnetName, FreeExternalSubnetType, vpcName, subnets)
		if err != nil {
			return err
		}
	} else {
		updateCallback(edgeproto.UpdateTask, "Creating Subnet")
		externalSubnetId, err := a.CreateSubnet(ctx, vpcName, extSubnetName, extCidr, MainRouteTable)
		if err != nil && !strings.Contains(err.Error(), SubnetAlreadyExistsError) {
			return err
		}
		updateCallback(edgeproto.UpdateTask, "Getting Elastic IP")
		eipId, err := a.GetElasticIP(ctx, vpcName, vpcId)
		if err != nil {
			if !strings.Contains(err.Error(), ElasticIpDoesNotExistError) {
				return err
			}
			eipId, err = a.AllocateElasticIP(ctx)
			if err != nil {
				return err
			}
		}
		updateCallback(edgeproto.UpdateTask, "Creating NAT Gateway")
		ngwId, err := a.CreateNatGateway(ctx, externalSubnetId, eipId, vpcName)
		if err != nil {
			return err
		}
		updateCallback(edgeproto.UpdateTask, "Creating Route Table")
		_, err = a.CreateInternalRouteTable(ctx, vpcId, ngwId, a.VMProperties.GetCloudletMexNetwork())
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *AwsEc2Platform) ActiveChanged(ctx context.Context, platformActive bool) error {
	return nil
}

func (a *AwsEc2Platform) PrepareRootLB(ctx context.Context, client ssh.Client, rootLBName string, secGrpName string, TrustPolicy *edgeproto.TrustPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB", "rootLBName", rootLBName)
	return nil
}

func (a *AwsEc2Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	if a.awsGenPf.IsAwsOutpost() {
		return a.GetOutpostFlavorsForCloudletInfo(ctx, info)
	} else {
		return a.awsGenPf.GatherCloudletInfo(ctx, a.awsGenPf.GetAwsFlavorMatchPattern(), info)
	}
}

func (a *AwsEc2Platform) GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList ")
	var info edgeproto.CloudletInfo
	if a.awsGenPf.IsAwsOutpost() {
		err := a.GetOutpostFlavorsForCloudletInfo(ctx, &info)
		if err != nil {
			return nil, err
		}
		return info.Flavors, nil
	}
	return a.awsGenPf.GetFlavorList(ctx, a.awsGenPf.GetAwsFlavorMatchPattern())
}

func (a *AwsEc2Platform) GetOutpostFlavorsForCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetOutpostFlavorsForCloudletInfo")
	flavs := a.awsGenPf.GetAwsOutpostFlavors()
	if flavs == "" {
		return fmt.Errorf("AWS_OUTPOST_FLAVORS not set")
	}
	fs := strings.Split(flavs, ";")
	for _, f := range fs {
		fss := strings.Split(f, ",")
		if len(fss) != 4 {
			return fmt.Errorf("badly formatted outpost flavor: %s", f)
		}
		fname := fss[0]
		vcpustr := fss[1]
		ramstr := fss[2]
		diskstr := fss[3]
		vcpu, err := strconv.ParseInt(vcpustr, 10, 64)
		if err != nil {
			return fmt.Errorf("badly formatted outpost flavor vcpus: %s", vcpustr)
		}
		ram, err := strconv.ParseInt(ramstr, 10, 64)
		if err != nil {
			return fmt.Errorf("badly formatted outpost flavor ram: %s", ramstr)
		}
		disk, err := strconv.ParseInt(diskstr, 10, 64)
		if err != nil {
			return fmt.Errorf("badly formatted outpost flavor disk: %s", diskstr)
		}
		info.Flavors = append(
			info.Flavors,
			&edgeproto.FlavorInfo{
				Name:  fname,
				Vcpus: uint64(vcpu),
				Ram:   uint64(ram),
				Disk:  uint64(disk),
			},
		)
	}
	return nil
}

func (a *AwsEc2Platform) GetVaultCloudletAccessPath(key *edgeproto.CloudletKey, region, physicalName string) string {
	return a.awsGenPf.GetVaultCloudletAccessPath(key, region, physicalName)
}

func (a *AwsEc2Platform) GetSessionTokens(ctx context.Context, vaultConfig *vault.Config, account string) (map[string]string, error) {
	return a.awsGenPf.GetSessionTokens(ctx, vaultConfig, account)
}

func (a *AwsEc2Platform) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	return []edgeproto.InfraResource{}, nil
}

func (a *AwsEc2Platform) GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error) {
	return &edgeproto.CloudletResourceQuotaProps{}, nil
}

func (a *AwsEc2Platform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	resInfo := make(map[string]edgeproto.InfraResource)
	return resInfo
}

func (a *AwsEc2Platform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

func (a *AwsEc2Platform) InternalCloudletUpdatedCallback(ctx context.Context, old *edgeproto.CloudletInternal, new *edgeproto.CloudletInternal) {
	log.SpanLog(ctx, log.DebugLevelInfra, "InternalCloudletUpdatedCallback")
}

func (a *AwsEc2Platform) GetGPUSetupStage(ctx context.Context) vmlayer.GPUSetupStage {
	return vmlayer.ClusterInstStage
}
