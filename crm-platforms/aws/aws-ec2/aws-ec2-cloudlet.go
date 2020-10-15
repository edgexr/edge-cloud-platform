package awsec2

import (
	"context"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (a *AwsEc2Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return a.awsGenPf.GatherCloudletInfo(ctx, info)
}

func (a *AwsEc2Platform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
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

func (o *AwsEc2Platform) GetApiAccessFilename() string {
	return "aws.json"
}

func (a *AwsEc2Platform) AddCloudletImageIfNotPresent(ctx context.Context, imgPathPrefix, imgVersion string, updateCallback edgeproto.CacheUpdateCallback) (string, error) {
	// we don't currently have the ability to download and setup the template, but we will verify it is there
	return "", fmt.Errorf("AddCloudletImageIfNotPresent not implemented")
}

func (a *AwsEc2Platform) GetApiEndpointAddr(ctx context.Context) (string, error) {
	return "", fmt.Errorf("GetApiEndpointAddr not implemented")
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
	return "", fmt.Errorf("GetExternalGateway not implemented")
}

func (s *AwsEc2Platform) GetNetworkList(ctx context.Context) ([]string, error) {
	return []string{}, nil
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
	a.InitData(ctx, caches)
	vpcName := a.GetVpcName()

	acct, err := a.GetIamAccountId(ctx)
	if err != nil {
		return err
	}
	a.IamAccountId = acct
	// aws cannot use the name "default" as a new security group name as it is reserved
	if a.VMProperties.GetCloudletSecurityGroupName() == "default" {
		a.VMProperties.SetCloudletSecurityGroupName(vpcName + "-cloudlet-sg")
	}

	ns := a.VMProperties.GetCloudletNetworkScheme()
	nspec, err := vmlayer.ParseNetSpec(ctx, ns)
	if err != nil {
		return nil
	}
	nspecCidr := strings.ToUpper(nspec.CIDR)
	// Use the last subnet as the internally facing side of the external network
	extCidr := strings.Replace(nspecCidr, "X", "255", 1)
	// vpc cidr is a network which encompasses all subnets
	vpcCidr, err := a.VMProperties.GetInternalNetworkRoute(ctx)
	vpcId, err := a.CreateVPC(ctx, vpcName, vpcCidr)
	if err != nil {
		return err
	}
	a.VpcCidr = vpcCidr
	updateCallback(edgeproto.UpdateTask, "Creating Internet Gateway")
	err = a.CreateInternetGateway(ctx, vpcName)
	if err != nil {
		return err
	}
	err = a.CreateInternetGatewayDefaultRoute(ctx, vpcName, vpcId)
	if err != nil {
		return err
	}

	secGrpName := a.VMProperties.GetCloudletSecurityGroupName()
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
	updateCallback(edgeproto.UpdateTask, "Creating Subnet")
	externalSubnetId, err := a.CreateSubnet(ctx, vpcName, a.VMProperties.GetCloudletExternalNetwork(), extCidr, MainRouteTable)
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

	return nil

}
func (a *AwsEc2Platform) PrepareRootLB(ctx context.Context, client ssh.Client, rootLBName string, secGrpName string, privacyPolicy *edgeproto.PrivacyPolicy) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB", "rootLBName", rootLBName)
	return nil
}

func (a *AwsEc2Platform) GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	return a.awsGenPf.GetFlavorList(ctx)
}
