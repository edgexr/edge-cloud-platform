package main

import (
	"fmt"

	awsec2 "github.com/mobiledgex/edge-cloud-infra/crm-platforms/aws/aws-ec2"
	awseks "github.com/mobiledgex/edge-cloud-infra/crm-platforms/aws/aws-eks"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/azure"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/edgebox"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/fakeinfra"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/gcp"
	k8sbm "github.com/mobiledgex/edge-cloud-infra/crm-platforms/k8s-baremetal"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/kindinfra"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/openstack"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/vcd"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/vmpool"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/vsphere"
	"github.com/mobiledgex/edge-cloud-infra/managedk8s"
	"github.com/mobiledgex/edge-cloud-infra/plugin/platform/common"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
)

func GetPlatform(plat string) (platform.Platform, error) {
	var outPlatform platform.Platform
	pfType := platform.GetType(plat)
	switch plat {
	case "PLATFORM_TYPE_OPENSTACK":
		openstackProvider := openstack.OpenstackPlatform{}
		outPlatform = &vmlayer.VMPlatform{
			Type:       pfType,
			VMProvider: &openstackProvider,
		}
	case "PLATFORM_TYPE_VSPHERE":
		vsphereProvider := vsphere.VSpherePlatform{}
		outPlatform = &vmlayer.VMPlatform{
			Type:       pfType,
			VMProvider: &vsphereProvider,
		}
	case "PLATFORM_TYPE_VM_POOL":
		vmpoolProvider := vmpool.VMPoolPlatform{}
		outPlatform = &vmlayer.VMPlatform{
			Type:       pfType,
			VMProvider: &vmpoolProvider,
		}
	case "PLATFORM_TYPE_VCD":
		vcdProvider := vcd.VcdPlatform{}
		outPlatform = &vmlayer.VMPlatform{
			Type:       pfType,
			VMProvider: &vcdProvider,
		}
	case "PLATFORM_TYPE_AWS_EC2":
		awsVMProvider := awsec2.AwsEc2Platform{}
		outPlatform = &vmlayer.VMPlatform{
			Type:       pfType,
			VMProvider: &awsVMProvider,
		}
	case "PLATFORM_TYPE_AZURE":
		azureProvider := &azure.AzurePlatform{}
		outPlatform = &managedk8s.ManagedK8sPlatform{
			Type:     pfType,
			Provider: azureProvider,
		}
	case "PLATFORM_TYPE_GCP":
		gcpProvider := &gcp.GCPPlatform{}
		outPlatform = &managedk8s.ManagedK8sPlatform{
			Type:     pfType,
			Provider: gcpProvider,
		}
	case "PLATFORM_TYPE_AWS_EKS":
		awsProvider := &awseks.AwsEksPlatform{}
		outPlatform = &managedk8s.ManagedK8sPlatform{
			Type:     pfType,
			Provider: awsProvider,
		}
	case "PLATFORM_TYPE_EDGEBOX":
		outPlatform = &edgebox.EdgeboxPlatform{}
	case "PLATFORM_TYPE_FAKEINFRA":
		outPlatform = &fakeinfra.Platform{}
	case "PLATFORM_TYPE_K8S_BARE_METAL":
		outPlatform = &k8sbm.K8sBareMetalPlatform{}
	case "PLATFORM_TYPE_KINDINFRA":
		outPlatform = &kindinfra.Platform{}
	default:
		return nil, fmt.Errorf("unknown platform %s", plat)
	}
	return outPlatform, nil
}

func GetClusterSvc() (platform.ClusterSvc, error) {
	return &common.ClusterSvc{}, nil
}

func main() {}
