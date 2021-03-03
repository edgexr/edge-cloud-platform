package k8sbm

import (
	"context"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var (
	ResourceExternalIps = "External IPs"
)

var k8sbmProps = map[string]*edgeproto.PropertyInfo{
	"K8S_CONTROL_ACCESS_IP": {
		Name:        "K8S Control Access IP",
		Description: "IP used to access the control plane externally",
		Mandatory:   true,
	},
	"K8S_EXTERNAL_IP_RANGES": {
		Name:        "External IP Ranges(s) for K8S Load Balancers",
		Description: "Range of External IP addresses for K8S LBs, Format: StartCIDR-EndCIDR,StartCIDR2-EndCIDR2,...",
		Mandatory:   true,
	},
	"K8S_INTERNAL_IP_RANGES": {
		Name:        "Internal IP Ranges(s) for K8S Control Plane",
		Description: "Range of Internal IP addresses for BareMetal Control plane, Format: StartCIDR-EndCIDR,StartCIDR2-EndCIDR2,...",
		Mandatory:   true,
	},
	"K8S_EXTERNAL_ETH_INTERFACE": {
		Name:        "External Ethernet Interface",
		Description: "Ethernet interface used for K8S LB, e.g. eno2",
		Mandatory:   true,
	},
	"K8S_INTERNAL_ETH_INTERFACE": {
		Name:        "Internal Ethernet Interface",
		Description: "Ethernet interface used for K8S internal control plane",
		Mandatory:   true,
	},
}

func (k *K8sBareMetalPlatform) GetControlAccessIp() string {
	value, _ := k.commonPf.Properties.GetValue("K8S_CONTROL_ACCESS_IP")
	return value
}

func (k *K8sBareMetalPlatform) GetExternalIpRanges() string {
	value, _ := k.commonPf.Properties.GetValue("K8S_EXTERNAL_IP_RANGES")
	return value
}

func (k *K8sBareMetalPlatform) GetInternalIpRanges() string {
	value, _ := k.commonPf.Properties.GetValue("K8S_INTERNAL_IP_RANGES")
	return value
}

func (k *K8sBareMetalPlatform) GetExternalEthernetInterface() string {
	value, _ := k.commonPf.Properties.GetValue("K8S_EXTERNAL_ETH_INTERFACE")
	return value
}

func (k *K8sBareMetalPlatform) GetInternalEthernetInterface() string {
	value, _ := k.commonPf.Properties.GetValue("K8S_INTERNAL_ETH_INTERFACE")
	return value
}

func (k *K8sBareMetalPlatform) GetCloudletProps(ctx context.Context) (*edgeproto.CloudletProps, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletProps")
	return &edgeproto.CloudletProps{Properties: k8sbmProps}, nil
}

func (k *K8sBareMetalPlatform) GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletResourceQuotaProps")
	return &edgeproto.CloudletResourceQuotaProps{
		Props: []edgeproto.InfraResource{
			edgeproto.InfraResource{
				Name:        ResourceExternalIps,
				Description: "Limit on external IPs available",
			},
		},
	}, nil
}
