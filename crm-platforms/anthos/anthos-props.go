package anthos

import (
	"context"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var (
	ResourceExternalIps = "External IPs"
)

var anthosProps = map[string]*edgeproto.PropertyInfo{
	// Property: Default-Value
	"ANTHOS_CONTROL_VIP": {
		Name:        "Anthos Control VIP",
		Description: "Virtual IP of Anthos Control Plane",
		Mandatory:   true,
	},
}

func (a *AnthosPlatform) GetControlVip() string {
	value, _ := a.commonPf.Properties.GetValue("ANTHOS_CONTROL_VIP")
	return value
}

func (a *AnthosPlatform) GetCloudletProps(ctx context.Context) (*edgeproto.CloudletProps, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletProps")
	return &edgeproto.CloudletProps{Properties: anthosProps}, nil
}

func (a *AnthosPlatform) GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error) {
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
