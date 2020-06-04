package vsphere

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer/terraform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type VSpherePlatform struct {
	vcenterVars  map[string]string
	vmProperties *vmlayer.VMProperties
	TestMode     bool
	caches       *platform.Caches
}

func (v *VSpherePlatform) GetType() string {
	return "vsphere"
}

func (v *VSpherePlatform) SetVMProperties(vmProperties *vmlayer.VMProperties) {
	v.vmProperties = vmProperties
}

func (v *VSpherePlatform) InitProvider(ctx context.Context, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider for VSphere")
	v.caches = caches
	err := v.TerraformSetupVsphere(ctx, updateCallback)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "TerraformSetupVsphere failed", "err", err)
		return fmt.Errorf("TerraformSetupVsphere failed - %v", err)
	}

	return nil

}

func (v *VSpherePlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo ")
	var err error
	info.Flavors, err = v.GetFlavorList(ctx)
	info.State = edgeproto.CloudletState_CLOUDLET_STATE_NEED_SYNC
	return err
}

func (v *VSpherePlatform) GetDatacenterName(ctx context.Context) string {
	return v.NameSanitize(v.vmProperties.CommonPf.PlatformConfig.CloudletKey.Organization + "-" + v.vmProperties.CommonPf.PlatformConfig.CloudletKey.Name)
}

// alphanumeric plus -_. first char must be alpha, <= 255 chars.
func (v *VSpherePlatform) NameSanitize(name string) string {
	r := strings.NewReplacer(
		" ", "",
		"&", "",
		",", "",
		"/", "_",
		"!", "")
	str := r.Replace(name)
	if str == "" {
		return str
	}
	if !unicode.IsLetter(rune(str[0])) {
		// first character must be alpha
		str = "a" + str
	}
	if len(str) > 255 {
		str = str[:254]
	}
	return str
}

// IdSanitize is NameSanitize plus removing "."
func (v *VSpherePlatform) IdSanitize(name string) string {
	str := v.NameSanitize(name)
	str = strings.ReplaceAll(str, ".", "-")
	return str
}

func (v *VSpherePlatform) DeleteResources(ctx context.Context, resourceGroupName string) error {
	return terraform.DeleteTerraformPlan(ctx, resourceGroupName)
}

func (v *VSpherePlatform) GetResourceID(ctx context.Context, resourceType vmlayer.ResourceType, resourceName string) (string, error) {
	if v.TestMode {
		return resourceName + "-testingID", nil
	}
	switch resourceType {
	case vmlayer.ResourceTypeSecurityGroup:
		return resourceName + "-id", nil
	}
	return "", fmt.Errorf("GetResourceID not implemented for resource type: %s ", resourceType)
}

func (o *VSpherePlatform) GetVMStats(ctx context.Context, key *edgeproto.AppInstKey) (*vmlayer.VMMetrics, error) {
	return nil, fmt.Errorf("vm stats not supported for VSphere")
}

func (s *VSpherePlatform) GetPlatformResourceInfo(ctx context.Context) (*vmlayer.PlatformResources, error) {
	return nil, fmt.Errorf("platform resource stats not supported for VSphere")
}
