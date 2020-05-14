package openstack

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type OpenstackPlatform struct {
	openRCVars   map[string]string
	vmProperties *vmlayer.VMProperties
	TestMode     bool
}

func (o *OpenstackPlatform) GetType() string {
	return "openstack"
}

func (o *OpenstackPlatform) SetVMProperties(vmProperties *vmlayer.VMProperties) {
	o.vmProperties = vmProperties
}

func (o *OpenstackPlatform) InitProvider(ctx context.Context) error {
	o.initDebug(o.vmProperties.CommonPf.PlatformConfig.NodeMgr)
	return o.PrepNetwork(ctx)
}

func (o *OpenstackPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return o.OSGetLimits(ctx, info)
}

// alphanumeric plus -_. first char must be alpha, <= 255 chars.
func (o *OpenstackPlatform) NameSanitize(name string) string {
	r := strings.NewReplacer(
		" ", "",
		"&", "",
		",", "",
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

func (o *OpenstackPlatform) DeleteResources(ctx context.Context, resourceGroupName string) error {
	return o.HeatDeleteStack(ctx, resourceGroupName)
}

func (o *OpenstackPlatform) GetResourceID(ctx context.Context, resourceType vmlayer.ResourceType, resourceName string) (string, error) {
	switch resourceType {
	case vmlayer.ResourceTypeSecurityGroup:
		// for testing mode, don't try to run APIs just fake a value
		if o.TestMode {
			return resourceName + "-testingID", nil
		}
		return o.GetSecurityGroupIDForName(ctx, resourceName)
		// TODO other types as needed
	}
	return "", fmt.Errorf("GetResourceID not implemented for resource type: %s ", resourceType)
}
