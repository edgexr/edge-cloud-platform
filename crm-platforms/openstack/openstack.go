package openstack

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	ssh "github.com/mobiledgex/golang-ssh"
)

type OpenstackPlatform struct {
	openRCVars   map[string]string
	VMProperties *vmlayer.VMProperties
	TestMode     bool
}

func (o *OpenstackPlatform) GetType() string {
	return "openstack"
}

func (o *OpenstackPlatform) SetVMProperties(vmProperties *vmlayer.VMProperties) {
	o.VMProperties = vmProperties
}

func (o *OpenstackPlatform) InitProvider(ctx context.Context, caches *platform.Caches, stage vmlayer.ProviderInitStage, updateCallback edgeproto.CacheUpdateCallback) error {
	if stage == vmlayer.ProviderInitPlatformStart {
		o.initDebug(o.VMProperties.CommonPf.PlatformConfig.NodeMgr)
		return o.PrepNetwork(ctx)
	}
	return nil
}

func (o *OpenstackPlatform) SetCaches(ctx context.Context, caches *platform.Caches) {
	// openstack doesn't need caches
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

// Openstack IdSanitize is the same as NameSanitize
func (o *OpenstackPlatform) IdSanitize(name string) string {
	return o.NameSanitize(name)
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

func (o *OpenstackPlatform) PrepareRootLB(ctx context.Context, client ssh.Client, rootLBName string, secGrpName string, privacyPolicy *edgeproto.PrivacyPolicy) error {
	// nothing to do
	return nil
}
