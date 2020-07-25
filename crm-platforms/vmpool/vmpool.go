package vmpool

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type VMPoolPlatform struct {
	openRCVars   map[string]string
	VMProperties *vmlayer.VMProperties
	TestMode     bool
	caches       *platform.Caches
}

func (o *VMPoolPlatform) GetType() string {
	return "vmpool"
}

func (o *VMPoolPlatform) SetVMProperties(vmProperties *vmlayer.VMProperties) {
	o.VMProperties = vmProperties
}

func (o *VMPoolPlatform) GetCloudletKey() *edgeproto.CloudletKey {
	return o.VMProperties.CommonPf.PlatformConfig.CloudletKey
}

func (o *VMPoolPlatform) InitProvider(ctx context.Context, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider for VM Pool")

	o.SetCaches(ctx, caches)
	updateCallback(edgeproto.UpdateTask, "Verifying VMs")
	return o.VerifyVMs(ctx, caches.VMPool.Vms)
}

func (o *VMPoolPlatform) SetCaches(ctx context.Context, caches *platform.Caches) {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetCaches")
	o.caches = caches
}

func (o *VMPoolPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo ")
	var err error
	info.Flavors, err = o.GetFlavorList(ctx)
	return err
}

// alphanumeric plus -_. first char must be alpha, <= 255 chars.
func (o *VMPoolPlatform) NameSanitize(name string) string {
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

// VMPool IdSanitize is the same as NameSanitize
func (o *VMPoolPlatform) IdSanitize(name string) string {
	return o.NameSanitize(name)
}

func (o *VMPoolPlatform) GetResourceID(ctx context.Context, resourceType vmlayer.ResourceType, resourceName string) (string, error) {
	switch resourceType {
	case vmlayer.ResourceTypeSecurityGroup:
		// not exists, just return same value
		return resourceName, nil
	}
	return "", fmt.Errorf("GetResourceID not implemented for resource type: %s ", resourceType)
}

func (o *VMPoolPlatform) PrepareRootLB(ctx context.Context, client ssh.Client, rootLBName string, secGrpName string, privacyPolicy *edgeproto.PrivacyPolicy) error {
	// nothing to do
	return nil
}
