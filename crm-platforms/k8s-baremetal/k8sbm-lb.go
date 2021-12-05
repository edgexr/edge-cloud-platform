package k8sbm

import (
	"context"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type LbInfo struct {
	Name            string
	ExternalIpAddr  string
	LbListenDevName string
}

// GetSharedLBName returns the "dedicated" FQDN of the default cluster
func (k *K8sBareMetalPlatform) GetSharedLBName(ctx context.Context, cloudletKey *edgeproto.CloudletKey) string {
	return cloudcommon.GetDedicatedLBFQDN(cloudletKey, &k.GetDefaultCluster(cloudletKey).Key.ClusterKey, k.commonPf.PlatformConfig.AppDNSRoot)
}

func (k *K8sBareMetalPlatform) GetLbName(ctx context.Context, appInst *edgeproto.AppInst) string {
	lbName := k.sharedLBName
	if appInst.DedicatedIp {
		return appInst.Uri
	}
	return lbName
}

func (k *K8sBareMetalPlatform) SetupLb(ctx context.Context, client ssh.Client, lbname string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupLb", "lbname", lbname)
	_, err := infracommon.GetIPAddressFromNetplan(ctx, client, lbname)
	if err != nil {
		if strings.Contains(err.Error(), infracommon.NetplanFileNotFound) {
			log.SpanLog(ctx, log.DebugLevelInfra, "lb ip does not exist", "lbname", lbname)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "unexpected error getting lb ip", "lbname", lbname, "err", err)
			return err
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "lb ip already exists")
		return nil
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "New LB, assign free IP")
	externalIp, err := k.AssignFreeLbIp(ctx, lbname, client)
	if err != nil {
		return err
	}
	if err = k.commonPf.ActivateFQDNA(ctx, lbname, externalIp); err != nil {
		return err
	}
	return nil
}

func (k *K8sBareMetalPlatform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &edgeproto.Flavor{
		Vcpus: uint64(0),
		Ram:   uint64(0),
		Disk:  uint64(0),
	}, nil
}
