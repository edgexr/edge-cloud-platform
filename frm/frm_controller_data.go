package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/accessapi"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/crmutil"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	pfutils "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/utils"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/redundancy"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/notify"
	"github.com/mobiledgex/edge-cloud/tls"
)

// ControllerData contains cache data for controller
type ControllerData struct {
	*crmutil.ControllerData
}

// NewControllerData creates a new instance to track data from the controller
func NewControllerData(plat pf.Platform, nodeMgr *node.NodeMgr, haMgr *redundancy.HighAvailabilityManager) *ControllerData {
	cd := &ControllerData{}
	cd.ControllerData = crmutil.NewControllerData(plat, &edgeproto.CloudletKey{}, nodeMgr, haMgr)
	return cd
}

func InitClientNotify(client *notify.Client, nodeMgr *node.NodeMgr, cd *ControllerData) {
	crmutil.InitClientNotify(client, nodeMgr, cd.ControllerData)
}

func InitFRM(ctx context.Context, nodeMgr *node.NodeMgr, haMgr *redundancy.HighAvailabilityManager, hostname, region, appDNSRoot, notifyAddrs string) (*notify.Client, *ControllerData, error) {
	// Load platform implementation.
	platform, err := pfutils.GetPlatform(ctx,
		edgeproto.PlatformType_PLATFORM_TYPE_FEDERATION.String(),
		nodeMgr.UpdateNodeProps)
	if err != nil {
		return nil, nil, err
	}

	controllerData := NewControllerData(platform, nodeMgr, haMgr)

	pc := pf.PlatformConfig{
		Region:        region,
		NodeMgr:       nodeMgr,
		DeploymentTag: nodeMgr.DeploymentTag,
		AppDNSRoot:    appDNSRoot,
		AccessApi:     accessapi.NewVaultGlobalClient(nodeMgr.VaultConfig),
	}
	caches := controllerData.GetCaches()
	noopCb := func(updateType edgeproto.CacheUpdateType, value string) {}
	err = platform.Init(ctx, &pc, caches, haMgr, noopCb)

	// ctrl notify
	addrs := strings.Split(notifyAddrs, ",")
	notifyClientTls, err := nodeMgr.InternalPki.GetClientTlsConfig(ctx,
		nodeMgr.CommonName(),
		node.CertIssuerRegional,
		[]node.MatchCA{node.SameRegionalMatchCA()})
	if err != nil {
		return nil, nil, err
	}
	dialOption := tls.GetGrpcDialOption(notifyClientTls)
	notifyClient := notify.NewClient(nodeMgr.Name(), addrs, dialOption)

	notifyClient.SetFilterByFederatedCloudlet()
	InitClientNotify(notifyClient, nodeMgr, controllerData)
	notifyClient.Start()

	haKey := fmt.Sprintf("nodeType: %s", node.NodeTypeFRM)
	haEnabled, err := controllerData.InitHAManager(ctx, haMgr, haKey)
	if err != nil {
		if err != nil {
			log.FatalLog(err.Error())
		}
	}
	if haEnabled {
		log.SpanLog(ctx, log.DebugLevelInfra, "HA enabled", "role", haMgr.HARole)
		if haMgr.PlatformInstanceActive {
			log.SpanLog(ctx, log.DebugLevelInfra, "HA instance is active", "role", haMgr.HARole)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "HA instance is not active", "role", haMgr.HARole)
		}
		controllerData.StartHAManagerActiveCheck(ctx, haMgr)
	}

	return notifyClient, controllerData, nil
}
