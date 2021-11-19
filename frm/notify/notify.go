package notify

import (
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/version"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/crmutil"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	pfutils "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/utils"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/redundancy"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/notify"
	"github.com/mobiledgex/edge-cloud/tls"
)

// ControllerData contains cache data for controller
type ControllerData struct {
	*crmutil.ControllerData
}

// NewControllerData creates a new instance to track data from the controller
func NewControllerData(pf platform.Platform, nodeMgr *node.NodeMgr, haMgr *redundancy.HighAvailabilityManager) *ControllerData {
	cd := &ControllerData{}
	cd.ControllerData = crmutil.NewControllerData(pf, &edgeproto.CloudletKey{}, nodeMgr, haMgr)
	return cd
}

func InitClientNotify(client *notify.Client, nodeMgr *node.NodeMgr, cd *ControllerData) {
	crmutil.InitClientNotify(client, nodeMgr, cd.ControllerData)
}

func SetupFRMNotify(nodeMgr *node.NodeMgr, haMgr *redundancy.HighAvailabilityManager, hostname, region, notifyAddrs string) (*notify.Client, *ControllerData, error) {
	ctx, span, err := nodeMgr.Init(node.NodeTypeFRM, node.CertIssuerRegional,
		node.WithName(hostname),
		node.WithRegion(region),
	)
	if err != nil {
		return nil, nil, err
	}
	defer span.Finish()
	nodeMgr.UpdateNodeProps(ctx, version.InfraBuildProps("Infra"))

	// Load platform implementation.
	platform, err := pfutils.GetPlatform(ctx,
		edgeproto.PlatformType_PLATFORM_TYPE_FEDERATION.String(),
		nodeMgr.UpdateNodeProps)
	if err != nil {
		return nil, nil, err
	}

	controllerData := NewControllerData(platform, nodeMgr, haMgr)

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

	return notifyClient, controllerData, nil
}
