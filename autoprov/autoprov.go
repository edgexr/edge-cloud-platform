package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mobiledgex/edge-cloud-infra/version"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/notify"
	"github.com/mobiledgex/edge-cloud/tls"
	"github.com/mobiledgex/edge-cloud/vault"
	"google.golang.org/grpc"
)

var debugLevels = flag.String("d", "", fmt.Sprintf("comma separated list of %v", log.DebugLevelStrings))
var notifyAddrs = flag.String("notifyAddrs", "127.0.0.1:50001", "Comma separated list of controller notify listener addresses")
var ctrlAddr = flag.String("ctrlAddrs", "127.0.0.1:55001", "controller api address")
var influxAddr = flag.String("influxAddr", "http://127.0.0.1:8086", "InfluxDB listener address")
var region = flag.String("region", "local", "region name")
var hostname = flag.String("hostname", "", "Unique hostname")

var sigChan chan os.Signal
var cacheData CacheData
var dialOpts grpc.DialOption
var notifyClient *notify.Client
var vaultConfig *vault.Config
var autoProvAggr *AutoProvAggr
var minMaxChecker *MinMaxChecker
var retryTracker *RetryTracker
var settings edgeproto.Settings
var nodeMgr node.NodeMgr

func main() {
	nodeMgr.InitFlags()
	flag.Parse()

	err := start()
	if err != nil {
		stop()
		log.FatalLog(err.Error())
	}
	defer stop()

	sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	// wait until killed/interrupted
	sig := <-sigChan
	fmt.Println(sig)
}

func start() error {
	log.SetDebugLevelStrs(*debugLevels)
	settings = *edgeproto.GetDefaultSettings()

	ctx, span, err := nodeMgr.Init("autoprov", node.CertIssuerRegional, node.WithName(*hostname), node.WithRegion(*region), node.WithVaultConfig(vaultConfig))
	if err != nil {
		return err
	}
	defer span.Finish()
	vaultConfig = nodeMgr.VaultConfig
	nodeMgr.UpdateNodeProps(ctx, version.InfraBuildProps("Infra"))

	clientTlsConfig, err := nodeMgr.InternalPki.GetClientTlsConfig(ctx,
		nodeMgr.CommonName(),
		node.CertIssuerRegional,
		[]node.MatchCA{node.SameRegionalMatchCA()})
	if err != nil {
		return err
	}
	dialOpts = tls.GetGrpcDialOption(clientTlsConfig)

	cacheData.init(&nodeMgr)
	retryTracker = newRetryTracker()
	autoProvAggr = NewAutoProvAggr(settings.AutoDeployIntervalSec, settings.AutoDeployOffsetSec, &cacheData)
	minMaxChecker = newMinMaxChecker(&cacheData)
	cacheData.alertCache.AddUpdatedCb(alertChanged)

	autoProvAggr.Start()

	addrs := strings.Split(*notifyAddrs, ",")
	notifyClient = notify.NewClient(nodeMgr.Name(), addrs, dialOpts)
	notifyClient.RegisterRecv(notify.GlobalSettingsRecv(&settings, settingsUpdated))
	cacheData.initNotifyClient(notifyClient)
	nodeMgr.RegisterClient(notifyClient)

	notifyClient.Start()
	return nil
}

func stop() {
	if autoProvAggr != nil {
		autoProvAggr.Stop()
	}
	if notifyClient != nil {
		notifyClient.Stop()
	}
	nodeMgr.Finish()
}

func settingsUpdated(ctx context.Context, old *edgeproto.Settings, new *edgeproto.Settings) {
	autoProvAggr.UpdateSettings(ctx, settings.AutoDeployIntervalSec, settings.AutoDeployOffsetSec)
}
