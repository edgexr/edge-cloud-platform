package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

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
	log.InitTracer(nodeMgr.TlsCertFile)
	settings = *edgeproto.GetDefaultSettings()

	span := log.StartSpan(log.DebugLevelInfo, "main")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	var err error
	vaultConfig, err = vault.BestConfig(nodeMgr.VaultAddr)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "vault auth", "type", vaultConfig.Auth.Type())

	err = nodeMgr.Init(ctx, "autoprov", node.WithName(*hostname), node.WithRegion(*region), node.WithVaultConfig(vaultConfig))

	clientTlsConfig, err := nodeMgr.InternalPki.GetClientTlsConfig(ctx,
		nodeMgr.CommonName(),
		node.CertIssuerRegional,
		[]node.MatchCA{node.SameRegionalMatchCA()})
	if err != nil {
		return err
	}
	dialOpts = tls.GetGrpcDialOption(clientTlsConfig)

	cacheData.init()
	autoProvAggr = NewAutoProvAggr(settings.AutoDeployIntervalSec, settings.AutoDeployOffsetSec, &cacheData)
	minMaxChecker = newMinMaxChecker(&cacheData)
	cacheData.alertCache.SetUpdatedCb(alertChanged)

	autoProvAggr.Start()
	minMaxChecker.Start()

	addrs := strings.Split(*notifyAddrs, ",")
	notifyClient = notify.NewClient(addrs, dialOpts)
	notifyClient.RegisterRecv(notify.GlobalSettingsRecv(&settings, settingsUpdated))
	cacheData.initNotifyClient(notifyClient)
	nodeMgr.RegisterClient(notifyClient)

	notifyClient.Start()
	return nil
}

func stop() {
	if minMaxChecker != nil {
		minMaxChecker.Stop()
	}
	if autoProvAggr != nil {
		autoProvAggr.Stop()
	}
	if notifyClient != nil {
		notifyClient.Stop()
	}
	log.FinishTracer()
}

func settingsUpdated(ctx context.Context, old *edgeproto.Settings, new *edgeproto.Settings) {
	autoProvAggr.UpdateSettings(ctx, settings.AutoDeployIntervalSec, settings.AutoDeployOffsetSec)
}
