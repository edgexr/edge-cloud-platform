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
var tlsCertFile = flag.String("tls", "", "server tls cert file.  Keyfile and CA file mex-ca.crt must be in same directory")
var notifyAddrs = flag.String("notifyAddrs", "127.0.0.1:50001", "Comma separated list of controller notify listener addresses")
var ctrlAddr = flag.String("ctrlAddrs", "127.0.0.1:55001", "controller api address")
var influxAddr = flag.String("influxAddr", "http://127.0.0.1:8086", "InfluxDB listener address")
var vaultAddr = flag.String("vaultAddr", "", "Vault address; local vault runs at http://127.0.0.1:8200")
var region = flag.String("region", "local", "region name")
var hostname = flag.String("hostname", "", "Unique hostname")

var sigChan chan os.Signal
var alertCache edgeproto.AlertCache
var appHandler AppHandler
var autoProvPolicyHandler AutoProvPolicyHandler
var frClusterInsts edgeproto.FreeReservableClusterInstCache
var dialOpts grpc.DialOption
var notifyClient *notify.Client
var vaultConfig *vault.Config
var autoProvAggr *AutoProvAggr
var settings edgeproto.Settings
var nodeMgr *node.NodeMgr

func main() {
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
	log.InitTracer(*tlsCertFile)
	settings = *edgeproto.GetDefaultSettings()

	span := log.StartSpan(log.DebugLevelInfo, "main")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	var err error
	vaultConfig, err = vault.BestConfig(*vaultAddr)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "vault auth", "type", vaultConfig.Auth.Type())

	dialOpts, err = tls.GetTLSClientDialOption(*ctrlAddr, *tlsCertFile, false)
	if err != nil {
		return fmt.Errorf("Failed to get TLS creds, %v", err)
	}

	nodeMgr = node.Init(ctx, "autoprov", node.WithName(*hostname))
	edgeproto.InitAlertCache(&alertCache)
	appHandler.Init()
	autoProvPolicyHandler.Init()
	frClusterInsts.Init()

	autoProvAggr = NewAutoProvAggr(settings.AutoDeployIntervalSec, settings.AutoDeployOffsetSec, &appHandler.cache, &autoProvPolicyHandler.cache, &frClusterInsts)
	autoProvAggr.Start()

	addrs := strings.Split(*notifyAddrs, ",")
	notifyClient = notify.NewClient(addrs, *tlsCertFile)
	notifyClient.RegisterRecv(notify.GlobalSettingsRecv(&settings, settingsUpdated))
	notifyClient.RegisterRecvAlertCache(&alertCache)
	notifyClient.RegisterRecv(notify.NewAutoProvPolicyRecv(&autoProvPolicyHandler))
	notifyClient.RegisterRecv(notify.NewAppRecv(&appHandler))
	frRecv := notify.NewClusterInstRecv(&frClusterInsts)
	notifyClient.RegisterRecv(frRecv)
	nodeMgr.RegisterClient(notifyClient)

	alertCache.SetUpdatedCb(alertChanged)

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
	log.FinishTracer()
}

func settingsUpdated(ctx context.Context, old *edgeproto.Settings, new *edgeproto.Settings) {
	autoProvAggr.UpdateSettings(ctx, settings.AutoDeployIntervalSec, settings.AutoDeployOffsetSec)
}
