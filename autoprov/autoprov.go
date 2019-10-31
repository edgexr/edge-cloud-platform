package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/notify"
	"github.com/mobiledgex/edge-cloud/tls"
	"google.golang.org/grpc"
)

var debugLevels = flag.String("d", "", fmt.Sprintf("comma separated list of %v", log.DebugLevelStrings))
var tlsCertFile = flag.String("tls", "", "server tls cert file.  Keyfile and CA file mex-ca.crt must be in same directory")
var notifyAddrs = flag.String("notifyAddrs", "127.0.0.1:50001", "Comma separated list of controller notify listener addresses")
var ctrlAddr = flag.String("ctrlAddrs", "127.0.0.1:55001", "controller api address")

var sigChan chan os.Signal
var alertCache edgeproto.AlertCache
var dialOpts grpc.DialOption
var notifyClient *notify.Client

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

	span := log.StartSpan(log.DebugLevelInfo, "main")
	defer span.Finish()

	var err error
	dialOpts, err = tls.GetTLSClientDialOption(*ctrlAddr, *tlsCertFile, false)
	if err != nil {
		return fmt.Errorf("Failed to get TLS creds, %v", err)
	}

	edgeproto.InitAlertCache(&alertCache)

	addrs := strings.Split(*notifyAddrs, ",")
	notifyClient = notify.NewClient(addrs, *tlsCertFile)
	notifyClient.RegisterRecvAlertCache(&alertCache)

	alertCache.SetUpdatedCb(alertChanged)

	notifyClient.Start()
	return nil
}

func stop() {
	notifyClient.Stop()
	log.FinishTracer()
}
