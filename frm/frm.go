package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	frmnotify "github.com/mobiledgex/edge-cloud-infra/frm/notify"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/notify"
)

var notifyAddrs = flag.String("notifyAddrs", "127.0.0.1:50001", "Comma separated list of controller notify listener addresses")
var hostname = flag.String("hostname", "", "Unique hostname")
var debugLevels = flag.String("d", "", fmt.Sprintf("Comma separated list of %v", log.DebugLevelStrings))
var region = flag.String("region", "local", "region name")

var sigChan chan os.Signal
var nodeMgr node.NodeMgr
var notifyClient *notify.Client
var controllerData *frmnotify.ControllerData

func main() {
	nodeMgr.InitFlags()
	nodeMgr.AccessKeyClient.InitFlags()
	flag.Parse()

	log.SetDebugLevelStrs(*debugLevels)

	sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	var err error
	notifyClient, controllerData, err = frmnotify.SetupFRMNotify(&nodeMgr, *hostname, *region, *notifyAddrs)
	if err != nil {
		log.FatalLog(err.Error())
	}
	defer nodeMgr.Finish()
	defer notifyClient.Stop()

	sig := <-sigChan
	fmt.Println(sig)
}
