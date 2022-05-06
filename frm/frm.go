// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/edgexr/edge-cloud-infra/version"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/redundancy"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	"github.com/edgexr/edge-cloud/integration/process"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/notify"
	"github.com/edgexr/edge-cloud/vault"
)

var notifyAddrs = flag.String("notifyAddrs", "127.0.0.1:50001", "Comma separated list of controller notify listener addresses")
var hostname = flag.String("hostname", "", "Unique hostname")
var debugLevels = flag.String("d", "", fmt.Sprintf("Comma separated list of %v", log.DebugLevelStrings))
var region = flag.String("region", "local", "region name")
var appDNSRoot = flag.String("appDNSRoot", "mobiledgex.net", "App domain name root")

var sigChan chan os.Signal
var nodeMgr node.NodeMgr
var haMgr redundancy.HighAvailabilityManager
var notifyClient *notify.Client
var controllerData *ControllerData
var vaultConfig *vault.Config

func main() {
	nodeMgr.InitFlags()
	nodeMgr.AccessKeyClient.InitFlags()
	haMgr.InitFlags()
	flag.Parse()

	log.SetDebugLevelStrs(*debugLevels)

	sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	nodeOps := []node.NodeOp{
		node.WithName(*hostname),
		node.WithNoUpdateMyNode(),
		node.WithRegion(*region),
		node.WithVaultConfig(vaultConfig),
	}
	if haMgr.HARole == string(process.HARoleSecondary) {
		nodeOps = append(nodeOps, node.WithHARole(process.HARoleSecondary))
	} else {
		nodeOps = append(nodeOps, node.WithHARole(process.HARolePrimary))
	}
	ctx, span, err := nodeMgr.Init(node.NodeTypeFRM, node.CertIssuerRegional, nodeOps...)
	if err != nil {
		log.FatalLog(err.Error())
	}
	defer span.Finish()
	nodeMgr.UpdateNodeProps(ctx, version.InfraBuildProps("Infra"))

	notifyClient, controllerData, err = InitFRM(ctx, &nodeMgr, &haMgr, *hostname, *region, *appDNSRoot, *notifyAddrs)
	if err != nil {
		log.FatalLog("Failed to init frm", "err", err)
	}
	defer nodeMgr.Finish()
	defer notifyClient.Stop()

	sig := <-sigChan
	fmt.Println(sig)
}
