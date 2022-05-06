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
	"time"

	"github.com/edgexr/edge-cloud-infra/mc/orm"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

var addr = flag.String("addr", "127.0.0.1:9900", "REST listener address")
var federationAddr = flag.String("federationAddr", "", "REST listener address for multi-operator platform federation")
var sqlAddr = flag.String("sqlAddr", "127.0.0.1:5432", "Postgresql address")
var localSql = flag.Bool("localSql", false, "Run local postgres db")
var consoleProxyAddr = flag.String("consoleproxyaddr", "127.0.0.1:6080", "Console proxy address")
var initSql = flag.Bool("initSql", false, "Init db when using localSql")
var debugLevels = flag.String("d", "", fmt.Sprintf("comma separated list of %v", log.DebugLevelStrings))
var apiTlsCertFile = flag.String("apiTlsCert", "", "API server tls cert file")
var apiTlsKeyFile = flag.String("apiTlsKey", "", "API server tls key file")
var localVault = flag.Bool("localVault", false, "Run local Vault")
var ldapAddr = flag.String("ldapAddr", "127.0.0.1:9389", "LDAP listener address")
var gitlabAddr = flag.String("gitlabAddr", "", "Gitlab server address")
var artifactoryAddr = flag.String("artifactoryAddr", "", "Artifactory server address")
var jaegerAddr = flag.String("jaegerAddr", "127.0.0.1:16686", "Jaeger server address - do not include scheme")
var pingInterval = flag.Duration("pingInterval", 20*time.Second, "SQL database ping keep-alive interval")
var skipVerifyEmail = flag.Bool("skipVerifyEmail", false, "skip email verification, for testing only")
var skipOriginCheck = flag.Bool("skipOriginCheck", false, "skip origin check constraint, for testing only")
var notifyAddrs = flag.String("notifyAddrs", "", "Parent notify listener addresses")
var notifySrvAddr = flag.String("notifySrvAddr", "127.0.0.1:52001", "Notify listener address")
var alertMgrAddr = flag.String("alertMgrApiAddr", "http://127.0.0.1:9094", "Global Alertmanager api address")
var publicAddr = flag.String("publicAddr", "http://127.0.0.1:9900", "Public facing address/hostname of MC")

var alertMgrResolveTimeout = flag.Duration("alertResolveTimeout", 3*time.Minute, "Alertmanager alert Resolution timeout")
var hostname = flag.String("hostname", "", "Unique hostname")
var billingPlatform = flag.String("billingPlatform", "fake", "Billing platform to use")
var usageCollectionInterval = flag.Duration("usageCollectionInterval", -1*time.Second, "Collection interval")
var usageCheckpointInterval = flag.String("usageCheckpointInterval", "MONTH", "Checkpointing interval(must be same as controller's checkpointInterval)")
var staticDir = flag.String("staticDir", "/", "Path to static data")
var controllerNotifyPort = flag.String("controllerNotifyPort", "50001", "Controller notify listener port to connect to")

// Following URL paths are UI console paths which will be used to send
// appropriate links to user's email for actions like password-reset, email-verification
var consoleAddr = flag.String("consoleAddr", "", "Address of the UI console using MC")
var passwordResetConsolePath = flag.String("passwordResetConsolePath", "#/passwordreset", "Console URL path to perform password reset action by end-user")
var verifyEmailConsolePath = flag.String("verifyEmailConsolePath", "#/verify", "Console URL path to perform email verification action by end-user")

var sigChan chan os.Signal
var nodeMgr node.NodeMgr
var alertCache edgeproto.AlertCache

func main() {
	nodeMgr.InitFlags()
	flag.Parse()
	log.SetDebugLevelStrs(*debugLevels)

	sigChan = make(chan os.Signal, 1)

	config := orm.ServerConfig{
		ServAddr:                 *addr,
		SqlAddr:                  *sqlAddr,
		VaultAddr:                nodeMgr.VaultAddr,
		FederationAddr:           *federationAddr,
		RunLocal:                 *localSql,
		InitLocal:                *initSql,
		LocalVault:               *localVault,
		ApiTlsCertFile:           *apiTlsCertFile,
		ApiTlsKeyFile:            *apiTlsKeyFile,
		LDAPAddr:                 *ldapAddr,
		GitlabAddr:               *gitlabAddr,
		ArtifactoryAddr:          *artifactoryAddr,
		PingInterval:             *pingInterval,
		SkipVerifyEmail:          *skipVerifyEmail,
		JaegerAddr:               *jaegerAddr,
		SkipOriginCheck:          *skipOriginCheck,
		Hostname:                 *hostname,
		NotifyAddrs:              *notifyAddrs,
		NotifySrvAddr:            *notifySrvAddr,
		NodeMgr:                  &nodeMgr,
		BillingPlatform:          *billingPlatform,
		AlertMgrAddr:             *alertMgrAddr,
		AlertCache:               &alertCache,
		AlertmgrResolveTimout:    *alertMgrResolveTimeout,
		UsageCheckpointInterval:  *usageCheckpointInterval,
		DomainName:               nodeMgr.CommonName(),
		StaticDir:                *staticDir,
		DeploymentTag:            nodeMgr.DeploymentTag,
		ControllerNotifyPort:     *controllerNotifyPort,
		PublicAddr:               *publicAddr,
		ConsoleAddr:              *consoleAddr,
		PasswordResetConsolePath: *passwordResetConsolePath,
		VerifyEmailConsolePath:   *verifyEmailConsolePath,
	}
	server, err := orm.RunServer(&config)
	if err != nil {
		log.FatalLog("Failed to run orm server", "err", err)
	}
	defer server.Stop()

	// Wait for server to set up the vault first
	err = server.WaitUntilReady()
	if err != nil {
		log.FatalLog("Server could not be started", "err", err)
	}

	go orm.CollectBillingUsage(*usageCollectionInterval)

	// start report generation thread
	orm.InitReporter()
	go orm.GenerateReports()

	// wait until process is killed/interrupted
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan
}
