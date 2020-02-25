package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/mc/orm"
	"github.com/mobiledgex/edge-cloud/log"
)

var addr = flag.String("addr", "127.0.0.1:9900", "REST listener address")
var sqlAddr = flag.String("sqlAddr", "127.0.0.1:5432", "Postgresql address")
var localSql = flag.Bool("localSql", false, "Run local postgres db")
var consoleProxyAddr = flag.String("consoleproxyaddr", "127.0.0.1:6080", "Console proxy address")
var initSql = flag.Bool("initSql", false, "Init db when using localSql")
var debugLevels = flag.String("d", "", fmt.Sprintf("comma separated list of %v", log.DebugLevelStrings))
var tlsCertFile = flag.String("tls", "", "server tls cert file")
var tlsKeyFile = flag.String("tlskey", "", "server tls key file")
var clientCert = flag.String("clientCert", "", "internal tls client cert file")
var vaultAddr = flag.String("vaultAddr", "http://127.0.0.1:8200", "Vault address")
var localVault = flag.Bool("localVault", false, "Run local Vault")
var ldapAddr = flag.String("ldapAddr", "127.0.0.1:9389", "LDAP listener address")
var gitlabAddr = flag.String("gitlabAddr", "http://127.0.0.1:80", "Gitlab server address")
var artifactoryAddr = flag.String("artifactoryAddr", "http://127.0.0.1:80", "Artifactory server address")
var jaegerAddr = flag.String("jaegerAddr", "127.0.0.1:16686", "Jaeger server address - do not include scheme")
var pingInterval = flag.Duration("pingInterval", 20*time.Second, "SQL database ping keep-alive interval")
var skipVerifyEmail = flag.Bool("skipVerifyEmail", false, "skip email verification, for testing only")
var skipOriginCheck = flag.Bool("skipOriginCheck", false, "skip origin check constraint, for testing only")
var notifyAddrs = flag.String("notifyAddrs", "127.0.0.1:53001", "Parent notify listener addresses")
var notifySrvAddr = flag.String("notifySrvAddr", "127.0.0.1:52001", "Notify listener address")
var hostname = flag.String("hostname", "", "Unique hostname")

var sigChan chan os.Signal

func main() {
	flag.Parse()
	log.SetDebugLevelStrs(*debugLevels)
	log.InitTracer(*tlsCertFile)
	defer log.FinishTracer()

	sigChan = make(chan os.Signal, 1)

	config := orm.ServerConfig{
		ServAddr:         *addr,
		SqlAddr:          *sqlAddr,
		VaultAddr:        *vaultAddr,
		ConsoleProxyAddr: *consoleProxyAddr,
		RunLocal:         *localSql,
		InitLocal:        *initSql,
		LocalVault:       *localVault,
		TlsCertFile:      *tlsCertFile,
		TlsKeyFile:       *tlsKeyFile,
		LDAPAddr:         *ldapAddr,
		GitlabAddr:       *gitlabAddr,
		ArtifactoryAddr:  *artifactoryAddr,
		ClientCert:       *clientCert,
		PingInterval:     *pingInterval,
		SkipVerifyEmail:  *skipVerifyEmail,
		JaegerAddr:       *jaegerAddr,
		SkipOriginCheck:  *skipOriginCheck,
		Hostname:         *hostname,
		NotifyAddrs:      *notifyAddrs,
		NotifySrvAddr:    *notifySrvAddr,
	}
	server, err := orm.RunServer(&config)
	if err != nil {
		log.FatalLog("Failed to run orm server", "err", err)
	}
	defer server.Stop()

	// wait until process is killed/interrupted
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan
}
