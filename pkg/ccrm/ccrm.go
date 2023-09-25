package ccrm

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/pkg/tls"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/go-redis/redis/v8"
)

// CCRM handles platform-specific code. It primarily
// converts notify-based events into platform API calls.
// CCRM should run alongside the Controller.
type CCRM struct {
	nodeType         string
	flags            Flags
	nodeMgr          node.NodeMgr
	notifyClient     *notify.Client
	platformBuilders map[string]platform.PlatformBuilder
	caches           CCRMCaches
	handler          CCRMHandler
	redisCfg         rediscache.RedisConfig
	redisClient      *redis.Client
}

type Flags struct {
	Region                        string
	AppDNSRoot                    string
	DnsZone                       string
	CloudletRegistryPath          string
	CloudletVMImagePath           string
	VersionTag                    string
	CommercialCerts               bool
	ControllerNotifyAddr          string
	ControllerPublicNotifyAddr    string
	ControllerPublicAccessApiAddr string
	ChefServerPath                string
	ThanosRecvAddr                string
	DebugLevels                   string
	TestMode                      bool
}

// NewCCRM creates a new CCRM. The nodeType identifies the service
// if there are other 3rd party CCRMs present, allowing requests
// for certain platforms to be directed to the correct CCRM type.
// PlatformBuilders provide the platforms supported by the CCRM.
func NewCCRM(nodeType string, platformBuilders map[string]platform.PlatformBuilder) *CCRM {
	ccrm := &CCRM{
		nodeType:         nodeType,
		platformBuilders: platformBuilders,
	}
	return ccrm
}

func (s *CCRM) Run() {
	s.InitFlags()
	flag.Parse()

	err := s.Start()
	if err != nil {
		s.Stop()
		log.FatalLog(err.Error())
	}
	defer s.Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	// wait until process is killed/interrupted
	sig := <-sigChan
	fmt.Println(sig)
}

func (s *CCRM) InitFlags() {
	s.flags.Init()
	s.nodeMgr.InitFlags()
	s.redisCfg.InitFlags(rediscache.DefaultCfgRedisHA)
}

func (s *Flags) Init() {
	flag.StringVar(&s.Region, "region", "local", "region name")
	flag.StringVar(&s.AppDNSRoot, "appDNSRoot", "appdnsroot.net", "App domain name root")
	flag.StringVar(&s.DnsZone, "dnsZone", "", "comma separated list of allowed dns zones for DNS update requests")
	flag.StringVar(&s.CloudletRegistryPath, "cloudletRegistryPath", "", "edge-cloud image registry path for deploying cloudlet services")
	flag.StringVar(&s.CloudletVMImagePath, "cloudletVMImagePath", "", "VM image for deploying cloudlet services")
	flag.StringVar(&s.VersionTag, "versionTag", "", "edge-cloud image tag indicating controller version")
	flag.BoolVar(&s.CommercialCerts, "commercialCerts", false, "Have CRM grab certs from LetsEncrypt. If false then CRM will generate its onwn self-signed cert")
	flag.StringVar(&s.ControllerNotifyAddr, "controllerNotifyAddr", "127.0.0.1:50001", "Controller's Notify listener address")
	flag.StringVar(&s.ControllerPublicNotifyAddr, "controllerPublicNotifyAddr", "127.0.0.1:50001", "Controller's Public facing notify address passed to CRM")
	flag.StringVar(&s.ControllerPublicAccessApiAddr, "controllerPublicAccessApiAddr", "127.0.0.1:41001", "Controller's Public facing access api address passed to CRM")
	flag.StringVar(&s.ChefServerPath, "chefServerPath", "", "Path to chef server organization")
	flag.StringVar(&s.ThanosRecvAddr, "thanosRecvAddr", "", "Address of thanos receive API endpoint including port")

	flag.StringVar(&s.DebugLevels, "d", "", fmt.Sprintf("comma separated list of %v", log.DebugLevelStrings))
	flag.BoolVar(&s.TestMode, "testMode", false, "Run CCRM in test mode")
}

// Start requires that flag.Parse() was called.
func (s *CCRM) Start() error {
	log.SetDebugLevelStrs(s.flags.DebugLevels)

	if !util.ValidRegion(s.flags.Region) {
		return fmt.Errorf("invalid region name")
	}
	if len(s.flags.AppDNSRoot) > cloudcommon.DnsDomainLabelMaxLen {
		return fmt.Errorf("appDNSRoot %q must be less than %d characters", s.flags.AppDNSRoot, cloudcommon.DnsDomainLabelMaxLen)
	}
	ctx, span, err := s.nodeMgr.Init(s.nodeType, node.CertIssuerRegional, node.WithContainerVersion(s.flags.VersionTag), node.WithRegion(s.flags.Region))
	if err != nil {
		return err
	}
	defer span.Finish()

	if err := s.validateRegistries(ctx); err != nil {
		return err
	}

	// initialize caches and handlers
	s.caches.Init(ctx, s.nodeType, &s.nodeMgr, s.platformBuilders)

	// init redis client
	s.redisClient, err = rediscache.NewClient(ctx, &s.redisCfg)
	if err != nil {
		return err
	}

	// set up notify TLS
	clientTlsConfig, err := s.nodeMgr.InternalPki.GetClientTlsConfig(ctx, s.nodeMgr.CommonName(), node.CertIssuerRegional, []node.MatchCA{node.SameRegionalMatchCA()})
	if err != nil {
		return err
	}
	dialOpts := tls.GetGrpcDialOption(clientTlsConfig)
	addrs := strings.Split(s.flags.ControllerNotifyAddr, ",")
	s.notifyClient = notify.NewClient(s.nodeMgr.Name(), addrs, dialOpts)

	// initialize and start the notify client
	s.caches.InitNotify(s.notifyClient, &s.nodeMgr)
	s.notifyClient.Start()

	s.handler.Init(ctx, s.nodeType, &s.nodeMgr, &s.caches, s.redisClient, &s.flags)

	return nil
}

func (s *CCRM) Stop() {
	if s.notifyClient != nil {
		s.notifyClient.Stop()
		s.notifyClient = nil
	}
	if s.handler.CancelHandlers != nil {
		s.handler.CancelHandlers()
		s.handler.CancelHandlers = nil
	}
	s.nodeMgr.Finish()
}

func (s *CCRM) validateRegistries(ctx context.Context) error {
	if s.flags.CloudletRegistryPath != "" {
		if s.flags.VersionTag == "" {
			return fmt.Errorf("Version tag is required")
		}
		if s.flags.CloudletRegistryPath == "edge-cloud-crm" {
			// local KIND operators testing, ignore
			log.SpanLog(ctx, log.DebugLevelInfo, "skipping cloudletRegistryPath validation for local KIND testing", "cloudletRegistryPath", s.flags.CloudletRegistryPath)
			return nil
		}
		parts := strings.Split(s.flags.CloudletRegistryPath, "/")
		if len(parts) < 2 || !strings.Contains(parts[0], ".") {
			return fmt.Errorf("Cloudlet registry path should be full registry URL: <domain-name>/<registry-path>")
		}
		urlObj, err := util.ImagePathParse(s.flags.CloudletRegistryPath)
		if err != nil {
			return fmt.Errorf("Invalid cloudlet registry path: %v", err)
		}
		out := strings.Split(urlObj.Path, ":")
		if len(out) == 2 {
			return fmt.Errorf("Cloudlet registry path should not have image tag")
		} else if len(out) != 1 {
			return fmt.Errorf("Invalid registry path")
		}
		platform_registry_path := s.flags.CloudletRegistryPath + ":" + strings.TrimSpace(s.flags.VersionTag)
		authApi := &cloudcommon.VaultRegistryAuthApi{
			VaultConfig: s.nodeMgr.VaultConfig,
		}
		err = cloudcommon.ValidateDockerRegistryPath(ctx, platform_registry_path, authApi)
		if err != nil {
			return err
		}
	}
	return nil
}
