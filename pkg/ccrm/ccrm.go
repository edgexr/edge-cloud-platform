// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ccrm

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/tls"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/labstack/echo/v4"
	"google.golang.org/grpc"
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
	echoServ         *echo.Echo
	ctrlConn         *grpc.ClientConn
	registryAuthAPI  cloudcommon.RegistryAuthApi
	listeners        []net.Listener
	grpcServer       *grpc.Server
	sync             *regiondata.Sync
}

type Flags struct {
	Region                        string
	AppDNSRoot                    string
	DnsZone                       string
	CloudletRegistryPath          string
	CloudletVMImagePath           string
	APIAddr                       string
	EtcdURLs                      string
	EnvoyWithCurlImage            string
	NginxWithCurlImage            string
	VersionTag                    string
	CommercialCerts               bool
	ControllerAPIAddr             string
	ControllerNotifyAddr          string
	ControllerPublicNotifyAddr    string
	ControllerPublicAccessApiAddr string
	AnsibleListenAddr             string
	AnsiblePublicAddr             string
	ThanosRecvAddr                string
	FederationExternalAddr        string
	DebugLevels                   string
	TestMode                      bool
}

// NewCCRM creates a new CCRM. The nodeType identifies the service
// if there are other 3rd party CCRMs present, allowing requests
// for certain platforms to be directed to the correct CCRM type.
// New implementations must use their own unique node type.
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
	flag.StringVar(&s.APIAddr, "apiAddr", "127.0.0.1:19001", "GRPC API listener address")
	flag.StringVar(&s.EtcdURLs, "etcdUrls", "http://127.0.0.1:2380", "etcd client listener URLs")
	flag.StringVar(&s.EnvoyWithCurlImage, "envoyWithCurlImage", "", "docker image for envoy with curl to use on LB as reverse proxy")
	flag.StringVar(&s.NginxWithCurlImage, "nginxWithCurlImage", "", "docker image for nginx with curl to use on LB as reverse proxy")
	flag.StringVar(&s.VersionTag, "versionTag", "", "edge-cloud image tag indicating controller version")
	flag.BoolVar(&s.CommercialCerts, "commercialCerts", false, "Have CRM grab certs from LetsEncrypt. If false then CRM will generate its onwn self-signed cert")
	flag.StringVar(&s.ControllerAPIAddr, "controllerApiAddr", "127.0.0.1:55001", "Controller's API listener address")
	flag.StringVar(&s.ControllerNotifyAddr, "controllerNotifyAddr", "127.0.0.1:50001", "Controller's Notify listener address")
	flag.StringVar(&s.ControllerPublicNotifyAddr, "controllerPublicNotifyAddr", "127.0.0.1:50001", "Controller's Public facing notify address passed to CRM")
	flag.StringVar(&s.ControllerPublicAccessApiAddr, "controllerPublicAccessApiAddr", "127.0.0.1:41001", "Controller's Public facing access api address passed to CRM")
	flag.StringVar(&s.ThanosRecvAddr, "thanosRecvAddr", "", "Address of thanos receive API endpoint including port")
	flag.StringVar(&s.AnsibleListenAddr, "ansibleListenAddr", "127.0.0.1:48880", "Address and port to serve ansible files from")
	flag.StringVar(&s.AnsiblePublicAddr, "ansiblePublicAddr", "http://127.0.0.1:48880", "Scheme, address, and port to pass to the CRM to reach the ansible server externally")
	flag.StringVar(&s.FederationExternalAddr, "federationExternalAddr", "", "Federation EWBI API endpoint for clients")

	flag.StringVar(&s.DebugLevels, "d", "", fmt.Sprintf("comma separated list of %v", log.DebugLevelStrings))
	flag.BoolVar(&s.TestMode, "testMode", false, "Run CCRM in test mode")
}

func (s *Flags) GetPlatformRegistryPath() string {
	return s.CloudletRegistryPath + ":" + strings.TrimSpace(s.VersionTag)
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
	ctx, span, err := s.nodeMgr.Init(s.nodeType, node.CertIssuerRegional, node.WithContainerVersion(s.flags.VersionTag), node.WithRegion(s.flags.Region), node.WithCachesLinkToKVStore())
	if err != nil {
		return err
	}
	defer span.Finish()

	if err := s.validateRegistries(ctx); err != nil {
		return err
	}
	regAuthMgr := cloudcommon.NewRegistryAuthMgr(s.nodeMgr.VaultConfig, s.nodeMgr.ValidDomains)
	s.registryAuthAPI = &cloudcommon.VaultRegistryAuthApi{
		RegAuthMgr: regAuthMgr,
	}

	// initialize caches and handlers
	s.caches.Init(ctx)
	s.handler.Init(ctx, &s.nodeMgr, &s.caches, s.platformBuilders, &s.flags, s.registryAuthAPI)

	objStore, err := regiondata.GetEtcdClientBasic(s.flags.EtcdURLs)
	if err != nil {
		return fmt.Errorf("Failed to initialize Object Store, %v", err)
	}
	err = objStore.CheckConnected(50, 20*time.Millisecond)
	if err != nil {
		return fmt.Errorf("Failed to connect to etcd servers, %v", err)
	}
	sync := regiondata.InitSync(objStore)

	// set up notify TLS
	clientTlsConfig, err := s.nodeMgr.InternalPki.GetClientTlsConfig(ctx, s.nodeMgr.CommonNamePrefix(), node.CertIssuerRegional, []node.MatchCA{node.SameRegionalMatchCA()})
	if err != nil {
		return err
	}
	dialOpts := tls.GetGrpcDialOption(clientTlsConfig)
	addrs := strings.Split(s.flags.ControllerNotifyAddr, ",")
	notifyClient := notify.NewClient(s.nodeMgr.Name(), addrs, dialOpts)

	clientConn, err := s.controllerConnect(ctx, dialOpts)
	if err != nil {
		return err
	}
	s.ctrlConn = clientConn

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(cloudcommon.AuditUnaryInterceptor)),
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(cloudcommon.AuditStreamInterceptor)),
		grpc.ForceServerCodec(&cloudcommon.ProtoCodec{}))

	s.handler.InitConnectivity(notifyClient, objStore, &s.nodeMgr, grpcServer, sync)

	echoServ := s.initAnsibleServer(ctx)

	sync.Start()
	s.sync = sync
	s.handler.Start(ctx, s.ctrlConn)
	notifyClient.Start()
	s.notifyClient = notifyClient

	s.startAnsibleServer(ctx, echoServ)

	lis, err := net.Listen("tcp", s.flags.APIAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on address %s, %s", s.flags.APIAddr, err)
	}
	s.listeners = append(s.listeners, lis)
	s.grpcServer = grpcServer
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			log.FatalLog("failed to serve", "err", err)
		}
	}()

	return nil
}

func (s *CCRM) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.Stop()
		s.grpcServer = nil
	}
	if s.notifyClient != nil {
		s.notifyClient.Stop()
		s.notifyClient = nil
	}
	s.handler.Stop()
	s.stopAnsibleServer()
	if s.ctrlConn != nil {
		s.ctrlConn.Close()
		s.ctrlConn = nil
	}
	for _, lis := range s.listeners {
		lis.Close()
	}
	s.listeners = nil
	if s.sync != nil {
		s.sync.Done()
		s.sync = nil
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
		platformRegistryPath := s.flags.GetPlatformRegistryPath()
		authApi := &cloudcommon.VaultRegistryAuthApi{
			RegAuthMgr: cloudcommon.NewRegistryAuthMgr(s.nodeMgr.VaultConfig, s.nodeMgr.ValidDomains),
		}
		err = cloudcommon.ValidateDockerRegistryPath(ctx, platformRegistryPath, authApi)
		if err != nil {
			return err
		}
		s.registryAuthAPI = authApi
		_, err = authApi.GetRegistryAuth(ctx, platformRegistryPath)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *CCRM) controllerConnect(ctx context.Context, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts = append(opts,
		grpc.WithBlock(),
		grpc.WithUnaryInterceptor(log.UnaryClientTraceGrpc),
		grpc.WithStreamInterceptor(log.StreamClientTraceGrpc),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(&cloudcommon.ProtoCodec{})))
	return grpc.Dial(s.flags.ControllerAPIAddr, opts...)
}
