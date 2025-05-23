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

package svcnode

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/edgexr/edge-cloud-platform/pkg/version"
	opensearch "github.com/opensearch-project/opensearch-go/v2"
	"github.com/opentracing/opentracing-go"
	"google.golang.org/grpc"
)

var SvcNodeTypeCRM = "crm"
var SvcNodeTypeDME = "dme"
var SvcNodeTypeController = "controller"
var SvcNodeTypeCCRM = "ccrm"
var SvcNodeTypeClusterSvc = "cluster-svc"
var SvcNodeTypeNotifyRoot = "notifyroot"
var SvcNodeTypeEdgeTurn = "edgeturn"
var SvcNodeTypeMC = "mc"
var SvcNodeTypeAutoProv = "autoprov"
var SvcNodeTypeFRM = "frm"
var SvcNodeTypeAddonMgr = "addonmgr"

// SvcNodeMgr tracks all the nodes connected via notify, and handles common
// requests over all nodes.
type SvcNodeMgr struct {
	iTlsCertFile string
	iTlsKeyFile  string
	iTlsCAFile   string
	VaultAddr    string

	MyNode            edgeproto.SvcNode
	SvcNodeCache      RegionSvcNodeCache
	Debug             DebugNode
	VaultConfig       *vault.Config
	Region            string
	InternalPki       internalPki
	InternalDomain    string
	OSClient          *opensearch.Client
	esEvents          [][]byte
	esEventsMux       sync.Mutex
	esWriteSignal     chan bool
	esEventsDone      chan struct{}
	ESWroteEvents     uint64
	tlsClientIssuer   string
	commonName        string
	commonNamePrefix  string
	DeploymentName    string
	DeploymentTag     string
	AccessKeyClient   AccessKeyClient
	AccessApiClient   edgeproto.CloudletAccessApiClient
	accessApiConn     *grpc.ClientConn // here so crm and cloudlet-dme can close it
	ZonePoolLookup    ZonePoolLookup
	CloudletLookup    CloudletLookup
	testTransport     http.RoundTripper // for unit tests
	ValidDomains      string
	cachesLinkToStore bool

	unitTestMode bool
}

// Most of the time there will only be one NodeMgr per process, and these
// settings will come from command line input.
func (s *SvcNodeMgr) InitFlags() {
	// itls uses a set of file-based certs for internal mTLS auth
	// between services. It is not production-safe and should only be
	// used if Vault-PKI cannot be used.
	flag.StringVar(&s.iTlsCertFile, "itlsCert", "", "internal mTLS cert file for communication between services")
	flag.StringVar(&s.iTlsKeyFile, "itlsKey", "", "internal mTLS key file for communication between services")
	flag.StringVar(&s.iTlsCAFile, "itlsCA", "", "internal mTLS CA file for communication between services")
	flag.StringVar(&s.VaultAddr, "vaultAddr", "", "Vault address; local vault runs at http://127.0.0.1:8200")
	flag.BoolVar(&s.InternalPki.UseVaultPki, "useVaultPki", false, "Use Vault Certs and CAs for internal mTLS and public TLS")
	flag.StringVar(&s.InternalDomain, "internalDomain", "internaldomain.net", "(deprecated) domain name for internal PKI")
	flag.StringVar(&s.commonName, "commonName", "", "(deprecated) common name to use for vault internal pki issued certificates")
	flag.StringVar(&s.DeploymentName, "deploymentName", "edgecloud", "Name of deployment setup, when managing multiple Edge Cloud setups for different customers")
	flag.StringVar(&s.DeploymentTag, "deploymentTag", "", "Tag to indicate type of deployment setup. Ex: production, staging, etc")
	// We handle certs internally for GRPC-based APIs. For uptime during
	// domain name migration, we allow server endpoints to be valid for
	// multiple domain names.
	// For certs issued from our internal PKI, all names can be on the same cert.
	// For certs issued by letsencrypt, via the "cloudcommon.GetPublicCertApi",
	// we need to issue multiple certs since domains may be validated by different
	// DNS providers.
	// Note that internal PKI certs do need real hostnames on them for traffic
	// going over the public internet (i.e. CRM to Controller) since CRM needs
	// to use a DNS resolvable hostname to traverse the public internet.
	flag.StringVar(&s.commonNamePrefix, "commonNamePrefix", "", "prefix to append valid domains to for certification common names")
	flag.StringVar(&s.ValidDomains, "validDomains", "internaldomain.net", "comma separated list of valid domains for certificates")
}

func (s *SvcNodeMgr) Init(nodeType, tlsClientIssuer string, ops ...NodeOp) (context.Context, opentracing.Span, error) {
	initCtx := log.ContextWithSpan(context.Background(), log.NoTracingSpan())
	log.SpanLog(initCtx, log.DebugLevelInfo, "start main nodeMgr init")

	opts := &NodeOptions{}
	opts.updateMyNode = true
	for _, op := range ops {
		op(opts)
	}
	s.MyNode.Key.Type = nodeType
	if opts.name != "" {
		s.MyNode.Key.Name = opts.name
	} else {
		roleSuffix := ""
		if string(opts.haRole) != "" {
			roleSuffix = "-" + string(opts.haRole)
		}
		s.MyNode.Key.Name = cloudcommon.Hostname() + roleSuffix
	}
	buildInfo := version.GetBuildInfo(initCtx)
	s.MyNode.Key.Region = opts.region
	s.MyNode.Key.CloudletKey = opts.cloudletKey
	s.MyNode.BuildMaster = buildInfo.BuildMaster
	s.MyNode.BuildHead = buildInfo.BuildHead
	s.MyNode.BuildAuthor = buildInfo.BuildAuthor
	s.MyNode.BuildDate = buildInfo.BuildDate
	s.MyNode.Hostname = cloudcommon.Hostname()
	s.MyNode.ContainerVersion = opts.containerVersion
	s.Region = opts.region
	s.tlsClientIssuer = tlsClientIssuer
	s.ZonePoolLookup = opts.zonePoolLookup
	s.CloudletLookup = opts.cloudletLookup
	s.testTransport = opts.testTransport
	s.cachesLinkToStore = opts.cachesLinkToStore
	if err := s.AccessKeyClient.init(initCtx, nodeType, tlsClientIssuer, opts.cloudletKey, s.DeploymentTag, opts.haRole); err != nil {
		log.SpanLog(initCtx, log.DebugLevelInfo, "access key client init failed", "err", err)
		return initCtx, nil, err
	}
	var err error
	if s.AccessKeyClient.enabled {
		log.SpanLog(initCtx, log.DebugLevelInfo, "Setup persistent access connection to Controller")
		s.accessApiConn, err = s.AccessKeyClient.ConnectController(initCtx)
		if err != nil {
			return initCtx, nil, fmt.Errorf("Failed to connect to controller %v", err)
		}
		s.AccessApiClient = edgeproto.NewCloudletAccessApiClient(s.accessApiConn)
	} else {
		// init vault before pki
		if opts.vaultConfig != nil {
			s.VaultConfig = opts.vaultConfig
		}
		if s.VaultConfig == nil {
			s.VaultConfig, err = vault.BestConfig(s.VaultAddr)
			if err != nil {
				return initCtx, nil, err
			}
			log.SpanLog(initCtx, log.DebugLevelInfo, "vault auth", "type", s.VaultConfig.Auth.Type())
		}
	}

	// init pki before logging, because access to logger needs pki certs
	log.SpanLog(initCtx, log.DebugLevelInfo, "init internal pki")
	err = s.initInternalPki(initCtx)
	if err != nil {
		return initCtx, nil, err
	}

	// init logger
	log.SpanLog(initCtx, log.DebugLevelInfo, "get logger tls")
	loggerTls, err := s.GetPublicClientTlsConfig(initCtx)
	if err != nil {
		return initCtx, nil, err
	}
	log.InitTracer(loggerTls)

	// logging is initialized so start the real span
	// nodemgr init should always be started from main.
	// Caller needs to handle span.Finish()
	var span opentracing.Span
	if opts.parentSpan != "" {
		span = log.NewSpanFromString(log.DebugLevelInfo, opts.parentSpan, "main")
	} else {
		span = log.StartSpan(log.DebugLevelInfo, "main")
	}
	ctx := log.ContextWithSpan(context.Background(), span)

	// start pki refresh after logging initialized
	s.InternalPki.start()

	if s.ZonePoolLookup == nil {
		// single region lookup for events
		zPoolLookup := &ZonePoolCache{}
		zPoolLookup.Init()
		s.ZonePoolLookup = zPoolLookup
	}

	if s.CloudletLookup == nil {
		cloudletLookup := &CloudletCache{}
		cloudletLookup.Init()
		s.CloudletLookup = cloudletLookup
	}
	err = s.initEvents(ctx, opts)
	if err != nil {
		span.Finish()
		return initCtx, nil, err
	}

	edgeproto.InitSvcNodeCache(&s.SvcNodeCache.SvcNodeCache)
	s.SvcNodeCache.setRegion = opts.region
	s.Debug.Init(s)
	if opts.updateMyNode {
		s.UpdateMyNode(ctx)
	}
	return ctx, span, nil
}

func (s *SvcNodeMgr) Name() string {
	return s.MyNode.Key.Name
}

func (s *SvcNodeMgr) Finish() {
	if s.accessApiConn != nil {
		s.accessApiConn.Close()
	}
	if s.OSClient != nil {
		close(s.esEventsDone)
	}
	s.AccessKeyClient.finish()
	log.FinishTracer()
}

func (s *SvcNodeMgr) CommonNamePrefix() string {
	cn := s.commonNamePrefix
	if cn == "" {
		cn = s.MyNode.Key.Type
		if cn == SvcNodeTypeController {
			cn = "ctrl"
		}
		if s.Region != "" {
			cn = strings.ToLower(s.Region) + "." + cn
		}
	}
	return cn
}

func (s *SvcNodeMgr) CommonNames() []string {
	cnp := s.CommonNamePrefix()
	cns := []string{}
	for _, domain := range strings.Split(s.ValidDomains, ",") {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		cns = append(cns, cnp+"."+domain)
	}
	if len(cns) == 0 {
		// no domains specified
		cns = []string{cnp}
	}
	return cns
}

func (s *SvcNodeMgr) UpdateNodeProps(ctx context.Context, props map[string]string) {
	for k, v := range props {
		if s.MyNode.Properties == nil {
			s.MyNode.Properties = make(map[string]string)
		}
		s.MyNode.Properties[k] = v
	}
	s.UpdateMyNode(ctx)
}

type NodeOptions struct {
	name              string
	cloudletKey       edgeproto.CloudletKey
	updateMyNode      bool
	containerVersion  string
	region            string
	vaultConfig       *vault.Config
	esUrls            string
	parentSpan        string
	zonePoolLookup    ZonePoolLookup
	cloudletLookup    CloudletLookup
	haRole            process.HARole
	testTransport     http.RoundTripper
	cachesLinkToStore bool // caches link direct to objstore, not updated over notify
}

type CloudletInPoolFunc func(region, key edgeproto.CloudletKey) bool

type NodeOp func(s *NodeOptions)

func WithName(name string) NodeOp {
	return func(opts *NodeOptions) { opts.name = name }
}

func WithCloudletKey(key *edgeproto.CloudletKey) NodeOp {
	return func(opts *NodeOptions) { opts.cloudletKey = *key }
}

func WithNoUpdateMyNode() NodeOp {
	return func(opts *NodeOptions) { opts.updateMyNode = false }
}

func WithContainerVersion(ver string) NodeOp {
	return func(opts *NodeOptions) { opts.containerVersion = ver }
}

func WithRegion(region string) NodeOp {
	return func(opts *NodeOptions) { opts.region = region }
}

func WithVaultConfig(vaultConfig *vault.Config) NodeOp {
	return func(opts *NodeOptions) { opts.vaultConfig = vaultConfig }
}

func WithESUrls(urls string) NodeOp {
	return func(opts *NodeOptions) { opts.esUrls = urls }
}

func WithParentSpan(parentSpan string) NodeOp {
	return func(opts *NodeOptions) { opts.parentSpan = parentSpan }
}

func WithZonePoolLookup(zonePoolLookup ZonePoolLookup) NodeOp {
	return func(opts *NodeOptions) { opts.zonePoolLookup = zonePoolLookup }
}

func WithCloudletLookup(cloudletLookup CloudletLookup) NodeOp {
	return func(opts *NodeOptions) { opts.cloudletLookup = cloudletLookup }
}

func WithHARole(haRole process.HARole) NodeOp {
	return func(opts *NodeOptions) { opts.haRole = haRole }
}

func WithTestTransport(tr http.RoundTripper) NodeOp {
	return func(opts *NodeOptions) { opts.testTransport = tr }
}

func WithCachesLinkToKVStore() NodeOp {
	return func(opts *NodeOptions) { opts.cachesLinkToStore = true }
}

func (s *SvcNodeMgr) UpdateMyNode(ctx context.Context) {
	s.SvcNodeCache.Update(ctx, &s.MyNode, 0)
}

func (s *SvcNodeMgr) RegisterClient(client *notify.Client) {
	client.RegisterSendSvcNodeCache(&s.SvcNodeCache)
	s.Debug.RegisterClient(client)
	// MC notify handling of ZonePoolCache is done outside of nodemgr.
	if s.MyNode.Key.Type != SvcNodeTypeMC && s.MyNode.Key.Type != SvcNodeTypeNotifyRoot && !s.cachesLinkToStore {
		cache := s.ZonePoolLookup.GetZonePoolCache(s.Region)
		client.RegisterRecvZonePoolCache(cache)
	}
}

func (s *SvcNodeMgr) RegisterServer(server *notify.ServerMgr) {
	server.RegisterRecvSvcNodeCache(&s.SvcNodeCache)
	s.Debug.RegisterServer(server)
	// MC notify handling of ZonePoolCache is done outside of nodemgr.
	if s.MyNode.Key.Type != SvcNodeTypeMC && s.MyNode.Key.Type != SvcNodeTypeNotifyRoot && s.MyNode.Key.Type != SvcNodeTypeController && s.MyNode.Key.Type != SvcNodeTypeCCRM {
		cache := s.ZonePoolLookup.GetZonePoolCache(s.Region)
		server.RegisterSendZonePoolCache(cache)
	}
}

func (s *SvcNodeMgr) GetInternalTlsCertFile() string {
	return s.iTlsCertFile
}

func (s *SvcNodeMgr) GetInternalTlsKeyFile() string {
	return s.iTlsKeyFile
}

func (s *SvcNodeMgr) GetInternalTlsCAFile() string {
	return s.iTlsCAFile
}

// setters are only used for unit testing
func (s *SvcNodeMgr) SetInternalTlsCertFile(file string) {
	s.iTlsCertFile = file
}

func (s *SvcNodeMgr) SetInternalTlsKeyFile(file string) {
	s.iTlsKeyFile = file
}

func (s *SvcNodeMgr) SetInternalTlsCAFile(file string) {
	s.iTlsCAFile = file
}
