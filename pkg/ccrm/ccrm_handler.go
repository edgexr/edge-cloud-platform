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
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/crmutil"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/cloudletssh"
	certscache "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs-cache"
	"github.com/go-redis/redis/v8"
	"google.golang.org/grpc"
)

// CCRMHandler handles converting notify-based events
// into functional API calls. If CCRM eventually wants
// to act as a central CRM, this can be replaced by
// crmutil.ControllerData. But for now, this only needs
// to handle cloudlet onboarding events.

type CCRMHandler struct {
	caches              *CCRMCaches
	nodeMgr             *svcnode.SvcNodeMgr
	nodeType            string
	flags               *Flags
	ctrlConn            *grpc.ClientConn // TODO: remove, we can write CloudletNodes direct to etcd instead
	cancelHandlers      []func()
	nodeAttributesCache NodeAttributesCache
	crmPlatforms        CRMPlatformCache
	vaultClient         *accessapi.VaultClient
	registryAuthAPI     cloudcommon.RegistryAuthApi
	platformBuilders    map[string]platform.PlatformBuilder
	crmHandler          *crmutil.CRMHandler
	cloudletSSHKey      *cloudletssh.SSHKey
	sync                edgeproto.DataSync
	proxyCertsCache     *certscache.ProxyCertsCache
}

type CRMPlatformCache struct {
	platforms map[edgeproto.CloudletKey]platform.Platform
	mux       sync.Mutex
}

type NodeAttributesCache struct {
	data map[edgeproto.CloudletNodeKey]NodeAttributesData
	mux  sync.Mutex
}

type NodeAttributesData struct {
	yamlData []byte
	checksum string
}

var ErrPlatformNotFound = errors.New("platform not found")
var ErrIgnoreForCrmOnEdge = errors.New("ignoring request because crmOnEdge is set")

const RedisKeepAliveInterval = 3 * time.Second

type MessageHandler func(ctx context.Context, redisMsg *redis.Message) error

func (s *CCRMHandler) Init(ctx context.Context, nodeMgr *svcnode.SvcNodeMgr, caches *CCRMCaches, platformBuilders map[string]platform.PlatformBuilder, flags *Flags, registryAuthAPI cloudcommon.RegistryAuthApi) {
	s.caches = caches
	s.nodeMgr = nodeMgr
	s.nodeType = nodeMgr.MyNode.Key.Type
	s.flags = flags
	s.registryAuthAPI = registryAuthAPI
	s.nodeAttributesCache.Init()
	s.crmPlatforms.Init()
	s.platformBuilders = platformBuilders
	s.vaultClient = accessapi.NewVaultClient(ctx, nodeMgr.VaultConfig, s, flags.Region, flags.DnsZone, nodeMgr.ValidDomains)
	s.cloudletSSHKey = cloudletssh.NewSSHKey(s.vaultClient)
	s.crmHandler = crmutil.NewCRMHandler(s.getCRMCloudletPlatform, s.nodeMgr)
	s.proxyCertsCache = certscache.NewProxyCertsCache(s.vaultClient)

	s.caches.CloudletNodeCache.AddUpdatedCb(s.cloudletNodeChanged)
	s.crmHandler.SettingsCache.AddUpdatedCb(s.crmHandler.SettingsChanged)
}

func (s *CCRMHandler) InitConnectivity(client *notify.Client, kvstore objstore.KVStore, nodeMgr *svcnode.SvcNodeMgr, grpcServer *grpc.Server, sync edgeproto.DataSync) {
	// Caches are updated via etcd watches.
	// In general most data sent from here to the Controller is
	// via return values from GRPC API calls the Controller makes to here.
	s.sync = sync
	s.crmHandler.AppCache.InitSync(sync)
	s.crmHandler.AppInstCache.InitSync(sync)
	s.crmHandler.CloudletInternalCache.InitSync(sync)
	s.crmHandler.CloudletCache.InitSync(sync)
	s.crmHandler.VMPoolCache.InitSync(sync)
	s.crmHandler.FlavorCache.InitSync(sync)
	s.crmHandler.ClusterInstCache.InitSync(sync)
	s.crmHandler.TrustPolicyCache.InitSync(sync)
	s.crmHandler.TrustPolicyExceptionCache.InitSync(sync)
	s.crmHandler.AutoProvPolicyCache.InitSync(sync)
	s.crmHandler.AutoScalePolicyCache.InitSync(sync)
	s.crmHandler.SettingsCache.InitSync(sync)
	s.crmHandler.ResTagTableCache.InitSync(sync)
	s.crmHandler.GPUDriverCache.InitSync(sync)
	s.crmHandler.AlertPolicyCache.InitSync(sync)
	s.crmHandler.NetworkCache.InitSync(sync)
	s.caches.PlatformFeaturesCache.InitSync(sync)
	s.caches.CloudletNodeCache.InitSync(sync)
	s.caches.CloudletInfoCache.InitSync(sync)
	s.caches.ClusterInstInfoCache.InitSync(sync)
	s.caches.AppInstInfoCache.InitSync(sync)
	nodeMgr.CloudletLookup.GetCloudletCache(nodeMgr.Region).InitSync(sync)
	nodeMgr.ZonePoolLookup.GetZonePoolCache(nodeMgr.Region).InitSync(sync)

	// notify handlers
	if client != nil {
		client.RegisterSendAlertCache(&s.crmHandler.AlertCache)
		client.RegisterRecv(notify.NewFedAppInstEventRecv(s))
		nodeMgr.RegisterClient(client)
	}

	// grpc handlers
	if grpcServer != nil {
		edgeproto.RegisterCloudletPlatformAPIServer(grpcServer, s)
		edgeproto.RegisterClusterPlatformAPIServer(grpcServer, s)
		edgeproto.RegisterAppInstPlatformAPIServer(grpcServer, s)
	}

	s.crmHandler.CloudletCache.AddUpdatedCb(func(ctx context.Context, old, new *edgeproto.Cloudlet) {
		// force re-init of platform in case env vars, etc, changed
		s.crmPlatforms.Delete(&new.Key)
	})
}

func (s *CCRMHandler) Start(ctx context.Context, ctrlConn *grpc.ClientConn) {
	s.ctrlConn = ctrlConn
	for _, builder := range s.platformBuilders {
		plat := builder()
		features := plat.GetFeatures()
		features.NodeType = s.nodeType
		_, err := s.caches.PlatformFeaturesCache.Store.Put(ctx, features, nil)
		if err != nil {
			log.FatalLog("failed to write platform features to store", "err", err)
		}
	}
}

func (s *CCRMHandler) RecvFedAppInstEvent(ctx context.Context, msg *edgeproto.FedAppInstEvent) {
	// distribute to all "live" platforms, as this event is only desired by
	// an existing platform running AppInst create that is waiting to be
	// notified of (or poll for) the AppInst create to be done.
	all := s.crmPlatforms.GetAll()
	go func() {
		span := log.StartSpan(log.DebugLevelApi, "recv federation AppInst event")
		ctx := log.ContextWithSpan(context.Background(), span)
		defer span.Finish()
		for _, p := range all {
			p.HandleFedAppInstCb(ctx, msg)
		}
	}()
}

func (s *CCRMHandler) Stop() {
	for _, cancel := range s.cancelHandlers {
		cancel()
	}
	s.cancelHandlers = []func(){}
}

func (s *CCRMHandler) addCancel(cancel func()) {
	s.cancelHandlers = append(s.cancelHandlers, cancel)
}

func (s *NodeAttributesCache) Init() {
	s.data = make(map[edgeproto.CloudletNodeKey]NodeAttributesData)
}

func (s *NodeAttributesCache) Update(key edgeproto.CloudletNodeKey, yamlData []byte, checksum string) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.data[key] = NodeAttributesData{
		yamlData: yamlData,
		checksum: checksum,
	}
}

func (s *NodeAttributesCache) Get(key edgeproto.CloudletNodeKey) (NodeAttributesData, bool) {
	s.mux.Lock()
	defer s.mux.Unlock()
	data, ok := s.data[key]
	return data, ok
}

func (s *CRMPlatformCache) Init() {
	s.platforms = make(map[edgeproto.CloudletKey]platform.Platform)
}

func (s *CRMPlatformCache) Get(key *edgeproto.CloudletKey) (platform.Platform, bool) {
	s.mux.Lock()
	defer s.mux.Unlock()
	p, ok := s.platforms[*key]
	return p, ok
}

func (s *CRMPlatformCache) Set(key *edgeproto.CloudletKey, pf platform.Platform) {
	s.mux.Lock()
	defer s.mux.Unlock()
	// note we don't care if there's a race and we overwrite an existing object,
	// this cache is just an optimization to avoid allocating and initializing
	// a platform object each time, it should have no bearing on functionality.
	s.platforms[*key] = pf
}

func (s *CRMPlatformCache) Delete(key *edgeproto.CloudletKey) {
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.platforms, *key)
}

func (s *CRMPlatformCache) GetAll() []platform.Platform {
	s.mux.Lock()
	defer s.mux.Unlock()
	all := []platform.Platform{}
	for _, p := range s.platforms {
		all = append(all, p)
	}
	return all
}

func (s *CCRMHandler) GetPlatformCache() *CRMPlatformCache {
	return &s.crmPlatforms
}

func (s *CCRMHandler) newPlatform(platformType string) (platform.Platform, bool) {
	builder, ok := s.platformBuilders[platformType]
	if !ok {
		return nil, false
	}
	plat := builder()
	return plat, true
}

func (s *CCRMHandler) getCloudletPlatform(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.Cloudlet, platform.Platform, error) {
	if key == nil {
		return nil, nil, fmt.Errorf("CloudletKey not specified")
	}
	cloudlet := edgeproto.Cloudlet{}
	// make sure to go direct to etcd to avoid any race condition
	// on cloudlet create, as cache may not be updated yet.
	if !s.crmHandler.CloudletCache.Store.Get(ctx, key, &cloudlet) {
		return nil, nil, key.NotFoundError()
	}
	cloudletPlatform, found := s.newPlatform(cloudlet.PlatformType)
	if !found {
		// This is not really an error, another CCRM should handle the request
		return nil, nil, fmt.Errorf("%s %s", cloudlet.PlatformType, ErrPlatformNotFound)
	}
	return &cloudlet, cloudletPlatform, nil
}

// TODO: need to periodically flush cached entries that haven't been
// used recently.
func (s *CCRMHandler) getCRMCloudletPlatform(ctx context.Context, key *edgeproto.CloudletKey) (platform.Platform, error) {
	pf, ok := s.crmPlatforms.Get(key)
	if ok {
		return pf, nil
	}
	cloudlet, pf, err := s.getCloudletPlatform(ctx, key)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "get cloudlet platform failed", "cloudletkey", key, "err", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "created new platform for cloudlet", "cloudlet", key, "platformType", cloudlet.PlatformType)

	cacheDir := fmt.Sprintf("/tmp/%s/%s/cache", key.Organization, key.Name)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to make cloudlet cache dir", "dir", cacheDir, "err", err)
		return nil, fmt.Errorf("get cloudlet platform failed to init cache dir, %s", err)
	}

	pfInitConfig := s.getPlatformInitConfig(cloudlet)
	updateCb := func(updateType edgeproto.CacheUpdateType, value string) {}

	// TODO: this somewhat duplicates the code in pkg/crm/crm.go, would be
	// good to combine into a common function if possible. Probably want a
	// common command line flags object shared between CRM and CCRM for some
	// of the fields.
	pfConfig := platform.PlatformConfig{
		CloudletKey:         key,
		CloudletObjID:       cloudlet.ObjId,
		PhysicalName:        cloudlet.PhysicalName,
		Region:              s.flags.Region,
		TestMode:            s.flags.TestMode,
		CloudletVMImagePath: s.flags.CloudletVMImagePath,
		EnvoyWithCurlImage:  s.flags.EnvoyWithCurlImage,
		NginxWithCurlImage:  s.flags.NginxWithCurlImage,
		EnvVars:             cloudlet.EnvVar,
		NodeMgr:             s.nodeMgr,
		AppDNSRoot:          s.flags.AppDNSRoot,
		RootLBFQDN:          cloudlet.RootLbFqdn,
		DeploymentTag:       s.nodeMgr.DeploymentTag,
		TrustPolicy:         cloudlet.TrustPolicy,
		CacheDir:            cacheDir,
		AnsiblePublicAddr:   s.flags.AnsiblePublicAddr,
		CommercialCerts:     s.flags.CommercialCerts,
		PlatformInitConfig:  *pfInitConfig,
		FedExternalAddr:     s.flags.FederationExternalAddr,
	}
	err = pf.InitCommon(ctx, &pfConfig, s.crmHandler.GetCaches(), nil, updateCb)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "platform init failed", "key", key, "platformType", cloudlet.PlatformType, "err", err)
		return nil, fmt.Errorf("%s platform init failed, %s", cloudlet.PlatformType, err)
	}
	s.crmPlatforms.Set(key, pf)
	return pf, nil
}
