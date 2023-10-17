package ccrm

import (
	"context"
	"sync"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
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
	nodeMgr             *node.NodeMgr
	flags               *Flags
	redisClient         *redis.Client
	ctrlConn            *grpc.ClientConn
	CancelHandlers      func()
	nodeAttributesCache NodeAttributesCache
	vaultClient         *accessapi.VaultClient
}

type NodeAttributesCache struct {
	data map[edgeproto.CloudletNodeKey]NodeAttributesData
	mux  sync.Mutex
}

type NodeAttributesData struct {
	yamlData []byte
	checksum string
}

type MessageHandler func(ctx context.Context, redisMsg *redis.Message) error

func (s *CCRMHandler) Init(ctx context.Context, nodeType string, nodeMgr *node.NodeMgr, caches *CCRMCaches, redisClient *redis.Client, ctrlConn *grpc.ClientConn, flags *Flags) error {
	s.caches = caches
	s.nodeMgr = nodeMgr
	s.redisClient = redisClient
	s.ctrlConn = ctrlConn
	s.flags = flags
	s.nodeAttributesCache.Init()

	// notify handlers
	s.caches.CloudletCache.AddUpdatedCb(s.cloudletChanged)
	s.caches.CloudletNodeCache.AddUpdatedCb(s.cloudletNodeChanged)

	if redisClient != nil {
		// redis handlers
		hctx, cancel := context.WithCancel(ctx)
		s.CancelHandlers = cancel
		server := rediscache.GetCCRMAPIServer(redisClient, nodeType, s)
		server.Start(hctx)
	}
	vaultClient, err := accessapi.NewVaultClient(ctx, nodeMgr.VaultConfig, s, flags.Region, flags.DnsZone, flags.DnsProvider)
	if err != nil {
		return err
	}
	s.vaultClient = vaultClient
	return nil
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
