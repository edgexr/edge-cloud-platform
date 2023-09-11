package ccrm

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/go-redis/redis/v8"
)

// CCRMHandler handles converting notify-based events
// into functional API calls. If CCRM eventually wants
// to act as a central CRM, this can be replaced by
// crmutil.ControllerData. But for now, this only needs
// to handle cloudlet onboarding events.

type CCRMHandler struct {
	caches         *CCRMCaches
	nodeMgr        *node.NodeMgr
	flags          *Flags
	redisClient    *redis.Client
	CancelHandlers func()
}

type MessageHandler func(ctx context.Context, redisMsg *redis.Message) error

func (s *CCRMHandler) Init(ctx context.Context, nodeType string, nodeMgr *node.NodeMgr, caches *CCRMCaches, redisClient *redis.Client, flags *Flags) {
	s.caches = caches
	s.nodeMgr = nodeMgr
	s.redisClient = redisClient
	s.flags = flags

	// notify handlers
	s.caches.CloudletCache.AddUpdatedCb(s.cloudletChanged)

	// redis handlers
	hctx, cancel := context.WithCancel(ctx)
	s.CancelHandlers = cancel
	server := rediscache.GetCCRMAPIServer(redisClient, nodeType, s)
	server.Start(hctx)
}
