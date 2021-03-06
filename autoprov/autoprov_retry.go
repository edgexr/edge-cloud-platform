package main

import (
	"context"
	"strings"
	"sync"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type RetryTracker struct {
	// failures key is AppInstKey without Cluster info.
	allFailures map[edgeproto.AppInstKey]struct{}
	mux         sync.Mutex
}

func newRetryTracker() *RetryTracker {
	s := RetryTracker{}
	s.allFailures = make(map[edgeproto.AppInstKey]struct{})
	return &s
}

func (s *RetryTracker) registerDeployResult(ctx context.Context, key edgeproto.AppInstKey, err error) {
	existsErr := key.ExistsError()

	// tracking is cluster agnostic. We assume any failures are
	// caused by the App config, or an issue with the Cloudlet, and
	// nothing specific to autoclusters, whose configuration is
	// derived from the App.
	key.ClusterInstKey.Organization = ""
	key.ClusterInstKey.ClusterKey.Name = ""

	s.mux.Lock()
	defer s.mux.Unlock()

	if err == nil ||
		strings.Contains(err.Error(), existsErr.Error()) ||
		strings.Contains(err.Error(), "already met, ignoring") ||
		strings.Contains(err.Error(), "AppInst against App which is being deleted") {
		delete(s.allFailures, key)
		return
	}
	log.SpanLog(ctx, log.DebugLevelApi, "Failed to deploy appInst, track it as part of retryTracker", "key", key, "err", err)
	// track new failure
	s.allFailures[key] = struct{}{}
	// Because the retry interval (the aggr thread interval) is so long
	// (default 5 minutes) we don't bother with any back-off from
	// multiple consecutive failures.
}

func (s *RetryTracker) doRetry(ctx context.Context, minmax *MinMaxChecker) {
	s.mux.Lock()
	defer s.mux.Unlock()

	for k, _ := range s.allFailures {
		// Because a retry may not necessarily try to deploy
		// to the same Cloudlet (or may not try to deploy anything
		// at all), we clear the failure state here, and just
		// retry the App. If there is another failure, then
		// the App+Cloudlet will be black-listed again for
		// another retry interval.
		delete(s.allFailures, k)
		// trigger retry
		minmax.workers.NeedsWork(ctx, k.AppKey)
	}
}

func (s *RetryTracker) hasFailure(ctx context.Context, appKey edgeproto.AppKey, cloudletKey edgeproto.CloudletKey) bool {
	key := edgeproto.AppInstKey{}
	key.AppKey = appKey
	key.ClusterInstKey.CloudletKey = cloudletKey

	s.mux.Lock()
	defer s.mux.Unlock()
	_, found := s.allFailures[key]
	return found
}
