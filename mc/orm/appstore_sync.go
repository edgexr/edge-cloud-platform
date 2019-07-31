package orm

import (
	"context"
	"time"

	"github.com/mobiledgex/edge-cloud/log"
)

// Gitlab's groups and group members are a duplicate of the Organizations
// and Org Roles in MC. So are Artifactory's groups. Because it's a
// duplicate, it's possible to get out of sync (either due to failed
// operations, or MC or gitlab DB reset or restored from backup, etc).
// AppStoreSync takes care of re-syncing. Syncs are triggered either by
// a failure, or by an API call.

// Sync Interval attempts to re-sync if there was a failure
var AppStoreSyncInterval = 5 * time.Minute

type AppStoreSync struct {
	run          chan bool
	needsSync    bool
	appStoreType string
	syncObjects  func(ctx context.Context)
}

func AppStoreNewSync(appStoreType string) *AppStoreSync {
	sync := AppStoreSync{}
	sync.run = make(chan bool, 1)
	sync.appStoreType = appStoreType
	return &sync
}

func (s *AppStoreSync) Start() {
	go func() {
		for {
			time.Sleep(AppStoreSyncInterval)
			if s.needsSync {
				s.wakeup()
			}
		}
	}()
	s.NeedsSync()
	s.wakeup()
	go s.runThread()
}

func (s *AppStoreSync) runThread() {
	var err error
	for {
		if err != nil {
			err = nil
		}
		select {
		case <-s.run:
		}
		span := log.StartSpan(log.DebugLevelApi, "appstore sync")
		span.SetTag("type", s.appStoreType)
		ctx := log.ContextWithSpan(context.Background(), span)

		s.needsSync = false
		s.syncObjects(ctx)

		span.Finish()
	}
}

func (s *AppStoreSync) NeedsSync() {
	s.needsSync = true
}

func (s *AppStoreSync) wakeup() {
	select {
	case s.run <- true:
	default:
	}
}

func (s *AppStoreSync) syncErr(ctx context.Context, err error) {
	log.SpanLog(ctx, log.DebugLevelApi, "AppStore Sync failed", "AppStore", s.appStoreType, "err", err)
	s.NeedsSync()
}
