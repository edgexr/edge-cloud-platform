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

package orm

import (
	"context"
	"time"

	"github.com/edgexr/edge-cloud/log"
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
	count        int64
}

type UserInfo struct {
	AppStoreUsers int
	MCUsers       int
	MissingUsers  []string
	ExtraUsers    []string
}
type GroupInfo struct {
	AppStoreGroups int
	AppStoreRepos  int
	AppStorePerms  int
	MCGroups       int
	ExtraGroups    []string
	MissingGroups  []string
	MissingRepos   []string
	MissingPerms   []string
}
type GroupMember struct {
	Group string
	User  string
}

type GroupMemberInfo struct {
	MissingGroupMembers []GroupMember
	ExtraGroupMembers   []GroupMember
}

type AppStoreSummary struct {
	Users        UserInfo
	Groups       GroupInfo
	GroupMembers GroupMemberInfo
}

func AppStoreNewSync(appStoreType string) *AppStoreSync {
	sync := AppStoreSync{}
	sync.run = make(chan bool, 1)
	sync.appStoreType = appStoreType
	return &sync
}

func (s *AppStoreSync) Start(done chan struct{}) {
	go func() {
		isDone := false
		for !isDone {
			select {
			case <-done:
				isDone = true
			case <-time.After(AppStoreSyncInterval):
				if s.needsSync {
					s.wakeup()
				}
			}
		}
	}()
	s.NeedsSync()
	s.wakeup()
	go s.runThread(done)
}

func (s *AppStoreSync) runThread(done chan struct{}) {
	var err error
	isDone := false
	for !isDone {
		if err != nil {
			err = nil
		}
		select {
		case <-done:
			isDone = true
		case <-s.run:
			span := log.StartSpan(log.DebugLevelApi, "appstore sync")
			span.SetTag("type", s.appStoreType)
			ctx := log.ContextWithSpan(context.Background(), span)

			s.needsSync = false
			s.syncObjects(ctx)
			s.count++

			span.Finish()
		}
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
