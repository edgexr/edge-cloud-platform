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

package crm

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

func (s *CRMData) cloudletChanged(ctx context.Context, old *edgeproto.Cloudlet, new *edgeproto.Cloudlet) {
	if !s.highAvailabilityManager.IsActive() {
		// the cloudlet state can be anything if this is an inactive CRM
		log.SpanLog(ctx, log.DebugLevelInfra, "doing notify controller connect cloudlet changed because not currently active", "newstate", new.State)
		s.notifyControllerConnect()
		return
	}
	responseSender := edgeproto.NewCloudletInfoCacheUpdater(ctx, &s.CloudletInfoCache, new.Key)

	go func() {
		span, ctx := log.ChildSpan(ctx, log.DebugLevelApi, "cloudletChanged")
		defer span.Finish()

		if old == nil {
			new.Fields = edgeproto.CloudletAllFields
		} else {
			new.Fields = old.GetDiffFields(new).Fields()
			if old.State != new.State {
				log.SpanLog(ctx, log.DebugLevelApi, "crm cloudlet state trans", "old", old.State, "new", new.State, "fields", new.Fields)
			}
			// Special case for dns update - only possible if appinst exists
			oldDNS, ok := new.Annotations[cloudcommon.AnnotationPreviousDNSName]
			if ok && oldDNS == old.RootLbFqdn {
				_ = s.CloudletDNSChanged(ctx, s.cloudletKey, old, new, responseSender)
				return
			}
		}
		log.SpanLog(ctx, log.DebugLevelApi, "crm cloudlet changed", "old", old, "new", new)
		if s.waitForCRMINITOK && new.State == edgeproto.TrackedState_CRM_INITOK {
			s.notifyControllerConnect()
		}
		s.CloudletChanged(ctx, s.cloudletKey, new, responseSender)
	}()
}

func (s *CRMData) cloudletDeleted(ctx context.Context, old *edgeproto.Cloudlet) {
	if !s.highAvailabilityManager.IsActive() {
		// the cloudlet state can be anything if this is an inactive CRM
		log.SpanLog(ctx, log.DebugLevelInfra, "ignoring cloudlet deleted because not active")
		return
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "cloudletDeleted", "Cloudlet", old)
	if old.Key.FederatedOrganization != "" {
		// cloudlet info
		info := edgeproto.CloudletInfo{Key: old.Key}
		s.CloudletInfoCache.Delete(ctx, &info, 0)
	}
}
