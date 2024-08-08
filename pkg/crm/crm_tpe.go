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
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

func (s *CRMData) tpeInstanceStateChanged(ctx context.Context, old *edgeproto.TPEInstanceState, new *edgeproto.TPEInstanceState) {
	if !s.highAvailabilityManager.IsActive() {
		log.SpanLog(ctx, log.DebugLevelInfra, "Ignoring VM Pool changed because not active")
		return
	}
	if new.RunCount == 0 || old.RunCount == new.RunCount {
		return
	}
	go func() {
		span, ctx := log.ChildSpan(ctx, log.DebugLevelApi, "trustPolicyExceptionChanged")
		defer span.Finish()
		s.HandleTrustPolicyException(ctx, new)
	}()
}
