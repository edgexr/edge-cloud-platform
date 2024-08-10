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

package crm

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

// ExecReqHandler just satisfies the Recv() function for the
// ExecRequest receive notify interface, and calls into the
// controller data which has all the cached information about the
// ClusterInst, AppInst, etc.
type ExecReqHandler struct {
	cd *CRMData
}

func NewExecReqHandler(cd *CRMData) *ExecReqHandler {
	return &ExecReqHandler{cd: cd}
}

func (s *ExecReqHandler) RecvExecRequest(ctx context.Context, msg *edgeproto.ExecRequest) {
	if !s.cd.highAvailabilityManager.PlatformInstanceActive {
		// send nothing in response as the controller only looks for one response
		return
	}
	// spawn go process so we don't stall notify messages
	go func() {
		cspan, ctx := log.ChildSpan(ctx, log.DebugLevelApi, "process exec req")
		defer cspan.Finish()
		err := s.cd.ProcessExecReq(ctx, platform, msg, func(reply *edgeproto.ExecRequest) {
			s.cd.ExecReqSend.Update(ctx, reply)
		})
		if err != nil {
			msg.Err = err.Error()
		}
		s.cd.ExecReqSend.Update(ctx, msg)
	}()
}
