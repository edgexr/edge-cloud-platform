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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/opentracing/opentracing-go"
)

func (s *CCRMHandler) ProcessExecRequest(ctx context.Context, in *edgeproto.CloudletExecReq) (*edgeproto.ExecRequest, error) {
	_, platform, err := s.getCloudletPlatform(ctx, in.CloudletKey)
	if err != nil {
		return nil, err
	}
	resp := make(chan *edgeproto.ExecRequest, 1)

	// Spawn a go func in case we're running an interactive shell, in which
	// case ProcessExecReq will block while the shell is open. However,
	// before it blocks it needs to send back the ExecReq response with the
	// info the client needs to connect to the EdgeTurn server.
	// It was designed this way for the CRM which cannot be directly connected
	// to from outside. Here in the CCRM we could allow an incoming connection
	// and avoid having to use EdgeTurn, but to keep a single implementation
	// the CCRM uses the same approach as the CRM.
	go func() {
		cspan := log.StartSpan(log.DebugLevelApi, "process exec req", opentracing.ChildOf(log.SpanFromContext(ctx).Context()))
		defer cspan.Finish()
		err := s.crmHandler.ProcessExecReq(ctx, platform, in.ExecReq, func(reply *edgeproto.ExecRequest) {
			resp <- reply
		})
		if err != nil {
			in.ExecReq.Err = err.Error()
		}
		resp <- in.ExecReq
	}()

	retVal := <-resp
	return retVal, nil
}
