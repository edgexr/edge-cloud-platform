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
