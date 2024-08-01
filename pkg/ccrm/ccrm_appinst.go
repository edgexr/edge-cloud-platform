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
)

// ApplyAppInst implements a GRPC AppInstPlatform server method
func (s *CCRMHandler) ApplyAppInst(in *edgeproto.AppInst, stream edgeproto.AppInstPlatformAPI_ApplyAppInstServer) error {
	ctx := stream.Context()
	updateResources := false
	responseSender := edgeproto.NewAppInstInfoSendUpdater(ctx, stream, in.Key)
	err := s.crmHandler.AppInstChanged(ctx, &in.Key.CloudletKey, in, &updateResources, responseSender)
	if err == nil && updateResources {
		s.vmResourceActionEnd(ctx, &in.Key.CloudletKey)
	}
	return err
}

func (s *CCRMHandler) ApplyTrustPolicyException(ctx context.Context, in *edgeproto.TPEInstanceState) (*edgeproto.Result, error) {
	err := s.crmHandler.HandleTrustPolicyException(ctx, in)
	return &edgeproto.Result{}, err
}
