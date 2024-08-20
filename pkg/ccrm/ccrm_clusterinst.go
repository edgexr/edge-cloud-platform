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

import "github.com/edgexr/edge-cloud-platform/api/edgeproto"

// ApplyClusterInst implements a GRPC ClusterInstPlatform server method
func (s *CCRMHandler) ApplyClusterInst(in *edgeproto.ClusterInst, stream edgeproto.ClusterPlatformAPI_ApplyClusterInstServer) error {
	ctx := stream.Context()
	responseSender := edgeproto.NewClusterInstInfoSendUpdater(ctx, stream, in.Key)
	needsUpdate, err := s.crmHandler.ClusterInstChanged(ctx, &in.CloudletKey, in, responseSender)
	if err == nil && needsUpdate.Resources {
		s.vmResourceActionEnd(ctx, &in.CloudletKey)
	}
	if err == nil && needsUpdate.AppInstRuntime {
		s.refreshAppInstRuntime(ctx, &in.CloudletKey, in, nil)
	}
	return err
}
