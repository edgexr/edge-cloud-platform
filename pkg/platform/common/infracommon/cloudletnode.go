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

package infracommon

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/confignode"
)

// CreateCloudletNode requests the Controller via the accessApi
// to register a new cloudlet node, and stores the new password
// into ConfigureNodeVars.
func CreateCloudletNode(ctx context.Context, config *confignode.ConfigureNodeVars, accessApi platform.AccessApi) error {
	cloudletNode := &edgeproto.CloudletNode{
		Key:       config.Key,
		NodeType:  config.NodeType.String(),
		NodeRole:  config.NodeRole.String(),
		OwnerTags: config.OwnerKey.GetTags(),
	}
	password, err := accessApi.CreateCloudletNode(ctx, cloudletNode)
	if err != nil {
		return err
	}
	config.Password = password
	return nil
}
