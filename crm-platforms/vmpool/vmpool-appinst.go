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

package vmpool

import (
	"context"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

func (o *VMPoolPlatform) GetConsoleUrl(ctx context.Context, serverName string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetConsoleUrl not supported")
	return "", nil
}

func (o *VMPoolPlatform) AddImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddImageIfNotPresent not supported")
	return nil
}
