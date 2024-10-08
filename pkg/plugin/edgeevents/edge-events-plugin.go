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

package edgeevents

import (
	"context"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	edgeevents "github.com/edgexr/edge-cloud-platform/pkg/edge-events"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	uaemcommon "github.com/edgexr/edge-cloud-platform/pkg/uaem-common"
)

func GetEdgeEventsHandler(ctx context.Context, edgeEventsCookieExpiration time.Duration) (uaemcommon.EdgeEventsHandler, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetEdgeEventHandler")
	edgeEventsHandlerPlugin := new(edgeevents.EdgeEventsHandlerPlugin)
	edgeEventsHandlerPlugin.EdgeEventsCookieExpiration = edgeEventsCookieExpiration
	edgeEventsHandlerPlugin.AppInsts = make(map[edgeproto.AppInstKey]*edgeevents.AppInstInfo) // Initialize Cloudlets hashmap
	return edgeEventsHandlerPlugin, nil
}

func main() {}
