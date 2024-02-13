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

package k8scommon

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

func GetFlavorList(ctx context.Context, caches *platform.Caches) ([]*edgeproto.FlavorInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList")
	if caches == nil {
		log.WarnLog("caches are nil")
		return nil, fmt.Errorf("caches are nil")
	}
	if caches.FlavorCache == nil {
		log.WarnLog("flavor cache is nil")
		return nil, fmt.Errorf("Flavor cache is nil")
	}
	var flavors []*edgeproto.FlavorInfo
	flavorkeys := make(map[edgeproto.FlavorKey]struct{})
	caches.FlavorCache.GetAllKeys(ctx, func(k *edgeproto.FlavorKey, modRev int64) {
		flavorkeys[*k] = struct{}{}
	})
	for f := range flavorkeys {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList found flavor", "key", f)
		var flav edgeproto.Flavor
		if caches.FlavorCache.Get(&f, &flav) {
			var flavInfo edgeproto.FlavorInfo
			_, gpu := flav.OptResMap["gpu"]
			if gpu {
				// gpu not currently supported
				log.SpanLog(ctx, log.DebugLevelInfra, "skipping GPU flavor", "flav", flav)
				continue
			}
			flavInfo.Name = flav.Key.Name
			flavInfo.Vcpus = flav.Vcpus
			flavInfo.Ram = flav.Ram
			flavors = append(flavors, &flavInfo)
		} else {
			return nil, fmt.Errorf("fail to fetch flavor %s", f)
		}
	}
	return flavors, nil
}
