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

package node

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

// Wrapper around edgeproto.NodeCache to add in the region
// There are three cases:
// NotifyRoot: region is "", region in NodeKey is already set
// Controller: region is set, override region in NodeKey
// CRM/DME: region is "", region is NodeKey is not set, but will get set
// once it goes to controller.

type RegionSvcNodeCache struct {
	edgeproto.SvcNodeCache
	setRegion string
}

func (s *RegionSvcNodeCache) Update(ctx context.Context, in *edgeproto.SvcNode, rev int64) {
	if s.setRegion != "" {
		in.Key.Region = s.setRegion
	}
	s.SvcNodeCache.Update(ctx, in, rev)
}

func (s *RegionSvcNodeCache) Delete(ctx context.Context, in *edgeproto.SvcNode, rev int64) {
	if s.setRegion != "" {
		in.Key.Region = s.setRegion
	}
	s.SvcNodeCache.Delete(ctx, in, rev)
}

func (s *RegionSvcNodeCache) Prune(ctx context.Context, validKeys map[edgeproto.SvcNodeKey]struct{}) {
	if s.setRegion != "" {
		keys := make(map[edgeproto.SvcNodeKey]struct{})
		for k, _ := range validKeys {
			k.Region = s.setRegion
			keys[k] = struct{}{}
		}
		validKeys = keys
	}
	s.SvcNodeCache.Prune(ctx, validKeys)
}

func nodeMatches(key *edgeproto.SvcNodeKey, filter *edgeproto.SvcNodeKey) bool {
	// if region is not set on node, then this is a node below
	// controller in the notify tree that doesn't know what region
	// it is in, so don't filter based on region.
	if key.Region == "" && filter.Region != "" {
		f := *filter
		f.Region = ""
		filter = &f
	}
	return key.Matches(filter, edgeproto.MatchFilter())
}
