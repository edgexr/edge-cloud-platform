package main

import (
	"context"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type AutoProvPolicyHandler struct {
	cache edgeproto.AutoProvPolicyCache
}

func (s *AutoProvPolicyHandler) Init() {
	edgeproto.InitAutoProvPolicyCache(&s.cache)
}

func (s *AutoProvPolicyHandler) Update(ctx context.Context, in *edgeproto.AutoProvPolicy, rev int64) {
	s.cache.Update(ctx, in, rev)
	if autoProvAggr != nil {
		autoProvAggr.UpdatePolicy(ctx, in)
	}
}

func (s *AutoProvPolicyHandler) Delete(ctx context.Context, in *edgeproto.AutoProvPolicy, rev int64) {
	s.cache.Delete(ctx, in, rev)
}

func (s *AutoProvPolicyHandler) Prune(ctx context.Context, keys map[edgeproto.PolicyKey]struct{}) {
	s.cache.Prune(ctx, keys)
}

func (s *AutoProvPolicyHandler) Flush(ctx context.Context, notifyId int64) {
	s.cache.Flush(ctx, notifyId)
}
