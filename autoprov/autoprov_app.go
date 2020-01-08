package main

import (
	"context"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type AppHandler struct {
	cache edgeproto.AppCache
}

func (s *AppHandler) Init() {
	edgeproto.InitAppCache(&s.cache)
}

func (s *AppHandler) Update(ctx context.Context, in *edgeproto.App, rev int64) {
	s.cache.Update(ctx, in, rev)
	if autoProvAggr != nil {
		autoProvAggr.UpdateApp(ctx, &in.Key)
	}
}

func (s *AppHandler) Delete(ctx context.Context, in *edgeproto.App, rev int64) {
	s.cache.Delete(ctx, in, rev)
	if autoProvAggr != nil {
		autoProvAggr.DeleteApp(ctx, &in.Key)
	}
}

func (s *AppHandler) Prune(ctx context.Context, keys map[edgeproto.AppKey]struct{}) {
	s.cache.Prune(ctx, keys)
	if autoProvAggr != nil {
		autoProvAggr.Prune(keys)
	}
}

func (s *AppHandler) Flush(ctx context.Context, notifyId int64) {
	s.cache.Flush(ctx, notifyId)
}
