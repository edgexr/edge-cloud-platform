package ctrlapi

import (
	"context"

	"google.golang.org/grpc"
)

type RegionConn interface {
	GetRegionConn(ctx context.Context, region string) (*grpc.ClientConn, error)
	GetNotifyRootConn(ctx context.Context) (*grpc.ClientConn, error)
}

type authzShow interface {
	Ok(org string) bool
}
