package main

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

func addTestPlatformFeatures(t *testing.T, ctx context.Context, apis *AllApis, featuresList []edgeproto.PlatformFeatures) {
	for _, features := range featuresList {
		apis.platformFeaturesApi.Update(ctx, &features, 0)
	}
}
