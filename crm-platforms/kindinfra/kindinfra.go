package kindinfra

import (
	"context"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/kind"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

// Kind platform with multi-tenant cluster support.
// We may also want to add shepherd/envoy to test metrics.
type Platform struct {
	kind.Platform
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	err := s.Platform.GatherCloudletInfo(ctx, info)
	if err != nil {
		return err
	}
	if info.Properties == nil {
		info.Properties = make(map[string]string)
	}
	info.Properties[cloudcommon.CloudletSupportsMT] = "true"
	info.OsMaxRam = 81920
	info.OsMaxVcores = 100
	info.OsMaxVolGb = 500
	return nil
}
