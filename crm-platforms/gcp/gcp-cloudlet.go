package gcp

import (
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (s *Platform) CreateCloudlet(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.DebugLog(log.DebugLevelMexos, "create cloudlet for GCP")
	return nil
}

func (s *Platform) DeleteCloudlet(cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	log.DebugLog(log.DebugLevelMexos, "delete cloudlet for GCP")
	return nil
}
