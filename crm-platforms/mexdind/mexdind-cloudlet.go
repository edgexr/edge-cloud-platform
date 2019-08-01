package mexdind

import (
	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (s *Platform) CreateCloudlet(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.DebugLog(log.DebugLevelMexos, "create cloudlet for mexdind")
	err := s.generic.CreateCloudlet(cloudlet, pfConfig, flavor, updateCallback)
	if err != nil {
		return err
	}
	return intprocess.StartShepherdService(cloudlet, pfConfig)
}

func (s *Platform) DeleteCloudlet(cloudlet *edgeproto.Cloudlet) error {
	log.DebugLog(log.DebugLevelMexos, "delete cloudlet for mexdind")
	err := s.generic.DeleteCloudlet(cloudlet)
	if err != nil {
		return err
	}
	return intprocess.StopShepherdService(cloudlet)
}
