package mexdind

import (
	"errors"
	"fmt"
	"time"

	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (s *Platform) CreateCloudlet(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.DebugLog(log.DebugLevelMexos, "create cloudlet for mexdind")
	err := s.generic.CreateCloudlet(cloudlet, pfConfig, flavor, updateCallback)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Starting Shepherd")
	shProc, err := intprocess.StartShepherdService(cloudlet, pfConfig)
	if err != nil {
		return err
	}
	fatal := make(chan bool, 1)

	go func() {
		shProc.Wait()
		fatal <- true
	}()
	select {
	case <-fatal:
		out := ""
		out, err = cloudcommon.GetCloudletLog(&cloudlet.Key)
		if err != nil || out == "" {
			out = fmt.Sprintf("Please look at %s for more details", cloudcommon.GetCloudletLogFile(cloudlet.Key.Name+".shepherd"))
		} else {
			out = fmt.Sprintf("Failure: %s", out)
		}
		return errors.New(out)
	case <-time.After(2 * time.Second):
		// Small timeout should be enough for Shepherd to connect to CRM as both will be present locally
		return nil
	}

}

func (s *Platform) DeleteCloudlet(cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	log.DebugLog(log.DebugLevelMexos, "delete cloudlet for mexdind")
	err := s.generic.DeleteCloudlet(cloudlet, updateCallback)
	if err != nil {
		return err
	}

	updateCallback(edgeproto.UpdateTask, "Stopping Shepherd")
	return intprocess.StopShepherdService(cloudlet)
}
