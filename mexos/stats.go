package mexos

import (
	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/dind"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

//GetLimits is used to retrieve tenant level platform stats
func GetLimits(info *edgeproto.CloudletInfo) error {
	switch GetCloudletKind() {
	case cloudcommon.CloudletKindOpenStack:
		err := OSGetLimits(info)
		if err != nil {
			return err
		}
	case cloudcommon.CloudletKindAzure:
		err := AzureGetLimits(info)
		if err != nil {
			return err
		}
	case cloudcommon.CloudletKindDIND:
		os, err := GetLocalOperatingSystem()
		if err != nil {
			return err
		}
		err = dind.DINDGetLimits(info, os)
		if err != nil {
			return err
		}
	default:
		// todo: we could try to get this from the local machine
		log.DebugLog(log.DebugLevelMexos, "GetLimits (hardcoded)")
		info.OsMaxVcores = 8
		info.OsMaxRam = 16
		info.OsMaxVolGb = 500
	}
	return nil
}
