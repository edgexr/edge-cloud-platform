package mexos

import (
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/gcloud"
	"github.com/mobiledgex/edge-cloud/log"
)

var GCPDefaultProjectID = "still-entity-201400" // XXX

func gcloudCreateGKE(mf *Manifest) error {
	var err error
	if mf.Metadata.Project == "" {
		log.DebugLog(log.DebugLevelMexos, "warning, empty gcp project ID, using default", "default", GCPDefaultProjectID)
	}
	if err = gcloud.SetProject(mf.Metadata.Project); err != nil {
		return err
	}
	if err = gcloud.SetZone(mf.Metadata.Zone); err != nil {
		return err
	}
	if err = gcloud.CreateGKECluster(mf.Metadata.Name); err != nil {
		return err
	}
	//race condition exists where the config file is not ready until just after the cluster create is done
	time.Sleep(3 * time.Second)
	saveKubeconfig()
	if err = gcloud.GetGKECredentials(mf.Metadata.Name); err != nil {
		return err
	}
	kconf, err := GetKconf(mf, false) //XXX
	if err != nil {
		return fmt.Errorf("cannot get kconf, %v, %v, %v", mf, kconf, err)
	}
	log.DebugLog(log.DebugLevelMexos, "warning, using default config") //XXX
	if err = copyFile(defaultKubeconfig(), kconf); err != nil {
		return fmt.Errorf("can't copy %s, %v", defaultKubeconfig(), err)
	}
	log.DebugLog(log.
		DebugLevelMexos, "created gke", "name", mf.Spec.Key)
	return nil
}
