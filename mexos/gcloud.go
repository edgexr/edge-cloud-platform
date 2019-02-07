package mexos

import (
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/gcloud"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func gcloudCreateGKE(clusterInst *edgeproto.ClusterInst) error {
	var err error
	project := GetCloudletGCPProject()
	zone := GetCloudletGCPZone()
	clusterName := clusterInst.Key.ClusterKey.Name

	if err = gcloud.SetProject(project); err != nil {
		return err
	}
	if err = gcloud.SetZone(zone); err != nil {
		return err
	}
	if err = gcloud.CreateGKECluster(clusterName); err != nil {
		return err
	}
	//race condition exists where the config file is not ready until just after the cluster create is done
	time.Sleep(3 * time.Second)
	saveKubeconfig()
	if err = gcloud.GetGKECredentials(clusterName); err != nil {
		return err
	}
	kconf, err := GetKconf(clusterInst, false) //XXX
	if err != nil {
		return fmt.Errorf("cannot get kconf, %v, %v", clusterInst, err)
	}
	log.DebugLog(log.DebugLevelMexos, "warning, using default config") //XXX
	if err = copyFile(defaultKubeconfig(), kconf); err != nil {
		return fmt.Errorf("can't copy %s, %v", defaultKubeconfig(), err)
	}
	log.DebugLog(log.DebugLevelMexos, "created gke", "name", clusterName)
	return CreateDockerRegistrySecret(clusterInst, "")
}
