package mexos

import (
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/dind"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func localCreateDIND(clusterInst *edgeproto.ClusterInst) error {
	var err error

	clusterName := clusterInst.Key.ClusterKey.Name
	log.DebugLog(log.DebugLevelMexos, "creating local dind cluster", "clusterName", clusterName)

	kconfName := GetKconfName(clusterInst)
	if err = dind.CreateDINDCluster(clusterName, kconfName); err != nil {
		return err
	}
	//race condition exists where the config file is not ready until just after the cluster create is done
	time.Sleep(3 * time.Second)

	kconf := GetKconfName(clusterInst) // XXX

	log.DebugLog(log.DebugLevelMexos, "warning, using default config") //XXX
	//XXX watch out for multiple cluster contexts
	if err = copyFile(defaultKubeconfig(), kconf); err != nil {
		return fmt.Errorf("can't copy %s, %v", defaultKubeconfig(), err)
	}
	log.DebugLog(log.DebugLevelMexos, "created dind", "name", clusterName)

	err = CreateDockerRegistrySecret(clusterInst, "")
	if err != nil {
		return fmt.Errorf("cannot create mexreg secret for: %s, err: %v", clusterName, err)
	}

	return nil
}
