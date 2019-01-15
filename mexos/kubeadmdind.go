package mexos

import (
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/dind"
	"github.com/mobiledgex/edge-cloud/log"
)

func localCreateDIND(mf *Manifest) error {
	var err error
	log.DebugLog(log.DebugLevelMexos, "creating local dind cluster", "name", mf.Metadata.Name)

	if err = dind.CreateDINDCluster(mf.Metadata.ResourceGroup, mf.Metadata.Name); err != nil {
		return err
	}
	//race condition exists where the config file is not ready until just after the cluster create is done
	time.Sleep(3 * time.Second)

	kconf, err := GetKconf(mf, false) // XXX
	if err != nil {
		return fmt.Errorf("cannot get kconf, %v, %v, %v", mf, kconf, err)
	}
	log.DebugLog(log.DebugLevelMexos, "warning, using default config") //XXX
	//XXX watch out for multiple cluster contexts
	if err = copyFile(defaultKubeconfig(), kconf); err != nil {
		return fmt.Errorf("can't copy %s, %v", defaultKubeconfig(), err)
	}
	log.DebugLog(log.DebugLevelMexos, "created dind", "name", mf.Spec.Key)

	err = CreateDockerRegistrySecret(mf)
	if err != nil {
		return fmt.Errorf("cannot create mexreg secret for: %s, err: %v", mf.Spec.Key, err)
	}

	return nil
}
