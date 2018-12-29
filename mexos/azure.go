package mexos

import (
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/azure"
	"github.com/mobiledgex/edge-cloud/log"
)

func azureCreateAKS(mf *Manifest) error {
	var err error
	if err = azure.CreateResourceGroup(mf.Metadata.ResourceGroup, mf.Metadata.Location); err != nil {
		return err
	}
	if err = azure.CreateAKSCluster(mf.Metadata.ResourceGroup, mf.Metadata.Name); err != nil {
		return err
	}
	//race condition exists where the config file is not ready until just after the cluster create is done
	time.Sleep(3 * time.Second)
	saveKubeconfig()
	if err = azure.GetAKSCredentials(mf.Metadata.ResourceGroup, mf.Metadata.Name); err != nil {
		return err
	}
	kconf, err := GetKconf(mf, false) // XXX
	if err != nil {
		return fmt.Errorf("cannot get kconf, %v, %v, %v", mf, kconf, err)
	}
	log.DebugLog(log.DebugLevelMexos, "warning, using default config") //XXX
	//XXX watch out for multiple cluster contexts
	if err = copyFile(defaultKubeconfig(), kconf); err != nil {
		return fmt.Errorf("can't copy %s, %v", defaultKubeconfig(), err)
	}
	log.DebugLog(log.DebugLevelMexos, "created aks", "name", mf.Spec.Key)
	return nil
}
