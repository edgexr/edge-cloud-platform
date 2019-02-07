package mexos

import (
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/azure"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func azureCreateAKS(clusterInst *edgeproto.ClusterInst) error {
	var err error
	resourceGroup := GetResourceGroupForCluster(clusterInst)
	clusterName := clusterInst.Key.ClusterKey.Name
	location := GetCloudletAzureLocation()
	if err = azure.CreateResourceGroup(resourceGroup, location); err != nil {
		return err
	}
	if err = azure.CreateAKSCluster(resourceGroup, clusterName); err != nil {
		return err
	}
	//race condition exists where the config file is not ready until just after the cluster create is done
	time.Sleep(3 * time.Second)
	saveKubeconfig()
	if err = azure.GetAKSCredentials(resourceGroup, clusterName); err != nil {
		return err
	}
	kconf, err := GetKconf(clusterInst, false) // XXX
	if err != nil {
		return fmt.Errorf("cannot get kconf, %v, %v, %v", clusterInst, kconf, err)
	}
	log.DebugLog(log.DebugLevelMexos, "warning, using default config") //XXX
	//XXX watch out for multiple cluster contexts
	if err = copyFile(defaultKubeconfig(), kconf); err != nil {
		return fmt.Errorf("can't copy %s, %v", defaultKubeconfig(), err)
	}
	log.DebugLog(log.DebugLevelMexos, "created aks", "name", clusterName)
	return CreateDockerRegistrySecret(clusterInst, "")
}
