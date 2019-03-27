package mexos

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/azure"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type AZName struct {
	LocalizedValue string
	Value          string
}

type AZLimit struct {
	CurrentValue string
	Limit        string
	LocalName    string
	Name         AZName
}

// AzureLogin logs into azure
func AzureLogin() error {
	log.DebugLog(log.DebugLevelMexos, "doing azure login")
	out, err := sh.Command("az", "login", "--username", GetCloudletAzureUserName(), "--password", GetCloudletAzurePassword()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Login Failed: %s %v", out, err)
	}
	return nil
}

func GetResourceGroupForCluster(clusterInst *edgeproto.ClusterInst) string {
	return clusterInst.Key.CloudletKey.Name + "_" + clusterInst.Key.ClusterKey.Name
}

func azureCreateAKS(clusterInst *edgeproto.ClusterInst) error {
	var err error
	resourceGroup := GetResourceGroupForCluster(clusterInst)
	clusterName := clusterInst.Key.ClusterKey.Name
	location := GetCloudletAzureLocation()
	cf, err := GetClusterFlavor(clusterInst.Flavor.Name)
	if err != nil {
		return err
	}
	if err = AzureLogin(); err != nil {
		return err
	}
	if err = azure.CreateResourceGroup(resourceGroup, location); err != nil {
		return err
	}
	num_nodes := fmt.Sprintf("%d", cf.NumNodes)
	if err = azure.CreateAKSCluster(resourceGroup, clusterName,
		cf.NodeFlavor.Name, num_nodes); err != nil {
		return err
	}
	//race condition exists where the config file is not ready until just after the cluster create is done
	time.Sleep(3 * time.Second)
	saveKubeconfig()
	if err = azure.GetAKSCredentials(resourceGroup, clusterName); err != nil {
		return err
	}
	kconf := GetKconfName(clusterInst) // XXX

	log.DebugLog(log.DebugLevelMexos, "warning, using default config") //XXX
	//XXX watch out for multiple cluster contexts
	if err = copyFile(defaultKubeconfig(), kconf); err != nil {
		return fmt.Errorf("can't copy %s, %v", defaultKubeconfig(), err)
	}
	log.DebugLog(log.DebugLevelMexos, "created aks", "name", clusterName)
	return CreateDockerRegistrySecret(clusterInst, "")
}

// Get resource limits
func AzureGetLimits(info *edgeproto.CloudletInfo) error {
	log.DebugLog(log.DebugLevelMexos, "GetLimits (Azure)")

	var limits []AZLimit
	out, err := sh.Command("az", "vm", "list-usage", "--location", GetCloudletAzureLocation(), sh.Dir("/tmp")).Output()
	if err != nil {
		err = fmt.Errorf("cannot get limits from azure, %v", err)
		return err
	}
	err = json.Unmarshal(out, &limits)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return err
	}
	for _, l := range limits {
		if l.LocalName == "Total Regional vCPUs" {
			vcpus, err := strconv.Atoi(l.Limit)
			if err != nil {
				err = fmt.Errorf("failed to parse azure output, %v", err)
				return err
			}
			info.OsMaxVcores = uint64(vcpus)
			info.OsMaxRam = uint64(4 * vcpus)
			info.OsMaxVolGb = uint64(500 * vcpus)
			break
		}
	}

	return nil
}
