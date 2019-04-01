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

type AZFlavor struct {
	Disk  int
	Name  string
	RAM   int
	VCPUs int
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

func azureCreateAKS(clusterInst *edgeproto.ClusterInst, flavor *edgeproto.ClusterFlavor) error {
	var err error
	resourceGroup := GetResourceGroupForCluster(clusterInst)
	clusterName := clusterInst.Key.ClusterKey.Name
	location := GetCloudletAzureLocation()
	if err = AzureLogin(); err != nil {
		return err
	}
	if err = azure.CreateResourceGroup(resourceGroup, location); err != nil {
		return err
	}
	num_nodes := fmt.Sprintf("%d", flavor.NumNodes)
	if err = azure.CreateAKSCluster(resourceGroup, clusterName,
		clusterInst.NodeFlavor, num_nodes); err != nil {
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

	/*
	 * We will not support all Azure flavors, only selected ones:
	 * https://azure.microsoft.com/en-in/pricing/details/virtual-machines/series/
	 */
	var vmsizes []AZFlavor
	out, err = sh.Command("az", "vm", "list-sizes",
		"--location", GetCloudletAzureLocation(),
		"--query", "[].{"+
			"Name:name,"+
			"VCPUs:numberOfCores,"+
			"RAM:memoryInMb, Disk:resourceDiskSizeInMb"+
			"}[?starts_with(Name,'Standard_DS')]|[?ends_with(Name,'v2')]",
		sh.Dir("/tmp")).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("cannot get vm-sizes from azure, %s %v", out, err)
		return err
	}
	err = json.Unmarshal(out, &vmsizes)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return err
	}
	for _, f := range vmsizes {
		info.Flavors = append(
			info.Flavors,
			&edgeproto.FlavorInfo{f.Name, uint64(f.VCPUs), uint64(f.RAM), uint64(f.Disk)},
		)
	}

	return nil
}
