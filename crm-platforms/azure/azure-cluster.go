package azure

import (
	"fmt"
	"strings"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// AzureLogin logs into azure
func (s *Platform) AzureLogin() error {
	log.DebugLog(log.DebugLevelMexos, "doing azure login")
	out, err := sh.Command("az", "login", "--username", s.props.UserName, "--password", s.props.Password).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Login Failed: %s %v", out, err)
	}
	return nil
}

func GetResourceGroupForCluster(clusterInst *edgeproto.ClusterInst) string {
	return clusterInst.Key.CloudletKey.Name + "_" + clusterInst.Key.ClusterKey.Name
}

func (s *Platform) CreateClusterInst(clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	var err error

	resourceGroup := GetResourceGroupForCluster(clusterInst)
	clusterName := AzureSanitize(clusterInst.Key.ClusterKey.Name)
	location := s.props.Location

	if err = s.AzureLogin(); err != nil {
		return err
	}
	if err = CreateResourceGroup(resourceGroup, location); err != nil {
		return err
	}
	num_nodes := fmt.Sprintf("%d", clusterInst.NumNodes)
	if err = CreateAKSCluster(resourceGroup, clusterName,
		clusterInst.NodeFlavor, num_nodes); err != nil {
		return err
	}
	//race condition exists where the config file is not ready until just after the cluster create is done
	time.Sleep(3 * time.Second)
	client, err := s.GetPlatformClient(clusterInst)
	if err != nil {
		return err
	}
	mexos.BackupKubeconfig(client)
	if err = GetAKSCredentials(resourceGroup, clusterName); err != nil {
		return err
	}
	kconf := k8smgmt.GetKconfName(clusterInst) // XXX

	log.DebugLog(log.DebugLevelMexos, "warning, using default config") //XXX
	//XXX watch out for multiple cluster contexts
	if err = pc.CopyFile(client, mexos.DefaultKubeconfig(), kconf); err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "created aks", "name", clusterName)
	return mexos.CreateDockerRegistrySecret(client, clusterInst)
}

func (s *Platform) DeleteClusterInst(clusterInst *edgeproto.ClusterInst) error {
	resourceGroup := GetResourceGroupForCluster(clusterInst)
	if err := s.AzureLogin(); err != nil {
		return err
	}
	return DeleteAKSCluster(resourceGroup)
}

func (s *Platform) UpdateClusterInst(clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Update cluster inst not implemented for Azure")
}

func AzureSanitize(clusterName string) string {
	return strings.NewReplacer(".", "").Replace(clusterName)
}
