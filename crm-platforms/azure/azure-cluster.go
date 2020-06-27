package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// AzureLogin logs into azure
func (a *AzurePlatform) AzureLogin(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "doing azure login")
	out, err := sh.Command("az", "login", "--username", a.GetAzureUser(), "--password", a.GetAzurePass()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Login Failed: %s %v", out, err)
	}
	return nil
}

func GetResourceGroupForCluster(clusterInst *edgeproto.ClusterInst) string {
	return clusterInst.Key.CloudletKey.Name + "_" + clusterInst.Key.ClusterKey.Name
}

func (s *AzurePlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	var err error

	resourceGroup := GetResourceGroupForCluster(clusterInst)
	clusterName := AzureSanitize(clusterInst.Key.ClusterKey.Name)
	location := s.GetAzureLocation()

	if err = s.AzureLogin(ctx); err != nil {
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
	client, err := s.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	infracommon.BackupKubeconfig(ctx, client)
	if err = GetAKSCredentials(resourceGroup, clusterName); err != nil {
		return err
	}
	kconf := k8smgmt.GetKconfName(clusterInst) // XXX

	log.SpanLog(ctx, log.DebugLevelInfra, "warning, using default config") //XXX
	//XXX watch out for multiple cluster contexts
	if err = pc.CopyFile(client, infracommon.DefaultKubeconfig(), kconf); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created aks", "name", clusterName)
	return nil
}

func (s *AzurePlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	resourceGroup := GetResourceGroupForCluster(clusterInst)
	if err := s.AzureLogin(ctx); err != nil {
		return err
	}
	return DeleteAKSCluster(resourceGroup)
}

func (s *AzurePlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Update cluster inst not implemented for Azure")
}

func AzureSanitize(clusterName string) string {
	return strings.NewReplacer(".", "").Replace(clusterName)
}
