package gcp

import (
	"context"
	"fmt"
	"os"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// GCPLogin logs into google cloud
func (g *GCPPlatform) GCPLogin(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "doing GcpLogin", "vault url", g.GetGcpAuthKeyUrl())
	filename := "/tmp/auth_key.json"
	err := infracommon.GetVaultDataToFile(g.commonPf.VaultConfig, g.GetGcpAuthKeyUrl(), filename)
	if err != nil {
		return fmt.Errorf("unable to write auth file %s: %s", filename, err.Error())
	}
	defer os.Remove(filename)
	out, err := sh.Command("gcloud", "auth", "activate-service-account", "--key-file", filename).CombinedOutput()
	log.SpanLog(ctx, log.DebugLevelInfra, "gcp login", "out", string(out), "err", err)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GCP login OK")
	return nil
}

func (g *GCPPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	clusterName := clusterInst.Key.ClusterKey.Name
	if err := CreateGKECluster(clusterName); err != nil {
		return err
	}
	//race condition exists where the config file is not ready until just after the cluster create is done
	time.Sleep(3 * time.Second)
	client, err := g.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	infracommon.BackupKubeconfig(ctx, client)
	if err = GetGKECredentials(clusterName); err != nil {
		return err
	}
	kconf := k8smgmt.GetKconfName(clusterInst) //XXX

	log.SpanLog(ctx, log.DebugLevelInfra, "warning, using default config") //XXX
	if err = pc.CopyFile(client, infracommon.DefaultKubeconfig(), kconf); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created gke", "name", clusterName)
	return nil
}

func (g *GCPPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	return DeleteGKECluster(clusterInst.Key.ClusterKey.Name)
}

func (g *GCPPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("update cluster inst not implemented for GCP")
}
