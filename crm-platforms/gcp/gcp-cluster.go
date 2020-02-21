package gcp

import (
	"context"
	"fmt"
	"os"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// GCPLogin logs into google cloud
func (s *Platform) GCPLogin(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "doing GcpLogin", "vault url", s.props.GcpAuthKeyUrl)
	filename := "/tmp/auth_key.json"
	err := mexos.GetVaultDataToFile(s.vaultConfig, s.props.GcpAuthKeyUrl, filename)
	if err != nil {
		return fmt.Errorf("unable to write auth file %s: %s", filename, err.Error())
	}
	defer os.Remove(filename)
	out, err := sh.Command("gcloud", "auth", "activate-service-account", GCPServiceAccount, "--key-file", filename).CombinedOutput()
	log.SpanLog(ctx, log.DebugLevelMexos, "gcp login", "out", string(out), "err", err)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "GCP login OK")
	return nil
}

func (s *Platform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	clusterName := clusterInst.Key.ClusterKey.Name
	if err := CreateGKECluster(clusterName); err != nil {
		return err
	}
	//race condition exists where the config file is not ready until just after the cluster create is done
	time.Sleep(3 * time.Second)
	client, err := s.GetPlatformClient(ctx, clusterInst)
	if err != nil {
		return err
	}
	mexos.BackupKubeconfig(ctx, client)
	if err = GetGKECredentials(clusterName); err != nil {
		return err
	}
	kconf := k8smgmt.GetKconfName(clusterInst) //XXX

	log.SpanLog(ctx, log.DebugLevelMexos, "warning, using default config") //XXX
	if err = pc.CopyFile(client, mexos.DefaultKubeconfig(), kconf); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "created gke", "name", clusterName)
	return nil
}

func (s *Platform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	return DeleteGKECluster(clusterInst.Key.ClusterKey.Name)
}

func (s *Platform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("update cluster inst not implemented for GCP")
}
