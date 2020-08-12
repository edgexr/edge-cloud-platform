package managedk8s

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

const MaxKubeCredentialsWait = 10 * time.Second

func (m *ManagedK8sPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateClusterInst", "clusterInst", clusterInst)
	clusterName := m.Provider.NameSanitize(k8smgmt.GetCloudletClusterName(clusterInst))
	updateCallback(edgeproto.UpdateTask, "Creating Kubernetes Cluster: "+clusterName)
	client, err := m.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	kconf := k8smgmt.GetKconfName(clusterInst)
	err = m.createClusterInstInternal(ctx, client, clusterName, kconf, clusterInst.NumNodes, clusterInst.NodeFlavor, updateCallback)
	if err != nil {
		if !clusterInst.SkipCrmCleanupOnFailure {
			log.SpanLog(ctx, log.DebugLevelInfra, "Cleaning up clusterInst after failure", "clusterInst", clusterInst)
			delerr := m.deleteClusterInstInternal(ctx, clusterName)
			if delerr != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "fail to cleanup cluster")
			}
		}
	}
	return err
}

func (m *ManagedK8sPlatform) createClusterInstInternal(ctx context.Context, client ssh.Client, clusterName string, kconf string, numNodes uint32, flavor string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "createClusterInstInternal", "clusterName", clusterName, "numNodes", numNodes, "flavor", flavor)
	var err error
	if err = m.Provider.Login(ctx); err != nil {
		return err
	}
	// perform any actions to create prereq resource before the cluster
	if err = m.Provider.CreateClusterPrerequisites(ctx, clusterName); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in creating cluster prereqs", "err", err)
		return err
	}
	// rename any existing kubeconfig to .save
	infracommon.BackupKubeconfig(ctx, client)
	if err = m.Provider.RunClusterCreateCommand(ctx, clusterName, numNodes, flavor); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in creating cluster", "err", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "cluster create done")

	if err = m.Provider.GetCredentials(ctx, clusterName); err != nil {
		return err
	}
	kconfFile := infracommon.DefaultKubeconfig()
	start := time.Now()
	for {
		// make sure the kubeconf is present and of nonzero length.  If not keep
		// waiting for it to show up to MaxKubeCredentialsWait
		finfo, err := os.Stat(kconfFile)
		if err == nil && finfo.Size() > 0 {
			break
		}
		time.Sleep(time.Second * 1)
		elapsed := time.Since(start)
		if elapsed >= (MaxKubeCredentialsWait) {
			return fmt.Errorf("Could not find kubeconfig file after GetCredentials: %s", kconfFile)
		}
	}
	if err = pc.CopyFile(client, kconfFile, kconf); err != nil {
		return err
	}
	return nil
}

func (m *ManagedK8sPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteClusterInst", "clusterInst", clusterInst)
	clusterName := m.Provider.NameSanitize(k8smgmt.GetCloudletClusterName(clusterInst))
	return m.deleteClusterInstInternal(ctx, clusterName)
}

func (m *ManagedK8sPlatform) deleteClusterInstInternal(ctx context.Context, clusterName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleteClusterInstInternal", "clusterName", clusterName)
	return m.Provider.RunClusterDeleteCommand(ctx, clusterName)
}

func (s *ManagedK8sPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Update cluster inst not implemented")
}
