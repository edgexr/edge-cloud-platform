package k8sbm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	ssh "github.com/mobiledgex/golang-ssh"
)

func (k *K8sBareMetalPlatform) GetClusterDir(clusterInst *edgeproto.ClusterInst) string {
	return k8smgmt.GetNormalizedClusterName(clusterInst)
}

func (k *K8sBareMetalPlatform) GetNamespaceNameForCluster(ctx context.Context, clusterInst *edgeproto.ClusterInst) string {
	return util.K8SSanitize(fmt.Sprintf("%s-%s", clusterInst.Key.Organization, clusterInst.Key.ClusterKey.Name))
}

// GetKubenamesForCluster is a temporary fix as we evolve towards consistent MT support.  It is needed to use MT functions like CreateNamespace
func (k *K8sBareMetalPlatform) GetKubenamesForCluster(ctx context.Context, clusterInst *edgeproto.ClusterInst) *k8smgmt.KubeNames {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetKubenamesForCluster", "clusterInst", clusterInst)
	namespace := k.GetNamespaceNameForCluster(ctx, clusterInst)
	clusterKconf := k8smgmt.GetKconfName(clusterInst)
	kubeNames := k8smgmt.KubeNames{
		MultitenantNamespace: namespace,
		BaseKconfName:        k.cloudletKubeConfig,
		KconfName:            clusterKconf,
	}
	return &kubeNames
}

func (k *K8sBareMetalPlatform) SetupVirtualCluster(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupVirtualCluster", "clusterInst", clusterInst)

	kubeNames := k.GetKubenamesForCluster(ctx, clusterInst)
	err := k8smgmt.CreateNamespace(ctx, client, kubeNames)
	if err != nil {
		return err
	}
	dir := k.GetClusterDir(clusterInst)
	policyName := kubeNames.MultitenantNamespace + "-netpol"
	manifest, err := infracommon.CreateK8sNetworkPolicyManifest(ctx, client, policyName, kubeNames.MultitenantNamespace, dir)
	if err != nil {
		return err
	}
	return infracommon.ApplyK8sNetworkPolicyManifest(ctx, client, manifest, k.cloudletKubeConfig)
}

func (k *K8sBareMetalPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateClusterInst")
	client, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Setting up Virtual Cluster")
	err = k.SetupVirtualCluster(ctx, client, clusterInst)
	if err != nil {
		return err
	}
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		lbName := k.GetLbNameForCluster(ctx, clusterInst)
		updateCallback(edgeproto.UpdateTask, "Setting up Dedicated Load Balancer")
		err = k.SetupLb(ctx, client, lbName)
		if err != nil {
			return err
		}
	}
	return nil
}

func (k *K8sBareMetalPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("UpdateClusterInst not supported")
}

func (k *K8sBareMetalPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteClusterInst")
	client, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
	if err != nil {
		return err
	}
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		externalDev := k.GetExternalEthernetInterface()
		rootLBName := k.GetLbNameForCluster(ctx, clusterInst)
		lbinfo, err := k.GetLbInfo(ctx, client, rootLBName)
		if err != nil {
			if strings.Contains(err.Error(), LbInfoDoesNotExist) {
				log.SpanLog(ctx, log.DebugLevelInfra, "lbinfo does not exist")

			} else {
				return err
			}
		} else {
			err := k.RemoveIp(ctx, client, lbinfo.ExternalIpAddr, externalDev)
			if err != nil {
				return err
			}
		}
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			err = k.DeleteLbInfo(ctx, client, rootLBName)
			if err != nil {
				return err
			}
			if err = k.commonPf.DeleteDNSRecords(ctx, rootLBName); err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete DNS record", "fqdn", rootLBName, "err", err)
			}
		}
	}
	err = k8smgmt.DeleteNamespace(ctx, client, k.GetKubenamesForCluster(ctx, clusterInst))
	if err != nil {
		return err
	}
	clusterDir := k.GetClusterDir(clusterInst)
	clusterKubeConf := k8smgmt.GetKconfName(clusterInst)

	err = pc.DeleteFile(client, clusterKubeConf)
	if err != nil {
		// DeleteFile uses -f so an error is really approblem
		return fmt.Errorf("Fail to delete cluster kubeconfig")
	}
	err = pc.DeleteDir(ctx, client, clusterDir, pc.NoSudo)
	if err != nil {
		// DeleteDir uses -rf so an error is really a problem
		return fmt.Errorf("Fail to delete cluster kubeconfig")
	}
	return nil
}
