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

func (k *K8sBareMetalPlatform) SetupVirtualCluster(ctx context.Context, client ssh.Client, namespace, kubeconfig, dir string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupVirtualCluster", "namespace", namespace)

	err := k.CreateNamespace(ctx, client, namespace, kubeconfig)

	if err != nil {
		return err
	}
	policyName := namespace + "-netpol"
	manifest, err := infracommon.CreateK8sNetworkPolicyManifest(ctx, client, policyName, namespace, dir)
	if err != nil {
		return err
	}
	return infracommon.ApplyK8sNetworkPolicyManifest(ctx, client, manifest, k.cloudletKubeConfig)
}

func (k *K8sBareMetalPlatform) CreateNamespace(ctx context.Context, client ssh.Client, nameSpace, kubeconfig string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateNamespace", "lbname", nameSpace)

	cmd := fmt.Sprintf("kubectl create namespace  %s --kubeconfig=%s", nameSpace, k.cloudletKubeConfig)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("Error in creating namespace: %s - %v", out, err)
	}
	// copy the kubeconfig add update the new one with the new namespace
	log.SpanLog(ctx, log.DebugLevelInfra, "create new kubeconfig for cluster namespace", "cloudletKubeConfig", k.cloudletKubeConfig, "clustKubeConfig", kubeconfig)

	err = pc.CopyFile(client, k.cloudletKubeConfig, kubeconfig)
	if err != nil {
		return fmt.Errorf("Failed to create new kubeconfig: %v", err)
	}
	// set the current context
	cmd = fmt.Sprintf("KUBECONFIG=%s kubectl config set-context --current --namespace=%s", kubeconfig, nameSpace)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("Error in setting new namespace context: %s - %v", out, err)
	}
	return nil
}

func (k *K8sBareMetalPlatform) DeleteNamespace(ctx context.Context, client ssh.Client, nameSpace string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteNamespace", "nameSpace", nameSpace)
	cmd := fmt.Sprintf("kubectl delete namespace  %s --kubeconfig=%s", nameSpace, k.cloudletKubeConfig)
	out, err := client.Output(cmd)
	if err != nil {
		if !strings.Contains(out, "not found") {
			return fmt.Errorf("Error in deleting namespace: %s - %v", out, err)
		}
	}
	return nil
}

func (k *K8sBareMetalPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateClusterInst")
	client, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Setting up Virtual Cluster")
	err = k.SetupVirtualCluster(ctx, client, k.GetNamespaceNameForCluster(ctx, clusterInst), k8smgmt.GetKconfName(clusterInst), k.GetClusterDir(clusterInst))
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
		internalDev := k.GetInternalEthernetInterface()
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
			err = k.RemoveIp(ctx, client, lbinfo.InternalIpAddr, internalDev)
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
	namespace := k.GetNamespaceNameForCluster(ctx, clusterInst)
	err = k.DeleteNamespace(ctx, client, namespace)
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
