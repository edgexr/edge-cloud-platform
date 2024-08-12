// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8sbm

import (
	"context"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/confignode"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
)

func (k *K8sBareMetalPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, flavor *edgeproto.Flavor, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateCloudlet", "cloudlet", cloudlet)

	if pfConfig.ContainerRegistryPath == "" {
		return false, fmt.Errorf("container registry path not specified")
	}
	cloudletResourcesCreated := false

	k.commonPf.PlatformConfig = infracommon.GetPlatformConfig(cloudlet, pfConfig, pfInitConfig)
	if err := k.commonPf.InitInfraCommon(ctx, k.commonPf.PlatformConfig, k8sbmProps); err != nil {
		return cloudletResourcesCreated, err
	}

	// edge-cloud image already contains the certs
	if pfConfig.TlsCertFile != "" {
		crtFile, err := infracommon.GetDockerCrtFile(pfConfig.TlsCertFile)
		if err != nil {
			return cloudletResourcesCreated, err
		}
		pfConfig.TlsCertFile = crtFile
	}

	// TODO: have cloudlet node ansible support k8sbm
	// previously used chef with nodeType PlatformHost.
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		return cloudletResourcesCreated, fmt.Errorf("Restricted access not yet supported on BareMetal")
	}

	sshClient, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
	if err != nil {
		return cloudletResourcesCreated, fmt.Errorf("Failed to get ssh client to control host: %v", err)
	}
	if pfConfig.CrmAccessPrivateKey != "" {
		err = pc.WriteFile(sshClient, " /root/accesskey/accesskey.pem", pfConfig.CrmAccessPrivateKey, "accesskey", pc.SudoOn)
		if err != nil {
			return cloudletResourcesCreated, fmt.Errorf("Write access key fail: %v", err)
		}
	}
	// once we get here, we require cleanup on failure because we have accessed the control node
	cloudletResourcesCreated = true

	// TODO: set up ansible cron job on server
	return cloudletResourcesCreated, nil
}

func (k *K8sBareMetalPlatform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("UpdateCloudlet TODO")
}

func (k *K8sBareMetalPlatform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	return fmt.Errorf("UpdateTrustPolicy TODO")
}

func (k *K8sBareMetalPlatform) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterInstKey *edgeproto.ClusterInstKey) error {
	return fmt.Errorf("UpdateTrustPolicyException TODO")
}

func (k *K8sBareMetalPlatform) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterInstKey *edgeproto.ClusterInstKey) error {
	return fmt.Errorf("DeleteTrustPolicyException TODO")
}

func (k *K8sBareMetalPlatform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudlet")
	updateCallback(edgeproto.UpdateTask, "Deleting cloudlet")
	k.commonPf.PlatformConfig = infracommon.GetPlatformConfig(cloudlet, pfConfig, pfInitConfig)
	if err := k.commonPf.InitInfraCommon(ctx, k.commonPf.PlatformConfig, k8sbmProps); err != nil {
		return err
	}
	sshClient, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
	if err != nil {
		return fmt.Errorf("Failed to get ssh client to control host: %v", err)
	}

	updateCallback(edgeproto.UpdateTask, "Deleting Shared RootLB")
	sharedLbName := cloudlet.StaticRootLbFqdn
	externalDev := k.GetExternalEthernetInterface()
	addr, err := infracommon.GetIPAddressFromNetplan(ctx, sshClient, sharedLbName)
	if err != nil {
		if strings.Contains(err.Error(), infracommon.NetplanFileNotFound) {
			log.SpanLog(ctx, log.DebugLevelInfra, "netplan file does not exist", "sharedLbName", sharedLbName)
		} else {
			return fmt.Errorf("unexpected error getting ip address from netplan for lb: %s - %v", sharedLbName, err)
		}
	} else {
		err = k.RemoveIp(ctx, sshClient, addr.IPV4(), externalDev, sharedLbName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "remove IP failed", "addr", addr, "err", err)
			return fmt.Errorf("failed to remove shared LB IP: %s - %v", addr, err)
		}
	}

	updateCallback(edgeproto.UpdateTask, "Removing platform containers")
	platContainers := []string{confignode.ServiceTypeCRM, confignode.ServiceTypeShepherd, confignode.ServiceTypeCloudletPrometheus}
	for _, p := range platContainers {
		out, err := sshClient.Output(fmt.Sprintf("sudo docker rm -f %s", p))
		if err != nil {
			if strings.Contains(err.Error(), "No such container") {
				log.SpanLog(ctx, log.DebugLevelInfra, "container does not exist", "plat", p)
			} else {
				return fmt.Errorf("error removing platform service: %s - %s - %v", p, out, err)
			}
		}
	}
	// clean up machine
	out, err := sshClient.Output("sudo rm -f /root/accesskey/*")
	log.SpanLog(ctx, log.DebugLevelInfra, "accesskey rm results", "out", out, "err", err)
	return nil
}

func (k *K8sBareMetalPlatform) GetNodeInfos(ctx context.Context) ([]*edgeproto.NodeInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNodeInfos")
	client, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
	if err != nil {
		return nil, err
	}
	return k8smgmt.GetNodeInfos(ctx, client, "--kubeconfig="+k.cloudletKubeConfig)
}

func (k *K8sBareMetalPlatform) ActiveChanged(ctx context.Context, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChanged")
	return nil
}

func (k *K8sBareMetalPlatform) NameSanitize(name string) string {
	return name
}
