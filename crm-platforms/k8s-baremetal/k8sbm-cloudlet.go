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

	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/util"

	"github.com/edgexr/edge-cloud-infra/chefmgmt"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type ChefClientConfigParams struct {
	ServerUrl string
	NodeName  string
}

// chefClientConfigTemplate is used to populate /etc/chef/client.rb
var chefClientConfigTemplate = `
log_level              :info
ssl_verify_mode        :verify_none
log_location           "/var/log/chef/client.log"
validation_client_name "mobiledgex-validator"
validation_key         "/etc/chef/client.pem"
client_key             "/etc/chef/client.pem"
chef_server_url        "{{.ServerUrl}}"
node_name              "{{.NodeName}}"
json_attribs           "/etc/chef/firstboot.json"
file_cache_path        "/var/cache/chef"
file_backup_path       "/var/backups/chef"
pid_file               "/var/run/chef/client.pid"
Chef::Log::Formatter.show_time = true`

func (k *K8sBareMetalPlatform) GetChefParams(nodeName, clientKey string, policyName string, attributes map[string]interface{}) *chefmgmt.ServerChefParams {
	chefServerPath := k.commonPf.ChefServerPath
	if chefServerPath == "" {
		chefServerPath = chefmgmt.DefaultChefServerPath
	}
	return &chefmgmt.ServerChefParams{
		NodeName:    nodeName,
		ServerPath:  chefServerPath,
		ClientKey:   clientKey,
		Attributes:  attributes,
		PolicyName:  policyName,
		PolicyGroup: k.commonPf.DeploymentTag,
	}
}

func (k *K8sBareMetalPlatform) GetChefClientName(ckey *edgeproto.CloudletKey) string {
	// Prefix with region name
	name := util.K8SSanitize(ckey.Name + "-" + ckey.Organization)
	return k.commonPf.DeploymentTag + "-" + k.commonPf.PlatformConfig.Region + "-" + name
}

func (k *K8sBareMetalPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateCloudlet", "cloudlet", cloudlet)

	cloudletResourcesCreated := false
	err := k.commonPf.InitCloudletSSHKeys(ctx, accessApi)
	if err != nil {
		return cloudletResourcesCreated, err
	}

	k.commonPf.PlatformConfig = infracommon.GetPlatformConfig(cloudlet, pfConfig, accessApi)
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

	if pfConfig.ChefServerPath == "" {
		pfConfig.ChefServerPath = chefmgmt.DefaultChefServerPath
	}
	if pfConfig.ContainerRegistryPath == "" {
		pfConfig.ContainerRegistryPath = infracommon.DefaultContainerRegistryPath
	}
	chefApi := chefmgmt.ChefApiAccess{}

	// TODO, we should switch bare metal k8s to use k8s chef policy
	nodeInfo := chefmgmt.ChefNodeInfo{
		NodeName: "baremetal-controller",
		NodeType: cloudcommon.NodeTypePlatformHost,
		Policy:   chefmgmt.ChefPolicyDocker,
	}
	chefAttributes, err := chefmgmt.GetChefPlatformAttributes(ctx, cloudlet, pfConfig, &nodeInfo, &chefApi, nil)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	if k.commonPf.ChefClient == nil {
		return cloudletResourcesCreated, fmt.Errorf("Chef client is not initialized")
	}

	chefPolicy := chefmgmt.ChefPolicyDocker
	if cloudlet.Deployment == cloudcommon.DeploymentTypeKubernetes {
		chefPolicy = chefmgmt.ChefPolicyK8s
	}
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		return cloudletResourcesCreated, fmt.Errorf("Restricted access not yet supported on BareMetal")
	}
	clientName := k.GetChefClientName(&cloudlet.Key)
	chefParams := k.GetChefParams(clientName, "", chefPolicy, chefAttributes)

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

	updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Creating Chef Client %s with cloudlet attributes", clientName))
	clientKey, err := chefmgmt.ChefClientCreate(ctx, k.commonPf.ChefClient, chefParams)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	// Store client key in cloudlet obj
	cloudlet.ChefClientKey = make(map[string]string)
	cloudlet.ChefClientKey[clientName] = clientKey

	// install chef
	err = k.SetupChefOnServer(ctx, sshClient, clientName, cloudlet, chefParams)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	return cloudletResourcesCreated, chefmgmt.GetChefRunStatus(ctx, k.commonPf.ChefClient, clientName, cloudlet, pfConfig, accessApi, updateCallback)
}

func (k *K8sBareMetalPlatform) SetupChefOnServer(ctx context.Context, sshClient ssh.Client, clientName string, cloudlet *edgeproto.Cloudlet, chefParams *chefmgmt.ServerChefParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupChefOnServer", "clientName", clientName)

	err := pc.WriteFile(sshClient, "/etc/chef/client.pem", cloudlet.ChefClientKey[clientName], "chef-key", pc.SudoOn)
	if err != nil {
		return fmt.Errorf("Failed to write chef client key: %v", err)
	}

	chefClientConfigParams := ChefClientConfigParams{
		ServerUrl: chefParams.ServerPath,
		NodeName:  clientName, //client and node name are the same
	}
	pBuf, err := infracommon.ExecTemplate("chefClientRb", chefClientConfigTemplate, chefClientConfigParams)
	if err != nil {
		return fmt.Errorf("Error in chef rb template: %v", err)
	}
	chefConfigFile := "/etc/chef/client.rb"
	log.SpanLog(ctx, log.DebugLevelInfra, "Creating chef-client config file", "chefConfigFile", chefConfigFile, "chefClientConfigParams", chefClientConfigParams)
	err = pc.WriteFile(sshClient, "/etc/chef/client.rb", pBuf.String(), "chef clientrb", pc.SudoOn)
	if err != nil {
		return fmt.Errorf("unable to chef config file %s: %s", chefConfigFile, err.Error())
	}

	command := fmt.Sprintf("sudo systemctl enable chef-client")
	log.SpanLog(ctx, log.DebugLevelInfra, "enable chef-client", "command", command)
	out, err := sshClient.Output(command)
	if err != nil {
		return fmt.Errorf("Failed to enable chef client: %s - %v", out, err)
	}
	command = fmt.Sprintf("sudo systemctl start chef-client")
	log.SpanLog(ctx, log.DebugLevelInfra, "start chef-client", "command", command)
	out, err = sshClient.Output(command)
	if err != nil {
		return fmt.Errorf("Failed to start chef client: %s - %v", out, err)
	}
	return nil
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

func (k *K8sBareMetalPlatform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudlet")
	updateCallback(edgeproto.UpdateTask, "Deleting cloudlet")
	err := k.commonPf.InitCloudletSSHKeys(ctx, accessApi)
	if err != nil {
		return err
	}
	k.commonPf.PlatformConfig = infracommon.GetPlatformConfig(cloudlet, pfConfig, accessApi)
	if err := k.commonPf.InitInfraCommon(ctx, k.commonPf.PlatformConfig, k8sbmProps); err != nil {
		return err
	}
	sshClient, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
	if err != nil {
		return fmt.Errorf("Failed to get ssh client to control host: %v", err)
	}

	updateCallback(edgeproto.UpdateTask, "Deleting Shared RootLB")
	sharedLbName := cloudlet.RootLbFqdn
	externalDev := k.GetExternalEthernetInterface()
	addr, err := infracommon.GetIPAddressFromNetplan(ctx, sshClient, sharedLbName)
	if err != nil {
		if strings.Contains(err.Error(), infracommon.NetplanFileNotFound) {
			log.SpanLog(ctx, log.DebugLevelInfra, "netplan file does not exist", "sharedLbName", sharedLbName)
		} else {
			return fmt.Errorf("unexpected error getting ip address from netplan for lb: %s - %v", sharedLbName, err)
		}
	} else {
		err = k.RemoveIp(ctx, sshClient, addr, externalDev, sharedLbName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "remove IP failed", "addr", addr, "err", err)
			return fmt.Errorf("failed to remove shared LB IP: %s - %v", addr, err)
		}
	}

	updateCallback(edgeproto.UpdateTask, "Removing platform containers")
	platContainers := []string{chefmgmt.ServiceTypeCRM, chefmgmt.ServiceTypeShepherd, chefmgmt.ServiceTypeCloudletPrometheus}
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
	// kill chef add other cleanup
	out, err := sshClient.Output("sudo systemctl stop chef-client")
	log.SpanLog(ctx, log.DebugLevelInfra, "chef stop results", "out", out, "err", err)
	out, err = sshClient.Output("sudo systemctl disable chef-client")
	log.SpanLog(ctx, log.DebugLevelInfra, "chef disable results", "out", out, "err", err)
	out, err = sshClient.Output("sudo rm -f /root/accesskey/*")
	log.SpanLog(ctx, log.DebugLevelInfra, "accesskey rm results", "out", out, "err", err)
	out, err = sshClient.Output("sudo rm -f /etc/chef/client.pem")
	log.SpanLog(ctx, log.DebugLevelInfra, "chef pem rm results", "out", out, "err", err)
	return nil
}

func (k *K8sBareMetalPlatform) GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList")
	var flavors []*edgeproto.FlavorInfo
	if k.caches == nil {
		log.WarnLog("flavor cache is nil")
		return nil, fmt.Errorf("Flavor cache is nil")
	}
	flavorkeys := make(map[edgeproto.FlavorKey]struct{})
	k.caches.FlavorCache.GetAllKeys(ctx, func(k *edgeproto.FlavorKey, modRev int64) {
		flavorkeys[*k] = struct{}{}
	})
	for f := range flavorkeys {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList found flavor", "key", k)
		var flav edgeproto.Flavor
		if k.caches.FlavorCache.Get(&f, &flav) {
			var flavInfo edgeproto.FlavorInfo
			_, gpu := flav.OptResMap["gpu"]
			if gpu {
				// gpu not currently supported
				log.SpanLog(ctx, log.DebugLevelInfra, "skipping GPU flavor", "flav", flav)
				continue
			}
			flavInfo.Name = flav.Key.Name
			flavInfo.Vcpus = flav.Vcpus
			flavInfo.Ram = flav.Ram
			flavors = append(flavors, &flavInfo)
		} else {
			return nil, fmt.Errorf("fail to fetch flavor %s", f)
		}
	}
	return flavors, nil
}

func (k *K8sBareMetalPlatform) GetNodeInfos(ctx context.Context) ([]*edgeproto.NodeInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNodeInfos")
	client, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
	if err != nil {
		return nil, err
	}
	return k8smgmt.GetNodeInfos(ctx, client, "KUBECONFIG="+k.cloudletKubeConfig)
}

func (k *K8sBareMetalPlatform) ActiveChanged(ctx context.Context, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChanged")
	return nil
}

func (k *K8sBareMetalPlatform) NameSanitize(name string) string {
	return name
}
