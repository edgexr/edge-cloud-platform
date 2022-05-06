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

package vmlayer

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type VMAccess struct {
	Name   string
	Client ssh.Client
	Role   VMRole
}

func (v *VMPlatform) GetSSHClientForCluster(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error) {
	rootLBName := v.VMProperties.SharedRootLBName
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		rootLBName = clusterInst.Fqdn
	}
	return v.GetSSHClientForServer(ctx, rootLBName, v.VMProperties.GetCloudletExternalNetwork(), pc.WithCachedIp(true))
}

//GetSSHClient returns ssh client handle for the server
func (v *VMPlatform) GetSSHClientForServer(ctx context.Context, serverName, networkName string, ops ...pc.SSHClientOp) (ssh.Client, error) {
	serverIp, err := v.GetIPFromServerName(ctx, networkName, "", serverName, ops...)
	if err != nil {
		return nil, err
	}
	externalAddr := serverIp.ExternalAddr
	return v.VMProperties.CommonPf.GetSSHClientFromIPAddr(ctx, externalAddr, ops...)
}

func (v *VMPlatform) GetAllCloudletVMs(ctx context.Context, caches *platform.Caches) ([]VMAccess, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAllCloudletVMs")
	// Store in slice as to preserve order
	cloudletVMs := []VMAccess{}

	// Platform VM Name
	pfName := v.GetPlatformVMName(v.VMProperties.CommonPf.PlatformConfig.CloudletKey)
	client, err := v.GetSSHClientForServer(ctx, pfName, v.VMProperties.GetCloudletExternalNetwork())
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error getting ssh client for platform VM", "vm", pfName, "err", err)
	}
	cloudletVMs = append(cloudletVMs, VMAccess{
		Name:   pfName,
		Client: client,
		Role:   RoleVMPlatform,
	})

	// Shared RootLB
	sharedRootLBName := v.VMProperties.SharedRootLBName
	sharedlbclient, err := v.GetSSHClientForServer(ctx, sharedRootLBName, v.VMProperties.GetCloudletExternalNetwork(), pc.WithCachedIp(true))
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error getting ssh client for shared rootlb", "vm", sharedRootLBName, "err", err)
	}

	// Dedicated RootLB + Cluster VMs
	clusterInstKeys := make(map[edgeproto.ClusterInstKey]struct{})
	caches.ClusterInstCache.GetAllKeys(ctx, func(k *edgeproto.ClusterInstKey, modRev int64) {
		clusterInstKeys[*k] = struct{}{}
	})
	clusterInst := &edgeproto.ClusterInst{}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAllCloudletVMs got clusters", "num clusters", len(clusterInstKeys))
	for k := range clusterInstKeys {
		if !caches.ClusterInstCache.Get(&k, clusterInst) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Error: failed to get cluster", "key", k)
			continue
		}

		log.SpanLog(ctx, log.DebugLevelInfra, "GetAllCloudletVMs handle cluster", "key", k, "deployment", clusterInst.Deployment, "IpAccess", clusterInst.IpAccess)
		var dedicatedlbclient ssh.Client
		var dedRootLBName string
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			dedRootLBName = v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
			dedicatedlbclient, err = v.GetSSHClientForServer(ctx, dedRootLBName, v.VMProperties.GetCloudletExternalNetwork(), pc.WithCachedIp(true))
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "error getting ssh client", "vm", dedRootLBName, "err", err)
			}
		}
		var lbClient ssh.Client
		if dedicatedlbclient != nil {
			lbClient = dedicatedlbclient
		} else {
			lbClient = sharedlbclient
		}

		switch clusterInst.Deployment {
		case cloudcommon.DeploymentTypeKubernetes:
			var masterClient ssh.Client
			masterNode := GetClusterMasterName(ctx, clusterInst)
			masterIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), masterNode)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "error getting masterIP", "vm", masterNode, "err", err)
			} else {
				masterClient, err = lbClient.AddHop(masterIP.ExternalAddr, 22)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "Fail to addhop to master", "masterIP", masterIP, "err", err)
				}
			}
			cloudletVMs = append(cloudletVMs, VMAccess{
				Name:   masterNode,
				Client: masterClient,
				Role:   RoleMaster,
			})
			for nn := uint32(1); nn <= clusterInst.NumNodes; nn++ {
				var nodeClient ssh.Client
				clusterNode := GetClusterNodeName(ctx, clusterInst, nn)
				nodeIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), clusterNode)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "error getting node IP", "vm", clusterNode, "err", err)
				} else {
					nodeClient, err = lbClient.AddHop(nodeIP.ExternalAddr, 22)
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfra, "Fail to addhop to node", "nodeIP", nodeIP, "err", err)
					}
				}
				cloudletVMs = append(cloudletVMs, VMAccess{
					Name:   clusterNode,
					Client: nodeClient,
					Role:   RoleK8sNode,
				})
			}

		case cloudcommon.DeploymentTypeDocker:
			var dockerNodeClient ssh.Client
			dockerNode := v.GetDockerNodeName(ctx, clusterInst)
			dockerNodeIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), dockerNode)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "error getting docker node IP", "vm", dockerNode, "err", err)
			} else {
				dockerNodeClient, err = lbClient.AddHop(dockerNodeIP.ExternalAddr, 22)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "Fail to addhop to docker node", "dockerNodeIP", dockerNodeIP, "err", err)
				}
			}
			cloudletVMs = append(cloudletVMs, VMAccess{
				Name:   dockerNode,
				Client: dockerNodeClient,
				Role:   RoleDockerNode,
			})
		} // switch deloyment

		// add dedicated LB after all the nodes
		if dedicatedlbclient != nil {
			cloudletVMs = append(cloudletVMs, VMAccess{
				Name:   dedRootLBName,
				Client: dedicatedlbclient,
				Role:   RoleAgent,
			})
		}
	}

	// now we need dedicated rootlb for VM Apps
	appInstKeys := make(map[edgeproto.AppInstKey]struct{})
	caches.AppInstCache.GetAllKeys(ctx, func(k *edgeproto.AppInstKey, modRev int64) {
		appInstKeys[*k] = struct{}{}
	})
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAllCloudletVMs got appinsts", "num appinsts", len(appInstKeys))
	for k := range appInstKeys {
		var appinst edgeproto.AppInst
		var app edgeproto.App
		if !caches.AppCache.Get(&k.AppKey, &app) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Failed to get appInst from cache", "appkey", k.AppKey)
			continue
		}
		if app.Deployment != cloudcommon.DeploymentTypeVM || app.AccessType != edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
			// only vm with load balancers need to be handled
			continue
		}
		if !caches.AppInstCache.Get(&k, &appinst) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Failed to get appInst from cache", "key", k)
			continue
		}
		appLbName := appinst.Uri
		log.SpanLog(ctx, log.DebugLevelInfra, "GetAllCloudletVMs handle VM appinst with LB", "key", k, "appLbName", appLbName)
		appLbClient, err := v.GetSSHClientForServer(ctx, appLbName, v.VMProperties.GetCloudletExternalNetwork(), pc.WithCachedIp(true))
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Failed to get client for VM App LB", "appLbName", appLbName, "err", err)
		}
		cloudletVMs = append(cloudletVMs, VMAccess{
			Name:   appLbName,
			Client: appLbClient,
			Role:   RoleAgent,
		})
	}

	// add the sharedLB last
	cloudletVMs = append(cloudletVMs, VMAccess{
		Name:   sharedRootLBName,
		Client: sharedlbclient,
		Role:   RoleAgent,
	})

	log.SpanLog(ctx, log.DebugLevelInfra, "GetAllCloudletVMs done", "cloudletVMs", fmt.Sprintf("%v", cloudletVMs))
	return cloudletVMs, nil
}

func GetVaultCAScript(publicSSHKey string) string {
	return fmt.Sprintf(`
#!/bin/bash

die() {
        echo "ERROR: $*" >&2
        exit 2
}

sudo cat > /etc/ssh/trusted-user-ca-keys.pem << EOL
%s
EOL

sudo grep "ssh-rsa" /etc/ssh/trusted-user-ca-keys.pem
[[ $? -ne 0 ]] && die "invalid CA cert from vault"

echo 'TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem' | sudo tee -a /etc/ssh/sshd_config
sudo systemctl reload ssh
[[ $? -ne 0 ]] && die "failed to reload ssh"

rm -f id_rsa_mex
echo "" > .ssh/authorized_keys

echo "Done setting up vault ssh"
`, publicSSHKey)
}

func GetVaultCAScriptForMasterNode(publicSSHKey string) string {
	k8sJoinSvcScript := `
mkdir -p /var/tmp/k8s-join
cp /tmp/k8s-join-cmd.tmp /var/tmp/k8s-join/k8s-join-cmd
[[ $? -ne 0 ]] && die "failed to copy k8s-join-cmd.tmp file"
chown ubuntu:ubuntu /var/tmp/k8s-join/k8s-join-cmd

sudo tee /etc/systemd/system/k8s-join.service <<'EOT'
[Unit]
Description=Job that runs k8s join script server
[Service]
Type=simple
WorkingDirectory=/var/tmp/k8s-join
ExecStart=/usr/bin/python3 -m http.server 20800
Restart=always
[Install]
WantedBy=multi-user.target
EOT

sudo systemctl enable k8s-join
[[ $? -ne 0 ]] && die "failed to enable k8s-join service"
sudo systemctl start k8s-join
[[ $? -ne 0 ]] && die "failed to start k8s-join service"

echo "Done setting k8s-join service"
`
	vaultCAScript := GetVaultCAScript(publicSSHKey)
	return vaultCAScript + k8sJoinSvcScript
}

func ExecuteUpgradeScript(ctx context.Context, vmName string, client ssh.Client, script string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "execute upgrade script", "vmName", vmName)
	err := pc.WriteFile(client, "upgradeCRMVault.sh", script, "upgrade script", pc.NoSudo)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to copy script", "err", err)
		return err
	}
	// Execute script
	out, err := client.Output("bash upgradeCRMVault.sh")
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to fix vm", "out", out, "err", err)
		return err
	}
	return nil
}

func (v *VMPlatform) UpgradeFuncHandleSSHKeys(ctx context.Context, accessApi platform.AccessApi, caches *platform.Caches) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpgradeFuncHandleSSHKeys")
	publicSSHKey, err := accessApi.GetSSHPublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault ssh cert: %v", err)
	}
	// Set SSH client to use mex private key
	v.VMProperties.CommonPf.SshKey.UseMEXPrivateKey = true
	fixVMs, err := v.GetAllCloudletVMs(ctx, caches)
	if err != nil {
		return nil, err
	}

	for _, vm := range fixVMs {
		log.SpanLog(ctx, log.DebugLevelInfra, "Upgrade VM", "vm", fmt.Sprintf("%v", vm))
		if vm.Client == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "missing ssh client", "vm", vm.Name)
			continue
		}
		script := ""
		if vm.Role == RoleMaster {
			// Start k8s-join webserver
			script = GetVaultCAScriptForMasterNode(publicSSHKey)
		} else {
			script = GetVaultCAScript(publicSSHKey)
		}
		err = ExecuteUpgradeScript(ctx, vm.Name, vm.Client, script)
		if err != nil {
			// continue fixing other VMs
			continue
		}
	}

	// Validate VMs with new vault SSH fix
	// Set SSH client to use vault signed Keys
	v.VMProperties.CommonPf.SshKey.UseMEXPrivateKey = false
	fixVMs, err = v.GetAllCloudletVMs(ctx, caches)
	if err != nil {
		return nil, err
	}
	results := make(map[string]string)
	for _, vm := range fixVMs {
		if vm.Client == nil {
			results[vm.Name] = "failed to get ssh client"
			continue
		}
		_, err = vm.Client.Output("hostname")
		if err != nil {
			results[vm.Name] = fmt.Sprintf("failed with error: %v", err)
			continue
		}
		results[vm.Name] = "fixed"
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Upgrade results", "results", results)
	return results, nil
}
