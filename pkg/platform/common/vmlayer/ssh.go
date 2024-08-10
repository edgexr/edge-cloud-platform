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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
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

// GetSSHClient returns ssh client handle for the server
func (v *VMPlatform) GetSSHClientForServer(ctx context.Context, serverName, networkName string, ops ...pc.SSHClientOp) (ssh.Client, error) {
	getIPOPs := GetIPOpsFromSSHOps(ops)
	serverIp, err := v.GetIPFromServerName(ctx, networkName, NoSubnets, serverName, getIPOPs...)
	if err != nil {
		return nil, err
	}
	externalAddr := serverIp.IPV4ExternalAddr()
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
			masterIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), v.GetClusterSubnetName(ctx, clusterInst), masterNode)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "error getting masterIP", "vm", masterNode, "err", err)
			} else {
				masterClient, err = lbClient.AddHop(masterIP.IPV4ExternalAddr(), 22)
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
				nodeIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), v.GetClusterSubnetName(ctx, clusterInst), clusterNode)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "error getting node IP", "vm", clusterNode, "err", err)
				} else {
					nodeClient, err = lbClient.AddHop(nodeIP.IPV4ExternalAddr(), 22)
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
			dockerNodeIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), v.GetClusterSubnetName(ctx, clusterInst), dockerNode)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "error getting docker node IP", "vm", dockerNode, "err", err)
			} else {
				dockerNodeClient, err = lbClient.AddHop(dockerNodeIP.IPV4ExternalAddr(), 22)
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
		if !caches.AppInstCache.Get(&k, &appinst) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Failed to get appInst from cache", "key", k)
			continue
		}
		if !caches.AppCache.Get(&appinst.AppKey, &app) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Failed to get appInst from cache", "appkey", appinst.AppKey)
			continue
		}
		if app.Deployment != cloudcommon.DeploymentTypeVM || app.AccessType != edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
			// only vm with load balancers need to be handled
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
