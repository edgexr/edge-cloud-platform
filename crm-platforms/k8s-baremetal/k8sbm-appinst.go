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

	"github.com/edgexr/edge-cloud/cloud-resource-manager/access"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/dockermgmt"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/crmutil"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/proxy"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	v1 "k8s.io/api/core/v1"
)

func (k *K8sBareMetalPlatform) GetClusterMasterNodeIp(ctx context.Context, client ssh.Client, kconfName string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetClusterMasterNodeIp", "kconfName", kconfName)
	cmd := fmt.Sprintf("KUBECONFIG=%s kubectl get nodes --selector=node-role.kubernetes.io/master -o jsonpath='{$.items[*].status.addresses[?(@.type==\"InternalIP\")].address}'", kconfName)
	ipaddr, err := client.Output(cmd)
	if err != nil {
		return "", err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetClusterMasterNodeIp", "ipaddr", ipaddr)
	return ipaddr, nil
}

func (k *K8sBareMetalPlatform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, appInstFlavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateAppInst", "appInst", appInst)

	var err error
	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		fallthrough
	case cloudcommon.DeploymentTypeHelm:
		rootLBName := k.GetLbName(ctx, appInst)
		appWaitChan := make(chan string)
		client, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return err
		}
		if appInst.DedicatedIp {
			updateCallback(edgeproto.UpdateTask, "Setting up Dedicated AppInst Local Balancer")
			err := k.SetupLb(ctx, client, rootLBName)
			if err != nil {
				return err
			}
		}

		updateCallback(edgeproto.UpdateTask, "Setting up registry secret")
		for _, imagePath := range names.ImagePaths {
			err = k8smgmt.CreateAllNamespaces(ctx, client, names)
			if err != nil {
				return err
			}
			err = infracommon.CreateDockerRegistrySecret(ctx, client, k.cloudletKubeConfig, imagePath, k.commonPf.PlatformConfig.AccessApi, names, nil)
			if err != nil {
				return err
			}
		}
		ipaddr, err := infracommon.GetIPAddressFromNetplan(ctx, client, rootLBName)
		if err != nil {
			return err
		}

		kconfName := k8smgmt.GetKconfName(clusterInst)
		masterNodeIpAddr, err := k.GetClusterMasterNodeIp(ctx, client, kconfName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetClusterMasterNodeIp failed", "kconfName", kconfName, "err", err)
		}
		deploymentVars := crmutil.DeploymentReplaceVars{
			Deployment: crmutil.CrmReplaceVars{
				ClusterIp:    masterNodeIpAddr,
				CloudletName: k8smgmt.NormalizeName(clusterInst.Key.CloudletKey.Name),
				ClusterName:  k8smgmt.NormalizeName(clusterInst.Key.ClusterKey.Name),
				CloudletOrg:  k8smgmt.NormalizeName(clusterInst.Key.CloudletKey.Organization),
				AppOrg:       k8smgmt.NormalizeName(app.Key.Organization),
				DnsZone:      k.commonPf.GetCloudletDNSZone(),
			},
		}
		ctx = context.WithValue(ctx, crmutil.DeploymentReplaceVarsKey, &deploymentVars)

		if deployment == cloudcommon.DeploymentTypeKubernetes {
			updateCallback(edgeproto.UpdateTask, "Creating Kubernetes App")
			err = k8smgmt.CreateAppInst(ctx, k.commonPf.PlatformConfig.AccessApi, client, names, app, appInst, appInstFlavor)
		} else {
			updateCallback(edgeproto.UpdateTask, "Creating Helm App")
			err = k8smgmt.CreateHelmAppInst(ctx, client, names, clusterInst, app, appInst)
		}
		if err != nil {
			return err
		}

		// wait for the appinst in parallel with other tasks
		go func() {
			if deployment == cloudcommon.DeploymentTypeKubernetes {
				waitErr := k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
				if waitErr == nil {
					appWaitChan <- ""
				} else {
					appWaitChan <- waitErr.Error()
				}
			} else { // no waiting for the helm apps currently, to be revisited
				appWaitChan <- ""
			}
		}()
		// get the lb IP provided by metalLb
		err = k8smgmt.PopulateAppInstLoadBalancerIps(ctx, client, names, appInst)
		if err != nil {
			return err
		}
		if err == nil {
			getDnsAction := func(svc v1.Service) (*infracommon.DnsSvcAction, error) {
				action := infracommon.DnsSvcAction{}
				action.PatchKube = false
				action.PatchIP = ""
				action.ExternalIP = ipaddr
				return &action, nil
			}
			// If this is all internal ports, all we need is patch of kube service
			if app.InternalPorts {
				err = k.commonPf.CreateAppDNSAndPatchKubeSvc(ctx, client, names, infracommon.NoDnsOverride, getDnsAction)
			} else {
				updateCallback(edgeproto.UpdateTask, "Configuring Service: LB, Firewall Rules add DNS")
				wlParams := infracommon.WhiteListParams{
					ServerName:  rootLBName,
					SecGrpName:  rootLBName,
					Label:       infracommon.GetAppWhitelistRulesLabel(app),
					AllowedCIDR: infracommon.GetAllowedClientCIDR(),
					Ports:       appInst.MappedPorts,
					DestIP:      ipaddr,
				}
				ops := infracommon.ProxyDnsSecOpts{AddProxy: true, AddDnsAndPatchKubeSvc: true, AddSecurityRules: true, ProxyNamePrefix: k8smgmt.GetKconfName(clusterInst) + "-"}
				err = k.commonPf.AddProxySecurityRulesAndPatchDNS(ctx, client, names, app, appInst, getDnsAction, k.WhitelistSecurityRules, &wlParams, ipaddr, "", ops, proxy.WithDockerNetwork("host"), proxy.WithDockerUser(DockerUser), proxy.WithMetricEndpoint(cloudcommon.ProxyMetricsListenUDS))
			}
		}

		appWaitErr := <-appWaitChan
		if appWaitErr != "" {
			return fmt.Errorf("app wait error, %v", appWaitErr)
		}
		if err != nil {
			return err
		}
	default:
		err = fmt.Errorf("unsupported deployment type for BareMetal %s", deployment)
	}
	return err
}

func (k *K8sBareMetalPlatform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteAppInst", "appInst", appInst)

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		rootLBName := k.GetLbName(ctx, appInst)
		client, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
		if err != nil {
			return err
		}
		ipaddr, err := infracommon.GetIPAddressFromNetplan(ctx, client, rootLBName)
		if err != nil {
			return err
		}
		names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
		if err != nil {
			return fmt.Errorf("get kube names failed: %s", err)
		}
		// Add crm local replace variables
		deploymentVars := crmutil.DeploymentReplaceVars{
			Deployment: crmutil.CrmReplaceVars{
				CloudletName: k8smgmt.NormalizeName(clusterInst.Key.CloudletKey.Name),
				ClusterName:  k8smgmt.NormalizeName(clusterInst.Key.ClusterKey.Name),
				CloudletOrg:  k8smgmt.NormalizeName(clusterInst.Key.CloudletKey.Organization),
				AppOrg:       k8smgmt.NormalizeName(app.Key.Organization),
				DnsZone:      k.commonPf.GetCloudletDNSZone(),
			},
		}
		ctx = context.WithValue(ctx, crmutil.DeploymentReplaceVarsKey, &deploymentVars)
		// Clean up security rules add proxy if app is external
		secGrp := infracommon.GetServerSecurityGroupName(rootLBName)
		containerName := k8smgmt.GetKconfName(clusterInst) + "-" + dockermgmt.GetContainerName(&app.Key)
		wlParams := infracommon.WhiteListParams{
			ServerName:  rootLBName,
			SecGrpName:  secGrp,
			Label:       infracommon.GetAppWhitelistRulesLabel(app),
			AllowedCIDR: infracommon.GetAllowedClientCIDR(),
			Ports:       appInst.MappedPorts,
			DestIP:      ipaddr,
		}
		if err := k.commonPf.DeleteProxySecurityGroupRules(ctx, client, containerName, k.RemoveWhitelistSecurityRules, &wlParams); err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "cannot delete security rules", "name", names.AppName, "rootlb", rootLBName, "error", err)
		}
		if !app.InternalPorts {
			// Clean up DNS entries
			configs := append(app.Configs, appInst.Configs...)
			aac, err := access.GetAppAccessConfig(ctx, configs, app.TemplateDelimiter)
			if err != nil {
				return err
			}
			if err := k.commonPf.DeleteAppDNS(ctx, client, names, aac.DnsOverride); err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cannot clean up DNS entries", "name", names.AppName, "rootlb", rootLBName, "error", err)
			}
		}

		if deployment == cloudcommon.DeploymentTypeKubernetes {
			err = k8smgmt.DeleteAppInst(ctx, client, names, app, appInst)
		} else {
			err = k8smgmt.DeleteHelmAppInst(ctx, client, names, clusterInst)
		}
		if err != nil {
			return err
		}
		if appInst.DedicatedIp {
			externalDev := k.GetExternalEthernetInterface()
			err := k.RemoveIp(ctx, client, ipaddr, externalDev, rootLBName)
			if err != nil {
				return err
			}
			if err = k.commonPf.DeleteDNSRecords(ctx, rootLBName); err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete DNS record", "fqdn", rootLBName, "err", err)
			}
		}
	default:
		return fmt.Errorf("unsupported deployment type for BareMetal %s", deployment)
	}
	return nil
}

func (k *K8sBareMetalPlatform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, appInstFlavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateAppInst", "appInst", appInst)

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return fmt.Errorf("get kube names failed: %s", err)
	}
	client, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
	if err != nil {
		return err
	}
	return k8smgmt.UpdateAppInst(ctx, k.commonPf.PlatformConfig.AccessApi, client, names, app, appInst, appInstFlavor)
}

func (k *K8sBareMetalPlatform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAppInstRuntime", "app", app)

	client, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: k.commonPf.PlatformConfig.CloudletKey.String(), Type: k8sControlHostNodeType})
	if err != nil {
		return nil, err
	}
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return nil, err
	}
	return k8smgmt.GetAppInstRuntime(ctx, client, names, app, appInst)
}

func (k *K8sBareMetalPlatform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetContainerCommand", "app", app)
	return k8smgmt.GetContainerCommand(ctx, clusterInst, app, appInst, req)
}
