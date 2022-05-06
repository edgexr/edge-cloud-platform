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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-infra/chefmgmt"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/crmutil"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	proxycerts "github.com/edgexr/edge-cloud/cloud-resource-manager/proxy/certs"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

const (
	MexSubnetPrefix = "mex-k8s-subnet-"

	ActionAdd                      = "add"
	ActionRemove                   = "remove"
	ActionNone                     = "none"
	cleanupClusterRetryWaitSeconds = 60
	updateClusterSetupMaxTime      = time.Minute * 15
)

//ClusterNodeFlavor contains details of flavor for the node
type ClusterNodeFlavor struct {
	Type string
	Name string
}

//ClusterFlavor contains definitions of cluster flavor
type ClusterFlavor struct {
	Kind           string
	Name           string
	PlatformFlavor string
	Status         string
	NumNodes       int
	MaxNodes       int
	NumMasterNodes int
	NetworkSpec    string
	StorageSpec    string
	NodeFlavor     ClusterNodeFlavor
	Topology       string
}

var MaxDockerVmWait = 2 * time.Minute

func GetClusterSubnetName(ctx context.Context, clusterInst *edgeproto.ClusterInst) string {
	return MexSubnetPrefix + k8smgmt.GetCloudletClusterName(&clusterInst.Key)
}

func GetClusterMasterName(ctx context.Context, clusterInst *edgeproto.ClusterInst) string {
	namePrefix := ClusterTypeKubernetesMasterLabel
	if clusterInst.Deployment == cloudcommon.DeploymentTypeDocker {
		namePrefix = ClusterTypeDockerVMLabel
	}
	return namePrefix + "-" + k8smgmt.GetCloudletClusterName(&clusterInst.Key)
}

// GetClusterMasterNameFromNodeList is used instead of GetClusterMasterName when getting the actual master name from
// a running cluster, because the name can get truncated if it is too long
func GetClusterMasterNameFromNodeList(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetClusterMasterNameFromNodeList")
	kconfName := k8smgmt.GetKconfName(clusterInst)
	cmd := fmt.Sprintf("KUBECONFIG=%s kubectl get nodes --no-headers -l node-role.kubernetes.io/master -o custom-columns=Name:.metadata.name", kconfName)
	out, err := client.Output(cmd)
	if err != nil {
		return "", err
	}
	nodes := strings.Split(strings.TrimSpace(out), "\n")
	if len(nodes) > 0 {
		return nodes[0], nil
	}
	return "", fmt.Errorf("unable to find cluster master")
}

func GetClusterNodeName(ctx context.Context, clusterInst *edgeproto.ClusterInst, nodeNum uint32) string {
	return ClusterNodePrefix(nodeNum) + "-" + k8smgmt.GetCloudletClusterName(&clusterInst.Key)
}

func (v *VMPlatform) GetDockerNodeName(ctx context.Context, clusterInst *edgeproto.ClusterInst) string {
	return ClusterTypeDockerVMLabel + "-" + k8smgmt.GetCloudletClusterName(&clusterInst.Key)
}

func ClusterNodePrefix(num uint32) string {
	return fmt.Sprintf("%s%d", cloudcommon.MexNodePrefix, num)
}

func ParseClusterNodePrefix(name string) (bool, uint32) {
	reg := regexp.MustCompile("^" + cloudcommon.MexNodePrefix + "(\\d+).*")
	matches := reg.FindSubmatch([]byte(name))
	if matches == nil || len(matches) < 2 {
		return false, 0
	}
	num, _ := strconv.Atoi(string(matches[1]))
	return true, uint32(num)
}

func (v *VMPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	lbName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
	client, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "get cloudlet base image")
	imgName, err := v.GetCloudletImageToUse(ctx, updateCallback)
	if err != nil {
		log.InfoLog("error with cloudlet base image", "imgName", imgName, "error", err)
		return err
	}
	return v.updateClusterInternal(ctx, client, lbName, imgName, clusterInst, updateCallback)
}

func (v *VMPlatform) updateClusterInternal(ctx context.Context, client ssh.Client, rootLBName, imgName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (reterr error) {
	updateCallback(edgeproto.UpdateTask, "Updating Cluster Resources")
	start := time.Now()

	chefUpdateInfo := make(map[string]string)
	masterTaintAction := k8smgmt.NoScheduleMasterTaintNone
	masterNodeName, err := GetClusterMasterNameFromNodeList(ctx, client, clusterInst)
	if err != nil {
		return err
	}
	if clusterInst.Deployment == cloudcommon.DeploymentTypeKubernetes {
		// if removing nodes, need to tell kubernetes that nodes are
		// going away forever so that tolerating pods can be migrated
		// off immediately.
		kconfName := k8smgmt.GetKconfName(clusterInst)
		cmd := fmt.Sprintf("KUBECONFIG=%s kubectl get nodes --no-headers -o custom-columns=Name:.metadata.name", kconfName)
		out, err := client.Output(cmd)
		if err != nil {
			return err
		}
		allnodes := strings.Split(strings.TrimSpace(out), "\n")
		toRemove := []string{}
		numExistingMaster := uint32(0)
		numExistingNodes := uint32(0)
		for _, n := range allnodes {
			if !strings.HasPrefix(n, cloudcommon.MexNodePrefix) {
				// skip master
				numExistingMaster++
				continue
			}
			ok, num := ParseClusterNodePrefix(n)
			if !ok {
				log.SpanLog(ctx, log.DebugLevelInfra, "unable to parse node name, ignoring", "name", n)
				continue
			}
			numExistingNodes++
			nodeName := GetClusterNodeName(ctx, clusterInst, num)
			// heat will remove the higher-numbered nodes
			if num > clusterInst.NumNodes {
				toRemove = append(toRemove, n)
				chefUpdateInfo[nodeName] = ActionRemove
			} else {
				chefUpdateInfo[nodeName] = ActionNone
			}
		}
		if len(toRemove) > 0 {
			if clusterInst.NumNodes == 0 {
				// We are removing all the nodes. Remove the master taint before deleting the node so the pods can migrate immediately
				err = k8smgmt.SetMasterNoscheduleTaint(ctx, client, masterNodeName, k8smgmt.GetKconfName(clusterInst), k8smgmt.NoScheduleMasterTaintRemove)
				if err != nil {
					return err
				}
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "delete nodes", "toRemove", toRemove)
			err = k8smgmt.DeleteNodes(ctx, client, kconfName, toRemove)
			if err != nil {
				return err
			}
		}
		for nn := uint32(1); nn <= clusterInst.NumNodes; nn++ {
			nodeName := GetClusterNodeName(ctx, clusterInst, nn)
			if _, ok := chefUpdateInfo[nodeName]; !ok {
				chefUpdateInfo[nodeName] = ActionAdd
			}
		}
		if numExistingMaster == clusterInst.NumMasters && numExistingNodes == clusterInst.NumNodes {
			// nothing changing
			log.SpanLog(ctx, log.DebugLevelInfra, "no change in nodes", "ClusterInst", clusterInst.Key, "numExistingMaster", numExistingMaster, "numExistingNodes", numExistingNodes)
			return nil
		}
		if clusterInst.NumNodes > 0 && numExistingNodes == 0 {
			// we are adding one or more nodes and there was previously none.  Add the taint to master after we do orchestration.
			// Note the case of removing the master taint is done earlier
			masterTaintAction = k8smgmt.NoScheduleMasterTaintAdd
		}
	}
	vmgp, err := v.PerformOrchestrationForCluster(ctx, imgName, clusterInst, ActionUpdate, chefUpdateInfo, updateCallback)
	if err != nil {
		return err
	}
	err = v.setupClusterRootLBAndNodes(ctx, rootLBName, clusterInst, updateCallback, start, updateClusterSetupMaxTime, vmgp, ActionUpdate)
	if err != nil {
		return err
	}
	// now that all nodes are back, update master taint if needed
	if masterTaintAction != k8smgmt.NoScheduleMasterTaintNone {
		err = k8smgmt.SetMasterNoscheduleTaint(ctx, client, masterNodeName, k8smgmt.GetKconfName(clusterInst), masterTaintAction)
		if err != nil {
			return err
		}
	}
	return nil
}

//DeleteCluster deletes kubernetes cluster
func (v *VMPlatform) deleteCluster(ctx context.Context, rootLBName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting kubernetes cluster", "clusterInst", clusterInst)

	chefClient := v.VMProperties.GetChefClient()
	if chefClient == nil {
		return fmt.Errorf("Chef client is not initialzied")
	}

	name := k8smgmt.GetCloudletClusterName(&clusterInst.Key)

	dedicatedRootLB := clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED
	client, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		if strings.Contains(err.Error(), ServerDoesNotExistError) || strings.Contains(err.Error(), ServerIPNotFound) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Dedicated RootLB is gone or has no IP, allow stack delete to proceed", "err", err)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "Error in getting platform client", "err", err)
			return err
		}
	}
	if !dedicatedRootLB && client != nil {
		clusterSnName := GetClusterSubnetName(ctx, clusterInst)
		ip, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), clusterSnName, rootLBName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "unable to get ips from server, proceed with VM deletion", "err", err)
		} else {
			err = v.DetachAndDisableRootLBInterface(ctx, client, rootLBName, clusterSnName, GetPortName(rootLBName, clusterSnName), ip.InternalAddr)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "unable to detach rootLB interface, proceed with VM deletion", "err", err)
			}
		}
	}
	err = v.VMProvider.DeleteVMs(ctx, name)
	if err != nil && err.Error() != ServerDoesNotExistError {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs failed", "name", name, "err", err)
		return err

	}

	if dedicatedRootLB {
		// Delete FQDN of dedicated RootLB
		if err = v.VMProperties.CommonPf.DeleteDNSRecords(ctx, rootLBName); err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete DNS record", "fqdn", rootLBName, "err", err)
		}
	} else {
		// cleanup manifest config dir
		if clusterInst.Deployment == cloudcommon.DeploymentTypeKubernetes || clusterInst.Deployment == cloudcommon.DeploymentTypeHelm {
			if client != nil {
				err = k8smgmt.CleanupClusterConfig(ctx, client, clusterInst)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "cleanup cluster config failed", "err", err)
				}
			}
			// cleanup GPU operator helm configs
			if clusterInst.OptRes == "gpu" && v.VMProvider.GetGPUSetupStage(ctx) == ClusterInstStage {
				err = CleanupGPUOperatorConfigs(ctx, client)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "failed to cleanup GPU operator configs", "err", err)
				}
			}
		}
	}

	// Delete Chef configs
	clientName := ""
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		// Dedicated RootLB
		clientName = v.GetChefClientName(v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst))
		err = chefmgmt.ChefClientDelete(ctx, chefClient, clientName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete client from Chef Server", "clientName", clientName, "err", err)
		}
	}
	if clusterInst.Deployment == cloudcommon.DeploymentTypeDocker {
		// Docker node
		clientName = v.GetChefClientName(v.GetDockerNodeName(ctx, clusterInst))
		err = chefmgmt.ChefClientDelete(ctx, chefClient, clientName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete client from Chef Server", "clientName", clientName, "err", err)
		}
	} else {
		// Master node
		clientName = v.GetChefClientName(GetClusterMasterName(ctx, clusterInst))
		err = chefmgmt.ChefClientDelete(ctx, chefClient, clientName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete client from Chef Server", "clientName", clientName, "err", err)
		}
		for nn := uint32(1); nn <= clusterInst.NumNodes; nn++ {
			// Worker node
			clientName = v.GetChefClientName(GetClusterNodeName(ctx, clusterInst, nn))
			err = chefmgmt.ChefClientDelete(ctx, chefClient, clientName)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete client from Chef Server", "clientName", clientName, "err", err)
			}
		}
	}

	if dedicatedRootLB {
		DeleteServerIpFromCache(ctx, rootLBName)
	}
	return nil
}

func (v *VMPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	lbName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateClusterInst", "clusterInst", clusterInst, "lbName", lbName)

	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	//find the flavor and check the disk size
	for _, flavor := range v.FlavorList {
		if flavor.Name == clusterInst.NodeFlavor && flavor.Disk < MINIMUM_DISK_SIZE && clusterInst.ExternalVolumeSize < MINIMUM_DISK_SIZE {
			log.SpanLog(ctx, log.DebugLevelInfra, "flavor disk size too small", "flavor", flavor, "ExternalVolumeSize", clusterInst.ExternalVolumeSize)
			return fmt.Errorf("Insufficient disk size, please specify a flavor with at least %dgb", MINIMUM_DISK_SIZE)
		}
	}

	//adjust the timeout just a bit to give some buffer for the API exchange and also sleep loops
	timeout -= time.Minute

	log.SpanLog(ctx, log.DebugLevelInfra, "verify if cloudlet base image exists")
	imgName, err := v.GetCloudletImageToUse(ctx, updateCallback)
	if err != nil {
		log.InfoLog("error with cloudlet base image", "imgName", imgName, "error", err)
		return err
	}
	return v.createClusterInternal(ctx, lbName, imgName, clusterInst, updateCallback, timeout)
}

func (v *VMPlatform) cleanupClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "cleanupClusterInst", "clusterInst", clusterInst)

	updateCallback(edgeproto.UpdateTask, "Cleaning up cluster instance")
	rootLBName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
	// try at least one cleanup attempt, plus the number of retries specified by the provider
	var err error
	for tryNum := 0; tryNum <= v.VMProperties.NumCleanupRetries; tryNum++ {
		err = v.deleteCluster(ctx, rootLBName, clusterInst, updateCallback)
		if err == nil {
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to cleanup cluster", "clusterInst", clusterInst, "tryNum", tryNum, "retries", v.VMProperties.NumCleanupRetries, "err", err)
		if tryNum < v.VMProperties.NumCleanupRetries {
			log.SpanLog(ctx, log.DebugLevelInfra, "sleeping and retrying cleanup", "cleanupRetryWaitSeconds", cleanupClusterRetryWaitSeconds)
			time.Sleep(time.Second * cleanupClusterRetryWaitSeconds)
			updateCallback(edgeproto.UpdateTask, "Retrying cleanup")
		}
	}
	v.VMProperties.CommonPf.PlatformConfig.NodeMgr.Event(ctx, "Failed to clean up cluster", clusterInst.Key.Organization, clusterInst.Key.GetTags(), err)
	return fmt.Errorf("Failed to cleanup cluster - %v", err)
}

func (v *VMPlatform) createClusterInternal(ctx context.Context, rootLBName string, imgName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (reterr error) {
	// clean-up func
	defer func() {
		if reterr == nil {
			return
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "error in CreateCluster", "err", reterr)
		if !clusterInst.SkipCrmCleanupOnFailure {
			delerr := v.cleanupClusterInst(ctx, clusterInst, updateCallback)
			if delerr != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cleanupCluster failed", "err", delerr)
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "skipping cleanup on failure")
		}
	}()

	start := time.Now()
	log.SpanLog(ctx, log.DebugLevelInfra, "creating cluster instance", "clusterInst", clusterInst, "timeout", timeout)

	var err error
	vmgp, err := v.PerformOrchestrationForCluster(ctx, imgName, clusterInst, ActionCreate, nil, updateCallback)
	if err != nil {
		return fmt.Errorf("Cluster VM create Failed: %v", err)
	}

	return v.setupClusterRootLBAndNodes(ctx, rootLBName, clusterInst, updateCallback, start, timeout, vmgp, ActionCreate)
}

func (vp *VMProperties) GetSharedCommonSubnetName() string {
	return vp.SharedRootLBName + "-common-internal"
}

func (v *VMPlatform) setupClusterRootLBAndNodes(ctx context.Context, rootLBName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, start time.Time, timeout time.Duration, vmgp *VMGroupOrchestrationParams, action ActionType) (reterr error) {
	client, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return fmt.Errorf("can't get rootLB client, %v", err)
	}

	if action == ActionCreate {
		if v.VMProperties.GetCloudletExternalRouter() == NoExternalRouter {
			if clusterInst.Deployment == cloudcommon.DeploymentTypeKubernetes ||
				(clusterInst.Deployment == cloudcommon.DeploymentTypeDocker) {
				log.SpanLog(ctx, log.DebugLevelInfra, "Need to attach internal interface on rootlb", "IpAccess", clusterInst.IpAccess, "deployment", clusterInst.Deployment)

				// after vm creation, the orchestrator will update some fields in the group params including gateway IP.
				// this IP is used on the rootLB to server as the GW for this new subnet
				subnetName := GetClusterSubnetName(ctx, clusterInst)
				gw, err := v.GetSubnetGatewayFromVMGroupParms(ctx, subnetName, vmgp)
				if err != nil {
					return err
				}
				if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_SHARED && v.VMProperties.UsesCommonSharedInternalLBNetwork {
					subnetName = v.VMProperties.GetSharedCommonSubnetName()
				}
				attachPort := true
				if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED && v.VMProvider.GetInternalPortPolicy() == AttachPortDuringCreate {
					attachPort = false
				}
				_, err = v.AttachAndEnableRootLBInterface(ctx, client, rootLBName, attachPort, subnetName, GetPortName(rootLBName, subnetName), gw, action)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "AttachAndEnableRootLBInterface failed", "err", err)
					return err
				}
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "No internal interface on rootlb", "IpAccess", clusterInst.IpAccess, "deployment", clusterInst.Deployment)
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "External router in use, no internal interface for rootlb")
		}
	}

	// the root LB was created as part of cluster creation, but it needs to be prepped
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		log.SpanLog(ctx, log.DebugLevelInfra, "new dedicated rootLB", "IpAccess", clusterInst.IpAccess)
		updateCallback(edgeproto.UpdateTask, "Setting Up Root LB")
		TrustPolicy := edgeproto.TrustPolicy{}
		err := v.SetupRootLB(ctx, rootLBName, rootLBName, &clusterInst.Key.CloudletKey, &TrustPolicy, updateCallback)
		if err != nil {
			return err
		}
	}

	if clusterInst.Deployment == cloudcommon.DeploymentTypeKubernetes {
		elapsed := time.Since(start)
		// subtract elapsed time from total time to get remaining time
		timeout -= elapsed
		updateCallback(edgeproto.UpdateTask, "Waiting for Cluster to Initialize")
		k8sTime := time.Now()
		masterIP, err := v.waitClusterReady(ctx, clusterInst, rootLBName, updateCallback, timeout)
		if err != nil {
			return err
		}
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Wait Cluster Complete time: %s", cloudcommon.FormatDuration(time.Since(k8sTime), 2)))
		updateCallback(edgeproto.UpdateTask, "Creating config map")

		if err := infracommon.CreateClusterConfigMap(ctx, client, clusterInst); err != nil {
			return err
		}
		if v.VMProperties.GetUsesMetalLb() {
			lbIpRange, err := v.VMProperties.GetMetalLBIp3rdOctetRangeFromMasterIp(ctx, masterIP)
			if err != nil {
				return err
			}
			if err := infracommon.InstallAndConfigMetalLbIfNotInstalled(ctx, client, clusterInst, lbIpRange); err != nil {
				return err
			}
		}
	} else if clusterInst.Deployment == cloudcommon.DeploymentTypeDocker {
		// ensure the docker node is ready before calling the cluster create done
		updateCallback(edgeproto.UpdateTask, "Waiting for Docker VM to Initialize")

		nodeClient, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeClusterVM)
		if err != nil {
			return err
		}
		vmName := GetClusterMasterName(ctx, clusterInst)
		err = WaitServerReady(ctx, v.VMProvider, nodeClient, vmName, MaxDockerVmWait)
		if err != nil {
			return err
		}
	}

	if clusterInst.OptRes == "gpu" {
		if v.VMProvider.GetGPUSetupStage(ctx) == ClusterInstStage {
			// setup GPU drivers
			err = v.setupGPUDrivers(ctx, client, clusterInst, updateCallback, action)
			if err != nil {
				return fmt.Errorf("failed to install GPU drivers on cluster VM: %v", err)
			}
			if clusterInst.Deployment == cloudcommon.DeploymentTypeKubernetes {
				// setup GPU operator helm repo
				v.manageGPUOperator(ctx, client, clusterInst, updateCallback, action)
			}
		} else {
			updateCallback(edgeproto.UpdateTask, "Skip setting up GPU driver on Cluster nodes")
		}
	}

	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		proxycerts.SetupTLSCerts(ctx, &clusterInst.Key.CloudletKey, rootLBName, client, v.VMProperties.CommonPf.PlatformConfig.NodeMgr)
	}

	for _, vmp := range vmgp.VMs {
		if len(vmp.Routes) == 0 {
			continue
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Adding additional route", "vm", vmp.Name)
		vmClient := client
		if vmp.Role != RoleAgent {
			nodeIp, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), vmp.Name)
			if err != nil {
				return err
			}
			vmClient, err = client.AddHop(nodeIp.ExternalAddr, 22)
			if err != nil {
				return err
			}
		}
		for netname, rs := range vmp.Routes {
			routeNetIp, err := v.GetIPFromServerName(ctx, netname, "", vmp.Name)
			if err != nil {
				return fmt.Errorf("Unable to find IP for network: %s - %v", netname, err)
			}
			for _, r := range rs {
				interfaceName := v.GetInterfaceNameForMac(ctx, vmClient, routeNetIp.MacAddress)
				if interfaceName == "" {
					log.SpanLog(ctx, log.DebugLevelInfra, "Unable to find interface name", "routeNetIp", routeNetIp)
					return fmt.Errorf("Unable to find interface name for mac - %s", routeNetIp.MacAddress)
				}
				err = v.VMProperties.AddRouteToServer(ctx, vmClient, vmp.Name, r.DestinationCidr, r.NextHopIp, interfaceName)
				if err != nil {
					return fmt.Errorf("failed to AddRouteToServer for VM: %s network: %s -  %v", vmp.Name, netname, err)
				}
			}
		}
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "created cluster")
	return nil
}

func (v *VMPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	lbName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
	return v.deleteCluster(ctx, lbName, clusterInst, updateCallback)
}

func (v *VMPlatform) GetClusterAccessIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	mip, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
	if err != nil {
		return "", err
	}
	if mip.ExternalAddr == "" {
		return "", fmt.Errorf("unable to find master IP")
	}
	return mip.ExternalAddr, nil
}

func (v *VMPlatform) waitClusterReady(ctx context.Context, clusterInst *edgeproto.ClusterInst, rootLBName string, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (string, error) {
	start := time.Now()
	masterName := ""
	masterIP := ""
	var currReadyCount uint32
	var err error
	log.SpanLog(ctx, log.DebugLevelInfra, "waitClusterReady", "cluster", clusterInst.Key, "timeout", timeout)

	for {
		if masterIP == "" {
			masterIP, err = v.GetClusterAccessIP(ctx, clusterInst)
			if err == nil {
				updateCallback(edgeproto.UpdateStep, "Checking Master for Available Nodes")
			}
		}
		if masterIP == "" {
			log.SpanLog(ctx, log.DebugLevelInfra, "master IP not available yet", "err", err)
		} else {
			ready, readyCount, err := v.isClusterReady(ctx, clusterInst, masterName, masterIP, rootLBName, updateCallback)
			if readyCount != currReadyCount {
				numNodes := readyCount - 1
				updateCallback(edgeproto.UpdateStep, fmt.Sprintf("%d of %d nodes active", numNodes, clusterInst.NumNodes))
			}
			currReadyCount = readyCount
			if err != nil {
				return masterIP, err
			}
			if ready {
				log.SpanLog(ctx, log.DebugLevelInfra, "kubernetes cluster ready")
				return masterIP, nil
			}
			if time.Since(start) > timeout {
				return masterIP, fmt.Errorf("cluster not ready (yet)")
			}
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "waiting for kubernetes cluster to be ready...")
		time.Sleep(30 * time.Second)
	}
}

//IsClusterReady checks to see if cluster is read, i.e. rootLB is running and active.  returns ready,nodecount, error
func (v *VMPlatform) isClusterReady(ctx context.Context, clusterInst *edgeproto.ClusterInst, masterName, masterIP string, rootLBName string, updateCallback edgeproto.CacheUpdateCallback) (bool, uint32, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "checking if cluster is ready", "masterIP", masterIP)

	// some commands are run on the rootlb and some on the master directly, so we use separate clients
	rootLBClient, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return false, 0, fmt.Errorf("can't get rootlb ssh client for cluster ready check, %v", err)
	}
	// masterClient is to run commands on the master
	masterClient, err := rootLBClient.AddHop(masterIP, 22)
	if err != nil {
		return false, 0, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "checking master k8s node for available nodes", "ipaddr", masterIP)
	cmd := "kubectl get nodes"
	out, err := masterClient.Output(cmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error checking for kubernetes nodes", "out", out, "err", err)
		return false, 0, nil //This is intentional
	}
	//                   node       state               role     age     version
	nodeMatchPattern := "(\\S+)\\s+(Ready|NotReady)\\s+(\\S+)\\s+\\S+\\s+\\S+"
	reg, err := regexp.Compile(nodeMatchPattern)
	if err != nil {
		// this is a bug if the regex does not compile
		log.SpanLog(ctx, log.DebugLevelInfo, "failed to compile regex", "pattern", nodeMatchPattern)
		return false, 0, fmt.Errorf("Internal Error compiling regex for k8s node")
	}
	masterString := ""
	lines := strings.Split(out, "\n")
	var readyCount uint32
	var notReadyCount uint32
	for _, l := range lines {
		if reg.MatchString(l) {
			matches := reg.FindStringSubmatch(l)
			nodename := matches[1]
			state := matches[2]
			role := matches[3]

			if role == "master" {
				masterString = nodename
			}
			if state == "Ready" {
				readyCount++
			} else {
				notReadyCount++
			}
		}
	}
	if readyCount < (clusterInst.NumNodes + clusterInst.NumMasters) {
		log.SpanLog(ctx, log.DebugLevelInfra, "kubernetes cluster not ready", "readyCount", readyCount, "notReadyCount", notReadyCount)
		return false, readyCount, nil
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "cluster nodes ready", "numnodes", clusterInst.NumNodes, "nummasters", clusterInst.NumMasters, "readyCount", readyCount, "notReadyCount", notReadyCount)

	if err := infracommon.CopyKubeConfig(ctx, rootLBClient, clusterInst, rootLBName, masterIP); err != nil {
		return false, 0, fmt.Errorf("kubeconfig copy failed, %v", err)
	}
	if clusterInst.NumNodes == 0 {
		// Untaint the master.  Note in the update case this has already been done when going from >0 nodes to 0 prior to node deletion but
		// for the create case this is the earliest it can be done
		err = k8smgmt.SetMasterNoscheduleTaint(ctx, rootLBClient, masterString, k8smgmt.GetKconfName(clusterInst), k8smgmt.NoScheduleMasterTaintRemove)
		if err != nil {
			return false, 0, err
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "cluster ready.")
	return true, readyCount, nil
}

func (v *VMPlatform) GetChefClusterTags(key *edgeproto.ClusterInstKey, nodeType cloudcommon.NodeType) []string {
	region := v.VMProperties.GetRegion()
	deploymentTag := v.VMProperties.GetDeploymentTag()
	return []string{
		"deploytag/" + deploymentTag,
		"cluster/" + key.ClusterKey.Name,
		"clusterorg/" + key.Organization,
		"cloudlet/" + key.CloudletKey.Name,
		"cloudletorg/" + key.CloudletKey.Organization,
		"region/" + region,
		"nodetype/" + nodeType.String(),
	}
}

func (v *VMPlatform) getVMRequestSpecForDockerCluster(ctx context.Context, imgName string, clusterInst *edgeproto.ClusterInst, action ActionType, lbNets, nodeNets map[string]NetworkType, lbRoutes, nodeRoutes map[string][]edgeproto.Route, updateCallback edgeproto.CacheUpdateCallback) ([]*VMRequestSpec, string, string, error) {

	log.SpanLog(ctx, log.DebugLevelInfo, "getVMRequestSpecForDockerCluster", "clusterInst", clusterInst)

	var vms []*VMRequestSpec
	var newSecgrpName string
	dockerVmName := v.GetDockerNodeName(ctx, clusterInst)
	newSubnetName := GetClusterSubnetName(ctx, clusterInst)

	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		tags := v.GetChefClusterTags(&clusterInst.Key, cloudcommon.NodeTypeDedicatedRootLB)
		rootlb, err := v.GetVMSpecForRootLB(ctx, v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst), newSubnetName, tags, lbNets, lbRoutes, updateCallback)
		if err != nil {
			return vms, newSubnetName, newSecgrpName, err
		}
		vms = append(vms, rootlb)
		newSecgrpName = infracommon.GetServerSecurityGroupName(rootlb.Name)
	} else {

		log.SpanLog(ctx, log.DebugLevelInfo, "creating shared rootlb port")
		// shared access means docker vm goes on its own subnet which is connected
		// via shared rootlb
		if v.VMProperties.GetCloudletExternalRouter() == NoExternalRouter {
			// If no router in use, create ports on the existing shared rootLB
			rootlb, err := v.GetVMSpecForSharedRootLBPorts(ctx, v.VMProperties.SharedRootLBName, newSubnetName)
			if err != nil {
				return vms, newSubnetName, newSecgrpName, err
			}
			vms = append(vms, rootlb)
		}
	}
	chefAttributes := make(map[string]interface{})
	chefAttributes["tags"] = v.GetChefClusterTags(&clusterInst.Key, cloudcommon.NodeTypeDockerClusterNode)
	clientName := v.GetChefClientName(dockerVmName)
	chefParams := v.GetServerChefParams(clientName, "", chefmgmt.ChefPolicyBase, chefAttributes)
	dockervm, err := v.GetVMRequestSpec(
		ctx,
		cloudcommon.NodeTypeDockerClusterNode,
		dockerVmName,
		clusterInst.NodeFlavor,
		imgName,
		false,
		WithExternalVolume(clusterInst.ExternalVolumeSize),
		WithSubnetConnection(newSubnetName),
		WithChefParams(chefParams),
		WithOptionalResource(clusterInst.OptRes),
		WithComputeAvailabilityZone(clusterInst.AvailabilityZone),
		WithAdditionalNetworks(nodeNets),
		WithRoutes(nodeRoutes),
	)
	if err != nil {
		return vms, newSubnetName, newSecgrpName, err
	}
	vms = append(vms, dockervm)
	return vms, newSubnetName, newSecgrpName, nil
}

func (v *VMPlatform) PerformOrchestrationForCluster(ctx context.Context, imgName string, clusterInst *edgeproto.ClusterInst, action ActionType, updateInfo map[string]string, updateCallback edgeproto.CacheUpdateCallback) (*VMGroupOrchestrationParams, error) {
	log.SpanLog(ctx, log.DebugLevelInfo, "PerformOrchestrationForCluster", "clusterInst", clusterInst, "action", action)

	var vms []*VMRequestSpec
	var err error
	vmgroupName := k8smgmt.GetCloudletClusterName(&clusterInst.Key)
	var newSubnetName string
	var newSecgrpName string

	networks, err := crmutil.GetNetworksForClusterInst(ctx, clusterInst, v.Caches.NetworkCache)
	if err != nil {
		return nil, err
	}
	lbNets := make(map[string]NetworkType)
	nodeNets := make(map[string]NetworkType)
	lbRoutes := make(map[string][]edgeproto.Route)
	nodeRoutes := make(map[string][]edgeproto.Route)
	for _, n := range networks {
		switch n.ConnectionType {
		case edgeproto.NetworkConnectionType_CONNECT_TO_LOAD_BALANCER:
			lbNets[n.Key.Name] = NetworkTypeExternalAdditionalRootLb
			lbRoutes[n.Key.Name] = append(lbRoutes[n.Key.Name], n.Routes...)
		case edgeproto.NetworkConnectionType_CONNECT_TO_CLUSTER_NODES:
			nodeNets[n.Key.Name] = NetworkTypeExternalAdditionalClusterNode
			nodeRoutes[n.Key.Name] = append(nodeRoutes[n.Key.Name], n.Routes...)
		case edgeproto.NetworkConnectionType_CONNECT_TO_ALL:
			lbNets[n.Key.Name] = NetworkTypeExternalAdditionalRootLb
			nodeNets[n.Key.Name] = NetworkTypeExternalAdditionalClusterNode
			lbRoutes[n.Key.Name] = append(lbRoutes[n.Key.Name], n.Routes...)
			nodeRoutes[n.Key.Name] = append(nodeRoutes[n.Key.Name], n.Routes...)
		}
	}

	if clusterInst.Deployment == cloudcommon.DeploymentTypeDocker {
		vms, newSubnetName, newSecgrpName, err = v.getVMRequestSpecForDockerCluster(ctx, imgName, clusterInst, action, lbNets, nodeNets, lbRoutes, nodeRoutes, updateCallback)
		if err != nil {
			return nil, err
		}
	} else {
		pfImage, err := v.GetCloudletImageToUse(ctx, updateCallback)
		if err != nil {
			return nil, err
		}
		newSubnetName = GetClusterSubnetName(ctx, clusterInst)
		var rootlb *VMRequestSpec
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			// dedicated for docker means the docker VM acts as its own rootLB
			tags := v.GetChefClusterTags(&clusterInst.Key, cloudcommon.NodeTypeDedicatedRootLB)
			rootlb, err = v.GetVMSpecForRootLB(ctx, v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst), newSubnetName, tags, lbNets, lbRoutes, updateCallback)
			if err != nil {
				return nil, err
			}
			vms = append(vms, rootlb)
			newSecgrpName = infracommon.GetServerSecurityGroupName(rootlb.Name)
		} else if v.VMProperties.GetCloudletExternalRouter() == NoExternalRouter {
			// If no router in use, create ports on the existing shared rootLB
			rootlb, err = v.GetVMSpecForSharedRootLBPorts(ctx, v.VMProperties.SharedRootLBName, newSubnetName)
			if err != nil {
				return nil, err
			}
			vms = append(vms, rootlb)
		}

		chefAttributes := make(map[string]interface{})
		chefAttributes["tags"] = v.GetChefClusterTags(&clusterInst.Key, cloudcommon.NodeTypeK8sClusterMaster)

		clientName := v.GetChefClientName(GetClusterMasterName(ctx, clusterInst))
		chefParams := v.GetServerChefParams(clientName, "", chefmgmt.ChefPolicyBase, chefAttributes)

		masterFlavor := clusterInst.MasterNodeFlavor
		if masterFlavor == "" {
			masterFlavor = clusterInst.NodeFlavor
		}
		masterAZ := ""
		if clusterInst.NumNodes == 0 {
			// master is used for workloads
			masterAZ = clusterInst.AvailabilityZone
		}
		master, err := v.GetVMRequestSpec(ctx,
			cloudcommon.NodeTypeK8sClusterMaster,
			GetClusterMasterName(ctx, clusterInst),
			masterFlavor,
			pfImage,
			false, //connect external
			WithSharedVolume(clusterInst.SharedVolumeSize),
			WithExternalVolume(clusterInst.ExternalVolumeSize),
			WithSubnetConnection(newSubnetName),
			WithChefParams(chefParams),
			WithComputeAvailabilityZone(masterAZ),
		)
		if err != nil {
			return nil, err
		}
		vms = append(vms, master)

		chefAttributes = make(map[string]interface{})
		chefAttributes["tags"] = v.GetChefClusterTags(&clusterInst.Key, cloudcommon.NodeTypeK8sClusterNode)
		for nn := uint32(1); nn <= clusterInst.NumNodes; nn++ {
			clientName := v.GetChefClientName(GetClusterNodeName(ctx, clusterInst, nn))
			chefParams := v.GetServerChefParams(clientName, "", chefmgmt.ChefPolicyBase, chefAttributes)
			node, err := v.GetVMRequestSpec(ctx,
				cloudcommon.NodeTypeK8sClusterNode,
				GetClusterNodeName(ctx, clusterInst, nn),
				clusterInst.NodeFlavor,
				pfImage,
				false, //connect external
				WithExternalVolume(clusterInst.ExternalVolumeSize),
				WithSubnetConnection(newSubnetName),
				WithChefParams(chefParams),
				WithComputeAvailabilityZone(clusterInst.AvailabilityZone),
				WithAdditionalNetworks(nodeNets),
				WithRoutes(nodeRoutes),
			)
			if err != nil {
				return nil, err
			}
			vms = append(vms, node)
		}
	}
	return v.OrchestrateVMsFromVMSpec(ctx,
		vmgroupName,
		vms,
		action,
		updateCallback,
		WithNewSubnet(newSubnetName),
		WithNewSecurityGroup(newSecgrpName),
		WithChefUpdateInfo(updateInfo),
		WithSkipCleanupOnFailure(clusterInst.SkipCrmCleanupOnFailure),
	)
}
