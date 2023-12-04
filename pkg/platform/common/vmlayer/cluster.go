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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/crmutil"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	proxycerts "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs"
	ssh "github.com/edgexr/golang-ssh"
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

func (v *VMPlatform) GetClusterSubnetName(ctx context.Context, clusterInst *edgeproto.ClusterInst) SubnetNames {
	subnetName := k8smgmt.GetCloudletClusterName(&clusterInst.Key)
	subnetNames := SubnetNames{}
	subnetNames[infracommon.IndexIPV4] = subnetName
	subnetNames[infracommon.IndexIPV6] = subnetName + "-ipv6"
	return subnetNames
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

	nodeUpdateAction := make(map[string]string)
	masterTaintAction := k8smgmt.NoScheduleMasterTaintNone
	var masterNodeName string

	if clusterInst.Deployment == cloudcommon.DeploymentTypeKubernetes {
		var err error
		masterNodeName, err = GetClusterMasterNameFromNodeList(ctx, client, clusterInst)
		if err != nil {
			return err
		}
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
				nodeUpdateAction[nodeName] = ActionRemove
			} else {
				nodeUpdateAction[nodeName] = ActionNone
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
			if _, ok := nodeUpdateAction[nodeName]; !ok {
				nodeUpdateAction[nodeName] = ActionAdd
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
	vmgp, err := v.PerformOrchestrationForCluster(ctx, imgName, clusterInst, ActionUpdate, nodeUpdateAction, updateCallback)
	if err != nil {
		return err
	}
	err = v.setupClusterRootLBAndNodes(ctx, rootLBName, clusterInst, updateCallback, start, updateClusterSetupMaxTime, vmgp, ActionUpdate)
	if err != nil {
		return err
	}
	if clusterInst.Deployment == cloudcommon.DeploymentTypeKubernetes {
		// now that all nodes are back, update master taint if needed
		if masterTaintAction != k8smgmt.NoScheduleMasterTaintNone {
			err = k8smgmt.SetMasterNoscheduleTaint(ctx, client, masterNodeName, k8smgmt.GetKconfName(clusterInst), masterTaintAction)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *VMPlatform) deleteCluster(ctx context.Context, rootLBName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting cluster", "clusterInst", clusterInst)

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
		clusterSnName := v.GetClusterSubnetName(ctx, clusterInst)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "unable to get ips from server, proceed with VM deletion", "err", err)
		} else {
			err = v.DetachAndDisableRootLBInterface(ctx, client, rootLBName, clusterSnName, GetPortNameFromSubnet(rootLBName, clusterSnName))
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

	// Delete CloudletNode configs
	accessApi := v.VMProperties.CommonPf.PlatformConfig.AccessApi
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		// Dedicated RootLB
		nodeName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
		nodeKey := &edgeproto.CloudletNodeKey{
			Name:        nodeName,
			CloudletKey: clusterInst.Key.CloudletKey,
		}
		err = accessApi.DeleteCloudletNode(ctx, nodeKey)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete cloudlet node registration", "name", nodeName, "err", err)
		}
	}
	if clusterInst.Deployment == cloudcommon.DeploymentTypeDocker {
		// Docker node
		nodeName := v.GetDockerNodeName(ctx, clusterInst)
		nodeKey := &edgeproto.CloudletNodeKey{
			Name:        nodeName,
			CloudletKey: clusterInst.Key.CloudletKey,
		}
		err = accessApi.DeleteCloudletNode(ctx, nodeKey)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete cloudlet node registration", "name", nodeName, "err", err)
		}
	} else {
		// Master node
		nodeName := GetClusterMasterName(ctx, clusterInst)
		nodeKey := &edgeproto.CloudletNodeKey{
			Name:        nodeName,
			CloudletKey: clusterInst.Key.CloudletKey,
		}
		err = accessApi.DeleteCloudletNode(ctx, nodeKey)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete cloudlet node registration", "name", nodeName, "err", err)
		}
		for nn := uint32(1); nn <= clusterInst.NumNodes; nn++ {
			// Worker node
			nodeName := GetClusterNodeName(ctx, clusterInst, nn)
			nodeKey := &edgeproto.CloudletNodeKey{
				Name:        nodeName,
				CloudletKey: clusterInst.Key.CloudletKey,
			}
			err = accessApi.DeleteCloudletNode(ctx, nodeKey)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to delete cloudlet node registration", "name", nodeName, "err", err)
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
	v.VMProperties.CommonPf.PlatformConfig.NodeMgr.Event(ctx, "Failed to clean up cluster", clusterInst.Key.ClusterKey.Organization, clusterInst.Key.GetTags(), err)
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

func (vp *VMProperties) GetSharedCommonSubnetName() SubnetNames {
	names := SubnetNames{}
	names[infracommon.IndexIPV4] = vp.SharedRootLBName + "-common-internal"
	names[infracommon.IndexIPV4] = vp.SharedRootLBName + "-common-internal-ipv6"
	return names
}

func (v *VMPlatform) setupClusterRootLBAndNodes(ctx context.Context, rootLBName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, start time.Time, timeout time.Duration, vmgp *VMGroupOrchestrationParams, action ActionType) (reterr error) {
	client, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return fmt.Errorf("can't get rootLB client, %v", err)
	}

	var rootLBDetail *ServerDetail
	if v.VMProperties.GetCloudletExternalRouter() == NoExternalRouter {
		if clusterInst.Deployment == cloudcommon.DeploymentTypeKubernetes ||
			(clusterInst.Deployment == cloudcommon.DeploymentTypeDocker) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Need to attach internal interface on rootlb", "IpAccess", clusterInst.IpAccess, "deployment", clusterInst.Deployment)

			// after vm creation, the orchestrator will update some fields in the group params including gateway IP.
			// this IP is used on the rootLB to server as the GW for this new subnet
			subnetName := v.GetClusterSubnetName(ctx, clusterInst)
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
			rootLBDetail, _, err = v.AttachAndEnableRootLBInterface(ctx, client, rootLBName, attachPort, subnetName, GetPortNameFromSubnet(rootLBName, subnetName), gw, action)
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

	// the root LB was created as part of cluster creation, but it needs to be prepped
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		log.SpanLog(ctx, log.DebugLevelInfra, "new dedicated rootLB", "IpAccess", clusterInst.IpAccess)
		updateCallback(edgeproto.UpdateTask, "Setting Up Root LB")
		TrustPolicy := edgeproto.TrustPolicy{}
		if rootLBDetail == nil {
			rootLBDetail, err = v.VMProvider.GetServerDetail(ctx, rootLBName)
			if err != nil {
				return err
			}
		}
		err := v.SetupRootLB(ctx, rootLBName, rootLBName, &clusterInst.Key.CloudletKey, &TrustPolicy, rootLBDetail, clusterInst.EnableIpv6, updateCallback)
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
		masterIPs, err := v.waitClusterReady(ctx, clusterInst, rootLBName, updateCallback, timeout)
		if err != nil {
			return err
		}
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Wait Cluster Complete time: %s", cloudcommon.FormatDuration(time.Since(k8sTime), 2)))
		updateCallback(edgeproto.UpdateTask, "Creating config map")

		if err := infracommon.CreateClusterConfigMap(ctx, client, clusterInst); err != nil {
			return err
		}
		if v.VMProperties.GetUsesMetalLb() {
			lbIpRange, err := v.VMProperties.GetMetalLBAddresses(ctx, masterIPs)
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
		if clusterInst.EnableIpv6 {
			if err := setupDockerIPV6(ctx, nodeClient); err != nil {
				return err
			}
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
		var sd *ServerDetail
		var err error
		if vmp.Name == rootLBName {
			sd = rootLBDetail
		} else {
			sd, err = v.VMProvider.GetServerDetail(ctx, vmp.Name)
			if err != nil {
				return fmt.Errorf("failed to get server details for %s, %s", vmp.Name, err)
			}
		}
		configNetworks := map[string]struct{}{
			v.VMProperties.GetCloudletMexNetwork(): {},
		}
		defaultRouteNets := map[string]struct{}{}
		if vmp.Name != rootLBName {
			defaultRouteNets[v.VMProperties.GetCloudletMexNetwork()] = struct{}{}
		}
		vmClient := client
		if vmp.Role != RoleAgent {
			nodeIps, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), v.GetClusterSubnetName(ctx, clusterInst), vmp.Name)
			if err != nil {
				return err
			}
			vmClient, err = client.AddHop(nodeIps.IPV4ExternalAddr(), 22)
			if err != nil {
				return err
			}
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Configuring network interfaces", "vm", vmp.Name)
		err = v.ConfigureNetworkInterfaces(ctx, vmClient, sd, configNetworks, defaultRouteNets, vmp.Routes)
		if err != nil {
			return fmt.Errorf("failed to configure network interfaces for vm %s, %s", vmp.Name, err)
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

func (v *VMPlatform) GetClusterAccessIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ServerIPs, error) {
	return v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), v.GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
}

func (v *VMPlatform) waitClusterReady(ctx context.Context, clusterInst *edgeproto.ClusterInst, rootLBName string, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (ServerIPs, error) {
	start := time.Now()
	masterName := ""
	var masterIPs ServerIPs
	var currReadyCount uint32
	var err error
	log.SpanLog(ctx, log.DebugLevelInfra, "waitClusterReady", "cluster", clusterInst.Key, "timeout", timeout)

	for {
		if !masterIPs.IsSet() {
			masterIPs, err = v.GetClusterAccessIP(ctx, clusterInst)
			if err == nil {
				updateCallback(edgeproto.UpdateStep, "Checking Master for Available Nodes")
			}
		}
		if !masterIPs.IsSet() {
			log.SpanLog(ctx, log.DebugLevelInfra, "master IP not available yet", "err", err)
		} else {
			ready, readyCount, err := v.isClusterReady(ctx, clusterInst, masterName, masterIPs, rootLBName, updateCallback)
			if readyCount != currReadyCount {
				numNodes := readyCount - 1
				updateCallback(edgeproto.UpdateStep, fmt.Sprintf("%d of %d nodes active", numNodes, clusterInst.NumNodes))
			}
			currReadyCount = readyCount
			if err != nil {
				return masterIPs, err
			}
			if ready {
				log.SpanLog(ctx, log.DebugLevelInfra, "kubernetes cluster ready")
				return masterIPs, nil
			}
			if time.Since(start) > timeout {
				return masterIPs, fmt.Errorf("cluster not ready (yet)")
			}
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "waiting for kubernetes cluster to be ready...")
		time.Sleep(30 * time.Second)
	}
}

//IsClusterReady checks to see if cluster is read, i.e. rootLB is running and active.  returns ready,nodecount, error
func (v *VMPlatform) isClusterReady(ctx context.Context, clusterInst *edgeproto.ClusterInst, masterName string, masterIPs ServerIPs, rootLBName string, updateCallback edgeproto.CacheUpdateCallback) (bool, uint32, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "checking if cluster is ready", "masterIPs", masterIPs)

	// some commands are run on the rootlb and some on the master directly, so we use separate clients
	rootLBClient, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return false, 0, fmt.Errorf("can't get rootlb ssh client for cluster ready check, %v", err)
	}
	// masterClient is to run commands on the master
	connectMasterIP := masterIPs.IPV4ExternalAddr()
	if connectMasterIP == "" {
		connectMasterIP = masterIPs.IPV6ExternalAddr()
	}
	masterClient, err := rootLBClient.AddHop(connectMasterIP, 22)
	if err != nil {
		return false, 0, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "checking master k8s node for available nodes", "ipaddr", connectMasterIP)
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

	if err := infracommon.CopyKubeConfig(ctx, rootLBClient, clusterInst, rootLBName, connectMasterIP); err != nil {
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

func (v *VMPlatform) getVMRequestSpecForDockerCluster(ctx context.Context, imgName string, clusterInst *edgeproto.ClusterInst, action ActionType, lbNets, nodeNets map[string]NetworkType, lbRoutes, nodeRoutes map[string][]edgeproto.Route, updateCallback edgeproto.CacheUpdateCallback) ([]*VMRequestSpec, SubnetNames, string, error) {

	log.SpanLog(ctx, log.DebugLevelInfo, "getVMRequestSpecForDockerCluster", "clusterInst", clusterInst)

	var vms []*VMRequestSpec
	var newSecgrpName string
	dockerVmName := v.GetDockerNodeName(ctx, clusterInst)
	newSubnetName := v.GetClusterSubnetName(ctx, clusterInst)

	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		rootlb, err := v.GetVMSpecForRootLB(ctx, v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst), newSubnetName, &clusterInst.Key, lbNets, lbRoutes, updateCallback)
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
	dockervm, err := v.GetVMRequestSpec(
		ctx,
		cloudcommon.NodeTypeDockerClusterNode,
		dockerVmName,
		clusterInst.NodeFlavor,
		imgName,
		false,
		WithExternalVolume(clusterInst.ExternalVolumeSize),
		WithSubnetConnection(newSubnetName),
		WithConfigureNodeVars(v, cloudcommon.NodeRoleBase, &clusterInst.Key.CloudletKey, &clusterInst.Key),
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
	var newSubnetName SubnetNames
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
		newSubnetName = v.GetClusterSubnetName(ctx, clusterInst)
		var rootlb *VMRequestSpec
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			// dedicated for docker means the docker VM acts as its own rootLB
			rootlb, err = v.GetVMSpecForRootLB(ctx, v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst), newSubnetName, &clusterInst.Key, lbNets, lbRoutes, updateCallback)
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
			WithConfigureNodeVars(v, cloudcommon.NodeRoleBase, &clusterInst.Key.CloudletKey, &clusterInst.Key),
			WithComputeAvailabilityZone(masterAZ),
		)
		if err != nil {
			return nil, err
		}
		vms = append(vms, master)

		for nn := uint32(1); nn <= clusterInst.NumNodes; nn++ {
			node, err := v.GetVMRequestSpec(ctx,
				cloudcommon.NodeTypeK8sClusterNode,
				GetClusterNodeName(ctx, clusterInst, nn),
				clusterInst.NodeFlavor,
				pfImage,
				false, //connect external
				WithExternalVolume(clusterInst.ExternalVolumeSize),
				WithSubnetConnection(newSubnetName),
				WithConfigureNodeVars(v, cloudcommon.NodeRoleBase, &clusterInst.Key.CloudletKey, &clusterInst.Key),
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
		WithNodeUpdateActions(updateInfo),
		WithSkipCleanupOnFailure(clusterInst.SkipCrmCleanupOnFailure),
		WithEnableIPV6(clusterInst.EnableIpv6),
	)
}

var dockerConf = `{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "20"
  },
  "ipv6": true,
  "fixed-cidr-v6": "fc00:dddd:1::/64",
  "experimental": true,
  "ip6tables": true
}
`

func setupDockerIPV6(ctx context.Context, client ssh.Client) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "setup docker IPv6")
	// enable ipv6 on docker
	_, err := client.Output(`grep ipv6 /etc/docker/daemon.json`)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "docker IPv6 already configured")
		return nil
	}
	err = pc.WriteFile(client, "/etc/docker/daemon.json", dockerConf, "dockerconfig", pc.SudoOn)
	if err != nil {
		return fmt.Errorf("failed to write docker config for ipv6, %s", err)
	}
	out, err := client.Output("sudo systemctl restart docker")
	if err != nil {
		return fmt.Errorf("failed to restart docker service for ipv6, %s, %s", out, err)
	}
	return nil
}
