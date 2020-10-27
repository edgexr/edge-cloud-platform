package vmlayer

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/chefmgmt"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

const (
	MexSubnetPrefix = "mex-k8s-subnet-"

	ActionAdd    = "add"
	ActionRemove = "remove"
	ActionNone   = "none"
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

func (v *VMPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
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
	return v.updateClusterInternal(ctx, client, lbName, imgName, clusterInst, privacyPolicy, updateCallback)
}

func (v *VMPlatform) updateClusterInternal(ctx context.Context, client ssh.Client, rootLBName, imgName string, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback) (reterr error) {
	updateCallback(edgeproto.UpdateTask, "Updating Cluster Resources")
	start := time.Now()

	chefUpdateInfo := make(map[string]string)
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
		numMaster := uint32(0)
		numNodes := uint32(0)
		for _, n := range allnodes {
			if !strings.HasPrefix(n, cloudcommon.MexNodePrefix) {
				// skip master
				numMaster++
				continue
			}
			ok, num := ParseClusterNodePrefix(n)
			if !ok {
				log.SpanLog(ctx, log.DebugLevelInfra, "unable to parse node name, ignoring", "name", n)
				continue
			}
			numNodes++
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
		if numMaster == clusterInst.NumMasters && numNodes == clusterInst.NumNodes {
			// nothing changing
			log.SpanLog(ctx, log.DebugLevelInfra, "no change in nodes", "ClusterInst", clusterInst.Key, "nummaster", numMaster, "numnodes", numNodes)
			return nil
		}
	}
	vmgp, err := v.PerformOrchestrationForCluster(ctx, imgName, clusterInst, privacyPolicy, ActionUpdate, chefUpdateInfo, updateCallback)
	if err != nil {
		return err
	}
	//todo: calculate timeouts instead of hardcoded value
	return v.setupClusterRootLBAndNodes(ctx, rootLBName, clusterInst, updateCallback, start, time.Minute*15, vmgp, privacyPolicy, ActionUpdate)
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
		if strings.Contains(err.Error(), ServerDoesNotExistError) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Dedicated RootLB is gone, allow stack delete to proceed")
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "Error in getting platform client", "err", err)
			return err
		}
	}
	if !dedicatedRootLB {
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
	if err != nil {
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
			err = k8smgmt.CleanupClusterConfig(ctx, client, clusterInst)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cleanup cluster config failed", "err", err)
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
		proxy.RemoveDedicatedCluster(ctx, clusterInst.Key.ClusterKey.Name)
		DeleteServerIpFromCache(ctx, rootLBName)
	}
	return nil
}

func (v *VMPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	lbName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateClusterInst", "clusterInst", clusterInst, "lbName", lbName)

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
	return v.createClusterInternal(ctx, lbName, imgName, clusterInst, privacyPolicy, updateCallback, timeout)
}

func (v *VMPlatform) createClusterInternal(ctx context.Context, rootLBName string, imgName string, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (reterr error) {
	// clean-up func
	defer func() {
		if reterr == nil {
			return
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "error in CreateCluster", "err", reterr)
		if !clusterInst.SkipCrmCleanupOnFailure {
			delerr := v.deleteCluster(ctx, rootLBName, clusterInst, updateCallback)
			if delerr != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "fail to cleanup cluster")
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "skipping cleanup on failure")
		}
	}()

	start := time.Now()
	log.SpanLog(ctx, log.DebugLevelInfra, "creating cluster instance", "clusterInst", clusterInst, "timeout", timeout)

	var err error
	vmgp, err := v.PerformOrchestrationForCluster(ctx, imgName, clusterInst, privacyPolicy, ActionCreate, nil, updateCallback)
	if err != nil {
		return fmt.Errorf("Cluster VM create Failed: %v", err)
	}

	return v.setupClusterRootLBAndNodes(ctx, rootLBName, clusterInst, updateCallback, start, timeout, vmgp, privacyPolicy, ActionCreate)
}

func (v *VMPlatform) setupClusterRootLBAndNodes(ctx context.Context, rootLBName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, start time.Time, timeout time.Duration, vmgp *VMGroupOrchestrationParams, privacyPolicy *edgeproto.PrivacyPolicy, action ActionType) (reterr error) {
	client, err := v.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return fmt.Errorf("can't get rootLB client, %v", err)
	}
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

			attachPort := true
			if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED && v.VMProvider.GetInternalPortPolicy() == AttachPortDuringCreate {
				attachPort = false
			}
			err = v.AttachAndEnableRootLBInterface(ctx, client, rootLBName, attachPort, subnetName, GetPortName(rootLBName, subnetName), gw)
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

	// the root LB was created as part of cluster creation, but it needs to be prepped and
	// mex agent started
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		log.SpanLog(ctx, log.DebugLevelInfra, "new dedicated rootLB", "IpAccess", clusterInst.IpAccess)
		updateCallback(edgeproto.UpdateTask, "Setting Up Root LB")
		err := v.SetupRootLB(ctx, rootLBName, &clusterInst.Key.CloudletKey, privacyPolicy, updateCallback)
		if err != nil {
			return err
		}
	}

	if clusterInst.Deployment == cloudcommon.DeploymentTypeKubernetes {
		elapsed := time.Since(start)
		// subtract elapsed time from total time to get remaining time
		timeout -= elapsed
		updateCallback(edgeproto.UpdateTask, "Waiting for Cluster to Initialize")
		err := v.waitClusterReady(ctx, clusterInst, rootLBName, updateCallback, timeout)
		if err != nil {
			return err
		}
		updateCallback(edgeproto.UpdateTask, "Creating config map")
		if err := infracommon.CreateClusterConfigMap(ctx, client, clusterInst); err != nil {
			return err
		}
	}
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		proxy.NewDedicatedCluster(ctx, clusterInst.Key.ClusterKey.Name, client)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created cluster")
	return nil
}

func (v *VMPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
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

func (v *VMPlatform) waitClusterReady(ctx context.Context, clusterInst *edgeproto.ClusterInst, rootLBName string, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
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
				return err
			}
			if ready {
				log.SpanLog(ctx, log.DebugLevelInfra, "kubernetes cluster ready")
				return nil
			}
			if time.Since(start) > timeout {
				return fmt.Errorf("cluster not ready (yet)")
			}
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "waiting for kubernetes cluster to be ready...")
		time.Sleep(30 * time.Second)
	}
}

//IsClusterReady checks to see if cluster is read, i.e. rootLB is running and active.  returns ready,nodecount, error
func (v *VMPlatform) isClusterReady(ctx context.Context, clusterInst *edgeproto.ClusterInst, masterName, masterIP string, rootLBName string, updateCallback edgeproto.CacheUpdateCallback) (bool, uint32, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "checking if cluster is ready")

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
		// k8s nodes are limited to MaxK8sNodeNameLen chars
		//remove the taint from the master if there are no nodes. This has potential side effects if the cluster
		// becomes very busy but is useful for testing and PoC type clusters.
		// TODO: if the cluster is subsequently increased in size do we need to add the taint?
		//For now leaving that alone since an increased cluster size means we needed more capacity.
		log.SpanLog(ctx, log.DebugLevelInfra, "removing NoSchedule taint from master", "master", masterString)
		cmd := fmt.Sprintf("kubectl taint nodes %s node-role.kubernetes.io/master:NoSchedule-", masterString)

		out, err := masterClient.Output(cmd)
		if err != nil {
			if strings.Contains(out, "not found") {
				log.SpanLog(ctx, log.DebugLevelInfra, "master taint already gone")
			} else {
				log.InfoLog("error removing master taint", "out", out, "err", err)
				return false, 0, fmt.Errorf("Cannot remove NoSchedule taint from master, %v", err)
			}
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "cluster ready.")
	return true, readyCount, nil
}

func (v *VMPlatform) GetChefClusterTags(key *edgeproto.ClusterInstKey, vmType VMType) []string {
	region := v.VMProperties.GetRegion()
	deploymentTag := v.VMProperties.GetDeploymentTag()
	return []string{
		"deploytag/" + deploymentTag,
		"cluster/" + key.ClusterKey.Name,
		"clusterorg/" + key.Organization,
		"cloudlet/" + key.CloudletKey.Name,
		"cloudletorg/" + key.CloudletKey.Organization,
		"region/" + region,
		"vmtype/" + string(vmType),
	}
}

func (v *VMPlatform) getVMRequestSpecForDockerCluster(ctx context.Context, imgName string, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, action ActionType, updateCallback edgeproto.CacheUpdateCallback) ([]*VMRequestSpec, string, string, error) {

	log.SpanLog(ctx, log.DebugLevelInfo, "getVMRequestSpecForDockerCluster", "clusterInst", clusterInst)

	var vms []*VMRequestSpec
	var newSecgrpName string
	dockerVmName := v.GetDockerNodeName(ctx, clusterInst)
	newSubnetName := GetClusterSubnetName(ctx, clusterInst)

	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		tags := v.GetChefClusterTags(&clusterInst.Key, VMTypeRootLB)
		rootlb, err := v.GetVMSpecForRootLB(ctx, v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst), newSubnetName, tags, updateCallback)
		if err != nil {
			return vms, newSubnetName, newSecgrpName, err
		}
		vms = append(vms, rootlb)
		newSecgrpName = GetServerSecurityGroupName(rootlb.Name)
	} else {

		log.SpanLog(ctx, log.DebugLevelInfo, "creating shared rootlb port")
		// shared access means docker vm goes on its own subnet which is connected
		// via shared rootlb
		if v.VMProperties.GetCloudletExternalRouter() == NoExternalRouter {
			// If no router in use, create ports on the existing shared rootLB
			rootlb, err := v.GetVMSpecForRootLBPorts(ctx, v.VMProperties.SharedRootLBName, newSubnetName)
			if err != nil {
				return vms, newSubnetName, newSecgrpName, err
			}
			vms = append(vms, rootlb)
		}
	}
	chefAttributes := make(map[string]interface{})
	chefAttributes["tags"] = v.GetChefClusterTags(&clusterInst.Key, VMTypeClusterNode)
	clientName := v.GetChefClientName(dockerVmName)
	chefParams := v.GetVMChefParams(clientName, "", chefmgmt.ChefPolicyBase, chefAttributes)
	dockervm, err := v.GetVMRequestSpec(
		ctx,
		VMTypeClusterNode,
		dockerVmName,
		clusterInst.NodeFlavor,
		imgName,
		false,
		WithExternalVolume(clusterInst.ExternalVolumeSize),
		WithSubnetConnection(newSubnetName),
		WithChefParams(chefParams),
		WithOptionalResource(clusterInst.OptRes),
		WithComputeAvailabilityZone(clusterInst.AvailabilityZone),
	)
	if err != nil {
		return vms, newSubnetName, newSecgrpName, err
	}
	vms = append(vms, dockervm)
	return vms, newSubnetName, newSecgrpName, nil
}

func (v *VMPlatform) PerformOrchestrationForCluster(ctx context.Context, imgName string, clusterInst *edgeproto.ClusterInst, privacyPolicy *edgeproto.PrivacyPolicy, action ActionType, updateInfo map[string]string, updateCallback edgeproto.CacheUpdateCallback) (*VMGroupOrchestrationParams, error) {
	log.SpanLog(ctx, log.DebugLevelInfo, "PerformOrchestrationForCluster", "clusterInst", clusterInst, "action", action)

	var vms []*VMRequestSpec
	var err error
	vmgroupName := k8smgmt.GetCloudletClusterName(&clusterInst.Key)
	var newSubnetName string
	var newSecgrpName string

	if clusterInst.Deployment == cloudcommon.DeploymentTypeDocker {
		vms, newSubnetName, newSecgrpName, err = v.getVMRequestSpecForDockerCluster(ctx, imgName, clusterInst, privacyPolicy, action, updateCallback)
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
			tags := v.GetChefClusterTags(&clusterInst.Key, VMTypeRootLB)
			rootlb, err = v.GetVMSpecForRootLB(ctx, v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst), newSubnetName, tags, updateCallback)
			if err != nil {
				return nil, err
			}
			vms = append(vms, rootlb)
			newSecgrpName = GetServerSecurityGroupName(rootlb.Name)
		} else if v.VMProperties.GetCloudletExternalRouter() == NoExternalRouter {
			// If no router in use, create ports on the existing shared rootLB
			rootlb, err = v.GetVMSpecForRootLBPorts(ctx, v.VMProperties.SharedRootLBName, newSubnetName)
			if err != nil {
				return nil, err
			}
			vms = append(vms, rootlb)
		}

		chefAttributes := make(map[string]interface{})
		chefAttributes["tags"] = v.GetChefClusterTags(&clusterInst.Key, VMTypeClusterMaster)

		clientName := v.GetChefClientName(GetClusterMasterName(ctx, clusterInst))
		chefParams := v.GetVMChefParams(clientName, "", chefmgmt.ChefPolicyBase, chefAttributes)

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
			VMTypeClusterMaster,
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
		chefAttributes["tags"] = v.GetChefClusterTags(&clusterInst.Key, VMTypeClusterNode)
		for nn := uint32(1); nn <= clusterInst.NumNodes; nn++ {
			clientName := v.GetChefClientName(GetClusterNodeName(ctx, clusterInst, nn))
			chefParams := v.GetVMChefParams(clientName, "", chefmgmt.ChefPolicyBase, chefAttributes)
			node, err := v.GetVMRequestSpec(ctx,
				VMTypeClusterNode,
				GetClusterNodeName(ctx, clusterInst, nn),
				clusterInst.NodeFlavor,
				pfImage,
				false, //connect external
				WithExternalVolume(clusterInst.ExternalVolumeSize),
				WithSubnetConnection(newSubnetName),
				WithChefParams(chefParams),
				WithComputeAvailabilityZone(clusterInst.AvailabilityZone),
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
		WithPrivacyPolicy(privacyPolicy),
		WithNewSecurityGroup(newSecgrpName),
		WithChefUpdateInfo(updateInfo),
		WithSkipCleanupOnFailure(clusterInst.SkipCrmCleanupOnFailure),
	)
}
