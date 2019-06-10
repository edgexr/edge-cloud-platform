package mexos

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

//XXX ClusterInst seems to have Nodes which is a number.
//   The Nodes should be part of the Cluster flavor.  And there should be Max nodes, and current num of nodes.
//   Because the whole point of k8s and similar other clusters is the ability to expand.
//   Cluster flavor defines what kind of cluster we have available for use.
//   A medium cluster flavor may say "I have three nodes, ..."
//   Can the Node or Flavor change for the ClusterInst?
//   What needs to be done when contents change.
//   The old and new values are supposedly to be passed in the future when Cache is updated.
//   We have to compare old values and new values and figure out what changed.
//   Then act on the changes noticed.
//   There is no indication of type of cluster being created.  So assume k8s.
//   Nor is there any tenant information, so no ability to isolate, identify, account for usage or quota.
//   And no network type information or storage type information.
//   So if an app needs an external IP, we can't figure out if that is the case.
//   Nor is there a way to return the IP address or DNS name. Or even know if it needs a DNS name.
//   No ability to open ports, redirect or set up any kind of reverse proxy control.  etc.

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

//NetworkSpec examples:
// TYPE,NAME,CIDR,OPTIONS,EXTRAS
// "priv-subnet,mex-k8s-net-1,10.201.X.0/24,rp-dns-name"
// "external-ip,external-network-shared,1.2.3.4/8,dhcp"
// "external-ip,external-network-shared,1.2.3.4/8"
// "external-dns,external-network-shared,1.2.3.4/8,dns-name"
// "net-custom-type,some-name,8.8.244.33/16,auto-1"

//StorageSpec examples:
// TYPE,NAME,PARAM,OPTIONS,EXTRAS
//  ceph,internal-ceph-cluster,param1:param2:param3,opt1:opt2,extra1:extra2
//  nfs,nfsv4-internal,param1,opt1,extra1
//  gluster,glusterv3-ext,param1,opt1,extra1
//  postgres-cluster,post-v3,param1,opt1,extra1

//ClusterNodeFlavor contains details of flavor for the node
type ClusterNodeFlavor struct {
	Type string
	Name string
}

var maxClusterWaitTime = 10 * time.Minute

func waitClusterReady(clusterInst *edgeproto.ClusterInst, rootLBName string, updateCallback edgeproto.CacheUpdateCallback) error {

	start := time.Now()
	masterName := ""
	masterIP := ""
	var currReadyCount uint32
	for {
		if masterIP == "" {
			masterName, masterIP, _ = GetMasterNameAndIP(clusterInst)
			if masterIP != "" {
				updateCallback(edgeproto.UpdateStep, "Checking Master for Available Nodes")
			}
		}
		if masterIP == "" {
			log.DebugLog(log.DebugLevelMexos, "master IP not available yet")
		} else {
			ready, readyCount, err := IsClusterReady(clusterInst, masterName, masterIP, rootLBName, updateCallback)
			if readyCount != currReadyCount {
				numNodes := readyCount - 1
				updateCallback(edgeproto.UpdateStep, fmt.Sprintf("%d of %d nodes active", numNodes, clusterInst.NumNodes))
			}
			currReadyCount = readyCount
			if err != nil {
				return err
			}
			if ready {
				log.DebugLog(log.DebugLevelMexos, "kubernetes cluster ready")
				return nil
			}
			if time.Since(start) > maxClusterWaitTime {
				return fmt.Errorf("cluster not ready (yet)")
			}
		}
		log.DebugLog(log.DebugLevelMexos, "waiting for kubernetes cluster to be ready...")
		time.Sleep(30 * time.Second)
	}
}

func UpdateCluster(rootLBName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (reterr error) {
	updateCallback(edgeproto.UpdateTask, "Updating Cluster Resources with Heat")

	err := HeatUpdateClusterKubernetes(clusterInst, "", updateCallback)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Waiting for Cluster to Update")
	return waitClusterReady(clusterInst, rootLBName, updateCallback)
}

func CreateCluster(rootLBName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (reterr error) {
	// clean-up func
	defer func() {
		if reterr == nil {
			return
		}

		log.DebugLog(log.DebugLevelMexos, "error in CreateCluster", "err", reterr)
		if GetCleanupOnFailure() {
			log.DebugLog(log.DebugLevelMexos, "cleaning up cluster resources after cluster fail, set envvar CLEANUP_ON_FAILURE to 'no' to avoid this")
			delerr := DeleteCluster(rootLBName, clusterInst)
			if delerr != nil {
				log.DebugLog(log.DebugLevelMexos, "fail to cleanup cluster")
			}
		} else {
			log.DebugLog(log.DebugLevelMexos, "skipping cleanup on failure")
		}
	}()

	log.DebugLog(log.DebugLevelMexos, "creating cluster instance", "clusterInst", clusterInst)

	dedicatedRootLBName := ""
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		dedicatedRootLBName = rootLBName
	}

	var err error
	singleNodeCluster := false
	if clusterInst.NumMasters == 0 {
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			//suitable for docker only
			log.DebugLog(log.DebugLevelMexos, "creating single VM cluster with just rootLB and no k8s")
			singleNodeCluster = true
			updateCallback(edgeproto.UpdateTask, "Creating Dedicated VM for Docker")
			err = HeatCreateRootLBVM(dedicatedRootLBName, k8smgmt.GetK8sNodeNameSuffix(clusterInst), clusterInst.NodeFlavor, updateCallback)
		} else {
			err = fmt.Errorf("NumMasters cannot be 0 for shared access")
		}
	} else {
		err = HeatCreateClusterKubernetes(clusterInst, dedicatedRootLBName, updateCallback)
	}
	if err != nil {
		return err
	}
	// the root LB was created as part of cluster creation, but it needs to be prepped and
	// mex agent started
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		log.DebugLog(log.DebugLevelMexos, "need dedicated rootLB", "IpAccess", clusterInst.IpAccess)
		_, err := NewRootLB(rootLBName)
		if err != nil {
			// likely already exists which means something went really wrong
			return err
		}
		updateCallback(edgeproto.UpdateTask, "Setting Up Root LB")
		err = SetupRootLB(rootLBName, "", updateCallback)
		if err != nil {
			return err
		}
	}
	client, err := GetSSHClient(rootLBName, GetCloudletExternalNetwork(), SSHUser)
	if err != nil {
		return fmt.Errorf("can't get rootLB client, %v", err)
	}
	if !singleNodeCluster {
		updateCallback(edgeproto.UpdateTask, "Waiting for Cluster to Initialize")
		err := waitClusterReady(clusterInst, rootLBName, updateCallback)
		if err != nil {
			return err
		}
	}
	updateCallback(edgeproto.UpdateTask, "Updating Docker Credentials for cluster")
	if err := SeedDockerSecret(client, clusterInst, singleNodeCluster); err != nil {
		return err
	}
	if !singleNodeCluster {
		if err := CreateDockerRegistrySecret(client, clusterInst); err != nil {
			return err
		}
		if err := CreateClusterConfigMap(client, clusterInst); err != nil {
			return err
		}
	}
	log.DebugLog(log.DebugLevelMexos, "created kubernetes cluster")
	return nil
}

//DeleteCluster deletes kubernetes cluster
func DeleteCluster(rootLBName string, clusterInst *edgeproto.ClusterInst) error {
	log.DebugLog(log.DebugLevelMexos, "deleting kubernetes cluster", "clusterInst", clusterInst)
	clusterName := k8smgmt.GetK8sNodeNameSuffix(clusterInst)
	err := HeatDeleteStack(clusterName)
	if err != nil {
		return err
	}
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		DeleteRootLB(rootLBName)
	}
	return nil
}

//IsClusterReady checks to see if cluster is read, i.e. rootLB is running and active.  returns ready,nodecount, error
func IsClusterReady(clusterInst *edgeproto.ClusterInst, masterName, masterIP string, rootLBName string, updateCallback edgeproto.CacheUpdateCallback) (bool, uint32, error) {
	log.DebugLog(log.DebugLevelMexos, "checking if cluster is ready")

	client, err := GetSSHClient(rootLBName, GetCloudletExternalNetwork(), SSHUser)
	if err != nil {
		return false, 0, fmt.Errorf("can't get ssh client for cluser ready check, %v", err)
	}
	log.DebugLog(log.DebugLevelMexos, "checking master k8s node for available nodes", "ipaddr", masterIP)
	cmd := fmt.Sprintf("ssh -o %s -o %s -o %s -i id_rsa_mex %s@%s kubectl get nodes -o json", sshOpts[0], sshOpts[1], sshOpts[2], SSHUser, masterIP)
	//log.DebugLog(log.DebugLevelMexos, "running kubectl get nodes", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "error checking for kubernetes nodes", "out", out, "err", err)
		return false, 0, nil //This is intentional
	}
	gitems := &genericItems{}
	err = json.Unmarshal([]byte(out), gitems)
	if err != nil {
		return false, 0, fmt.Errorf("failed to json unmarshal kubectl get nodes output, %v, %v", err, out)
	}
	log.DebugLog(log.DebugLevelMexos, "kubectl reports nodes", "numnodes", len(gitems.Items))
	readyCount := uint32(len(gitems.Items))

	if readyCount < (clusterInst.NumNodes + clusterInst.NumMasters) {
		//log.DebugLog(log.DebugLevelMexos, "kubernetes cluster not ready", "log", out)
		log.DebugLog(log.DebugLevelMexos, "kubernetes cluster not ready", "len items", len(gitems.Items))
		return false, 0, nil
	}
	log.DebugLog(log.DebugLevelMexos, "cluster nodes", "numnodes", clusterInst.NumNodes, "nummasters", clusterInst.NumMasters)
	//kcpath := MEXDir() + "/" + name[strings.LastIndex(name, "-")+1:] + ".kubeconfig"
	if err := CopyKubeConfig(client, clusterInst, rootLBName, masterIP); err != nil {
		return false, 0, fmt.Errorf("kubeconfig copy failed, %v", err)
	}
	if clusterInst.NumNodes == 0 {
		//remove the taint from the master if there are no nodes. This has potential side effects if the cluster
		// becomes very busy but is useful for testing and PoC type clusters.
		// TODO: if the cluster is subsequently increased in size do we need to add the taint?
		//For now leaving that alone since an increased cluster size means we needed more capacity.
		log.DebugLog(log.DebugLevelMexos, "removing NoSchedule taint from master", "master", masterName)
		cmd := fmt.Sprintf("ssh -o %s -o %s -o %s -i id_rsa_mex %s@%s kubectl taint nodes %s node-role.kubernetes.io/master:NoSchedule-", sshOpts[0], sshOpts[1], sshOpts[2], SSHUser, masterIP, masterName)
		out, err := client.Output(cmd)
		if err != nil {
			if strings.Contains(out, "not found") {
				log.DebugLog(log.DebugLevelMexos, "master taint already gone")
			} else {
				log.InfoLog("error removing master taint", "out", out, "err", err)
				return false, 0, fmt.Errorf("Cannot remove NoSchedule taint from master, %v", err)
			}
		}
	}
	log.DebugLog(log.DebugLevelMexos, "cluster ready.")
	return true, readyCount, nil
}

//FindClusterWithKey finds cluster given a key string
func FindClusterMaster(key string, srvs []OSServer) (string, error) {
	log.DebugLog(log.DebugLevelMexos, "FindClusterMaster", "key", key)
	if key == "" {
		return "", fmt.Errorf("empty key")
	}
	for _, s := range srvs {
		if s.Status == "ACTIVE" && strings.HasSuffix(s.Name, key) && strings.HasPrefix(s.Name, "mex-k8s-master") {
			//log.DebugLog(log.DebugLevelMexos, "find cluster with key", "key", key, "found", s.Name)
			return s.Name, nil
		}
	}
	return "", fmt.Errorf("key %s not found", key)
}
