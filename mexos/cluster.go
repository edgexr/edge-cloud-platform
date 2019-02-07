package mexos

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/azure"
	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/dind"
	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/gcloud"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
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
	MasterFlavor   ClusterMasterFlavor
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

//ClusterMasterFlavor contains details of flavor for the master node
type ClusterMasterFlavor struct {
	Type string
	Name string
}

//mexCreateClusterKubernetes creates a cluster of nodes. It can take a while, so call from a goroutine.
func mexCreateClusterKubernetes(clusterInst *edgeproto.ClusterInst, rootLBName string) error {

	log.DebugLog(log.DebugLevelMexos, "create kubernetes cluster", "cluster", clusterInst)

	nameSuffix := GetK8sNodeNameSuffix(clusterInst)
	flavorName := clusterInst.Flavor.Name
	tenantName := GetCloudletTenant()
	clusterName := clusterInst.Key.ClusterKey.Name

	if flavorName == "" {
		return fmt.Errorf("empty cluster flavor")
	}
	cf, err := GetClusterFlavor(flavorName)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "invalid platform flavor, can't create cluster")
		return err
	}
	//TODO more than one networks
	netScheme := GetCloudletNetworkScheme()
	if netScheme == "" {
		return fmt.Errorf("empty network spec")
	}
	if !strings.HasPrefix(netScheme, "priv-subnet") {
		return fmt.Errorf("unsupported netSpec kind %s", netScheme)
		// XXX for now
	}

	//tags are derived from the cluster name currently
	tags := clusterInst.Key.ClusterKey.Name + "-tag"
	//TODO allow more net types
	//TODO validate CIDR, etc.

	// this does nothing currently
	err = ValidateTenant(tenantName)

	if err != nil {
		return fmt.Errorf("can't validate tenant, %v", err)
	}
	err = ValidateTags(tags)
	if err != nil {
		return fmt.Errorf("invalid tag, %v", err)
	}
	tags += "," + cf.PlatformFlavor
	//TODO add whole manifest yaml->json into stringified property of the kvm instance for later
	//XXX should check for quota, permissions, access control, etc. here
	//guid := xid.New().String()
	//kvmname := fmt.Sprintf("%s-1-%s-%s", "mex-k8s-master", mf.Metadata.Name, guid)
	kvmname := fmt.Sprintf("%s-1-%s", "mex-k8s-master", nameSuffix)
	sd, err := GetServerDetails(kvmname)
	if err == nil {
		if sd.Name == kvmname {
			log.DebugLog(log.DebugLevelMexos, "k8s master exists", "kvmname", kvmname)
			return nil
		}
	}
	log.DebugLog(log.DebugLevelMexos, "proceed to create k8s master kvm", "kvmname", kvmname, "netspec", netScheme, "tags", tags, "flavor", flavorName)
	err = CreateMEXKVM(kvmname,
		"k8s-master",
		netScheme,
		tags,
		tenantName,
		1,
		clusterInst,
		cf.PlatformFlavor,
	)
	if err != nil {
		return fmt.Errorf("can't create k8s master, %v", err)
	}
	for i := 1; i <= cf.NumNodes; i++ {
		//construct node name
		//kvmnodename := fmt.Sprintf("%s-%d-%s-%s", "mex-k8s-node", i, mf.Metadata.Name, guid)
		kvmnodename := fmt.Sprintf("%s-%d-%s", "mex-k8s-node", i, nameSuffix)
		err = CreateMEXKVM(kvmnodename,
			"k8s-node",
			netScheme,
			tags,
			tenantName,
			i,
			clusterInst,
			cf.PlatformFlavor,
		)
		if err != nil {
			return fmt.Errorf("can't create k8s node, %v", err)
		}
	}
	if GetCloudletExternalNetwork() == "" {
		return fmt.Errorf("missing external network in platform config")
	}
	if err = LBAddRoute(rootLBName, GetCloudletExternalNetwork(), kvmname); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot add route on rootlb", "error", err)
		//return err
	}
	if err = SetServerProperty(kvmname, "mex-flavor="+flavorName); err != nil {
		return err
	}
	ready := false
	for i := 0; i < 10; i++ {
		ready, err = IsClusterReady(clusterInst, flavorName, rootLBName)
		if err != nil {
			return err
		}
		if ready {
			log.DebugLog(log.DebugLevelMexos, "kubernetes cluster ready")
			break
		}
		log.DebugLog(log.DebugLevelMexos, "waiting for kubernetes cluster to be ready...")
		time.Sleep(30 * time.Second)
	}
	if !ready {
		return fmt.Errorf("cluster not ready (yet)")
	}
	if err := SeedDockerSecret(clusterName, rootLBName); err != nil {
		return err
	}
	/* TODO: Swarm is not integrated with the controller, needs work here.
	if mf.Metadata.Swarm != "" {
		log.DebugLog(log.DebugLevelMexos, "metadata swarm is set, creating docker swarm", "swarm")
		if err := CreateDockerSwarm(clusterName, rootLBName); err != nil {
			return err
		}
	}
	*/
	if err := CreateDockerRegistrySecret(clusterInst, rootLBName); err != nil {
		return err
	}
	//return &guid, nil
	return nil
}

//mexDeleteClusterKubernetes deletes kubernetes cluster
func mexDeleteClusterKubernetes(clusterInst *edgeproto.ClusterInst, rootLBName string) error {
	log.DebugLog(log.DebugLevelMexos, "deleting kubernetes cluster", "clusterInst", clusterInst)
	nameSuffix := GetK8sNodeNameSuffix(clusterInst)

	rootLB, err := getRootLB(rootLBName)
	if err != nil {
		return err
	}
	if rootLB == nil {
		return fmt.Errorf("can't delete kubernetes cluster, rootLB is null")
	}

	if nameSuffix == "" {
		log.DebugLog(log.DebugLevelMexos, "error, empty name")
		return fmt.Errorf("empty name")
	}
	srvs, err := ListServers()
	if err != nil {
		return err
	}
	// clname, err := FindClusterWithKey(mf, mf.Spec.Key)
	// if err != nil {
	// 	return fmt.Errorf("can't find cluster with key %s, %v", mf.Spec.Key, err)
	// }
	//log.DebugLog(log.DebugLevelMexos, "looking for server", "name", name, "servers", srvs)
	force := true // TODO: consider a way to specify this
	serverDeleted := false
	for _, s := range srvs {
		if strings.Contains(s.Name, nameSuffix) {
			if !strings.HasPrefix(s.Name, "mex-k8s-") {
				continue
			}
			if strings.Contains(s.Name, "mex-k8s-master") {
				err = LBRemoveRoute(rootLB.Name, GetCloudletExternalNetwork(), s.Name)
				if err != nil {
					if !force {
						err = fmt.Errorf("failed to remove route for %s, %v", s.Name, err)
						log.DebugLog(log.DebugLevelMexos, "failed to remove route", "name", s.Name, "error", err)
						return err
					}
					log.DebugLog(log.DebugLevelMexos, "forced to continue, failed to remove route ", "name", s.Name, "error", err)
				}
			}
			log.DebugLog(log.DebugLevelMexos, "delete kubernetes server", "name", s.Name)
			err = DeleteServer(s.Name)
			if err != nil {
				if !force {
					log.DebugLog(log.DebugLevelMexos, "delete server fail", "error", err)
					return err
				}
				log.DebugLog(log.DebugLevelMexos, "forced to continue, error while deleting server", "server", s.Name, "error", err)
			}
			serverDeleted = true
			//kconfname := fmt.Sprintf("%s.kubeconfig", s.Name[strings.LastIndex(s.Name, "-")+1:])
			// kconfname := GetLocalKconfName(mf)
			// rerr := os.Remove(kconfname)
			// if rerr != nil {
			// 	log.DebugLog(log.DebugLevelMexos, "error can't remove file", "name", kconfname, "error", rerr)
			// }
		}
	}
	if !serverDeleted {
		log.DebugLog(log.DebugLevelMexos, "server not found", "name", nameSuffix)
		return fmt.Errorf("no server with name %s", nameSuffix)
	}
	sns, err := ListSubnets("")
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "can't list subnets", "error", err)
		return err
	}
	rn := GetCloudletExternalRouter() //XXX for now
	for _, s := range sns {
		if strings.Contains(s.Name, nameSuffix) {
			rerr := RemoveRouterSubnet(rn, s.Name)
			if rerr != nil {
				log.DebugLog(log.DebugLevelMexos, "not fatal, continue, can't remove router from subnet", "error", rerr)
				//return rerr
			}
			err = DeleteSubnet(s.Name)
			if err != nil {
				log.DebugLog(log.DebugLevelMexos, "warning, problems deleting subnet", "error", err)
			}
			break
		}
	}
	//XXX tell agent to remove the route
	//XXX remove kubectl proxy instance
	// if err = DeleteNginxKCProxy(mf, rootLB.Name, clname); err != nil {
	// 	log.DebugLog(log.DebugLevelMexos, "warning,cannot clean nginx kubectl proxy", "error", err)
	// 	//return err
	// }
	return nil
}

//IsClusterReady checks to see if cluster is read, i.e. rootLB is running and active
func IsClusterReady(clusterInst *edgeproto.ClusterInst, flavorName, rootLBName string) (bool, error) {
	log.DebugLog(log.DebugLevelMexos, "checking if cluster is ready")

	nameSuffix := GetK8sNodeNameSuffix(clusterInst)
	cf, err := GetClusterFlavor(flavorName)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "invalid cluster flavor, can't check if cluster is ready")
		return false, err
	}
	master, err := FindClusterMaster(nameSuffix)
	if err != nil {
		return false, fmt.Errorf("can't find cluster with name %s, %v", nameSuffix, err)
	}
	ipaddr, err := FindNodeIP(master)
	if err != nil {
		return false, err
	}
	if GetCloudletExternalNetwork() == "" {
		return false, fmt.Errorf("is cluster ready, missing external network in platform config")
	}
	client, err := GetSSHClient(rootLBName, GetCloudletExternalNetwork(), sshUser)
	if err != nil {
		return false, fmt.Errorf("can't get ssh client for cluser ready check, %v", err)
	}
	log.DebugLog(log.DebugLevelMexos, "checking master k8s node for available nodes", "ipaddr", ipaddr)
	cmd := fmt.Sprintf("ssh -o %s -o %s -o %s -i id_rsa_mex %s@%s kubectl get nodes -o json", sshOpts[0], sshOpts[1], sshOpts[2], sshUser, ipaddr)
	//log.DebugLog(log.DebugLevelMexos, "running kubectl get nodes", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "error checking for kubernetes nodes", "out", out, "err", err)
		return false, nil //This is intentional
	}
	gitems := &genericItems{}
	err = json.Unmarshal([]byte(out), gitems)
	if err != nil {
		return false, fmt.Errorf("failed to json unmarshal kubectl get nodes output, %v, %v", err, out)
	}
	log.DebugLog(log.DebugLevelMexos, "kubectl reports nodes", "numnodes", len(gitems.Items))
	if len(gitems.Items) < (cf.NumNodes + cf.NumMasterNodes) {
		//log.DebugLog(log.DebugLevelMexos, "kubernetes cluster not ready", "log", out)
		log.DebugLog(log.DebugLevelMexos, "kubernetes cluster not ready", "len items", len(gitems.Items))
		return false, nil
	}
	log.DebugLog(log.DebugLevelMexos, "cluster nodes", "numnodes", cf.NumNodes, "nummasters", cf.NumMasterNodes)
	//kcpath := MEXDir() + "/" + name[strings.LastIndex(name, "-")+1:] + ".kubeconfig"
	if err := CopyKubeConfig(clusterInst, rootLBName, master); err != nil {
		return false, fmt.Errorf("kubeconfig copy failed, %v", err)
	}
	log.DebugLog(log.DebugLevelMexos, "cluster ready.")
	return true, nil
}

//FindClusterWithKey finds cluster given a key string
func FindClusterMaster(key string) (string, error) {
	//log.DebugLog(log.DebugLevelMexos, "find cluster with key", "key", key)
	if key == "" {
		return "", fmt.Errorf("empty key")
	}
	srvs, err := ListServers()
	if err != nil {
		return "", err
	}
	for _, s := range srvs {
		if s.Status == "ACTIVE" && strings.HasSuffix(s.Name, key) && strings.HasPrefix(s.Name, "mex-k8s-master") {
			//log.DebugLog(log.DebugLevelMexos, "find cluster with key", "key", key, "found", s.Name)
			return s.Name, nil
		}
	}
	return "", fmt.Errorf("key %s not found", key)
}

//MEXClusterCreateInst creates a cluster
func MEXClusterCreateClustInst(clusterInst *edgeproto.ClusterInst, rootLBName string) error {
	log.DebugLog(log.DebugLevelMexos, "creating cluster instance", "clusterInst", clusterInst, "rootLBName", rootLBName)
	if IsLocalDIND() {
		return localCreateDIND(clusterInst)
	}
	operatorName := NormalizeName(clusterInst.Key.CloudletKey.OperatorKey.Name)

	switch operatorName {
	case cloudcommon.OperatorGCP:
		return gcloudCreateGKE(clusterInst)
	case cloudcommon.OperatorAzure:
		return azureCreateAKS(clusterInst)
	default:
		//guid, err := mexCreateClusterKubernetes(mf)
		err := mexCreateClusterKubernetes(clusterInst, rootLBName)
		if err != nil {
			return fmt.Errorf("can't create cluster, %v", err)
		}
		//log.DebugLog(log.DebugLevelMexos, "new guid", "guid", *guid)
		log.DebugLog(log.DebugLevelMexos, "created kubernetes cluster")
		return nil
	}
}

func MEXClusterRemoveClustInst(clusterInst *edgeproto.ClusterInst, rootLBName string) error {
	log.DebugLog(log.DebugLevelMexos, "removing cluster")

	clusterName := clusterInst.Key.ClusterKey.Name

	if IsLocalDIND() {
		return dind.DeleteDINDCluster(clusterName)
	}
	operatorName := NormalizeName(clusterInst.Key.CloudletKey.OperatorKey.Name)

	switch operatorName {
	case cloudcommon.OperatorGCP:
		return gcloud.DeleteGKECluster(clusterInst.Key.ClusterKey.Name)
	case cloudcommon.OperatorAzure:
		resourceGroup := GetResourceGroupForCluster(clusterInst)
		return azure.DeleteAKSCluster(resourceGroup)
	default:
		if err := mexDeleteClusterKubernetes(clusterInst, rootLBName); err != nil {
			return fmt.Errorf("can't remove cluster, %v", err)
		}
		return nil
	}
}
