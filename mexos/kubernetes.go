package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/cloudflare"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/nanobox-io/golang-ssh"
)

type KubeNames struct {
	appName      string
	appURI       string
	appImage     string
	clusterName  string
	operatorName string
	kconfName    string
}

// GetKubeNames udpates kubeNames with normalized strings for the included clusterinst, app, and appisnt
func GetKubeNames(clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, kubeNames *KubeNames) (err error) {
	if clusterInst == nil {
		return fmt.Errorf("nil cluster inst")
	}
	if app == nil {
		return fmt.Errorf("nil app")
	}
	if appInst == nil {
		return fmt.Errorf("nil app inst")
	}
	kubeNames.clusterName = clusterInst.Key.ClusterKey.Name
	kubeNames.appName = NormalizeName(app.Key.Name)
	kubeNames.appURI = appInst.Uri
	kubeNames.appImage = NormalizeName(app.ImagePath)
	kubeNames.operatorName = NormalizeName(clusterInst.Key.CloudletKey.OperatorKey.Name)
	kubeNames.kconfName = GetKconfName(clusterInst)
	return nil

}

//CreateKubernetesAppInst instantiates a new kubernetes deployment
func CreateKubernetesAppInst(rootLB *MEXRootLB, kubeNames *KubeNames, clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst, kubeManifest string) error {
	log.DebugLog(log.DebugLevelMexos, "create kubernetes app")

	if rootLB == nil {
		return fmt.Errorf("cannot create kubernetes app manifest, rootLB is null")
	}
	if appInst.Uri == "" {
		return fmt.Errorf("empty app URI")
	}
	kp, err := ValidateKubernetesParameters(rootLB, kubeNames, clusterInst)
	if err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "will launch app into cluster", "kubeconfig", kp.kubeconfig, "ipaddr", kp.ipaddr)
	var cmd string
	if GetCloudletDockerPass() == "" {
		return fmt.Errorf("empty docker registry password environment variable")
	}
	file, err := WriteConfigFile(kp, kubeNames.appName, kubeManifest, "K8s Deployment")
	if err != nil {
		return err
	}
	cmd = fmt.Sprintf("%s kubectl create -f %s", kp.kubeconfig, file)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deploying kubernetes app, %s, %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "applied kubernetes manifest")
	// Add security rules
	if err = AddProxySecurityRules(rootLB, kp.ipaddr, kubeNames.appName, appInst); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot create security rules", "error", err)
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "ok, added ports", "ports", appInst.MappedPorts)
	// Add DNS Zone
	if err = KubeAddDNSRecords(rootLB, kp, appInst.Uri, kubeNames.appName); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot add DNS entries", "error", err)
		return err
	}
	return nil
}

type kubeParam struct {
	kubeconfig string
	client     ssh.Client
	ipaddr     string
}

//ValidateKubernetesParameters checks the kubernetes parameters and kubeconfig settings
func ValidateKubernetesParameters(rootLB *MEXRootLB, kubeNames *KubeNames, clusterInst *edgeproto.ClusterInst) (*kubeParam, error) {
	log.DebugLog(log.DebugLevelMexos, "validate kubernetes parameters", "kubeNames", kubeNames)

	if CloudletIsDirectKubectlAccess() {
		// No ssh jump host (rootlb) but kconf configures how to
		// talk to remote kubernetes cluster.  This includes DIND, AKS, GCP
		kconf, err := GetKconf(clusterInst)
		if err != nil {
			return nil, fmt.Errorf("kconf missing, %v, %v", kubeNames.clusterName, err)
		}
		kp := kubeParam{
			kubeconfig: fmt.Sprintf("KUBECONFIG=%s", kconf),
			client:     &sshLocal{},
		}
		return &kp, nil
	}
	if rootLB == nil {
		return nil, fmt.Errorf("cannot validate kubernetes parameters, rootLB is null")
	}
	if GetCloudletExternalNetwork() == "" {
		return nil, fmt.Errorf("validate kubernetes parameters, missing external network in platform config")
	}
	client, err := GetSSHClient(rootLB.Name, GetCloudletExternalNetwork(), sshUser)
	if err != nil {
		return nil, err
	}
	master, err := FindClusterMaster(kubeNames.clusterName)
	if err != nil {
		return nil, fmt.Errorf("can't find cluster with key %s, %v", kubeNames.clusterName, err)
	}
	ipaddr, err := FindNodeIP(master)
	if err != nil {
		return nil, err
	}
	//kubeconfig := fmt.Sprintf("KUBECONFIG=%s.kubeconfig", name[strings.LastIndex(name, "-")+1:])
	kubeconfig := fmt.Sprintf("KUBECONFIG=%s", kubeNames.kconfName)
	return &kubeParam{kubeconfig, client, ipaddr}, nil
}

func DeleteKubernetesAppInst(rootLB *MEXRootLB, kubeNames *KubeNames, clusterInst *edgeproto.ClusterInst) error {
	log.DebugLog(log.DebugLevelMexos, "delete kubernetes app")

	kp, err := ValidateKubernetesParameters(rootLB, kubeNames, clusterInst)
	if err != nil {
		return err
	}
	// Clean up security rules and nginx proxy
	if err = DeleteProxySecurityRules(rootLB, kp.ipaddr, kubeNames.appName); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot clean up security rules", "name", kubeNames.appName, "rootlb", rootLB.Name, "error", err)
	}
	if err := cloudflare.InitAPI(GetCloudletCFUser(), GetCloudletCFKey()); err != nil {
		return fmt.Errorf("cannot init cloudflare api, %v", err)
	}
	// Clean up DNS entries
	if err = KubeDeleteDNSRecords(rootLB, kp, kubeNames.appURI, kubeNames.appName); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot clean up DNS entries", "name", kubeNames.appName, "rootlb", rootLB.Name, "error", err)
		return err
	}
	cmd := fmt.Sprintf("%s kubectl delete -f %s.yaml", kp.kubeconfig, kubeNames.appName)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deleting kuberknetes app, %s, %s, %s, %v", kubeNames.appName, cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "deleted deployment", "name", kubeNames.appName)
	return nil
}

type KubernetesNode struct {
	Name string
	Role string
	Addr string
}

type KNodeMetadata struct {
	Labels map[string]string `json:"labels"`
	//TODO annotations, resourceVersion, creationTimestamp, name, selfLink, uid
}

type KNodeAddr struct {
	Address string `json:"address"`
	Type    string `json:"type"`
}

type KNodeStatus struct {
	Addresses []KNodeAddr `json:"addresses"`
	//TODO allocatable, capacity,conditions,daemonEndpoints,images,nodeInfo,
}

type KAPINode struct {
	ApiVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Metadata   KNodeMetadata `json:"metadata"`
	//TODO spec
	Status KNodeStatus `json:"status"`
}

type KAPINodes struct {
	ApiVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Items      []KAPINode `json:"items"`
	//TODO metadata
}

/* TODO: fix for swarm
func GetKubernetesNodes(mf *Manifest, rootLB *MEXRootLB) ([]KubernetesNode, error) {
	log.DebugLog(log.DebugLevelMexos, "getting kubernetes nodes")
	clusterName := clusterInst.Key.ClusterKey.Name

	master, err := FindClusterMaster(clusterName)
	if err != nil {
		return nil, fmt.Errorf("can't find cluster with key %s, %v", mf.Spec.Key, err)
	}
	ipaddr, err := FindNodeIP(master)
	if err != nil {
		return nil, err
	}
	client, err := GetSSHClient(rootLB.Name, GetCloudletExternalNetwork(), sshUser)
	if err != nil {
		return nil, fmt.Errorf("can't get ssh client for getting kubernetes nodes, %v", err)
	}
	cmd := fmt.Sprintf("ssh -o %s -o %s -o %s -i id_rsa_mex %s@%s kubectl get nodes -o json", sshOpts[0], sshOpts[1], sshOpts[2], sshUser, ipaddr)
	log.DebugLog(log.DebugLevelMexos, "running kubectl get nodes", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "error checking for kubernetes nodes", "out", out, "err", err)
		return nil, fmt.Errorf("error doing kubectl get nodes, %v", err)
	}
	knodes := KAPINodes{}
	err = json.Unmarshal([]byte(out), &knodes)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling kubectl get nodes result, %v, %s", err, out)
	}
	if knodes.Kind != "List" {
		return nil, fmt.Errorf("error, kubectl get nodes result is not a list")
	}
	kl := make([]KubernetesNode, 0)
	for _, n := range knodes.Items {
		if n.Kind != "Node" {
			continue
		}
		kn := KubernetesNode{}
		for _, a := range n.Status.Addresses {
			if a.Type == "InternalIP" {
				kn.Addr = a.Address
			}
			if a.Type == "Hostname" {
				kn.Name = a.Address
			}
			if _, ok := n.Metadata.Labels["node-role.kubernetes.io/master"]; ok {
				kn.Role = "master"
			} else {
				kn.Role = "worker"
			}
		}
		kl = append(kl, kn)
	}
	return kl, nil
}
*/
