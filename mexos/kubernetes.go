package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/nanobox-io/golang-ssh"
)

//CreateKubernetesAppInst instantiates a new kubernetes deployment
func CreateKubernetesAppInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst, kubeManifest string, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	log.DebugLog(log.DebugLevelMexos, "create kubernetes app")

	clusterName := clusterInst.Key.ClusterKey.Name
	appName := NormalizeName(app.Key.Name)

	if rootLB == nil {
		return fmt.Errorf("cannot create kubernetes app manifest, rootLB is null")
	}

	if appInst.Uri == "" {
		return fmt.Errorf("empty app URI")
	}
	kp, err := ValidateKubernetesParameters(clusterInst, rootLB, clusterName)
	if err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "will launch app into cluster", "kubeconfig", kp.kubeconfig, "ipaddr", kp.ipaddr)
	var cmd string
	if GetCloudletDockerPass() == "" {
		return fmt.Errorf("empty docker registry password environment variable")
	}
	//if err := CreateDockerRegistrySecret(mf); err != nil {
	//	return err
	//}
	//TODO do not create yaml file but use remote yaml file over https
	cmd = fmt.Sprintf("cat <<'EOF'> %s.yaml \n%s\nEOF", appName, kubeManifest)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error writing KubeManifest, %s, %s, %v", cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "wrote kubernetes manifest file")
	cmd = fmt.Sprintf("%s kubectl create -f %s.yaml", kp.kubeconfig, appName)
	out, err = kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deploying kubernetes app, %s, %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "applied kubernetes manifest")
	// Add security rules
	if err = AddProxySecurityRules(rootLB, kp.ipaddr, appInst); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot create security rules", "error", err)
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "ok, added ports", "ports", appInst.MappedPorts)
	// Add DNS Zone
	if err = KubeAddDNSRecords(rootLB, kp, appInst.Uri, appName); err != nil {
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
func ValidateKubernetesParameters(clusterInst *edgeproto.ClusterInst, rootLB *MEXRootLB, clustName string) (*kubeParam, error) {
	log.DebugLog(log.DebugLevelMexos, "validate kubernetes parameters rootLB", "cluster", clustName)
	clusterName := clusterInst.Key.ClusterKey.Name

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
	master, err := FindClusterMaster(clusterName)
	if err != nil {
		return nil, fmt.Errorf("can't find cluster with key %s, %v", clustName, err)
	}
	ipaddr, err := FindNodeIP(master)
	if err != nil {
		return nil, err
	}
	//kubeconfig := fmt.Sprintf("KUBECONFIG=%s.kubeconfig", name[strings.LastIndex(name, "-")+1:])
	kubeconfig := fmt.Sprintf("KUBECONFIG=%s", GetKconfName(clusterInst))
	return &kubeParam{kubeconfig, client, ipaddr}, nil
}

func DeleteKubernetesAppInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst, kubeManifest string, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	log.DebugLog(log.DebugLevelMexos, "delete kubernetes app")

	clusterName := clusterInst.Key.ClusterKey.Name
	appName := NormalizeName(app.Key.Name)

	kp, err := ValidateKubernetesParameters(clusterInst, rootLB, clusterName)
	if err != nil {
		return err
	}
	// Clean up security rules and nginx proxy
	if err = DeleteProxySecurityRules(rootLB, kp.ipaddr, appInst); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot clean up security rules", "name", appName, "rootlb", rootLB.Name, "error", err)
	}
	// Clean up DNS entries
	if err = KubeDeleteDNSRecords(rootLB, kp, appInst.Uri, appName); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot clean up DNS entries", "name", appName, "rootlb", rootLB.Name, "error", err)
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "deleted deployment", "name", appName)
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

/*
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
