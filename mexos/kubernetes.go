package mexos

import (
	"encoding/json"
	"fmt"

	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/nanobox-io/golang-ssh"
)

//CreateKubernetesAppManifest instantiates a new kubernetes deployment
func CreateKubernetesAppManifest(mf *Manifest, kubeManifest string) error {
	log.DebugLog(log.DebugLevelMexos, "create kubernetes app")
	rootLB, err := getRootLB(mf.Spec.RootLB)
	if err != nil {
		return err
	}
	if rootLB == nil {
		return fmt.Errorf("cannot create kubernetes app manifest, rootLB is null")
	}
	if err = ValidateCommon(mf); err != nil {
		return err
	}
	if mf.Spec.URI == "" { //XXX TODO register to the DNS registry for public IP app,controller needs to tell us which kind of app
		return fmt.Errorf("empty app URI")
	}
	kp, err := ValidateKubernetesParameters(mf, rootLB, mf.Spec.Key)
	if err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "will launch app into cluster", "kubeconfig", kp.kubeconfig, "ipaddr", kp.ipaddr)
	var cmd string
	if mexEnv(mf, "MEX_DOCKER_REG_PASS") == "" {
		return fmt.Errorf("empty docker registry password environment variable")
	}
	if err := CreateDockerRegistrySecret(mf); err != nil {
		return err
	}
	cmd = fmt.Sprintf("cat <<'EOF'> %s.yaml \n%s\nEOF", mf.Metadata.Name, kubeManifest)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error writing KubeManifest, %s, %s, %v", cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "wrote kubernetes manifest file")
	cmd = fmt.Sprintf("%s kubectl create -f %s.yaml", kp.kubeconfig, mf.Metadata.Name)
	out, err = kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deploying kubernetes app, %s, %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "applied kubernetes manifest")
	// Add security rules
	if err = AddProxySecurityRules(rootLB, mf, kp.ipaddr); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot create security rules", "error", err)
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "ok, added spec ports", "ports", mf.Spec.Ports)
	// Add DNS Zone
	if err = KubeAddDNSRecords(rootLB, mf, kp); err != nil {
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
func ValidateKubernetesParameters(mf *Manifest, rootLB *MEXRootLB, clustName string) (*kubeParam, error) {
	log.DebugLog(log.DebugLevelMexos, "validate kubernetes parameters rootLB", "cluster", clustName)
	if rootLB == nil {
		return nil, fmt.Errorf("cannot validate kubernetes parameters, rootLB is null")
	}
	if rootLB.PlatConf == nil {
		return nil, fmt.Errorf("validate kubernetes parameters, missing platform config")
	}
	if mf.Values.Network.External == "" {
		return nil, fmt.Errorf("validate kubernetes parameters, missing external network in platform config")
	}
	client, err := GetSSHClient(mf, rootLB.Name, mf.Values.Network.External, sshUser)
	if err != nil {
		return nil, err
	}
	name, err := FindClusterWithKey(mf, clustName)
	if err != nil {
		return nil, fmt.Errorf("can't find cluster with key %s, %v", clustName, err)
	}
	ipaddr, err := FindNodeIP(mf, name)
	if err != nil {
		return nil, err
	}
	//kubeconfig := fmt.Sprintf("KUBECONFIG=%s.kubeconfig", name[strings.LastIndex(name, "-")+1:])
	kubeconfig := fmt.Sprintf("KUBECONFIG=%s", GetKconfName(mf))
	return &kubeParam{kubeconfig, client, ipaddr}, nil
}

//KubernetesApplyManifest does `apply` on the manifest yaml
func KubernetesApplyManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "apply kubernetes manifest")
	rootLB, err := getRootLB(mf.Spec.RootLB)
	if err != nil {
		return err
	}
	if rootLB == nil {
		return fmt.Errorf("cannot apply kubernetes manifest, rootLB is null")
	}
	if mf.Metadata.Name == "" {
		return fmt.Errorf("missing name")
	}
	kp, err := ValidateKubernetesParameters(mf, rootLB, mf.Spec.Key)
	if err != nil {
		return err
	}
	kubeManifest := mf.Config.ConfigDetail.Manifest
	cmd := fmt.Sprintf("cat <<'EOF'> %s \n%s\nEOF", mf.Metadata.Name, kubeManifest)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error writing deployment, %s, %s, %v", cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "wrote deployment file")
	cmd = fmt.Sprintf("%s kubectl apply -f %s", kp.kubeconfig, mf.Metadata.Name)
	out, err = kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error applying kubernetes manifest, %s, %s, %v", cmd, out, err)
	}
	return nil
}

//CreateKubernetesNamespaceManifest creates a new namespace in kubernetes
func CreateKubernetesNamespaceManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "create kubernetes namespace")
	err := KubernetesApplyManifest(mf)
	if err != nil {
		return fmt.Errorf("error applying kubernetes namespace manifest, %v", err)
	}
	return nil
}

//TODO DeleteKubernetesNamespace

//TODO allow configmap creation from files

//SetKubernetesConfigmapValues sets a key-value in kubernetes configmap
// func SetKubernetesConfigmapValues(rootLBName string, clustername string, configname string, keyvalues ...string) error {
// 	log.DebugLog(log.DebugLevelMexos, "set configmap values", "rootlbname", rootLBName, "clustername", clustername, "configname", configname)
// 	rootLB, err := getRootLB(rootLBName)
// 	if err != nil {
// 		return err
// 	}
// 	if rootLB == nil {
// 		return fmt.Errorf("cannot set kubeconfig map values, rootLB is null")
// 	}
// 	kp, err := ValidateKubernetesParameters(mf, rootLB, clustername)
// 	if err != nil {
// 		return err
// 	}
// 	//TODO support namespace
// 	cmd := fmt.Sprintf("%s kubectl create configmap %s ", kp.kubeconfig, configname)
// 	for _, kv := range keyvalues {
// 		items := strings.Split(kv, "=")
// 		if len(items) != 2 {
// 			return fmt.Errorf("malformed key=value pair, %s", kv)
// 		}
// 		cmd = cmd + " --from-literal=" + kv
// 	}
// 	out, err := kp.client.Output(cmd)
// 	if err != nil {
// 		return fmt.Errorf("error setting key/values to  kubernetes configmap, %s, %s, %v", cmd, out, err)
// 	}
// 	return nil
// }

//TODO
//func GetKubernetesConfigmapValues(rootLB, clustername, configname string) (map[string]string, error) {
//}

//GetKubernetesConfigmapYAML returns yaml reprentation of the key-values
// func GetKubernetesConfigmapYAML(rootLBName string, clustername, configname string) (string, error) {
// 	log.DebugLog(log.DebugLevelMexos, "get kubernetes configmap", "rootlbname", rootLBName, "clustername", clustername, "configname", configname)
// 	rootLB, err := getRootLB(rootLBName)
// 	if err != nil {
// 		return "", err
// 	}
// 	if rootLB == nil {
// 		return "", fmt.Errorf("cannot get kubeconfigmap yaml, rootLB is null")
// 	}
// 	kp, err := ValidateKubernetesParameters(mf, rootLB, clustername)
// 	if err != nil {
// 		return "", err
// 	}
// 	//TODO support namespace
// 	cmd := fmt.Sprintf("%s kubectl get configmap %s -o yaml", kp.kubeconfig, configname)
// 	out, err := kp.client.Output(cmd)
// 	if err != nil {
// 		return "", fmt.Errorf("error getting configmap yaml, %s, %s, %v", cmd, out, err)
// 	}
// 	return out, nil
// }

func DeleteKubernetesAppManifest(mf *Manifest, kubeManifest string) error {
	log.DebugLog(log.DebugLevelMexos, "delete kubernetes app")
	rootLB, err := getRootLB(mf.Spec.RootLB)
	if err != nil {
		return err
	}
	if rootLB == nil {
		return fmt.Errorf("cannot remove kubernetes app manifest, rootLB is null")
	}
	if mf.Spec.URI == "" { //XXX TODO register to the DNS registry for public IP app,controller needs to tell us which kind of app
		return fmt.Errorf("empty app URI")
	}
	//TODO: support other URI: file://, nfs://, ftp://, git://, or embedded as base64 string
	//if !strings.Contains(mf.Spec.Flavor, "kubernetes") {
	//	return fmt.Errorf("unsupported kubernetes flavor %s", mf.Spec.Flavor)
	//}
	if err = ValidateCommon(mf); err != nil {
		return err
	}
	kp, err := ValidateKubernetesParameters(mf, rootLB, mf.Spec.Key)
	if err != nil {
		return err
	}
	// Clean up security rules and nginx proxy
	if err = DeleteProxySecurityRules(rootLB, mf, kp.ipaddr); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot clean up security rules", "name", mf.Metadata.Name, "rootlb", rootLB.Name, "error", err)
	}
	// Clean up DNS entries
	if err = KubeDeleteDNSRecords(rootLB, mf, kp); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot clean up DNS entries", "name", mf.Metadata.Name, "rootlb", rootLB.Name, "error", err)
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "deleted deployment", "name", mf.Metadata.Name)
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

func GetKubernetesNodes(mf *Manifest, rootLB *MEXRootLB) ([]KubernetesNode, error) {
	log.DebugLog(log.DebugLevelMexos, "getting kubernetes nodes")
	name, err := FindClusterWithKey(mf, mf.Spec.Key)
	if err != nil {
		return nil, fmt.Errorf("can't find cluster with key %s, %v", mf.Spec.Key, err)
	}
	ipaddr, err := FindNodeIP(mf, name)
	if err != nil {
		return nil, err
	}
	client, err := GetSSHClient(mf, rootLB.Name, mf.Values.Network.External, sshUser)
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
