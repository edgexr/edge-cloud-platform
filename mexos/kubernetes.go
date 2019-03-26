package mexos

import (
	"fmt"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/cloudflare"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/nanobox-io/golang-ssh"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
)

type KubeNames struct {
	appName           string
	appURI            string
	appImage          string
	clusterName       string
	k8sNodeNameSuffix string
	operatorName      string
	kconfName         string
	serviceNames      []string
}

func (k *KubeNames) containsService(svc string) bool {
	for _, s := range k.serviceNames {
		if s == svc {
			return true
		}
	}
	return false
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
	kubeNames.k8sNodeNameSuffix = GetK8sNodeNameSuffix(clusterInst)
	kubeNames.appName = NormalizeName(app.Key.Name)
	kubeNames.appURI = appInst.Uri
	kubeNames.appImage = NormalizeName(app.ImagePath)
	kubeNames.operatorName = NormalizeName(clusterInst.Key.CloudletKey.OperatorKey.Name)
	kubeNames.kconfName = GetKconfName(clusterInst)

	//get service names from the yaml
	if app.Deployment == cloudcommon.AppDeploymentTypeKubernetes {
		objs, _, err := cloudcommon.DecodeK8SYaml(app.DeploymentManifest)
		if err != nil {
			return fmt.Errorf("invalid kubernetes deployment yaml, %s", err.Error())
		}
		for _, o := range objs {
			log.DebugLog(log.DebugLevelMexos, "k8s obj", "obj", o)
			ksvc, ok := o.(*v1.Service)
			if !ok {
				continue
			}
			svcName := ksvc.ObjectMeta.Name
			kubeNames.serviceNames = append(kubeNames.serviceNames, svcName)
		}
	}
	return nil

}

// Merge in all the environment variables into
func MergeEnvVars(kubeManifest string, configs []*edgeproto.ConfigFile) (string, error) {
	var envVars []v1.EnvVar
	var files []string
	//quick bail, if nothing to do
	if len(configs) == 0 {
		return kubeManifest, nil
	}

	// Walk the Configs in the App and get all the environment variables together
	for _, v := range configs {
		if v.Kind == AppConfigEnvYaml {
			var curVars []v1.EnvVar
			if err1 := yaml.Unmarshal([]byte(v.Config), &curVars); err1 != nil {
				log.DebugLog(log.DebugLevelMexos, "cannot unmarshal env vars", "kind", v.Kind,
					"config", v.Config, "error", err1)
			} else {
				envVars = append(envVars, curVars...)
			}
		}
	}
	//nothing to do if no variables to merge
	if len(envVars) == 0 {
		return kubeManifest, nil
	}
	log.DebugLog(log.DebugLevelMexos, "Merging environment variables", "envVars", envVars)
	mf, err := cloudcommon.GetDeploymentManifest(kubeManifest)
	if err != nil {
		return mf, err
	}
	//decode the objects so we can find the container objects, where we'll add the env vars
	objs, _, err := cloudcommon.DecodeK8SYaml(mf)
	if err != nil {
		return kubeManifest, fmt.Errorf("invalid kubernetes deployment yaml, %s", err.Error())
	}

	//walk the objects
	for i, _ := range objs {
		//make sure we are working on the Deployment object
		deployment, ok := objs[i].(*appsv1.Deployment)
		if !ok {
			continue
		}
		//walk the containers and append environment variables to each
		for i, _ := range deployment.Spec.Template.Spec.Containers {
			deployment.Spec.Template.Spec.Containers[i].Env =
				append(deployment.Spec.Template.Spec.Containers[i].Env, envVars...)
		}
		//there should only be one deployment object, so break out of the loop
		break
	}
	//marshal the objects back together and return as one string
	for _, o := range objs {
		d, err := yaml.Marshal(o)
		if err != nil {
			return kubeManifest, fmt.Errorf("unable to marshal the k8s objects back together, %s", err.Error())
		} else {
			files = append(files, string(d))
		}
	}
	mf = strings.Join(files, "---\n")
	return mf, nil
}

//CreateKubernetesAppInst instantiates a new kubernetes deployment
func CreateKubernetesAppInst(rootLB *MEXRootLB, kubeNames *KubeNames, clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst, kubeManifest string, configs []*edgeproto.ConfigFile) error {
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

	// Merge in environment variables
	mf, err := MergeEnvVars(kubeManifest, configs)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "failed to merge env vars", "error", err)
	}
	log.DebugLog(log.DebugLevelMexos, "writing config file", "kubeManifest", mf)
	file, err := WriteConfigFile(kp, kubeNames.appName, mf, "K8s Deployment")
	if err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "running kubectl create ", "file", file)
	cmd = fmt.Sprintf("%s kubectl create -f %s", kp.kubeconfig, file)

	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deploying kubernetes app, %s, %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "done kubectl create")
	err = AddProxySecurityRulesAndPatchDNS(rootLB, kp, kubeNames, appInst)
	if err != nil {
		return fmt.Errorf("CreateKubernetesAppInst error: %v", err)
	}

	return nil
}

type kubeParam struct {
	kubeconfig string
	client     ssh.Client
	ipaddr     string
}

func getClusterSSHClient(rootLBName string) (ssh.Client, error) {
	if CloudletIsDirectKubectlAccess() {
		// No ssh jump host (rootlb) but kconf configures how to
		// talk to remote kubernetes cluster.  This includes DIND, AKS, GCP
		return &sshLocal{}, nil
	}
	if rootLBName == "" {
		return nil, fmt.Errorf("cannot validate kubernetes parameters, rootLB is empty")
	}
	if GetCloudletExternalNetwork() == "" {
		return nil, fmt.Errorf("validate kubernetes parameters, missing external network in platform config")
	}
	client, err := GetSSHClient(rootLBName, GetCloudletExternalNetwork(), sshUser)
	if err != nil {
		return nil, err
	}
	return client, nil
}

//ValidateKubernetesParameters checks the kubernetes parameters and kubeconfig settings
func ValidateKubernetesParameters(rootLB *MEXRootLB, kubeNames *KubeNames, clusterInst *edgeproto.ClusterInst) (*kubeParam, error) {
	log.DebugLog(log.DebugLevelMexos, "validate kubernetes parameters", "kubeNames", kubeNames)

	if rootLB == nil {
		return nil, fmt.Errorf("cannot validate kubernetes parameters, rootLB is null")
	}
	client, err := getClusterSSHClient(rootLB.Name)
	if err != nil {
		return nil, err
	}
	if CloudletIsDirectKubectlAccess() {
		// No ssh jump host (rootlb) but kconf configures how to
		// talk to remote kubernetes cluster.  This includes DIND, AKS, GCP
		kconf, err := GetKconf(clusterInst)
		if err != nil {
			return nil, fmt.Errorf("kconf missing, %v, %v", kubeNames.clusterName, err)
		}
		kp := kubeParam{
			kubeconfig: fmt.Sprintf("KUBECONFIG=%s", kconf),
			client:     client,
		}
		return &kp, nil
	}
	if GetCloudletExternalNetwork() == "" {
		return nil, fmt.Errorf("validate kubernetes parameters, missing external network in platform config")
	}
	srvs, err := ListServers()
	if err != nil {
		return nil, fmt.Errorf("error getting server list: %v", err)

	}
	master, err := FindClusterMaster(kubeNames.k8sNodeNameSuffix, srvs)
	if err != nil {
		return nil, fmt.Errorf("can't find cluster with key %s, %v", kubeNames.k8sNodeNameSuffix, err)
	}
	ipaddr, err := FindNodeIP(master, srvs)
	if err != nil {
		return nil, err
	}
	kubeconfig := fmt.Sprintf("KUBECONFIG=%s", kubeNames.kconfName)
	return &kubeParam{kubeconfig, client, ipaddr}, nil
}

func DeleteKubernetesAppInst(rootLB *MEXRootLB, kubeNames *KubeNames, clusterInst *edgeproto.ClusterInst) error {
	log.DebugLog(log.DebugLevelMexos, "delete kubernetes app", "kubeNames", kubeNames)

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
	if err = KubeDeleteDNSRecords(rootLB, kp, kubeNames); err != nil {
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
