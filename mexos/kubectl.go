package mexos

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"k8s.io/api/core/v1"
)

func CreateDockerRegistrySecret(clusterInst *edgeproto.ClusterInst, rootLBName string) error {
	var out string

	log.DebugLog(log.DebugLevelMexos, "creating docker registry secret in kubrnetes cluster")

	client, err := getClusterSSHClient(rootLBName)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf("kubectl create secret docker-registry mexregistrysecret "+
		"--docker-server=%s --docker-username=mobiledgex --docker-password=%s "+
		"--docker-email=mobiledgex@mobiledgex.com --kubeconfig=%s",
		GetCloudletDockerRegistry(), GetCloudletDockerPass(), GetKconfName(clusterInst))
	out, err = client.Output(cmd)
	if err != nil {
		if !strings.Contains(out, "AlreadyExists") {
			return fmt.Errorf("can't add docker registry secret, %s, %v", out, err)
		} else {
			log.DebugLog(log.DebugLevelMexos, "warning, docker registry secret already exists.")
		}
	}
	log.DebugLog(log.DebugLevelMexos, "ok, created mexregistrysecret")
	return nil
}

// ConfigMap of cluster instance details such as cluster name, cloudlet name, and operator name
func CreateClusterConfigMap(clusterInst *edgeproto.ClusterInst, rootLBName string) error {
	var out string

	log.DebugLog(log.DebugLevelMexos, "creating cluster config map in kubernetes cluster")

	client, err := getClusterSSHClient(rootLBName)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf("kubectl create configmap cluster-info "+
		"--from-literal=ClusterName=%s "+
		"--from-literal=CloudletName=%s "+
		"--from-literal=OperatorName=%s --kubeconfig=%s",
		clusterInst.Key.ClusterKey.Name, clusterInst.Key.CloudletKey.Name,
		clusterInst.Key.CloudletKey.OperatorKey.Name, GetKconfName(clusterInst))

	out, err = client.Output(cmd)
	if err != nil {
		if !strings.Contains(out, "AlreadyExists") {
			return fmt.Errorf("can't add cluster ConfigMap, %s, %v", out, err)
		} else {
			log.DebugLog(log.DebugLevelMexos, "warning, Cluster ConfigMap already exists.")
		}
	}
	log.DebugLog(log.DebugLevelMexos, "ok, created cluster-info configmap")
	return nil
}

func runKubectlCreateApp(rootLB *MEXRootLB, kubeNames *KubeNames, clusterInst *edgeproto.ClusterInst, kubeManifest string) error {
	log.DebugLog(log.DebugLevelMexos, "run kubectl create app", "kubeManifest", kubeManifest)

	kfile := kubeNames.appName + ".yaml"

	if err := writeKubeManifest(kubeManifest, kfile); err != nil {
		return err
	}
	defer os.Remove(kfile)

	kp, err := ValidateKubernetesParameters(rootLB, kubeNames, clusterInst)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf("%s kubectl create -f %s", kp.kubeconfig, kfile)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error creating app, %s, %v, %s", out, err, kubeManifest)
	}
	defer func() {
		if err != nil {
			cmd = fmt.Sprintf("%s kubectl delete -f %s", kp.kubeconfig, kfile)
			out, undoerr := kp.client.Output(cmd)
			if undoerr != nil {
				log.DebugLog(log.DebugLevelMexos, "undo kubectl create app failed", "kubeNames", kubeNames, "out", out, "err", undoerr)
			}
		}
	}()
	err = createAppDNS(kp, kubeNames)
	if err != nil {
		return fmt.Errorf("error creating dns entry for app, %v", err)
	}
	return nil
}

func getSvcExternalIP(name string, kp *kubeParam) (string, error) {
	log.DebugLog(log.DebugLevelMexos, "get service external IP", "name", name, "kp", kp)
	externalIP := ""
	//wait for Load Balancer to assign external IP address. It takes a variable amount of time.
	for i := 0; i < 100; i++ {
		cmd := fmt.Sprintf("%s kubectl get svc -o json", kp.kubeconfig)
		out, err := kp.client.Output(cmd)
		if err != nil {
			return "", fmt.Errorf("error getting svc %s, %s, %v", name, out, err)
		}
		svcs, err := getServices(kp)
		if err != nil {
			return "", err
		}
		log.DebugLog(log.DebugLevelMexos, "getting externalIP, examine list of services", "name", name, "svcs", svcs)
		for _, svc := range svcs {
			log.DebugLog(log.DebugLevelMexos, "svc item", "item", svc, "name", name)
			if svc.ObjectMeta.Name != name {
				log.DebugLog(log.DebugLevelMexos, "service name mismatch", "name", name, "svc.ObjectMeta.Name", svc.ObjectMeta.Name)
				continue
			}
			for _, ingress := range svc.Status.LoadBalancer.Ingress {
				log.DebugLog(log.DebugLevelMexos, "found ingress ip", "ingress.IP", ingress.IP, "svc.ObjectMeta.Name", svc.ObjectMeta.Name)
				if ingress.IP != "" {
					externalIP = ingress.IP
					log.DebugLog(log.DebugLevelMexos, "got externaIP for app", "externalIP", externalIP)
					return externalIP, nil
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
	if externalIP == "" {
		return "", fmt.Errorf("timed out trying to get externalIP")
	}
	return externalIP, nil
}

func getServices(kp *kubeParam) ([]v1.Service, error) {
	log.DebugLog(log.DebugLevelMexos, "running kubectl get svc", "kubeconfig", kp.kubeconfig)

	cmd := fmt.Sprintf("%s kubectl get svc -o json", kp.kubeconfig)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("can not get list of services, %s, %v", out, err)
	}
	svcs := svcItems{}
	err = json.Unmarshal([]byte(out), &svcs)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot unmarshal svc json", "out", out, "err", err)
		return nil, fmt.Errorf("cannot unmarshal svc json, %s", err.Error())
	}
	return svcs.Items, nil
}

func runKubectlDeleteApp(rootLB *MEXRootLB, kubeNames *KubeNames, clusterInst *edgeproto.ClusterInst, kubeManifest string) error {

	kp, err := ValidateKubernetesParameters(rootLB, kubeNames, clusterInst)
	if err != nil {
		return err
	}
	kfile := kubeNames.appName + ".yaml"
	err = writeKubeManifest(kubeManifest, kfile)
	if err != nil {
		return err
	}
	defer os.Remove(kfile)
	cmd := fmt.Sprintf("%s kubectl delete -f %s", kp.kubeconfig, kfile)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deleting app, %s, %v", out, err)
	}
	err = deleteAppDNS(kp, kubeNames)
	if err != nil {
		return fmt.Errorf("error deleting dns entry for app, %v, %v", kubeNames.appName, err)
	}
	return nil
}

func saveKubeconfig() {
	kc := defaultKubeconfig()
	if err := os.Rename(kc, kc+".save"); err != nil {
		log.DebugLog(log.DebugLevelMexos, "can't rename", "name", kc, "error", err)
	}
}

func parseKCPort(ln string) int {
	if !strings.Contains(ln, "kubectl") {
		return 0
	}
	if !strings.Contains(ln, "--port") {
		return 0
	}
	var a, b, c, port string
	n, serr := fmt.Sscanf(ln, "%s %s %s %s", &a, &b, &c, &port)
	if serr != nil {
		return 0
	}
	if n != 4 {
		return 0
	}
	portnum, aerr := strconv.Atoi(port)
	if aerr != nil {
		return 0
	}
	return portnum
}

func parseKCPid(ln string, key string) int {
	ln = strings.TrimSpace(ln)
	if !strings.Contains(ln, "kubectl") {
		return 0
	}
	if !strings.HasSuffix(ln, key) {
		return 0
	}
	var pid string
	n, serr := fmt.Sscanf(ln, "%s", &pid)
	if serr != nil {
		return 0
	}
	if n != 1 {
		return 0
	}
	pidnum, aerr := strconv.Atoi(pid)
	if aerr != nil {
		return 0
	}
	return pidnum
}
