package mexos

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	v1 "k8s.io/api/core/v1"
)

func CreateDockerRegistrySecret(client pc.PlatformClient, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, vaultAddr string) error {
	var out string
	log.DebugLog(log.DebugLevelMexos, "creating docker registry secret in kubernetes cluster")
	auth, err := cloudcommon.GetRegistryAuth(app.ImagePath, vaultAddr)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "warning, cannot get docker registry secret from vault - assume public registry", "err", err)
		return nil
	}
	if auth.AuthType != cloudcommon.BasicAuth {
		return fmt.Errorf("auth type for %s is not basic auth type", auth.Hostname)
	}

	// Note that the registry secret name must be per-app, since a developer
	// may put multiple apps in the same ClusterInst and they may come
	// from different registries.
	cmd := fmt.Sprintf("kubectl create secret docker-registry %s "+
		"--docker-server=%s --docker-username=%s --docker-password=%s "+
		"--docker-email=mobiledgex@mobiledgex.com --kubeconfig=%s",
		auth.Hostname, auth.Hostname, auth.Username, auth.Password,
		k8smgmt.GetKconfName(clusterInst))
	log.DebugLog(log.DebugLevelMexos, "CreateDockerRegistrySecret", "cmd", cmd)
	out, err = client.Output(cmd)
	if err != nil {
		if !strings.Contains(out, "AlreadyExists") {
			return fmt.Errorf("can't add docker registry secret, %s, %v", out, err)
		} else {
			log.DebugLog(log.DebugLevelMexos, "warning, docker registry secret already exists.")
		}
	}
	log.DebugLog(log.DebugLevelMexos, "ok, created registry secret", "out", out)
	return nil
}

// ConfigMap of cluster instance details such as cluster name, cloudlet name, and operator name
func CreateClusterConfigMap(client pc.PlatformClient, clusterInst *edgeproto.ClusterInst) error {
	var out string

	log.DebugLog(log.DebugLevelMexos, "creating cluster config map in kubernetes cluster")

	cmd := fmt.Sprintf("kubectl create configmap mexcluster-info "+
		"--from-literal=ClusterName=%s "+
		"--from-literal=CloudletName=%s "+
		"--from-literal=OperatorName=%s --kubeconfig=%s",
		clusterInst.Key.ClusterKey.Name, clusterInst.Key.CloudletKey.Name,
		clusterInst.Key.CloudletKey.OperatorKey.Name,
		k8smgmt.GetKconfName(clusterInst))

	out, err := client.Output(cmd)
	if err != nil {
		if !strings.Contains(out, "AlreadyExists") {
			return fmt.Errorf("can't add cluster ConfigMap, %s, %v", out, err)
		} else {
			log.DebugLog(log.DebugLevelMexos, "warning, Cluster ConfigMap already exists.")
		}
	}
	log.DebugLog(log.DebugLevelMexos, "ok, created mexcluster-info configmap")
	return nil
}

func GetSvcExternalIP(client pc.PlatformClient, kubeNames *k8smgmt.KubeNames, name string) (string, error) {
	log.DebugLog(log.DebugLevelMexos, "get service external IP", "name", name)
	externalIP := ""
	//wait for Load Balancer to assign external IP address. It takes a variable amount of time.
	for i := 0; i < 100; i++ {
		cmd := fmt.Sprintf("%s kubectl get svc -o json", kubeNames.KconfEnv)
		out, err := client.Output(cmd)
		if err != nil {
			return "", fmt.Errorf("error getting svc %s, %s, %v", name, out, err)
		}
		svcs, err := GetServices(client, kubeNames)
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

func GetServices(client pc.PlatformClient, names *k8smgmt.KubeNames) ([]v1.Service, error) {
	log.DebugLog(log.DebugLevelMexos, "get services", "kconf", names.KconfName)
	svcs := svcItems{}
	if names.DeploymentType == cloudcommon.AppDeploymentTypeDocker {
		// just populate the service names
		for _, sn := range names.ServiceNames {
			item := v1.Service{}
			item.Name = sn
			svcs.Items = append(svcs.Items, item)
		}
		return svcs.Items, nil
	}

	cmd := fmt.Sprintf("%s kubectl get svc -o json", names.KconfEnv)
	out, err := client.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("can not get list of services, %s, %v", out, err)
	}
	err = json.Unmarshal([]byte(out), &svcs)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot unmarshal svc json", "out", out, "err", err)
		return nil, fmt.Errorf("cannot unmarshal svc json, %s", err.Error())
	}
	return svcs.Items, nil
}

func BackupKubeconfig(client pc.PlatformClient) {
	kc := DefaultKubeconfig()
	cmd := fmt.Sprintf("mv %s %s.save", kc, kc)
	out, err := client.Output(cmd)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "can't rename", "name", kc, "err", err, "out", out)
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
