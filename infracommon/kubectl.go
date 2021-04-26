package infracommon

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
	v1 "k8s.io/api/core/v1"
)

// getSecretAuth returns secretName, dockerServer, auth, error
func getSecretAuth(ctx context.Context, imagePath string, authApi cloudcommon.RegistryAuthApi, existingCreds *cloudcommon.RegistryAuth) (string, string, *cloudcommon.RegistryAuth, error) {
	var err error
	var auth *cloudcommon.RegistryAuth
	if existingCreds == nil {
		auth, err = authApi.GetRegistryAuth(ctx, imagePath)
		if err != nil {
			return "", "", nil, err
		}
	} else {
		auth = existingCreds
		if auth.Username == "" || auth.Password == "" {
			// no creds found, assume public registry
			log.SpanLog(ctx, log.DebugLevelApi, "warning, no credentials found, assume public registry")
			auth.AuthType = cloudcommon.NoAuth
		}
	}
	if auth == nil || auth.AuthType == cloudcommon.NoAuth {
		log.SpanLog(ctx, log.DebugLevelInfra, "warning, cannot get docker registry secret from vault - assume public registry")
		return "", "", nil, nil
	}
	if auth.AuthType != cloudcommon.BasicAuth {
		return "", "", nil, fmt.Errorf("auth type for %s is not basic auth type", auth.Hostname)
	}
	// Note: docker-server must contain port if imagepath contains port,
	// otherwise imagepullsecrets won't work.
	// Also secret name includes port in case multiple docker registries
	// are running on different ports on the same host.
	secretName := auth.Hostname
	dockerServer := auth.Hostname
	if auth.Port != "" {
		secretName = auth.Hostname + "-" + auth.Port
		dockerServer = auth.Hostname + ":" + auth.Port
	}
	return secretName, dockerServer, auth, nil
}

func DeleteDockerRegistrySecret(ctx context.Context, client ssh.Client, kconf string, imagePath string, authApi cloudcommon.RegistryAuthApi, names *k8smgmt.KubeNames, existingCreds *cloudcommon.RegistryAuth) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting docker registry secret in kubernetes cluster", "imagePath", imagePath)
	secretName, _, auth, err := getSecretAuth(ctx, imagePath, authApi, existingCreds)
	if err != nil {
		return err
	}
	if auth == nil {
		return nil
	}
	cmd := fmt.Sprintf("kubectl delete secret  %s --kubeconfig=%s", secretName, kconf)
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateDockerRegistrySecret", "secretName", secretName)
	out, err := client.Output(cmd)
	if err != nil {
		if !strings.Contains(out, "not found") {
			return fmt.Errorf("can't delete docker registry secret, %s, %v", out, err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "warning, docker registry secret already gone")
	}
	return nil
}

func CreateDockerRegistrySecret(ctx context.Context, client ssh.Client, kconf string, imagePath string, authApi cloudcommon.RegistryAuthApi, names *k8smgmt.KubeNames, existingCreds *cloudcommon.RegistryAuth) error {
	var out string
	log.SpanLog(ctx, log.DebugLevelInfra, "creating docker registry secret in kubernetes cluster", "imagePath", imagePath)
	secretName, dockerServer, auth, err := getSecretAuth(ctx, imagePath, authApi, existingCreds)
	if err != nil {
		return err
	}
	if auth == nil {
		return nil
	}
	// Note that the registry secret name must be per-app, since a developer
	// may put multiple apps in the same ClusterInst and they may come
	// from different registries.
	cmd := fmt.Sprintf("kubectl create secret docker-registry %s "+
		"--docker-server=%s --docker-username='%s' --docker-password='%s' "+
		"--docker-email=mobiledgex@mobiledgex.com --kubeconfig=%s",
		secretName, dockerServer, auth.Username, auth.Password,
		kconf)
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateDockerRegistrySecret", "secretName", secretName)
	out, err = client.Output(cmd)
	if err != nil {
		if !strings.Contains(out, "AlreadyExists") {
			return fmt.Errorf("can't add docker registry secret, %s, %v", out, err)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "warning, docker registry secret already exists.")
		}
	}
	names.ImagePullSecrets = append(names.ImagePullSecrets, secretName)
	log.SpanLog(ctx, log.DebugLevelInfra, "ok, created registry secret", "out", out)
	return nil
}

// ConfigMap of cluster instance details such as cluster name, cloudlet name, and operator name
func CreateClusterConfigMap(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst) error {
	var out string

	log.SpanLog(ctx, log.DebugLevelInfra, "creating cluster config map in kubernetes cluster")

	cmd := fmt.Sprintf("kubectl create configmap mexcluster-info "+
		"--from-literal=ClusterName='%s' "+
		"--from-literal=CloudletName='%s' "+
		"--from-literal=Organization='%s' --kubeconfig=%s",
		clusterInst.Key.ClusterKey.Name, clusterInst.Key.CloudletKey.Name,
		clusterInst.Key.CloudletKey.Organization,
		k8smgmt.GetKconfName(clusterInst))

	out, err := client.Output(cmd)
	if err != nil {
		if !strings.Contains(out, "AlreadyExists") {
			return fmt.Errorf("can't add cluster ConfigMap cmd %s, %s, %v", cmd, out, err)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "warning, Cluster ConfigMap already exists.")
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "ok, created mexcluster-info configmap")
	return nil
}

// GetSvcExternalIpOrHost returns ipaddr, hostname.  Either the IP or the DNS will be blank depending
// on whether the service has an IP address or a name.
func GetSvcExternalIpOrHost(ctx context.Context, client ssh.Client, kubeNames *k8smgmt.KubeNames, name string) (string, string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "get service external IP", "name", name)
	externalIP := ""
	dnsName := ""
	//wait for Load Balancer to assign external IP address. It takes a variable amount of time.
	for i := 0; i < 100; i++ {
		cmd := fmt.Sprintf("%s kubectl get svc -o json", kubeNames.KconfEnv)
		out, err := client.Output(cmd)
		if err != nil {
			return "", "", fmt.Errorf("error getting svc %s, %s, %v", name, out, err)
		}
		svcs, err := GetServices(ctx, client, kubeNames)
		if err != nil {
			return "", "", err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "getting externalIP, examine list of services", "name", name, "svcs", svcs)
		for _, svc := range svcs {
			log.SpanLog(ctx, log.DebugLevelInfra, "svc item", "item", svc, "name", name)
			if svc.ObjectMeta.Name != name {
				log.SpanLog(ctx, log.DebugLevelInfra, "service name mismatch", "name", name, "svc.ObjectMeta.Name", svc.ObjectMeta.Name)
				continue
			}
			for _, ingress := range svc.Status.LoadBalancer.Ingress {
				log.SpanLog(ctx, log.DebugLevelInfra, "found ingress ip", "ingress.IP", ingress.IP, "svc.ObjectMeta.Name", svc.ObjectMeta.Name)
				if ingress.Hostname != "" {
					dnsName = ingress.Hostname
					log.SpanLog(ctx, log.DebugLevelInfra, "got external dnsName for app", "dnsName", dnsName)
					return externalIP, dnsName, nil
				}
				if ingress.IP != "" {
					externalIP = ingress.IP
					log.SpanLog(ctx, log.DebugLevelInfra, "got external IP for app", "externalIP", externalIP)
					return externalIP, dnsName, nil
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
	if externalIP == "" {
		return "", "", fmt.Errorf("timed out trying to get externalIP")
	}
	return externalIP, dnsName, nil
}

func GetServices(ctx context.Context, client ssh.Client, names *k8smgmt.KubeNames) ([]v1.Service, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "get services", "kconf", names.KconfName)
	svcs := svcItems{}
	if names.DeploymentType == cloudcommon.DeploymentTypeDocker {
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
		return nil, fmt.Errorf("can not get list of services: %s, %s, %v", cmd, out, err)
	}
	err = json.Unmarshal([]byte(out), &svcs)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot unmarshal svc json", "out", out, "err", err)
		return nil, fmt.Errorf("cannot unmarshal svc json, %s", err.Error())
	}
	return svcs.Items, nil
}

func BackupKubeconfig(ctx context.Context, client ssh.Client) {
	kc := DefaultKubeconfig()
	cmd := fmt.Sprintf("mv %s %s.save", kc, kc)
	out, err := client.Output(cmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "can't rename", "name", kc, "err", err, "out", out)
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
