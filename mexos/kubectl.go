package mexos

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/cloudflare"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

/*
func RunKubectl(clusterInst *edgeproto.ClusterInst, params string, rootLBName string) (*string, error) {
	log.DebugLog(log.DebugLevelMexos, "run kubectl", "params", params)

	//name, err := FindClusterWithKey(mf, mf.Spec.Key)
	//if err != nil {
	//	return nil, fmt.Errorf("can't find cluster with key %s, %v", mf.Spec.Key, err)
	//}
	client, err := GetSSHClient(rootLBName, GetCloudletExternalNetwork(), sshUser)
	if err != nil {
		return nil, fmt.Errorf("can't get ssh client, %v", err)
	}
	cmd := fmt.Sprintf("kubectl --kubeconfig %s.kubeconfig %s", rootLBName, params)
	out, err := client.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("kubectl failed, %v, %s", err, out)
	}
	return &out, nil
}
*/
func CreateDockerRegistrySecret(clusterInst *edgeproto.ClusterInst, rootLBName string) error {
	log.DebugLog(log.DebugLevelMexos, "creating docker registry secret in kubernetes")

	var out string
	var err error
	log.DebugLog(log.DebugLevelMexos, "creating docker registry secret in kubernetes cluster")
	if rootLBName == "" {
		log.DebugLog(log.DebugLevelMexos, "CreateDockerRegistrySecret locally, no rootLB")
		var o []byte
		o, err = sh.Command("kubectl", "create", "secret", "docker-registry", "mexregistrysecret", "--docker-server="+GetCloudletDockerRegistry(), "--docker-username=mobiledgex", "--docker-password="+GetCloudletDockerPass(), "--docker-email=mobiledgex@mobiledgex.com").CombinedOutput()
		out = string(o)
	} else {
		client, err := GetSSHClient(rootLBName, GetCloudletExternalNetwork(), sshUser)
		if err != nil {
			return fmt.Errorf("can't get ssh client, %v", err)
		}
		cmd := fmt.Sprintf("kubectl create secret docker-registry mexregistrysecret --docker-server=%s --docker-username=mobiledgex --docker-password=%s --docker-email=mobiledgex@mobiledgex.com --kubeconfig=%s", GetCloudletDockerRegistry(), GetCloudletDockerPass(), GetKconfName(clusterInst))

		out, err = client.Output(cmd)
	}
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

func runKubectlCreateApp(clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst, kubeManifest string) error {
	log.DebugLog(log.DebugLevelMexos, "run kubectl create app", "kubeManifest", kubeManifest)

	appName := NormalizeName(appInst.Key.AppKey.Name)

	kfile := appName + ".yaml"
	if err := writeKubeManifest(kubeManifest, kfile); err != nil {
		return err
	}
	defer os.Remove(kfile)
	kconf, err := GetKconf(clusterInst, false)
	if err != nil {
		return fmt.Errorf("error creating app due to kconf missing, %v, %v", clusterInst, err)
	}
	out, err := sh.Command("kubectl", "create", "-f", kfile, "--kubeconfig="+kconf).Output()
	if err != nil {
		return fmt.Errorf("error creating app, %s, %v, %v", out, appName, err)
	}
	err = createAppDNS(kconf, appInst.Uri, appName)
	if err != nil {
		return fmt.Errorf("error creating dns entry for app, %v, %v", appName, err)
	}
	return nil
}

func getSvcExternalIP(name string, kconf string) (string, error) {
	log.DebugLog(log.DebugLevelMexos, "get service external IP", "name", name, "kconf", kconf)
	externalIP := ""
	var out []byte
	var err error
	//wait for Load Balancer to assign external IP address. It takes a variable amount of time.
	for i := 0; i < 100; i++ {
		out, err = sh.Command("kubectl", "get", "svc", "--kubeconfig="+kconf, "-o", "json").Output()
		if err != nil {
			return "", fmt.Errorf("error getting svc %s, %s, %v", name, out, err)
		}
		svcs := &svcItems{}
		err = json.Unmarshal(out, svcs)
		if err != nil {
			return "", fmt.Errorf("error unmarshalling svc json, %v", err)
		}
		log.DebugLog(log.DebugLevelMexos, "getting externalIP, examine list of services", "name", name, "svcs", svcs)
		for _, item := range svcs.Items {
			log.DebugLog(log.DebugLevelMexos, "svc item", "item", item, "name", name)
			if item.Metadata.Name != name {
				log.DebugLog(log.DebugLevelMexos, "service name mismatch", "name", name, "item.Metadata.Name", item.Metadata.Name)
				continue
			}
			for _, ingress := range item.Status.LoadBalancer.Ingresses {
				log.DebugLog(log.DebugLevelMexos, "found ingress ip", "ingress.IP", ingress.IP, "item.Metadata.Name", item.Metadata.Name)

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

func getSvcNames(name string, kconf string) ([]string, error) {
	out, err := sh.Command("kubectl", "get", "svc", "--kubeconfig="+kconf, "-o", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("error getting svc %s, %s, %v", name, out, err)
	}
	svcs := &svcItems{}
	err = json.Unmarshal(out, svcs)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling svc json, %v", err)
	}
	var serviceNames []string
	for _, item := range svcs.Items {
		if strings.HasPrefix(item.Metadata.Name, name) {
			serviceNames = append(serviceNames, item.Metadata.Name)
		}
	}
	log.DebugLog(log.DebugLevelMexos, "service names", "names", serviceNames)
	return serviceNames, nil
}

func runKubectlDeleteApp(clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst, kubeManifest string) error {
	if err := cloudflare.InitAPI(GetCloudletCFUser(), GetCloudletCFKey()); err != nil {
		return fmt.Errorf("cannot init cloudflare api, %v", err)
	}

	appName := NormalizeName(appInst.Key.AppKey.Name)

	kconf, err := GetKconf(clusterInst, false)
	if err != nil {
		return fmt.Errorf("error deleting app due to kconf missing,  %v, %v", clusterInst, err)
	}
	kfile := appName + ".yaml"
	err = writeKubeManifest(kubeManifest, kfile)
	if err != nil {
		return err
	}
	defer os.Remove(kfile)
	serviceNames, err := getSvcNames(appName, kconf)
	if err != nil {
		return err
	}
	if len(serviceNames) < 1 {
		return fmt.Errorf("no service names starting with %s", appName)
	}
	out, err := sh.Command("kubectl", "delete", "-f", kfile, "--kubeconfig="+kconf).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error deleting app, %s, %v, %v", out, appName, err)
	}

	fqdnBase := uri2fqdn(appInst.Uri)
	dr, err := cloudflare.GetDNSRecords(GetCloudletDNSZone())
	if err != nil {
		return fmt.Errorf("cannot get dns records for %s, %v", GetCloudletDNSZone(), err)
	}
	for _, sn := range serviceNames {
		fqdn := cloudcommon.ServiceFQDN(sn, fqdnBase)
		for _, d := range dr {
			if d.Type == "A" && d.Name == fqdn {
				if err := cloudflare.DeleteDNSRecord(GetCloudletDNSZone(), d.ID); err != nil {
					return fmt.Errorf("cannot delete DNS record, %v", d)
				}
				log.DebugLog(log.DebugLevelMexos, "deleted DNS record", "name", fqdn)
			}
		}
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
