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
	"github.com/mobiledgex/edge-cloud/log"
)

func RunKubectl(mf *Manifest, params string) (*string, error) {
	log.DebugLog(log.DebugLevelMexos, "run kubectl", "params", params)
	rootLB, err := getRootLB(mf.Spec.RootLB)
	if err != nil {
		return nil, err
	}
	if rootLB == nil {
		return nil, fmt.Errorf("failed to create docker registry secret, rootLB is null")
	}
	//name, err := FindClusterWithKey(mf, mf.Spec.Key)
	//if err != nil {
	//	return nil, fmt.Errorf("can't find cluster with key %s, %v", mf.Spec.Key, err)
	//}
	client, err := GetSSHClient(mf, rootLB.Name, mf.Values.Network.External, sshUser)
	if err != nil {
		return nil, fmt.Errorf("can't get ssh client, %v", err)
	}
	cmd := fmt.Sprintf("kubectl --kubeconfig %s.kubeconfig %s", rootLB.Name, params)
	out, err := client.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("kubectl failed, %v, %s", err, out)
	}
	return &out, nil
}

func CreateDockerRegistrySecret(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "creating docker registry secret in kubernetes")
	rootLB, err := getRootLB(mf.Spec.RootLB)
	if err != nil {
		return err
	}
	if rootLB == nil {
		return fmt.Errorf("failed to create docker registry secret, rootLB is null")
	}

	var out string
	//log.DebugLog(log.DebugLevelMexos, "CreateDockerRegistrySecret", "mf", mf)
	log.DebugLog(log.DebugLevelMexos, "creating docker registry secret in kubernetes cluster")
	if IsLocalDIND(mf) || mf.Metadata.Operator == "gcp" || mf.Metadata.Operator == "azure" {
		log.DebugLog(log.DebugLevelMexos, "CreateDockerRegistrySecret locally non OpenStack case")
		var o []byte
		o, err = sh.Command("kubectl", "create", "secret", "docker-registry", "mexregistrysecret", "--docker-server="+mf.Values.Registry.Docker, "--docker-username=mobiledgex", "--docker-password="+mexEnv(mf, "MEX_DOCKER_REG_PASS"), "--docker-email=mobiledgex@mobiledgex.com").CombinedOutput()
		out = string(o)
	} else {
		client, err := GetSSHClient(mf, rootLB.Name, mf.Values.Network.External, sshUser)
		if err != nil {
			return fmt.Errorf("can't get ssh client, %v", err)
		}
		cmd := fmt.Sprintf("kubectl create secret docker-registry mexregistrysecret --docker-server=%s --docker-username=mobiledgex --docker-password=%s --docker-email=mobiledgex@mobiledgex.com --kubeconfig=%s", mf.Values.Registry.Docker, mexEnv(mf, "MEX_DOCKER_REG_PASS"), GetKconfName(mf))

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

func runKubectlCreateApp(mf *Manifest, kubeManifest string) error {
	log.DebugLog(log.DebugLevelMexos, "run kubectl create app", "kubeManifest", kubeManifest)
	//if err := CreateDockerRegistrySecret(mf); err != nil {
	//	return err
	//}
	kfile := mf.Metadata.Name + ".yaml"
	if err := writeKubeManifest(kubeManifest, kfile); err != nil {
		return err
	}
	defer os.Remove(kfile)
	kconf, err := GetKconf(mf, false)
	if err != nil {
		return fmt.Errorf("error creating app due to kconf missing, %v, %v", mf, err)
	}
	out, err := sh.Command("kubectl", "create", "-f", kfile, "--kubeconfig="+kconf).Output()
	if err != nil {
		return fmt.Errorf("error creating app, %s, %v, %v", out, err, mf)
	}
	err = createAppDNS(mf, kconf)
	if err != nil {
		return fmt.Errorf("error creating dns entry for app, %v, %v", err, mf)
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

func runKubectlDeleteApp(mf *Manifest, kubeManifest string) error {
	if err := CheckCredentialsCF(mf); err != nil {
		return err
	}
	if err := cloudflare.InitAPI(mexEnv(mf, "MEX_CF_USER"), mexEnv(mf, "MEX_CF_KEY")); err != nil {
		return fmt.Errorf("cannot init cloudflare api, %v", err)
	}
	kconf, err := GetKconf(mf, false)
	if err != nil {
		return fmt.Errorf("error deleting app due to kconf missing,  %v, %v", mf, err)
	}
	kfile := mf.Metadata.Name + ".yaml"
	err = writeKubeManifest(kubeManifest, kfile)
	if err != nil {
		return err
	}
	defer os.Remove(kfile)
	serviceNames, err := getSvcNames(mf.Metadata.Name, kconf)
	if err != nil {
		return err
	}
	if len(serviceNames) < 1 {
		return fmt.Errorf("no service names starting with %s", mf.Metadata.Name)
	}
	out, err := sh.Command("kubectl", "delete", "-f", kfile, "--kubeconfig="+kconf).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error deleting app, %s, %v, %v", out, mf, err)
	}
	if mf.Metadata.DNSZone == "" {
		return fmt.Errorf("missing dns zone, metadata %v", mf.Metadata)
	}
	fqdnBase := uri2fqdn(mf.Spec.URI)
	dr, err := cloudflare.GetDNSRecords(mf.Metadata.DNSZone)
	if err != nil {
		return fmt.Errorf("cannot get dns records for %s, %v", mf.Metadata.DNSZone, err)
	}
	for _, sn := range serviceNames {
		fqdn := cloudcommon.ServiceFQDN(sn, fqdnBase)
		for _, d := range dr {
			if d.Type == "A" && d.Name == fqdn {
				if err := cloudflare.DeleteDNSRecord(mf.Metadata.DNSZone, d.ID); err != nil {
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
