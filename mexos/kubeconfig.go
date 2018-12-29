package mexos

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ghodss/yaml"
	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/azure"
	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/gcloud"
	"github.com/mobiledgex/edge-cloud/log"
)

func GetLocalKconfName(mf *Manifest) string {
	kconf := fmt.Sprintf("%s/%s", MEXDir(), GetKconfName(mf))
	if mf.Metadata.Operator != "gcp" &&
		mf.Metadata.Operator != "azure" {
		return kconf + "-proxy"
	}
	return kconf
}

func GetKconfName(mf *Manifest) string {
	return fmt.Sprintf("%s.%s.%s.kubeconfig",
		mf.Values.Cluster.Name,
		mf.Values.Operator.Name,
		mf.Values.Network.DNSZone)
}

func GetKconf(mf *Manifest, createIfMissing bool) (string, error) {
	name := GetLocalKconfName(mf)
	log.DebugLog(log.DebugLevelMexos, "get kubeconfig name", "name", name)
	if createIfMissing { // XXX
		log.DebugLog(log.DebugLevelMexos, "warning, creating missing kubeconfig", "name", name)
		if _, err := os.Stat(name); os.IsNotExist(err) {
			// if kubeconfig does not exist, optionally create it.  It is possible it was
			// created on a different container or we had a restart of the container
			log.DebugLog(log.DebugLevelMexos, "creating missing kconf file", "name", name)
			switch mf.Metadata.Operator {
			case "gcp":
				if err = gcloud.GetGKECredentials(mf.Metadata.Name); err != nil {
					return "", fmt.Errorf("unable to get GKE credentials %v", err)
				}
				if err = copyFile(defaultKubeconfig(), name); err != nil {
					return "", fmt.Errorf("can't copy %s, %v", defaultKubeconfig(), err)
				}
			case "azure":
				if err = azure.GetAKSCredentials(mf.Metadata.ResourceGroup, mf.Metadata.Name); err != nil {
					return "", fmt.Errorf("unable to get AKS credentials %v", err)
				}
				if err = copyFile(defaultKubeconfig(), name); err != nil {
					return "", fmt.Errorf("can't copy %s, %v", defaultKubeconfig(), err)
				}
			default:
				log.DebugLog(log.DebugLevelMexos, "warning, not creating missing kubeconfig for operator", "operator", mf.Metadata.Operator)
			}
		}
	}
	return name, nil
}

type clusterDetailKc struct {
	CertificateAuthorityData string `json:"certificate-authority-data"`
	Server                   string `json:"server"`
}

type clusterKc struct {
	Name    string          `json:"name"`
	Cluster clusterDetailKc `json:"cluster"`
}

type clusterKcContextDetail struct {
	Cluster string `json:"cluster"`
	User    string `json:"user"`
}

type clusterKcContext struct {
	Name    string                 `json:"name"`
	Context clusterKcContextDetail `json:"context"`
}

type clusterKcUserDetail struct {
	ClientCertificateData string `json:"client-certificate-data"`
	ClientKeyData         string `json:"client-key-data"`
}

type clusterKcUser struct {
	Name string              `json:"name"`
	User clusterKcUserDetail `json:"user"`
}

type clusterKubeconfig struct {
	APIVersion     string             `json:"apiVersion"`
	Kind           string             `json:"kind"`
	CurrentContext string             `json:"current-context"`
	Users          []clusterKcUser    `json:"users"`
	Clusters       []clusterKc        `json:"clusters"`
	Contexts       []clusterKcContext `json:"contexts"`
	//XXX Missing preferences
}

//CopyKubeConfig copies over kubeconfig from the cluster
func CopyKubeConfig(mf *Manifest, rootLB *MEXRootLB, name string) error {
	log.DebugLog(log.DebugLevelMexos, "copying kubeconfig", "name", name)
	if rootLB == nil {
		return fmt.Errorf("cannot copy kubeconfig, rootLB is null")
	}
	ipaddr, err := FindNodeIP(mf, name)
	if err != nil {
		return err
	}
	if mf.Values.Network.External == "" {
		return fmt.Errorf("copy kube config, missing external network in platform config")
	}
	client, err := GetSSHClient(mf, rootLB.Name, mf.Values.Network.External, sshUser)
	if err != nil {
		return fmt.Errorf("can't get ssh client for copying kubeconfig, %v", err)
	}
	//kconfname := fmt.Sprintf("%s.kubeconfig", name[strings.LastIndex(name, "-")+1:])
	kconfname := GetKconfName(mf)
	log.DebugLog(log.DebugLevelMexos, "attempt to get kubeconfig from k8s master", "name", name, "ipaddr", ipaddr, "dest", kconfname)
	cmd := fmt.Sprintf("scp -o %s -o %s -i id_rsa_mex %s@%s:.kube/config %s", sshOpts[0], sshOpts[1], sshUser, ipaddr, kconfname)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't copy kubeconfig from %s, %s, %v", name, out, err)
	}
	cmd = fmt.Sprintf("cat %s", kconfname)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't cat %s, %s, %v", kconfname, out, err)
	}
	port, serr := StartKubectlProxy(mf, rootLB, kconfname)
	if serr != nil {
		return serr
	}
	return ProcessKubeconfig(mf, rootLB, name, port, []byte(out))
}

//ProcessKubeconfig validates kubeconfig and saves it and creates a copy for proxy access
func ProcessKubeconfig(mf *Manifest, rootLB *MEXRootLB, name string, port int, dat []byte) error {
	log.DebugLog(log.DebugLevelMexos, "process kubeconfig file", "name", name)
	if rootLB == nil {
		return fmt.Errorf("cannot process kubeconfig, rootLB is null")
	}
	kc := &clusterKubeconfig{}
	err := yaml.Unmarshal(dat, kc)
	if err != nil {
		return fmt.Errorf("can't unmarshal kubeconfig %s, %v", name, err)
	}
	if len(kc.Clusters) < 1 {
		return fmt.Errorf("insufficient clusters info in kubeconfig %s", name)
	}
	//kconfname := fmt.Sprintf("%s.kubeconfig", name[strings.LastIndex(name, "-")+1:])
	kconfname := GetLocalKconfName(mf)
	log.DebugLog(log.DebugLevelMexos, "writing local kubeconfig file", "name", kconfname)
	err = ioutil.WriteFile(kconfname, dat, 0666)
	if err != nil {
		return fmt.Errorf("can't write kubeconfig name %s filename %s,%v", name, kconfname, err)
	}
	log.DebugLog(log.DebugLevelMexos, "wrote kubeconfig", "file", kconfname)
	kc.Clusters[0].Cluster.Server = fmt.Sprintf("http://%s:%d", rootLB.Name, port)
	dat, err = yaml.Marshal(kc)
	if err != nil {
		return fmt.Errorf("can't marshal kubeconfig proxy edit %s, %v", name, err)
	}
	kconfname = kconfname + "-proxy"
	err = ioutil.WriteFile(kconfname, dat, 0666)
	if err != nil {
		return fmt.Errorf("can't write kubeconfig proxy %s, %v", kconfname, err)
	}
	log.DebugLog(log.DebugLevelMexos, "kubeconfig-proxy file saved", "file", kconfname)
	return nil
}
