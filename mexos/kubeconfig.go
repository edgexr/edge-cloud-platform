package mexos

import (
	"fmt"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/azure"
	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/gcloud"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func GetLocalKconfName(clusterInst *edgeproto.ClusterInst) string {
	kconf := fmt.Sprintf("%s/%s", MEXDir(), GetKconfName(clusterInst))
	return kconf
}

func GetKconfName(clusterInst *edgeproto.ClusterInst) string {
	return fmt.Sprintf("%s.%s.%s.kubeconfig",
		clusterInst.Key.ClusterKey.Name,
		clusterInst.Key.CloudletKey.OperatorKey.Name,
		GetCloudletDNSZone())
}

func GetKconf(clusterInst *edgeproto.ClusterInst) (string, error) {
	name := GetLocalKconfName(clusterInst)
	operatorName := clusterInst.Key.CloudletKey.OperatorKey.Name
	clusterName := clusterInst.Key.ClusterKey.Name

	log.DebugLog(log.DebugLevelMexos, "get kubeconfig name", "name", name)
	if _, err := os.Stat(name); os.IsNotExist(err) {
		// if kubeconfig does not exist, optionally create it.  It is possible it was
		// created on a different container or we had a restart of the container
		log.DebugLog(log.DebugLevelMexos, "creating missing kconf file", "name", name)
		switch operatorName {
		case cloudcommon.OperatorGCP:
			if err = gcloud.GetGKECredentials(clusterName); err != nil {
				return "", fmt.Errorf("unable to get GKE credentials %v", err)
			}
			if err = copyFile(defaultKubeconfig(), name); err != nil {
				return "", fmt.Errorf("can't copy %s, %v", defaultKubeconfig(), err)
			}
		case cloudcommon.OperatorAzure:
			rg := GetResourceGroupForCluster(clusterInst)
			if err = azure.GetAKSCredentials(rg, clusterName); err != nil {
				return "", fmt.Errorf("unable to get AKS credentials %v", err)
			}
			if err = copyFile(defaultKubeconfig(), name); err != nil {
				return "", fmt.Errorf("can't copy %s, %v", defaultKubeconfig(), err)
			}
		default:
			log.DebugLog(log.DebugLevelMexos, "warning, not creating missing kubeconfig for operator", "operator", operatorName)
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
func CopyKubeConfig(clusterInst *edgeproto.ClusterInst, rootLBName, name string, srvs []OSServer) error {
	log.DebugLog(log.DebugLevelMexos, "copying kubeconfig", "name", name)

	ipaddr, err := FindNodeIP(name, srvs)
	if err != nil {
		return err
	}
	if GetCloudletExternalNetwork() == "" {
		return fmt.Errorf("copy kube config, missing external network in platform config")
	}
	client, err := GetSSHClient(rootLBName, GetCloudletExternalNetwork(), sshUser)
	if err != nil {
		return fmt.Errorf("can't get ssh client for copying kubeconfig, %v", err)
	}
	//kconfname := fmt.Sprintf("%s.kubeconfig", name[strings.LastIndex(name, "-")+1:])
	kconfname := GetKconfName(clusterInst)
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
	//TODO generate per proxy password and record in vault
	//port, serr := StartKubectlProxy(mf, rootLB, name, kconfname)
	//if serr != nil {
	//	return serr
	//}
	//return ProcessKubeconfig(mf, rootLB, name, port, []byte(out))
	return nil
}
