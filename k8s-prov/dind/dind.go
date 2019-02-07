package dind

import (
	"fmt"
	"net"
	"os"

	"github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/log"
)

func getClusterID() string {
	return "1"
}

// Get gets the ip address of the k8s master that nginx proxy will route to
func GetMasterAddr() string {
	return "10.192." + getClusterID() + ".2"
}

// GetLocalAddr gets the IP address the machine uses for outbound comms
func GetLocalAddr() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String(), nil
}

func GetDockerNetworkName(clusterName string) string {
	return "kubeadm-dind-net-" + clusterName + "-" + getClusterID()
}

//CreateDINDCluster creates kubernetes cluster on local mac
func CreateDINDCluster(name string) error {
	os.Setenv("DIND_LABEL", name)
	os.Setenv("CLUSTER_ID", getClusterID())
	log.DebugLog(log.DebugLevelMexos, "CreateDINDCluster via dind-cluster-v1.13.sh", "name", name, "clusterid", getClusterID())

	out, err := sh.Command("dind-cluster-v1.13.sh", "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ERROR creating Dind Cluster: [%s] %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "Finished CreateDINDCluster", "name", name)

	//now set the k8s config
	out, err = sh.Command("kubectl", "config", "use-context", "dind-"+name+"-"+getClusterID()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ERROR setting kube config context: [%s] %v", out, err)
	}

	return nil
}

//DeleteDINDCluster creates kubernetes cluster on local mac
func DeleteDINDCluster(name string) error {
	os.Setenv("DIND_LABEL", name)
	os.Setenv("CLUSTER_ID", getClusterID())
	log.DebugLog(log.DebugLevelMexos, "DeleteDINDCluster", "name", name)

	out, err := sh.Command("dind-cluster-v1.13.sh", "clean").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "Finished dind-cluster-v1.13.sh clean", "name", name, "out", out)

	/* network is already deleted by the clean
	netname := GetDockerNetworkName(name)
	log.DebugLog(log.DebugLevelMexos, "removing docker network", "netname", netname, "out", out)
	out, err = sh.Command("docker", "network", "rm", netname).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	fmt.Printf("ran command docker network rm for network: %s.  Result: %s", netname, out)
	*/
	return nil
}
