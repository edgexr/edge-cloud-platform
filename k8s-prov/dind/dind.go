package dind

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/log"
)

var clusterID = 0

type DindCluster struct {
	ClusterName string
	ClusterID   int
	MasterAddr  string
	KContext    string
}

var dindClusters = make(map[string]*DindCluster)

func getClusterID(id int) string {
	return strconv.Itoa(id)
}

// Get gets the ip address of the k8s master that nginx proxy will route to
func GetMasterAddr(clusterName string) string {
	c, found := dindClusters[clusterName]
	if !found {
		return ""
	}
	return c.MasterAddr
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
	cluster, found := dindClusters[clusterName]
	if !found {
		log.DebugLog(log.DebugLevelMexos, "ERROR - Cluster %s doesn't exists", clusterName)
		return ""
	}
	return "kubeadm-dind-net-" + cluster.ClusterName + "-" + getClusterID(cluster.ClusterID)
}

//CreateDINDCluster creates kubernetes cluster on local mac
func CreateDINDCluster(clusterName, kconfName string) error {
	cluster, found := dindClusters[clusterName]
	if found {
		return fmt.Errorf("ERROR - Cluster %s already exists (%v)", clusterName, *cluster)
	}
	clusterID++
	os.Setenv("DIND_LABEL", clusterName)
	os.Setenv("CLUSTER_ID", getClusterID(clusterID))
	cluster = &DindCluster{
		ClusterName: clusterName,
		ClusterID:   clusterID,
		KContext:    "dind-" + clusterName + "-" + getClusterID(clusterID),
		MasterAddr:  "10.192." + getClusterID(clusterID) + ".2",
	}
	log.DebugLog(log.DebugLevelMexos, "CreateDINDCluster via dind-cluster-v1.13.sh", "name", clusterName, "clusterid", getClusterID(clusterID))

	out, err := sh.Command("dind-cluster-v1.13.sh", "up").Command("tee", "/tmp/dind.log").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ERROR creating Dind Cluster: [%s] %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "Finished CreateDINDCluster", "name", clusterName)

	//now set the k8s config
	out, err = sh.Command("kubectl", "config", "use-context", cluster.KContext).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ERROR setting kube config context: [%s] %v", out, err)
	}
	//copy kubeconfig locally
	log.DebugLog(log.DebugLevelMexos, "locally copying kubeconfig", "kconfName", kconfName)
	home := os.Getenv("HOME")
	out, err = sh.Command("cp", home+"/.kube/config", kconfName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	// add cluster to cluster map
	dindClusters[clusterName] = cluster
	return nil
}

//DeleteDINDCluster creates kubernetes cluster on local mac
func DeleteDINDCluster(name string) error {
	cluster, found := dindClusters[name]
	if !found {
		return fmt.Errorf("ERROR - Cluster %s doesn't exists", name)
	}
	os.Setenv("DIND_LABEL", cluster.ClusterName)
	os.Setenv("CLUSTER_ID", getClusterID(cluster.ClusterID))
	log.DebugLog(log.DebugLevelMexos, "DeleteDINDCluster", "name", name)

	out, err := sh.Command("dind-cluster-v1.13.sh", "clean").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "Finished dind-cluster-v1.13.sh clean", "name", name, "out", out)
	// Delete the entry from the dindClusters
	delete(dindClusters, name)

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
