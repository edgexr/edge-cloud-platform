package dind

import (
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
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

// GetDINDServiceIP depending on the type of DIND cluster will return either the interface or external address
func GetDINDServiceIP(networkScheme string) (string, error) {
	if networkScheme == cloudcommon.NetworkSchemePrivateIP {
		return getLocalAddr()
	}
	return getExternalPublicAddr()

}

// GetLocalAddr gets the IP address the machine uses for outbound comms
func getLocalAddr() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// Get the externally visible public IP address
func getExternalPublicAddr() (string, error) {
	out, err := sh.Command("dig", "@resolver1.opendns.com", "ANY", "myip.opendns.com", "+short").Output()
	log.DebugLog(log.DebugLevelMexos, "dig to resolver1.opendns.com called", "out", string(out), "err", err)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), err
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
	return nil
}

func getMacLimits(info *edgeproto.CloudletInfo) error {

	// get everything
	s, err := sh.Command("sysctl", "-a").Output()
	if err != nil {
		return err
	}
	sysout := string(s)

	rmem, _ := regexp.Compile("hw.memsize:\\s+(\\d+)")
	if rmem.MatchString(sysout) {
		matches := rmem.FindStringSubmatch(sysout)
		memoryB, err := strconv.Atoi(matches[1])
		if err != nil {
			return err
		}
		memoryMb := math.Round((float64(memoryB) / 1024 / 1024))
		info.OsMaxRam = uint64(memoryMb)
	}
	rcpu, _ := regexp.Compile("hw.ncpu:\\s+(\\d+)")
	if rcpu.MatchString(sysout) {
		matches := rcpu.FindStringSubmatch(sysout)
		cpus, err := strconv.Atoi(matches[1])
		if err != nil {
			return err
		}
		info.OsMaxVcores = uint64(cpus)
	}
	// hardcoding disk size for now, TODO: consider changing this but we need to consider that the
	// whole disk is not available for DIND.
	info.OsMaxVolGb = 500
	log.DebugLog(log.DebugLevelMexos, "getMacLimits results", "info", info)
	return nil
}

func getLinuxLimits(info *edgeproto.CloudletInfo) error {
	// get memory
	m, err := sh.Command("grep", "MemTotal", "/proc/meminfo").Output()
	memline := string(m)
	if err != nil {
		return err
	}
	rmem, _ := regexp.Compile("MemTotal:\\s+(\\d+)\\s+kB")

	if rmem.MatchString(string(memline)) {
		matches := rmem.FindStringSubmatch(memline)
		memoryKb, err := strconv.Atoi(matches[1])
		if err != nil {
			return err
		}
		memoryMb := math.Round((float64(memoryKb) / 1024))
		info.OsMaxRam = uint64(memoryMb)
	}
	c, err := sh.Command("grep", "-c", "processor", "/proc/cpuinfo").Output()
	cpuline := string(c)
	cpuline = strings.TrimSpace(cpuline)
	cpus, err := strconv.Atoi(cpuline)
	if err != nil {
		return err
	}
	info.OsMaxVcores = uint64(cpus)

	// disk space
	fd, err := sh.Command("fdisk", "-l").Output()
	fdstr := string(fd)
	rdisk, err := regexp.Compile("Disk\\s+\\S+:\\s+(\\d+)\\s+GiB")
	if err != nil {
		return err
	}
	matches := rdisk.FindStringSubmatch(fdstr)
	if matches != nil {
		//for now just looking for one disk
		diskGb, err := strconv.Atoi(matches[1])
		if err != nil {
			return err
		}
		info.OsMaxVolGb = uint64(diskGb)
	}
	log.DebugLog(log.DebugLevelMexos, "getLinuxLimits results", "info", info)
	return nil

}

// DINDGetLimits gets CPU, Memory from the local machine
func DINDGetLimits(info *edgeproto.CloudletInfo, os string) error {
	log.DebugLog(log.DebugLevelMexos, "DINDGetLimits called")
	switch os {
	case cloudcommon.OperatingSystemMac:
		return getMacLimits(info)
	case cloudcommon.OperatingSystemLinux:
		return getLinuxLimits(info)
	}
	return fmt.Errorf("Unsupported OS Type for DIND")
}
