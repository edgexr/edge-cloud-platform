package mexos

import (
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var defaultPrivateNetRange = "10.101.X.0/24"

type NetSpecInfo struct {
	Kind, Name, CIDR, Options string
	NetworkAddress            string
	NetmaskBits               string
	Octets                    []string
	DelimiterOctet            int // this is the X
	FloatingIPNet             string
	FloatingIPSubnet          string
	Extra                     []string
}

//ParseNetSpec decodes netspec string
//TODO: IPv6
func ParseNetSpec(netSpec string) (*NetSpecInfo, error) {
	ni := &NetSpecInfo{}
	if netSpec == "" {
		return nil, fmt.Errorf("empty netspec")
	}
	log.DebugLog(log.DebugLevelMexos, "parsing netspec", "netspec", netSpec)
	items := strings.Split(netSpec, ",")
	if len(items) < 3 {
		return nil, fmt.Errorf("malformed net spec, insufficient items %v", items)
	}
	ni.Kind = items[NetTypeVal]
	ni.Name = items[NetNameVal]
	ni.CIDR = items[NetCIDRVal]
	if len(items) > NetFloatingIPVal {
		fi := items[NetFloatingIPVal]
		fs := strings.Split(fi, "|")
		if len(fs) != 2 {
			return nil, fmt.Errorf("floating ip format wrong expected: internalnet|internalsubnet")
		}
		ni.FloatingIPNet = fs[0]
		ni.FloatingIPSubnet = fs[1]
	}
	if len(items) > NetOptVal {
		ni.Options = items[NetOptVal]
	}
	if len(items) > NetOptVal+1 {
		ni.Extra = items[NetOptVal+1:]
	}

	sits := strings.Split(ni.CIDR, "/")
	if len(sits) < 2 {
		return nil, fmt.Errorf("invalid CIDR, no net mask")
	}
	ni.NetworkAddress = sits[0]
	ni.NetmaskBits = sits[1]

	ni.Octets = strings.Split(ni.NetworkAddress, ".")
	for i, it := range ni.Octets {
		if it == "X" {
			ni.DelimiterOctet = i
		}
	}
	if len(ni.Octets) != 4 {
		log.DebugLog(log.DebugLevelMexos, "invalid network address, wrong number of octets", items[NetTypeVal])
		return nil, fmt.Errorf("invalid network address structure")
	}
	if ni.DelimiterOctet != 2 {
		log.DebugLog(log.DebugLevelMexos, "invalid network address, third octet must be X", items[NetTypeVal])
		return nil, fmt.Errorf("invalid network address delimiter")
	}

	switch items[NetTypeVal] {
	case "priv-subnet":
	case "external-ip":
	default:
		log.DebugLog(log.DebugLevelMexos, "error, invalid NetTypeVal", "net-type-val", items[NetTypeVal])
		return nil, fmt.Errorf("unsupported netspec type")
	}

	log.DebugLog(log.DebugLevelMexos, "netspec info", "ni", ni, "items", items)
	return ni, nil
}

//GetInternalIP returns IP of the server
func GetInternalIP(name string, srvs []OSServer) (string, error) {
	for _, s := range srvs {
		if s.Name == name {
			return s.GetServerInternalIP()
		}
	}
	return "", fmt.Errorf("No internal IP found for %s", name)
}

//GetInternalCIDR returns CIDR of server
func GetInternalCIDR(name string, srvs []OSServer) (string, error) {
	addr, err := GetInternalIP(name, srvs)
	if err != nil {
		return "", err
	}
	cidr := addr + "/24" // XXX we use this convention of /24 in k8s priv-net
	return cidr, nil
}

func GetAllowedClientCIDR() string {
	//XXX TODO get real list of allowed clients from remote database or template configuration
	return "0.0.0.0/0"
}

//GetServerIPAddr gets the server IP
//TODO: consider replacing this function with GetServerNetworkIP, however that function
// requires some rework to use in all cases
func GetServerIPAddr(networkName, serverName string) (string, error) {
	// if this is a root lb, look it up and get the IP if we have it cached
	rootLB, err := getRootLB(serverName)
	if err == nil && rootLB != nil {
		if rootLB.IP != "" {
			log.DebugLog(log.DebugLevelMexos, "using existing rootLB IP", "addr", rootLB.IP)
			return rootLB.IP, nil
		}
	}
	sd, err := GetServerDetails(serverName)
	if err != nil {
		return "", err
	}
	its := strings.Split(sd.Addresses, ";")
	for _, it := range its {
		sits := strings.Split(it, "=")
		if len(sits) != 2 {
			return "", fmt.Errorf("GetServerIPAddr: Unable to parse '%s'", it)
		}
		if strings.Contains(sits[0], networkName) {
			addr := sits[1]
			if strings.Contains(addr, ",") {
				addrs := strings.Split(addr, ",")
				if len(addrs) == 2 {
					addr = addrs[1]
				} else {
					return "", fmt.Errorf("GetServerIPAddr: Unable to parse '%s'", addr)
				}
			}
			addr = strings.TrimSpace(addr)
			log.DebugLog(log.DebugLevelMexos, "retrieved server ipaddr", "ipaddr", addr, "netname", networkName, "servername", serverName)
			return addr, nil
		}
	}
	return "", fmt.Errorf("GetServerIPAddr: Unable to find network %s for server %s", networkName, serverName)
}

//FindNodeIP finds IP for the given node
func FindNodeIP(name string, srvs []OSServer) (string, error) {
	//log.DebugLog(log.DebugLevelMexos, "find node ip", "name", name)
	if name == "" {
		return "", fmt.Errorf("empty name")
	}

	for _, s := range srvs {
		if s.Status == "ACTIVE" && s.Name == name {
			ipaddr, err := s.GetServerInternalIP()
			if err != nil {
				return "", fmt.Errorf("can't get IP for %s, %v", s.Name, err)
			}
			//log.DebugLog(log.DebugLevelMexos, "found node ip", "name", name, "ipaddr", ipaddr)
			return ipaddr, nil
		}
	}
	return "", fmt.Errorf("node %s, ip not found", name)
}

// GetMasterIP gets the IP address of the cluster's master node.
func GetMasterIP(clusterInst *edgeproto.ClusterInst, networkName string) (string, error) {
	log.DebugLog(log.DebugLevelMexos, "get master IP", "cluster", clusterInst.Key.ClusterKey.Name)
	srvs, err := ListServers()
	if err != nil {
		return "", fmt.Errorf("error getting server list: %v", err)

	}
	nodeNameSuffix := k8smgmt.GetK8sNodeNameSuffix(clusterInst)
	master, err := FindClusterMaster(nodeNameSuffix, srvs)
	if err != nil {
		return "", fmt.Errorf("can't find cluster with key %s, %v", nodeNameSuffix, err)
	}
	return FindNodeIP(master, srvs)
}
