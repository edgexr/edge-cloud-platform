package mexos

import (
	"context"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type NetSpecInfo struct {
	Name, CIDR        string
	NetworkAddress    string
	NetmaskBits       string
	Octets            []string
	MasterIPLastOctet string
	DelimiterOctet    int // this is the X
	FloatingIPNet     string
	FloatingIPSubnet  string
	VnicType          string
}

//ParseNetSpec decodes netspec string
//TODO: IPv6
func ParseNetSpec(ctx context.Context, netSpec string) (*NetSpecInfo, error) {
	ni := &NetSpecInfo{}
	if netSpec == "" {
		return nil, fmt.Errorf("empty netspec")
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "parsing netspec", "netspec", netSpec)
	items := strings.Split(netSpec, ",")
	for _, i := range items {
		kvs := strings.Split(i, "=")
		if len(kvs) != 2 {
			return nil, fmt.Errorf("incorrect netspec item format, expect key=value: %s", i)
		}
		k := strings.ToLower(kvs[0])
		v := kvs[1]

		switch k {
		case "name":
			ni.Name = v
		case "cidr":
			ni.CIDR = v
		case "floatingipnet":
			ni.FloatingIPNet = v
		case "floatingipsubnet":
			ni.FloatingIPSubnet = v
		case "vnictype":
			ni.VnicType = v
		default:
			return nil, fmt.Errorf("unknown netspec item key: %s", k)
		}
	}
	if ni.Name == "" {
		return nil, fmt.Errorf("Missing name=(value) in netspec")
	}
	if ni.CIDR == "" {
		return nil, fmt.Errorf("Missing cidr=(value) in netspec")
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
		log.SpanLog(ctx, log.DebugLevelMexos, "invalid network address, wrong number of octets", "octets", ni.Octets)
		return nil, fmt.Errorf("invalid network address structure")
	}
	if ni.DelimiterOctet != 2 {
		log.SpanLog(ctx, log.DebugLevelMexos, "invalid network address, third octet must be X", "delimiterOctet", ni.DelimiterOctet)
		return nil, fmt.Errorf("invalid network address delimiter")
	}

	log.SpanLog(ctx, log.DebugLevelMexos, "netspec info", "ni", ni, "items", items)
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
func GetServerIPAddr(ctx context.Context, networkName, serverName string) (string, error) {
	// if this is a root lb, look it up and get the IP if we have it cached
	rootLB, err := getRootLB(ctx, serverName)
	if err == nil && rootLB != nil {
		if rootLB.IP != "" {
			log.SpanLog(ctx, log.DebugLevelMexos, "using existing rootLB IP", "addr", rootLB.IP)
			return rootLB.IP, nil
		}
	}
	sd, err := GetServerDetails(ctx, serverName)
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
			log.SpanLog(ctx, log.DebugLevelMexos, "retrieved server ipaddr", "ipaddr", addr, "netname", networkName, "servername", serverName)
			return addr, nil
		}
	}
	return "", fmt.Errorf("GetServerIPAddr: Unable to find network %s for server %s", networkName, serverName)
}

//FindNodeIP finds IP for the given node
func FindNodeIP(name string, srvs []OSServer) (string, error) {
	//log.SpanLog(ctx,log.DebugLevelMexos, "find node ip", "name", name)
	if name == "" {
		return "", fmt.Errorf("empty name")
	}

	for _, s := range srvs {
		if s.Status == "ACTIVE" && s.Name == name {
			ipaddr, err := s.GetServerInternalIP()
			if err != nil {
				return "", fmt.Errorf("can't get IP for %s, %v", s.Name, err)
			}
			//log.SpanLog(ctx,log.DebugLevelMexos, "found node ip", "name", name, "ipaddr", ipaddr)
			return ipaddr, nil
		}
	}
	return "", fmt.Errorf("node %s, ip not found", name)
}

// GetMasterNameAndIP gets the name and IP address of the cluster's master node.
func GetMasterNameAndIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, string, error) {
	log.SpanLog(ctx, log.DebugLevelMexos, "get master IP", "cluster", clusterInst.Key.ClusterKey.Name)
	srvs, err := ListServers(ctx)
	if err != nil {
		return "", "", fmt.Errorf("error getting server list: %v", err)

	}
	nodeNameSuffix := k8smgmt.GetK8sNodeNameSuffix(&clusterInst.Key)
	masterName, err := FindClusterMaster(ctx, nodeNameSuffix, srvs)
	if err != nil {
		return "", "", fmt.Errorf("can't find cluster with key %s, %v", nodeNameSuffix, err)
	}
	masterIP, err := FindNodeIP(masterName, srvs)
	return masterName, masterIP, err
}
