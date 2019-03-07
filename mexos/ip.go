package mexos

import (
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
)

var defaultPrivateNetRange = "10.101.X.0/24"

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
	its := strings.Split(sd.Addresses, "=")
	if len(its) != 2 {
		its = strings.Split(sd.Addresses, ";")
		foundaddr := ""
		if len(its) > 1 {
			for _, it := range its {
				sits := strings.Split(it, "=")
				if len(sits) == 2 {
					if strings.Contains(sits[0], "mex-k8s-net") {
						continue
					}
					if strings.TrimSpace(sits[0]) == networkName { // XXX
						foundaddr = sits[1]
						break
					}
				}
			}
		}
		if foundaddr != "" {
			log.DebugLog(log.DebugLevelMexos, "retrieved server ipaddr", "ipaddr", foundaddr, "netname", networkName, "servername", serverName)
			return foundaddr, nil
		}
		return "", fmt.Errorf("GetServerIPAddr: can't parse server detail addresses, %v, %v", sd, err)
	}
	if its[0] != networkName {
		return "", fmt.Errorf("invalid network name in server detail address, %s", sd.Addresses)
	}
	addr := its[1]
	//log.DebugLog(log.DebugLevelMexos, "got server ip addr", "ipaddr", addr, "netname", networkName, "servername", serverName)
	return addr, nil
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
