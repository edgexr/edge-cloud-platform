package mexos

import (
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
)

var defaultPrivateNetRange = "10.101.X.0/24"

//GetInternalIP returns IP of the server
func GetInternalIP(mf *Manifest, name string) (string, error) {
	sd, err := GetServerDetails(mf, name)
	if err != nil {
		return "", err
	}
	its := strings.Split(sd.Addresses, "=")
	if len(its) != 2 {
		return "", fmt.Errorf("GetInternalIP: can't parse server detail addresses, %v, %v", sd, err)
	}
	return its[1], nil
}

//GetInternalCIDR returns CIDR of server
func GetInternalCIDR(mf *Manifest, name string) (string, error) {
	addr, err := GetInternalIP(mf, name)
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

//XXX allow creating more than one LB

//GetServerIPAddr gets the server IP
func GetServerIPAddr(mf *Manifest, networkName, serverName string) (string, error) {
	//TODO: mexosagent cache
	log.DebugLog(log.DebugLevelMexos, "get server ip addr", "networkname", networkName, "servername", serverName)
	//sd, err := GetServerDetails(rootLB)
	sd, err := GetServerDetails(mf, serverName)
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
	log.DebugLog(log.DebugLevelMexos, "got server ip addr", "ipaddr", addr, "netname", networkName, "servername", serverName)
	return addr, nil
}

//FindNodeIP finds IP for the given node
func FindNodeIP(mf *Manifest, name string) (string, error) {
	log.DebugLog(log.DebugLevelMexos, "find node ip", "name", name)
	if name == "" {
		return "", fmt.Errorf("empty name")
	}
	srvs, err := ListServers(mf)
	if err != nil {
		return "", err
	}
	for _, s := range srvs {
		if s.Status == "ACTIVE" && s.Name == name {
			ipaddr, err := GetInternalIP(mf, s.Name)
			if err != nil {
				return "", fmt.Errorf("can't get IP for %s, %v", s.Name, err)
			}
			log.DebugLog(log.DebugLevelMexos, "found node ip", "name", name, "ipaddr", ipaddr)
			return ipaddr, nil
		}
	}
	return "", fmt.Errorf("node %s, ip not found", name)
}
