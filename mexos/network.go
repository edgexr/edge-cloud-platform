package mexos

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
)

//GetExternalGateway retrieves Gateway IP from the external network information. It first gets external
//  network information. Using that it further gets subnet information. Inside that subnet information
//  there should be gateway IP if the network is set up correctly.
// Not to be confused with GetRouterDetailExternalGateway.
func GetExternalGateway(extNetName string) (string, error) {
	nd, err := GetNetworkDetail(extNetName)
	if err != nil {
		return "", fmt.Errorf("can't get details for external network %s, %v", extNetName, err)
	}

	if nd.Status != "ACTIVE" {
		return "", fmt.Errorf("network %s is not active, status %s", extNetName, nd.Status)
	}
	if nd.AdminStateUp != "UP" {
		return "", fmt.Errorf("network %s is not admin-state set to up", extNetName)
	}
	subnets := strings.Split(nd.Subnets, ",")
	//XXX beware of extra spaces
	if len(subnets) < 1 {
		return "", fmt.Errorf("no subnets for %s", extNetName)
	}
	//XXX just use first subnet -- may not work in all cases, but there is no tagging done rightly yet
	sd, err := GetSubnetDetail(subnets[0])
	if err != nil {
		return "", fmt.Errorf("cannot get details for subnet %s, %v", subnets[0], err)
	}
	//TODO check status of subnet
	if sd.GatewayIP == "" {
		return "", fmt.Errorf("cannot get external network's gateway IP")
	}
	log.DebugLog(log.DebugLevelMexos, "get external gatewayIP", "gatewayIP", sd.GatewayIP, "subnet detail", sd)
	return sd.GatewayIP, nil
}

//GetRouterDetailExternalGateway is different than GetExternalGateway.  This function gets
// the gateway interface in the subnet within external network.  This is
// accessible from private networks to route packets to the external network.
// The GetExternalGateway gets the gateway for the outside network.   This is
// for the packets to be routed out to the external network, i.e. internet.
func GetRouterDetailExternalGateway(rd *OSRouterDetail) (*OSExternalGateway, error) {
	if rd.ExternalGatewayInfo == "" {
		return nil, fmt.Errorf("empty external gateway info")
	}
	externalGateway := &OSExternalGateway{}
	err := json.Unmarshal([]byte(rd.ExternalGatewayInfo), externalGateway)
	if err != nil {
		return nil, fmt.Errorf("can't get unmarshal external gateway info, %v", err)
	}
	//log.DebugLog(log.DebugLevelMexos, "get router detail external gateway", "external gateway", externalGateway)
	return externalGateway, nil
}

// GetRouterDetailInterfaces gets the list of interfaces on the router. For example, each private
// subnet connected to the router will be listed here with own interface definition.
func GetRouterDetailInterfaces(rd *OSRouterDetail) ([]OSRouterInterface, error) {
	if rd.InterfacesInfo == "" {
		return nil, fmt.Errorf("missing interfaces info in router details")
	}
	interfaces := []OSRouterInterface{}
	err := json.Unmarshal([]byte(rd.InterfacesInfo), &interfaces)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal router detail interfaces")
	}
	log.DebugLog(log.DebugLevelMexos, "get router detail interfaces", "interfaces", interfaces)
	return interfaces, nil
}

func GetMexRouterIP() (string, error) {
	rtr := GetCloudletExternalRouter()
	rd, rderr := GetRouterDetail(rtr)
	if rderr != nil {
		return "", fmt.Errorf("can't get router detail for %s, %v", rtr, rderr)
	}
	log.DebugLog(log.DebugLevelMexos, "router detail", "detail", rd)
	reg, regerr := GetRouterDetailExternalGateway(rd)
	if regerr != nil {
		log.InfoLog("can't get router detail")
		return "", fmt.Errorf("can't get router detail")
	}
	if reg != nil && len(reg.ExternalFixedIPs) > 0 {
		fip := reg.ExternalFixedIPs[0]
		log.DebugLog(log.DebugLevelMexos, "external fixed ips", "ips", fip)
		return fip.IPAddress, nil

	} else {
		log.InfoLog("can't get external fixed ips list from router detail external gateway")
		return "", fmt.Errorf("can't get external fixed ips list from router detail")
	}
}
