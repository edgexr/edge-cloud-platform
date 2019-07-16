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

func ValidateNetwork() error {
	nets, err := ListNetworks()
	if err != nil {
		return err
	}

	found := false
	for _, n := range nets {
		if n.Name == GetCloudletExternalNetwork() {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("cannot find external network %s", GetCloudletExternalNetwork())
	}

	found = false
	for _, n := range nets {
		if n.Name == GetCloudletMexNetwork() {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("cannot find network %s", GetCloudletMexNetwork())
	}

	routers, err := ListRouters()
	if err != nil {
		return err
	}

	found = false
	for _, r := range routers {
		if r.Name == GetCloudletExternalRouter() {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("ext router %s not found", GetCloudletExternalRouter())
	}

	return nil
}

//PrepNetwork validates and does the work needed to ensure MEX network setup
func PrepNetwork() error {
	nets, err := ListNetworks()
	if err != nil {
		return err
	}

	// Not having external network setup by GDDT is a hard error.
	// GDDT must have setup a network connected to external / internet
	// that is named properly.
	// This is the case at Buckhorn.
	// The providers are expected to set up one external shared internet
	// routed network with a specific name.

	found := false
	for _, n := range nets {
		if n.Name == GetCloudletExternalNetwork() {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("cannot find ext net %s", GetCloudletExternalNetwork())
	}

	found = false
	for _, n := range nets {
		if n.Name == GetCloudletMexNetwork() {
			found = true
			break
		}
	}
	if !found {
		// We need at least one network for `mex` clusters
		err = CreateNetwork(GetCloudletMexNetwork())
		if err != nil {
			return fmt.Errorf("cannot create mex network %s, %v", GetCloudletMexNetwork(), err)
		}
	}

	routers, err := ListRouters()
	if err != nil {
		return err
	}

	found = false
	for _, r := range routers {
		if r.Name == GetCloudletExternalRouter() {
			found = true
			break
		}
	}
	if !found {
		// We need at least one router for our `mex` network and external network
		err = CreateRouter(GetCloudletExternalRouter())
		if err != nil {
			return fmt.Errorf("cannot create the ext router %s, %v", GetCloudletExternalRouter(), err)
		}
		err = SetRouter(GetCloudletExternalRouter(), GetCloudletExternalNetwork())
		if err != nil {
			return fmt.Errorf("cannot set default network to router %s, %v", GetCloudletExternalRouter(), err)
		}
	}

	return nil
}

//GetCloudletSubnets returns subnets inside MEX Network
func GetCloudletSubnets() ([]string, error) {
	nd, err := GetNetworkDetail(GetCloudletMexNetwork())
	if err != nil {
		return nil, fmt.Errorf("can't get MEX network detail, %v", err)
	}

	subnets := strings.Split(nd.Subnets, ",")
	if len(subnets) < 1 {
		return nil, fmt.Errorf("can't get a list of subnets for MEX network")
	}

	return subnets, nil
}
