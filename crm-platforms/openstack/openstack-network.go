// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openstack

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

//GetExternalGateway retrieves Gateway IP from the external network information. It first gets external
//  network information. Using that it further gets subnet information. Inside that subnet information
//  there should be gateway IP if the network is set up correctly.
// Not to be confused with GetRouterDetailExternalGateway.
func (s *OpenstackPlatform) GetExternalGateway(ctx context.Context, extNetName string) (string, error) {
	nd, err := s.GetNetworkDetail(ctx, extNetName)
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
	sd, err := s.GetSubnetDetail(ctx, subnets[0])
	if err != nil {
		return "", fmt.Errorf("cannot get details for subnet %s, %v", subnets[0], err)
	}
	//TODO check status of subnet
	if sd.GatewayIP == "" {
		return "", fmt.Errorf("cannot get external network's gateway IP")
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "get external gatewayIP", "gatewayIP", sd.GatewayIP, "subnet detail", sd)
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
	//log.SpanLog(ctx,log.DebugLevelInfra, "get router detail external gateway", "external gateway", externalGateway)
	return externalGateway, nil
}

// GetRouterDetailInterfaces gets the list of interfaces on the router. For example, each private
// subnet connected to the router will be listed here with own interface definition.
func GetRouterDetailInterfaces(ctx context.Context, rd *OSRouterDetail) ([]OSRouterInterface, error) {
	if rd.InterfacesInfo == "" {
		return nil, fmt.Errorf("missing interfaces info in router details")
	}
	interfaces := []OSRouterInterface{}
	err := json.Unmarshal([]byte(rd.InterfacesInfo), &interfaces)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal router detail interfaces")
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "get router detail interfaces", "interfaces", interfaces)
	return interfaces, nil
}

func (o *OpenstackPlatform) ValidateNetwork(ctx context.Context) error {
	nets, err := o.ListNetworks(ctx)
	if err != nil {
		return err
	}

	found := false
	for _, n := range nets {
		if n.Name == o.VMProperties.GetCloudletExternalNetwork() {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("cannot find external network %s", o.VMProperties.GetCloudletExternalNetwork())
	}

	found = false
	for _, n := range nets {
		if n.Name == o.VMProperties.GetCloudletMexNetwork() {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("cannot find network %s", o.VMProperties.GetCloudletMexNetwork())
	}

	rtr := o.VMProperties.GetCloudletExternalRouter()
	if rtr != vmlayer.NoConfigExternalRouter && rtr != vmlayer.NoExternalRouter {
		routers, err := o.ListRouters(ctx)
		if err != nil {
			return err
		}

		found = false
		for _, r := range routers {
			if r.Name == o.VMProperties.GetCloudletExternalRouter() {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("ext router %s not found", o.VMProperties.GetCloudletExternalRouter())
		}
	}

	return nil
}

// ValidateAdditionalNetworks ensures that any specified additional networks have
// just one subnet with no default GW and DHCP must be enabled
func (o *OpenstackPlatform) ValidateAdditionalNetworks(ctx context.Context, additionalNets map[string]vmlayer.NetworkType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ValidateAdditionalNetworks")

	netTypes := []vmlayer.NetworkType{vmlayer.NetworkTypeExternalAdditionalPlatform, vmlayer.NetworkTypeExternalAdditionalRootLb}
	cloudletAddNets := o.VMProperties.GetNetworksByType(ctx, netTypes)

	for n := range additionalNets {
		subnetName := n
		subnets, err := o.ListSubnets(ctx, n)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "list subnets for network failed, assume network is a subnet", "name", n)
		} else {
			// network is not a subnet
			if len(subnets) != 1 {
				return fmt.Errorf("Unexpected number of subnets: %d in network %s", len(subnets), n)
			}
			// we only allow specifying as a network name and not a subnet for the cloudlet-wide additional networks which
			// is mainly replaced by per-cluster networks. We don't want to fail the startup for those for backwards compatibility
			_, ok := cloudletAddNets[n]
			if !ok {
				return fmt.Errorf("specified network %s must be an openstack subnet name", n)
			}
			subnetName = subnets[0].Name
		}
		subnet, err := o.GetSubnetDetail(ctx, subnetName)
		if err != nil {
			return err
		}
		if subnet.GatewayIP != "" {
			return fmt.Errorf("Additional network cannot have a Gateway IP: %s", subnet.Name)
		}
		if !subnet.EnableDHCP {
			return fmt.Errorf("Additional network must have DHCP enabled: %s", subnet.Name)
		}
	}
	return nil
}

// PrepNetwork validates and does the work needed to ensure MEX network setup
func (o *OpenstackPlatform) PrepNetwork(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PrepNetwork")

	nets, err := o.ListNetworks(ctx)
	if err != nil {
		return err
	}

	found := false
	for _, n := range nets {
		if n.Name == o.VMProperties.GetCloudletExternalNetwork() {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("cannot find ext net %s", o.VMProperties.GetCloudletExternalNetwork())
	}

	netTypes := []vmlayer.NetworkType{vmlayer.NetworkTypeExternalAdditionalRootLb}
	err = o.ValidateAdditionalNetworks(ctx, o.VMProperties.GetNetworksByType(ctx, netTypes))
	if err != nil {
		return err
	}

	found = false
	for _, n := range nets {
		if n.Name == o.VMProperties.GetCloudletMexNetwork() {
			found = true
			break
		}
	}
	if !found {
		ni, err := vmlayer.ParseNetSpec(ctx, o.VMProperties.GetCloudletNetworkScheme())
		if err != nil {
			return err
		}
		// We need at least one network for `mex` clusters
		err = o.CreateNetwork(ctx, o.VMProperties.GetCloudletMexNetwork(), ni.NetworkType, o.VMProperties.GetCloudletNetworkAvailabilityZone())
		if err != nil {
			return fmt.Errorf("cannot create mex network %s, %v", o.VMProperties.GetCloudletMexNetwork(), err)
		}
	}

	rtr := o.VMProperties.GetCloudletExternalRouter()
	if rtr != vmlayer.NoConfigExternalRouter && rtr != vmlayer.NoExternalRouter {
		routers, err := o.ListRouters(ctx)
		if err != nil {
			return err
		}

		found = false
		for _, r := range routers {
			if r.Name == o.VMProperties.GetCloudletExternalRouter() {
				found = true
				break
			}
		}
		if !found {
			// We need at least one router for our `mex` network and external network
			err = o.CreateRouter(ctx, o.VMProperties.GetCloudletExternalRouter())
			if err != nil {
				return fmt.Errorf("cannot create the ext router %s, %v", o.VMProperties.GetCloudletExternalRouter(), err)
			}
			err = o.SetRouter(ctx, o.VMProperties.GetCloudletExternalRouter(), o.VMProperties.GetCloudletExternalNetwork())
			if err != nil {
				return fmt.Errorf("cannot set default network to router %s, %v", o.VMProperties.GetCloudletExternalRouter(), err)
			}
		}
	}
	return nil
}

// GetCloudletSubnets returns subnets inside MEX Network
func (o *OpenstackPlatform) GetCloudletSubnets(ctx context.Context) ([]string, error) {
	nd, err := o.GetNetworkDetail(ctx, o.VMProperties.GetCloudletMexNetwork())
	if err != nil {
		return nil, fmt.Errorf("can't get MEX network detail, %v", err)
	}

	subnets := strings.Split(nd.Subnets, ",")
	if len(subnets) < 1 {
		return nil, fmt.Errorf("can't get a list of subnets for MEX network")
	}

	return subnets, nil
}

func getNameAndIPFromNetwork(network string) (string, string, error) {
	nets := strings.Split(network, "=")
	if len(nets) != 2 {
		return "", "", fmt.Errorf("unable to parse net %s", network)
	}
	return nets[0], nets[1], nil
}

func GetServerNetworkIP(networks, netmatch string) (string, error) {
	for _, n := range strings.Split(networks, "'") {
		netname, ip, err := getNameAndIPFromNetwork(n)
		if err != nil {
			return "", err
		}
		if strings.Contains(netname, netmatch) {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no network matching: %s", netmatch)
}

func (o *OpenstackPlatform) GetServerExternalIP(networks string) (string, error) {
	extNet := o.VMProperties.GetCloudletExternalNetwork()
	return GetServerNetworkIP(networks, extNet)
}

func (o *OpenstackPlatform) GetServerInternalIP(networks string) (string, error) {
	mexNet := o.VMProperties.GetCloudletMexNetwork()
	return GetServerNetworkIP(networks, mexNet)
}

//GetInternalIP returns IP of the server
func (s *OpenstackPlatform) GetInternalIP(name string, srvs []OSServer) (string, error) {
	for _, srv := range srvs {
		if srv.Name == name {
			return s.GetServerInternalIP(srv.Networks)
		}
	}
	return "", fmt.Errorf("No internal IP found for %s", name)
}

//GetInternalCIDR returns CIDR of server
func (s *OpenstackPlatform) GetInternalCIDR(name string, srvs []OSServer) (string, error) {
	addr, err := s.GetInternalIP(name, srvs)
	if err != nil {
		return "", err
	}
	cidr := addr + "/24" // XXX we use this convention of /24 in k8s priv-net
	return cidr, nil
}

// TODO collapse common keys into a single entry with multi-part values ex: "hw"
// (We don't use this property values today, but perhaps in the future)
func ParseFlavorProperties(f OSFlavorDetail) map[string]string {

	var props map[string]string

	ms := strings.Split(f.Properties, ",")
	props = make(map[string]string)
	for _, m := range ms {
		// ex: pci_passthrough:alias='t4gpu:1’
		var val []string
		if strings.Contains(m, ":") {
			val = strings.Split(m, ":")
		} else if strings.Contains(m, "=") {
			// handle vio (wwt) flavor syntax
			val = strings.Split(m, "=")
		}

		if len(val) > 1 {
			val[0] = strings.TrimSpace(val[0])
			var s []string
			for i := 1; i < len(val); i++ {
				val[i] = strings.Replace(val[i], "'", "", -1)
				if _, err := strconv.Atoi(val[i]); err == nil {
					s = append(s, ":")
				}
				s = append(s, val[i])
			}
			props[val[0]] = strings.Join(s, "")
		}

	}
	return props
}

func (o *OpenstackPlatform) GetRouterDetail(ctx context.Context, routerName string) (*vmlayer.RouterDetail, error) {

	var rd vmlayer.RouterDetail
	rd.Name = routerName

	ord, err := o.GetOpenStackRouterDetail(ctx, routerName)
	if err != nil {
		return nil, err
	}
	gw, err := GetRouterDetailExternalGateway(ord)
	if err != nil {
		return nil, err
	}
	fip := gw.ExternalFixedIPs
	log.SpanLog(ctx, log.DebugLevelInfra, "external fixed ips", "ips", fip)

	if len(fip) != 1 {
		return nil, fmt.Errorf("Unexpected fixed ips for mex router %v", fip)
	}
	rd.ExternalIP = fip[0].IPAddress
	return &rd, nil
}

func (o *OpenstackPlatform) GetInternalPortPolicy() vmlayer.InternalPortAttachPolicy {
	return vmlayer.AttachPortAfterCreate
}
