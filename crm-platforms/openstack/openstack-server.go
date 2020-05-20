package openstack

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (o *OpenstackPlatform) GetServerDetail(ctx context.Context, serverName string) (*vmlayer.ServerDetail, error) {
	var sd vmlayer.ServerDetail
	osd, err := o.GetOpenstackServerDetails(ctx, serverName)
	if err != nil {
		return &sd, err
	}
	// to populate the MAC addrs we need to query the ports
	ports, err := o.ListPortsServer(ctx, serverName)
	if err != nil {
		return &sd, err
	}
	sd.Name = osd.Name
	sd.ID = osd.ID
	sd.Status = osd.Status
	err = o.UpdateServerIPs(ctx, osd.Addresses, ports, &sd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to update server IPs", "sd", sd, "err", err)
		return &sd, fmt.Errorf("unable to update server IPs -- %v", err)
	}
	return &sd, nil
}

// UpdateServerIPsFromAddrs gets the ServerIPs forthe given network from the addresses and ports
func (o *OpenstackPlatform) UpdateServerIPs(ctx context.Context, addresses string, ports []OSPort, serverDetail *vmlayer.ServerDetail) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateServerIPs", "addresses", addresses, "serverDetail", serverDetail, "ports", ports)

	externalNetname := o.VMProperties.GetCloudletExternalNetwork()
	its := strings.Split(addresses, ";")

	for _, it := range its {
		sits := strings.Split(it, "=")
		if len(sits) != 2 {
			return fmt.Errorf("GetServerIPFromAddrs: Unable to parse '%s'", it)
		}
		network := strings.TrimSpace(sits[0])

		addr := sits[1]

		if network == externalNetname {
			var serverIP vmlayer.ServerIP
			serverIP.Network = network
			// multiple ips for an external network indicates a floating ip on a single port
			if strings.Contains(addr, ",") {
				addrs := strings.Split(addr, ",")
				if len(addrs) == 2 {
					serverIP.InternalAddr = strings.TrimSpace(addrs[0])
					serverIP.ExternalAddr = strings.TrimSpace(addrs[1])
					serverIP.ExternalAddrIsFloating = true
				} else {
					return fmt.Errorf("GetServerExternalIPFromAddr: Unable to parse '%s'", addr)
				}
			} else {
				// no floating IP, internal and external are the same
				addr = strings.TrimSpace(addr)
				serverIP.InternalAddr = addr
				serverIP.ExternalAddr = addr
				serverDetail.Addresses = append(serverDetail.Addresses, serverIP)
			}
		} else {
			// for internal networks we need to find the subnet and there are no floating ips.
			// There maybe be multiple IPs due to multiple subnets for this network attached to this server
			subnets, err := o.ListSubnets(ctx, network)
			if err != nil {
				return fmt.Errorf("unable to find subnet for network: %s", network)
			}
			addrs := strings.Split(addr, ",")
			for _, addr := range addrs {
				addr = strings.TrimSpace(addr)
				ipaddr := net.ParseIP(addr)
				subnetfound := false
				for _, s := range subnets {
					_, ipnet, err := net.ParseCIDR(s.Subnet)
					if err != nil {
						return fmt.Errorf("unable to parse subnet cidr %s -- %v", s.Subnet, err)
					}
					if ipnet.Contains(ipaddr) {
						var serverIP vmlayer.ServerIP
						serverIP.Network = s.Name
						serverIP.InternalAddr = addr
						serverIP.ExternalAddr = addr
						serverDetail.Addresses = append(serverDetail.Addresses, serverIP)
						subnetfound = true
						break
					}
				}
				if !subnetfound {
					log.SpanLog(ctx, log.DebugLevelInfra, "Did not find subnet for address", "addr", addr, "subnets", subnets)
					return fmt.Errorf("no subnet found for internal addr: %s", addr)
				}
			}
		}
		// now look through the ports and assign port name and mac addresses
		for _, port := range ports {
			for ai, serverAddr := range serverDetail.Addresses {
				if strings.Contains(port.FixedIPs, serverAddr.InternalAddr) {
					serverDetail.Addresses[ai].MacAddress = port.MACAddress
					serverDetail.Addresses[ai].PortName = port.Name
				}
			}
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Updated ServerIPs", "serverDetail", serverDetail)
	return nil
}

func (o *OpenstackPlatform) CreateVMs(ctx context.Context, vmGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	return o.HeatCreateVMs(ctx, vmGroupOrchestrationParams, updateCallback)
}
func (o *OpenstackPlatform) UpdateVMs(ctx context.Context, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	return o.HeatUpdateVMs(ctx, VMGroupOrchestrationParams, updateCallback)
}

func (o *OpenstackPlatform) SyncVMs(ctx context.Context, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SyncVMs")
	// nothing to do right now for openstack
	return nil

}
func (o *OpenstackPlatform) DeleteVMs(ctx context.Context, vmGroupName string) error {
	return o.deleteHeatStack(ctx, vmGroupName)
}
