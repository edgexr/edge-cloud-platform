package openstack

import (
	"context"
	"fmt"
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

	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateServerIPs", "addresses", addresses, "serverDetail", serverDetail)
	its := strings.Split(addresses, ";")

	for _, it := range its {
		var serverIP vmlayer.ServerIP
		sits := strings.Split(it, "=")
		if len(sits) != 2 {
			return fmt.Errorf("GetServerIPFromAddrs: Unable to parse '%s'", it)
		}
		network := strings.TrimSpace(sits[0])
		serverIP.Network = network
		addr := sits[1]
		// the comma indicates a floating IP is present.
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
		}
		for _, p := range ports {
			if strings.Contains(p.FixedIPs, serverIP.InternalAddr) {
				serverIP.MacAddress = p.MACAddress
			}
		}
		serverDetail.Addresses = append(serverDetail.Addresses, serverIP)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Updated ServerIPS", "serverDetail", serverDetail)
	return nil
}

func (o *OpenstackPlatform) CreateVMs(ctx context.Context, vmGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	return o.HeatCreateVMs(ctx, vmGroupOrchestrationParams, updateCallback)
}
func (o *OpenstackPlatform) UpdateVMs(ctx context.Context, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	return o.HeatUpdateVMs(ctx, VMGroupOrchestrationParams, updateCallback)
}

func (o *OpenstackPlatform) DeleteVMs(ctx context.Context, vmGroupName string) error {
	return o.deleteHeatStack(ctx, vmGroupName)
}
