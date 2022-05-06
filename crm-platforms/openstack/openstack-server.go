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
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
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

// UpdateServerIPs gets the ServerIPs for the given network from the addresses and ports
func (o *OpenstackPlatform) UpdateServerIPs(ctx context.Context, addresses string, ports []OSPort, serverDetail *vmlayer.ServerDetail) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateServerIPs", "addresses", addresses, "serverDetail", serverDetail, "ports", ports)

	netTypes := []vmlayer.NetworkType{
		vmlayer.NetworkTypeExternalAdditionalPlatform,
		vmlayer.NetworkTypeExternalAdditionalRootLb,
		vmlayer.NetworkTypeExternalAdditionalClusterNode,
		vmlayer.NetworkTypeExternalPrimary,
	}
	externalNetMap := o.VMProperties.GetNetworksByType(ctx, netTypes)
	its := strings.Split(addresses, ";")

	for _, it := range its {
		sits := strings.Split(it, "=")
		if len(sits) != 2 {
			return fmt.Errorf("UpdateServerIPs: Unable to parse '%s'", it)
		}
		network := strings.TrimSpace(sits[0])
		addr := sits[1]
		_, isExternal := externalNetMap[network]
		if isExternal {
			var serverIP vmlayer.ServerIP
			serverIP.Network = network
			// multiple ips for an external network indicates a floating ip on a single port
			if strings.Contains(addr, ",") {
				addrs := strings.Split(addr, ",")
				if len(addrs) == 2 {
					serverIP.InternalAddr = strings.TrimSpace(addrs[0])
					serverIP.ExternalAddr = strings.TrimSpace(addrs[1])
					serverIP.ExternalAddrIsFloating = true
					serverDetail.Addresses = append(serverDetail.Addresses, serverIP)
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

func (o *OpenstackPlatform) DeleteVMs(ctx context.Context, vmGroupName string) error {
	return o.deleteHeatStack(ctx, vmGroupName)
}

// Helper function to asynchronously get the metric from openstack
func (s *OpenstackPlatform) goGetMetricforId(ctx context.Context, id string, measurement string, osMetric *OSMetricMeasurement) chan string {
	waitChan := make(chan string)
	go func() {
		// We don't want to have a bunch of data, just get from last 2*interval
		startTime := time.Now().Add(-time.Minute * 10)
		metrics, err := s.OSGetMetricsRangeForId(ctx, id, measurement, startTime)
		if err == nil && len(metrics) > 0 {
			*osMetric = metrics[len(metrics)-1]
			waitChan <- ""
		} else if len(metrics) == 0 {
			waitChan <- "no metric"
		} else {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Error getting metric", "id", id,
				"measurement", measurement, "error", err)
			waitChan <- err.Error()
		}
	}()
	return waitChan
}

func (s *OpenstackPlatform) GetVMStats(ctx context.Context, appInst *edgeproto.AppInst) (*vmlayer.VMMetrics, error) {
	var Cpu, Mem, NetSent, NetRecv OSMetricMeasurement
	netSentChan := make(chan string)
	netRecvChan := make(chan string)
	vmMetrics := vmlayer.VMMetrics{}
	// note disk stats are available via disk.device.usage, but they are useless for our purposes, as they do not reflect
	// OS usage inside the VM, rather the disk metrics measure the size of various VM files on the datastore

	if appInst == nil {
		return &vmMetrics, fmt.Errorf("Nil AppInst passed")
	}

	server, err := s.GetActiveServerDetails(ctx, appInst.UniqueId)
	if err != nil {
		return &vmMetrics, err
	}

	// Get a bunch of the results in parallel as it might take a bit of time
	cpuChan := s.goGetMetricforId(ctx, server.ID, "cpu_util", &Cpu)
	memChan := s.goGetMetricforId(ctx, server.ID, "memory.usage", &Mem)

	// For network we try to get the id of the instance_network_interface for an instance
	netIf, err := s.OSFindResourceByInstId(ctx, "instance_network_interface", server.ID, "")
	if err == nil {
		netSentChan = s.goGetMetricforId(ctx, netIf.Id, "network.outgoing.bytes.rate", &NetSent)
		netRecvChan = s.goGetMetricforId(ctx, netIf.Id, "network.incoming.bytes.rate", &NetRecv)
	} else {
		go func() {
			netRecvChan <- "Unavailable"
			netSentChan <- "Unavailable"
		}()
	}
	cpuErr := <-cpuChan
	memErr := <-memChan
	netInErr := <-netRecvChan
	netOutErr := <-netSentChan

	// Now fill the metrics that we actually got
	if cpuErr == "" {
		time, err := time.Parse(time.RFC3339, Cpu.Timestamp)
		if err == nil {
			vmMetrics.Cpu = Cpu.Value
			vmMetrics.CpuTS, _ = types.TimestampProto(time)
		}
	}
	if memErr == "" {
		time, err := time.Parse(time.RFC3339, Mem.Timestamp)
		if err == nil {
			// Openstack gives it to us in MB
			vmMetrics.Mem = uint64(Mem.Value * 1024 * 1024)
			vmMetrics.MemTS, _ = types.TimestampProto(time)
		}
	}
	if netInErr == "" {
		time, err := time.Parse(time.RFC3339, NetRecv.Timestamp)
		if err == nil {
			vmMetrics.NetRecv = uint64(NetRecv.Value)
			vmMetrics.NetRecvTS, _ = types.TimestampProto(time)
		}
	}
	if netOutErr == "" {
		time, err := time.Parse(time.RFC3339, NetSent.Timestamp)
		if err == nil {
			vmMetrics.NetSent = uint64(NetSent.Value)
			vmMetrics.NetSentTS, _ = types.TimestampProto(time)
		}
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "Finished openstack vm metrics", "metrics", vmMetrics)
	return &vmMetrics, nil
}

func (o *OpenstackPlatform) VmAppChangedCallback(ctx context.Context, appInst *edgeproto.AppInst, newState edgeproto.TrackedState) {
}

// Given pool ranges return total number of available ip addresses
// Example: 10.10.10.1-10.10.10.20,10.10.10.30-10.10.10.40
//  Returns 20+11 = 31
func getIpCountFromPools(ipPools string) (uint64, error) {
	var total uint64
	total = 0
	pools := strings.Split(ipPools, ",")
	for _, p := range pools {
		ipRange := strings.Split(p, "-")
		if len(ipRange) != 2 {
			return 0, fmt.Errorf("invalid ip pool format")
		}
		ipStart := net.ParseIP(ipRange[0])
		ipEnd := net.ParseIP(ipRange[1])
		if ipStart == nil || ipEnd == nil {
			return 0, fmt.Errorf("Could not parse ip pool limits")
		}
		numStart := new(big.Int)
		numEnd := new(big.Int)
		diff := new(big.Int)
		numStart = numStart.SetBytes(ipStart)
		numEnd = numEnd.SetBytes(ipEnd)
		if numStart == nil || numEnd == nil {
			return 0, fmt.Errorf("cannot convert bytes to bigInt")
		}
		diff = diff.Sub(numEnd, numStart)
		total += diff.Uint64()
		// add extra 1 for the start of pool
		total += 1
	}
	return total, nil
}

func (s *OpenstackPlatform) addIpUsageDetails(ctx context.Context, platformRes *vmlayer.PlatformResources) error {
	externalNet, err := s.GetNetworkDetail(ctx, s.VMProperties.GetCloudletExternalNetwork())
	if err != nil {
		return err
	}
	if externalNet == nil {
		return fmt.Errorf("No external network")
	}
	subnets := strings.Split(externalNet.Subnets, ",")
	if len(subnets) < 1 {
		return nil
	}
	// Assume first subnet for now - see similar note in GetExternalGateway()
	sd, err := s.GetSubnetDetail(ctx, subnets[0])
	if err != nil {
		return err
	}
	if platformRes.Ipv4Max, err = getIpCountFromPools(sd.AllocationPools); err != nil {
		return err
	}
	// Get current usage
	srvs, err := s.ListServers(ctx)
	if err != nil {
		return err
	}
	platformRes.Ipv4Used = 0
	for _, srv := range srvs {
		if strings.Contains(srv.Networks, s.VMProperties.GetCloudletExternalNetwork()) {
			platformRes.Ipv4Used++
		}
	}
	return nil
}

func (s *OpenstackPlatform) GetPlatformResourceInfo(ctx context.Context) (*vmlayer.PlatformResources, error) {
	platformRes := vmlayer.PlatformResources{}
	limits, err := s.OSGetAllLimits(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "openstack limits", "error", err)
		return &platformRes, err
	}

	platformRes.CollectTime, _ = types.TimestampProto(time.Now())
	// Openstack limits for RAM in MB and Disk is in GBs
	for _, l := range limits {

		if l.Name == "maxTotalRAMSize" {
			platformRes.MemMax = uint64(l.Value)
		} else if l.Name == "totalRAMUsed" {
			platformRes.MemUsed = uint64(l.Value)
		} else if l.Name == "maxTotalCores" {
			platformRes.VCpuMax = uint64(l.Value)
		} else if l.Name == "totalCoresUsed" {
			platformRes.VCpuUsed = uint64(l.Value)
		} else if l.Name == "maxTotalVolumeGigabytes" {
			platformRes.DiskMax = uint64(l.Value)
		} else if l.Name == "totalGigabytesUsed" {
			platformRes.DiskUsed = uint64(l.Value)
		} else if l.Name == "maxTotalFloatingIps" {
			platformRes.FloatingIpsMax = uint64(l.Value)
		} else if l.Name == "totalFloatingIpsUsed" {
			platformRes.FloatingIpsUsed = uint64(l.Value)
		}
	}
	// TODO - collect network data for all the VM instances

	// Get Ip pool usage
	if s.addIpUsageDetails(ctx, &platformRes) != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "get ip pool information", "error", err)
	}
	return &platformRes, nil
}

func (s *OpenstackPlatform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	return nil
}

func (s *OpenstackPlatform) CheckServerReady(ctx context.Context, client ssh.Client, serverName string) error {
	// no special checks to be done
	return nil
}

func (o *OpenstackPlatform) GetServerGroupResources(ctx context.Context, name string) (*edgeproto.InfraResources, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetServerGroupResources")
	var resources edgeproto.InfraResources
	serverMap, err := o.ListServers(ctx)
	if err != nil {
		return nil, err
	}
	stackTemplate, err := o.getHeatStackTemplateDetail(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch heat stack template for %s: %v", name, err)
	}
	for resourceName, resource := range stackTemplate.Resources {
		if resource.Type != "OS::Nova::Server" {
			continue
		}
		vmName, ok := resource.Properties["name"]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "missing VM Name", "resourceName", resourceName, "resource", resource)
			continue
		}
		vmNameStr, ok := vmName.(string)
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "invalid vm name", "vmName", vmName)
			continue
		}
		svr, ok := serverMap[vmNameStr]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "unable to find server name in map", "vmNameStr", vmNameStr)
			continue
		}
		var ports []OSPort
		var sd vmlayer.ServerDetail
		err = o.UpdateServerIPs(ctx, svr.Networks, ports, &sd)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "fail to get server IPs", "vmNameStr", vmNameStr, "networks", svr.Networks, "err", err)
			continue
		}
		vmInfo := edgeproto.VmInfo{
			Name:        vmNameStr,
			Status:      svr.Status,
			InfraFlavor: svr.Flavor,
		}
		netTypes := []vmlayer.NetworkType{
			vmlayer.NetworkTypeExternalAdditionalPlatform,
			vmlayer.NetworkTypeExternalAdditionalRootLb,
			vmlayer.NetworkTypeExternalAdditionalClusterNode,
			vmlayer.NetworkTypeExternalPrimary,
		}
		externalNetMap := o.VMProperties.GetNetworksByType(ctx, netTypes)
		for _, sip := range sd.Addresses {
			vmip := edgeproto.IpAddr{}
			_, isExternal := externalNetMap[sip.Network]
			if isExternal {
				vmip.ExternalIp = sip.ExternalAddr
				if sip.InternalAddr != "" && sip.InternalAddr != sip.ExternalAddr {
					vmip.InternalIp = sip.InternalAddr
				}
			} else {
				vmip.InternalIp = sip.InternalAddr
			}
			vmInfo.Ipaddresses = append(vmInfo.Ipaddresses, vmip)
		}
		// fetch the role from the metadata, if available
		role := ""
		metadata, ok := resource.Properties["metadata"]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "missing metadata", "resource", resource)
		} else {
			metamap, ok := metadata.(map[string]interface{})
			if !ok {
				log.SpanLog(ctx, log.DebugLevelInfra, "invalid meta data", "metadata", metadata)
			} else {
				roleobj, ok := metamap["role"]
				if ok {
					rolestr, ok := roleobj.(string)
					if ok {
						role = rolestr
					} else {
						log.SpanLog(ctx, log.DebugLevelInfra, "invalid metadata role", "roleobj", roleobj)
					}
				} else {
					log.SpanLog(ctx, log.DebugLevelInfra, "no role in metadata", "metamap", metamap)
				}
			}
		}
		vmInfo.Type = o.VMProperties.GetNodeTypeForVmNameAndRole(vmNameStr, role).String()
		resources.Vms = append(resources.Vms, vmInfo)
	}
	return &resources, nil
}
