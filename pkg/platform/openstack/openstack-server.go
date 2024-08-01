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
	"net/netip"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/vmlayer"
	ssh "github.com/edgexr/golang-ssh"
	"github.com/gogo/protobuf/types"
)

func (o *OpenstackPlatform) GetServerDetail(ctx context.Context, serverName string) (*vmlayer.ServerDetail, error) {
	var sd vmlayer.ServerDetail
	osd, err := o.GetOpenstackServerDetails(ctx, serverName)
	if err != nil && strings.Contains(err.Error(), "No Server found") {
		return nil, fmt.Errorf(vmlayer.ServerDoesNotExistError + " for " + serverName)
	}
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
	log.SpanLog(ctx, log.DebugLevelInfra, "got server details", "serverDetails", sd)
	return &sd, nil
}

// UpdateServerIPs gets the ServerIPs for the given network from the addresses and ports
func (o *OpenstackPlatform) UpdateServerIPs(ctx context.Context, addresses map[string][]string, ports []OSPort, serverDetail *vmlayer.ServerDetail) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateServerIPs", "addresses", addresses, "serverDetail", serverDetail, "ports", ports)

	// get floating IPs
	floatingIPs, err := o.ListFloatingIPs(ctx, "")
	if err != nil {
		return err
	}
	floatingIPLookup := make(map[string]OSFloatingIP)
	for _, fip := range floatingIPs {
		floatingIPLookup[fip.FloatingIPAddress] = fip
	}

	// cache network lookups
	networksByName := make(map[string]*vmlayer.NetworkDetail)
	networksByID := make(map[string]*vmlayer.NetworkDetail)
	lookupNetwork := func(nameOrID string) (*vmlayer.NetworkDetail, error) {
		networkDetail, found := networksByID[nameOrID]
		if !found {
			networkDetail, found = networksByName[nameOrID]
		}
		if !found {
			osnd, err := o.GetOSNetworkDetail(ctx, nameOrID)
			if err != nil {
				return nil, fmt.Errorf("failed to look up network detail for network %s, %s", nameOrID, err)
			}
			networkDetail = &vmlayer.NetworkDetail{
				ID:     osnd.ID,
				Name:   osnd.Name,
				Status: osnd.Status,
				MTU:    osnd.MTU,
			}
			networksByName[osnd.Name] = networkDetail
			networksByID[osnd.ID] = networkDetail
		}
		return networkDetail, nil
	}

	// Iterate over fixed IPs on ports. The source of truth for fixed IPs are
	// the ports, not those reported on the server. In fact, adding a new
	// fixed IP to a port already attached to the server does not update the
	// IPs reported on the server with the new IP.
	fixedIPs := make(map[string]OSPort)
	for _, port := range ports {
		for _, ip := range port.FixedIPs {
			fixedIPs[ip.IPAddress] = port

			ipaddr, err := netip.ParseAddr(ip.IPAddress)
			if err != nil {
				return fmt.Errorf("failed to parse ip address %s on server %s", ip.IPAddress, serverDetail.Name)
			}
			ossd, err := o.GetSubnetDetail(ctx, ip.SubnetID)
			if err != nil {
				return fmt.Errorf("failed to look up subnet %s for ip %s, %s", ip.SubnetID, ip.IPAddress, err)
			}
			subnetDetail, err := o.GetVMSubnetDetail(ctx, ossd)
			if err != nil {
				return err
			}
			networkDetail, err := lookupNetwork(ossd.NetworkID)
			if err != nil {
				return err
			}
			// assume there won't be more than one fixed IP per subnet
			networkDetail.Subnets = append(networkDetail.Subnets, *subnetDetail)

			var serverIP vmlayer.ServerIP
			serverIP.Network = networkDetail.Name
			serverIP.InternalAddr = ip.IPAddress
			serverIP.ExternalAddr = ip.IPAddress
			if ipaddr.Is4() {
				serverIP.IPVersion = infracommon.IPV4
			} else if ipaddr.Is6() {
				serverIP.IPVersion = infracommon.IPV6
			}
			serverIP.SubnetName = subnetDetail.Name
			serverIP.MacAddress = port.MACAddress
			serverIP.PortName = port.Name
			log.SpanLog(ctx, log.DebugLevelInfra, "updated fixed IP", "serverIP", serverIP)
			serverDetail.Addresses = append(serverDetail.Addresses, serverIP)
		}
	}

	// Register floating IPs from the server address list.
	// Unlike fixed IPs which are attached to ports, floating IPs are attached
	// directly to the server.
	for network, ips := range addresses {
		for _, addr := range ips {
			if _, found := fixedIPs[addr]; found {
				continue
			}
			if _, found := floatingIPLookup[addr]; !found {
				// this can happen when a port is removed, the fixed IPs
				// on the port aren't removed from the server addresses.
				log.SpanLog(ctx, log.DebugLevelInfra, "server address not found on fixed or floating IPs, may be from removed port, ignoring", "addr", addr)
				continue
			}

			// must be floating IP
			addr = strings.TrimSpace(addr)
			ipaddr, err := netip.ParseAddr(addr)
			if err != nil {
				return fmt.Errorf("failed to parse floating ip address %s on server %s", addr, serverDetail.Name)
			}
			ipversion := infracommon.IPV4
			if ipaddr.Is6() {
				ipversion = infracommon.IPV6
			}

			// find the internal fixed IP on the same network
			found := false
			for ii, sip := range serverDetail.Addresses {
				if sip.Network == network && ipversion == sip.IPVersion {
					serverDetail.Addresses[ii].ExternalAddr = addr
					serverDetail.Addresses[ii].ExternalAddrIsFloating = true
					found = true
					log.SpanLog(ctx, log.DebugLevelInfra, "registered floating IP", "serverIP", serverDetail.Addresses[ii])
					break
				}
			}
			if !found {
				return fmt.Errorf("floating IP %s on network %s, but no private IP on same network found", addr, network)
			}
		}
	}
	serverDetail.Networks = networksByName
	return nil
}

func (o *OpenstackPlatform) CreateVMs(ctx context.Context, vmGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	return o.HeatCreateVMs(ctx, vmGroupOrchestrationParams, updateCallback)
}
func (o *OpenstackPlatform) UpdateVMs(ctx context.Context, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	return o.HeatUpdateVMs(ctx, VMGroupOrchestrationParams, updateCallback)
}

func (o *OpenstackPlatform) DeleteVMs(ctx context.Context, vmGroupName, ownerID string) error {
	err := o.deleteHeatStack(ctx, vmGroupName)
	if err != nil {
		return err
	}
	err = o.reservedSubnets.ReleaseForOwner(ctx, ownerID)
	if err != nil {
		return err
	}
	err = o.reservedFloatingIPs.ReleaseForOwner(ctx, ownerID)
	if err != nil {
		return err
	}
	return nil
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
// Returns 20+11 = 31
func getIpCountFromPools(ipPools []OSAllocationPool) (uint64, error) {
	var total uint64
	total = 0
	for _, pool := range ipPools {
		ipStart := net.ParseIP(pool.Start)
		ipEnd := net.ParseIP(pool.End)
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
	externalNet, err := s.GetOSNetworkDetail(ctx, s.VMProperties.GetCloudletExternalNetwork())
	if err != nil {
		return err
	}
	if externalNet == nil {
		return fmt.Errorf("No external network")
	}
	subnets := externalNet.Subnets
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
		for netname, ips := range srv.Networks {
			if strings.Contains(netname, s.VMProperties.GetCloudletExternalNetwork()) {
				platformRes.Ipv4Used += uint64(len(ips))
			}
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
		sd, err := o.GetServerDetail(ctx, vmNameStr)
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
			vmlayer.NetworkTypeExternalSecondary,
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
