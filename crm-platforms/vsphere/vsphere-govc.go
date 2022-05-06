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

package vsphere

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/log"
)

var maxGuestWait = time.Minute * 2

const VMMatchAny = "*"
const PortGrpMatchAny = "*"

type MetricsCollectionRequestType struct {
	CollectNetworkStats bool
	CollectCPUStats     bool
	CollectMemStats     bool
}

type GovcVMNet struct {
	IpAddress  []string
	MacAddress string
	Network    string
}

type DPGNetwork struct {
	Type  string
	Value string
}

type DistributedPortGroup struct {
	Name    string
	Network DPGNetwork
	Path    string
}

type GovcNetwork struct {
	Type  string
	Value string
}
type GovcNetworkElementSummary struct {
	Name    string
	Network GovcNetwork
}

type GovcNetworkObject struct {
	Summary GovcNetworkElementSummary
}
type GovcNetworkElement struct {
	Object GovcNetworkObject
}
type GovcNetworkObjects struct {
	Elements []GovcNetworkElement `json:"elements"`
}

type GovcDatastoreSummary struct {
	Capacity  uint64
	FreeSpace uint64
}
type GovcDatastore struct {
	Summary GovcDatastoreSummary
}
type GovcDatastoreInfo struct {
	Datastores []GovcDatastore
}

type GovcRuntime struct {
	PowerState string
}

type GovcVMGuest struct {
	GuestState  string
	ToolsStatus string
	Net         []GovcVMNet
}

type GovcDeviceBackingPort struct {
	PortgroupKey string
}
type GovcDeviceBacking struct {
	Port GovcDeviceBackingPort
}
type GovcVMHardwareDevice struct {
	Backing    GovcDeviceBacking
	MacAddress string
}

type GovcVMHardware struct {
	MemoryMB uint64
	NumCPU   uint64
	Device   []GovcVMHardwareDevice
}

type GovcVMConfig struct {
	Hardware GovcVMHardware
}

type GovcVMFile struct {
	Name string
	Size uint64
}

type GovcVMLayout struct {
	File []GovcVMFile
}

type GovcVMDevice struct {
	Name string
	Type string
}

type GovcVMDeviceList struct {
	Devices []GovcVMDevice
}

type GovcVM struct {
	Name     string
	Runtime  GovcRuntime
	Config   GovcVMConfig
	Guest    GovcVMGuest
	Path     string
	LayoutEx GovcVMLayout
}

type GovcVMs struct {
	VirtualMachines []GovcVM
}

type GovcTagCategory struct {
	Name string `json:"name"`
}

type GovcTag struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category_id"`
}

type GovcHostCpuInfo struct {
	NumCpuCores   uint64
	NumCpuThreads uint64
}

type GovcHostHardware struct {
	CpuInfo    GovcHostCpuInfo
	MemorySize uint64
}

type GovcHost struct {
	Hardware GovcHostHardware
}

type GovcHosts struct {
	HostSystems []GovcHost
}

type GovcResourceInfo struct {
	MaxUsage     uint64
	OverallUsage uint64
}

type GovcPoolRuntime struct {
	Memory GovcResourceInfo
	Cpu    GovcResourceInfo
}
type GovcPool struct {
	Name    string
	Path    string
	Runtime GovcPoolRuntime
}
type GovcPools struct {
	ResourcePools []GovcPool
}

type GovcMetricSampleInfo struct {
	Interval  uint64
	Timestamp string
}

type GovcMetricSampleValue struct {
	Instance string
	Name     string
	Value    []uint64
}

type GovcMetricSample struct {
	SampleInfo []GovcMetricSampleInfo
	Value      []GovcMetricSampleValue
}

type GovcMetricSamples struct {
	Sample []GovcMetricSample
}

type MetricsResult struct {
	BytesTxAverage  uint64
	BytesRxAverage  uint64
	CpuUsagePercent float64
	MemUsageBytes   uint64
	DiskUsageBytes  uint64
	Interval        uint64
	Timestamp       string
}

func (v *VSpherePlatform) TimedGovcCommand(ctx context.Context, name string, a ...string) ([]byte, error) {
	parmstr := strings.Join(a, " ")
	start := time.Now()

	log.SpanLog(ctx, log.DebugLevelInfra, "Govc Command Start", "name", name, "parms", parmstr)
	newSh := infracommon.Sh(v.vcenterVars)

	out, err := newSh.Command(name, a).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Govc command returned error", "parms", parmstr, "out", string(out), "err", err, "elapsed time", time.Since(start))
		return out, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Govc Command Done", "parmstr", parmstr, "elapsed time", time.Since(start))
	return out, nil
}

func (v *VSpherePlatform) GetDistributedPortGroups(ctx context.Context, portgrpNameMatch string) (map[string]DistributedPortGroup, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetDistributedPortGroups", "portgrpNameMatch", portgrpNameMatch)

	var pgrps = make(map[string]DistributedPortGroup)
	dcName := v.GetDatacenterName(ctx)
	networkSearchPath := fmt.Sprintf("/%s/network", dcName)
	out, err := v.TimedGovcCommand(ctx, "govc", "ls", "-dc", dcName, "-json", networkSearchPath)
	if err != nil {
		return nil, err
	}

	var objs GovcNetworkObjects
	err = json.Unmarshal(out, &objs)
	if err != nil {
		return nil, err
	}
	for _, element := range objs.Elements {
		if element.Object.Summary.Network.Type == "DistributedVirtualPortgroup" {
			if portgrpNameMatch == PortGrpMatchAny || strings.Contains(element.Object.Summary.Name, portgrpNameMatch) {
				var pgrp DistributedPortGroup
				pgrp.Name = element.Object.Summary.Name
				pgrp.Path = networkSearchPath + "/" + pgrp.Name
				pgrps[element.Object.Summary.Network.Value] = pgrp
			}
		}
	}
	return pgrps, nil
}

func (v *VSpherePlatform) GetResourcePools(ctx context.Context) (*GovcPools, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetResourcePools")

	dcName := v.GetDatacenterName(ctx)
	computeCluster := v.GetHostCluster()
	pathPrefix := fmt.Sprintf("/%s/host/%s/Resources/", dcName, computeCluster)
	poolSearchPath := pathPrefix + "*"

	out, err := v.TimedGovcCommand(ctx, "govc", "pool.info", "-json", "-dc", dcName, poolSearchPath)
	if err != nil {
		return nil, err
	}

	var pools GovcPools
	err = json.Unmarshal(out, &pools)
	if err != nil {
		return nil, err
	}
	for i, p := range pools.ResourcePools {
		log.SpanLog(ctx, log.DebugLevelInfra, "Found resource pool", "pool", p.Name)
		pools.ResourcePools[i].Path = pathPrefix + p.Name
	}
	return &pools, err
}

func (v *VSpherePlatform) GetHosts(ctx context.Context) (*GovcHosts, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetHosts")

	dcName := v.GetDatacenterName(ctx)
	computeCluster := v.GetHostCluster()
	pathPrefix := fmt.Sprintf("/%s/host/%s/", dcName, computeCluster)
	poolSearchPath := pathPrefix + "*"

	out, err := v.TimedGovcCommand(ctx, "govc", "host.info", "-json", "-dc", dcName, poolSearchPath)
	if err != nil {
		return nil, err
	}

	var hosts GovcHosts
	err = json.Unmarshal(out, &hosts)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal hosts: %v", err)
	}
	return &hosts, nil
}

func (v *VSpherePlatform) GetDataStoreInfo(ctx context.Context) (*GovcDatastoreInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetDataStoreInfo")

	dcName := v.GetDatacenterName(ctx)
	dsName := v.GetDataStore()

	out, err := v.TimedGovcCommand(ctx, "govc", "datastore.info", "-json", "-dc", dcName, dsName)
	if err != nil {
		return nil, err
	}

	var dsinfo GovcDatastoreInfo
	err = json.Unmarshal(out, &dsinfo)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal datastores: %v", err)
	}
	return &dsinfo, nil
}

func (v *VSpherePlatform) GetUsedSubnetCIDRs(ctx context.Context) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetUsedSubnetCIDRs")

	cidrUsed := make(map[string]string)
	tags, err := v.GetTagsForCategory(ctx, v.GetSubnetTagCategory(ctx), vmlayer.VMDomainAny)
	if err != nil {
		return nil, err
	}
	for _, t := range tags {
		subnetTagContents, err := v.ParseSubnetTag(ctx, t.Name)
		if err != nil {
			return nil, err
		}
		cidrUsed[subnetTagContents.Cidr] = subnetTagContents.SubnetName
	}

	return cidrUsed, nil
}

func (v *VSpherePlatform) GetExternalIPForServer(ctx context.Context, server string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetExternalIPForServer", "server", server)
	ips, err := v.GetUsedExternalIPs(ctx)
	if err != nil {
		return "", err
	}
	for ip, svr := range ips {
		if svr == server {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no external ip found for server: %s", server)
}

func (v *VSpherePlatform) GetUsedExternalIPs(ctx context.Context) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetUsedExternalIPs")

	ipsUsed := make(map[string]string)
	extNetId := v.IdSanitize(v.vmProperties.GetCloudletExternalNetwork())

	tags, err := v.GetTagsForCategory(ctx, v.GetVmIpTagCategory(ctx), vmlayer.VMDomainAny)
	if err != nil {
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetUsedExternalIPs tags found", "tags", tags)

	for _, t := range tags {
		vmIpTagContents, err := v.ParseVMIpTag(ctx, t.Name)
		if err != nil {
			return nil, err
		}
		if vmIpTagContents.Network == extNetId {
			log.SpanLog(ctx, log.DebugLevelInfra, "Found external ip", "vm", vmIpTagContents.Vmname, "ip", vmIpTagContents.Ipaddr)
			ipsUsed[vmIpTagContents.Ipaddr] = vmIpTagContents.Vmname
		}
	}
	return ipsUsed, nil
}

func (v *VSpherePlatform) IsPortGrpAttached(ctx context.Context, serverName, portGrpName string) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "IsPortGrpAttached", "serverName", serverName, "portGrpName", portGrpName)

	govcVm, err := v.GetGovcVm(ctx, serverName)
	if err != nil {
		return false, err
	}
	pgrps, err := v.GetDistributedPortGroups(ctx, PortGrpMatchAny)
	if err != nil {
		return false, fmt.Errorf("Failed to get distributed port groups: %v", err)
	}
	for _, dev := range govcVm.Config.Hardware.Device {
		if dev.MacAddress != "" {
			pgrpId := dev.Backing.Port.PortgroupKey
			pgrp, ok := pgrps[pgrpId]
			if ok && pgrp.Name == portGrpName {
				log.SpanLog(ctx, log.DebugLevelInfra, "IsPortGrpAttached found portgrp")
				return true, nil
			}
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "IsPortGrpAttached portgrp not found")
	return false, nil
}

func (v *VSpherePlatform) getServerDetailFromGovcVm(ctx context.Context, govcVm *GovcVM) (*vmlayer.ServerDetail, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getServerDetailFromGovcVm", "name", govcVm.Name)

	pgrps, err := v.GetDistributedPortGroups(ctx, PortGrpMatchAny)
	if err != nil {
		return nil, fmt.Errorf("Failed to get distributed port groups: %v", err)
	}
	var sd vmlayer.ServerDetail
	sd.Name = govcVm.Name
	switch govcVm.Runtime.PowerState {
	case "poweredOn":
		sd.Status = vmlayer.ServerActive
	case "poweredOff":
		sd.Status = vmlayer.ServerShutoff
	default:
		log.SpanLog(ctx, log.DebugLevelInfra, "unexpected power state", "state", govcVm.Runtime.PowerState)
		sd.Status = "unknown"
	}
	err = v.GetIpsFromTagsForVM(ctx, sd.Name, &sd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetIpsFromTagsForVM failed", "err", err)
	}

	for i, sip := range sd.Addresses {
		portGrp, err := v.GetPortGroup(ctx, govcVm.Name, sip.Network)
		if err != nil {
			return nil, err
		}
		macFound := ""
		log.SpanLog(ctx, log.DebugLevelInfra, "Looking for mac for server ip", "sip", sip, "portGrp", portGrp)
		for _, dev := range govcVm.Config.Hardware.Device {
			if dev.MacAddress != "" {
				pgrpId := dev.Backing.Port.PortgroupKey
				pgrp, ok := pgrps[pgrpId]
				if !ok {
					return nil, fmt.Errorf("Port group id not found: %s for VM %s", pgrpId, govcVm.Name)
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "Found a MAC", "MacAddress", dev.MacAddress, "pgrp", pgrp)

				if portGrp == pgrp.Name {
					if macFound != "" {
						log.SpanLog(ctx, log.DebugLevelInfra, "MAC already on different network", "macFound", macFound, "dev.MacAddress", dev.MacAddress)
						return nil, fmt.Errorf("multiple MACs found for network: %s", pgrp.Name)
					}
					macFound = dev.MacAddress
					sd.Addresses[i].MacAddress = dev.MacAddress
					log.SpanLog(ctx, log.DebugLevelInfra, "Setting MAC for address", "MacAddress", dev.MacAddress, "sip", sip.ExternalAddr)

				}
			}
		}
		if macFound == "" {
			// this can happen if port is allocated for the server but not attached
			log.SpanLog(ctx, log.DebugLevelInfra, "Could not find port group to locate MAC for server address on net", "net", sip.Network)
		}
	}
	return &sd, nil
}

// GetNetworkListForVm get a sorted list of attached network names for the VM
func (v *VSpherePlatform) GetNetworkListForVm(ctx context.Context, vmname string) ([]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNetworkListForGovcVm", "name", vmname)

	dcName := v.GetDatacenterName(ctx)
	vmPath := "/" + dcName + "/vm/" + vmname

	out, err := v.TimedGovcCommand(ctx, "govc", "vm.info", "-r", "-dc", dcName, vmPath)
	if err != nil {
		return nil, fmt.Errorf("Unable to get network summary for vm: %s - %v", vmname, err)
	}
	networkPattern := "\\s*Network:\\s+(.*)"
	nreg := regexp.MustCompile(networkPattern)
	lines := strings.Split(string(out), "\n")
	// Example format for what we are looking for
	// Network:              DPGAdminDEV, mex-k8s-subnet-dev-cluster2-mobiledge
	for _, line := range lines {
		if nreg.MatchString(line) {
			matches := nreg.FindStringSubmatch(line)
			networks := strings.ReplaceAll(matches[1], " ", "")
			return strings.Split(networks, ","), nil
		}
	}
	return nil, fmt.Errorf("no networks found for vm: %s", vmname)
}

func (v *VSpherePlatform) GetGovcVm(ctx context.Context, vmname string) (*GovcVM, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetGovcVm", "vmname", vmname)
	dcName := v.GetDatacenterName(ctx)
	vmPath := "/" + dcName + "/vm/" + vmname
	var err error

	out, err := v.TimedGovcCommand(ctx, "govc", "vm.info", "-dc", dcName, "-json", vmPath)
	if err != nil {
		return nil, err
	}
	var vms GovcVMs
	err = json.Unmarshal(out, &vms)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetGovcVm unmarshal fail", "vmname", vmname, "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetGovcVm num vms found", "numVMs", len(vms.VirtualMachines))
	if len(vms.VirtualMachines) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetGovcVm not found", "vmname", vmname)
		return nil, fmt.Errorf(vmlayer.ServerDoesNotExistError)
	}
	if len(vms.VirtualMachines) > 1 {
		log.SpanLog(ctx, log.DebugLevelInfra, "unexpected number of VM found", "vmname", vmname, "vms", vms, "out", string(out), "err", err)
		return nil, fmt.Errorf("unexpected number of VM found: %d", len(vms.VirtualMachines))
	}
	return &vms.VirtualMachines[0], nil
}

func (v *VSpherePlatform) GetServerDetail(ctx context.Context, vmname string) (*vmlayer.ServerDetail, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetail", "vmname", vmname)

	govcVm, err := v.GetGovcVm(ctx, vmname)
	if err != nil {
		return nil, err
	}
	return v.getServerDetailFromGovcVm(ctx, govcVm)
}

func (v *VSpherePlatform) ConnectNetworksForVM(ctx context.Context, vmName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ConnectNetworksForVM", "vmName", vmName)
	dcName := v.GetDatacenterName(ctx)

	var devices GovcVMDeviceList
	// list devices
	out, err := v.TimedGovcCommand(ctx, "govc", "device.ls", "-dc", dcName, "-vm", vmName, "-json")
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in listing VM devices", "out", string(out), "err", err)
		return fmt.Errorf("Error in listing VM devices: %s - %v", string(out), err)
	}
	err = json.Unmarshal(out, &devices)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "List devices unmarshal fail", "out", string(out), "err", err)
		return fmt.Errorf("cannot unmarshal govc device list: %v", err)
	}

	for _, d := range devices.Devices {
		if strings.HasPrefix(d.Name, "ethernet") {
			log.SpanLog(ctx, log.DebugLevelInfra, "Connect network interface", "vmName", vmName, "deviceName", d.Name)
			// it is ok to connect a device already connected
			out, err = v.TimedGovcCommand(ctx, "govc", "device.connect", "-dc", dcName, "-vm", vmName, d.Name)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "Error in connecting network interface", "vmName", vmName, "deviceName", d.Name, "out", string(out), "err", err)
				return fmt.Errorf("Error in connecting network interface for VM: %s - %s, %v", vmName, string(out), err)
			}
		}
	}
	return nil
}

func (v *VSpherePlatform) GetVMs(ctx context.Context, vmNameMatch string, domainMatch vmlayer.VMDomain) (*GovcVMs, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVMs", "vmNameMatch", vmNameMatch, "domainMatch", domainMatch)
	var vms GovcVMs
	dcName := v.GetDatacenterName(ctx)

	vmtags, err := v.GetTagsForCategory(ctx, v.GetVMDomainTagCategory(ctx), domainMatch)
	if err != nil {
		return nil, err
	}

	vmPath := "/" + dcName + "/vm/"
	out, err := v.TimedGovcCommand(ctx, "govc", "vm.info", "-dc", dcName, "-json", vmPath+vmNameMatch)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(out, &vms)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetVMs unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal govc vms, %v", err)
		return nil, err
	}
	for i, vm := range vms.VirtualMachines {
		vms.VirtualMachines[i].Path = vmPath + vm.Name
	}
	if domainMatch == vmlayer.VMDomainAny {
		// no tag filtering
		return &vms, nil
	}
	vmnames, err := v.GetVmNamesFromTags(ctx, vmtags)
	if err != nil {
		return nil, err
	}
	// filter the list
	var matchedVms GovcVMs
	for _, vm := range vms.VirtualMachines {
		_, ok := vmnames[vm.Name]
		if ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "VM Matched tag", "vmName", vm.Name, "tagMatch", domainMatch)
			matchedVms.VirtualMachines = append(matchedVms.VirtualMachines, vm)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "VM Did not match tag", "vmName", vm.Name, "tagMatch", domainMatch)
		}
	}
	return &matchedVms, nil
}

func (v *VSpherePlatform) SetPowerState(ctx context.Context, serverName, serverAction string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetPowerState", "serverName", serverName, "serverAction", serverAction)
	dcName := v.GetDatacenterName(ctx)
	vmPath := "/" + dcName + "/vm/" + serverName
	var err error

	switch serverAction {
	case vmlayer.ActionStop:
		_, err = v.TimedGovcCommand(ctx, "govc", "vm.power", "-dc", dcName, "-off", vmPath)
	case vmlayer.ActionStart:
		_, err = v.TimedGovcCommand(ctx, "govc", "vm.power", "-dc", dcName, "-on", vmPath)
	case vmlayer.ActionReboot:
		_, err = v.TimedGovcCommand(ctx, "govc", "vm.power", "-dc", dcName, "-reset", vmPath)
	default:
		return fmt.Errorf("unsupported server action: %s", serverAction)
	}
	return err
}

func (v *VSpherePlatform) GetConsoleUrl(ctx context.Context, serverName string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetConsoleUrl", "serverName", serverName)
	dcName := v.GetDatacenterName(ctx)
	vmPath := "/" + dcName + "/vm/" + serverName
	out, err := v.TimedGovcCommand(ctx, "govc", "vm.console", "-dc", dcName, "-h5", vmPath)

	consoleUrl := strings.TrimSpace(string(out))
	urlObj, err := url.Parse(consoleUrl)
	if err != nil {
		return "", fmt.Errorf("unable to parse console url - %v", err)
	}
	//append the port if it is not there
	if !strings.Contains(urlObj.Host, ":") {
		if urlObj.Scheme == "https" {
			urlObj.Host = urlObj.Host + ":443"
		} else {
			urlObj.Host = urlObj.Host + ":80"
		}
	}
	// now we need a session cookie
	cookieString, err := v.GetVCenterConsoleSessionCookie(ctx)
	if err != nil {
		return "", err
	}
	cookie64 := base64.StdEncoding.EncodeToString([]byte(cookieString))

	return urlObj.String() + "&" + "sessioncookie=" + cookie64, nil
}

func (v *VSpherePlatform) GetMetrics(ctx context.Context, vmMatch string, collectRequest *MetricsCollectionRequestType) (*MetricsResult, error) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "GetMetrics", "vm", vmMatch)
	var result MetricsResult
	dcName := v.GetDatacenterName(ctx)
	vmPath := "/" + dcName + "/vm/" + vmMatch
	var err error

	args := []string{"metric.sample", "-n", "1", "-json", "-dc", dcName, vmPath}
	if collectRequest.CollectNetworkStats {
		args = append(args, "net.bytesTx.average")
		args = append(args, "net.bytesRx.average")
	}
	if collectRequest.CollectCPUStats {
		args = append(args, "cpu.usage.average")
	}
	if collectRequest.CollectMemStats {
		args = append(args, "mem.active.average")
	}
	out, err := v.TimedGovcCommand(ctx, "govc", args...)
	if err != nil {
		return nil, err
	}

	var samples GovcMetricSamples
	err = json.Unmarshal(out, &samples)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal network samples: %v", err)
	}

	for _, s := range samples.Sample {
		if len(s.SampleInfo) > 0 {
			result.Interval = s.SampleInfo[0].Interval
			result.Timestamp = s.SampleInfo[0].Timestamp
		} else {
			return nil, fmt.Errorf("no network metric sample info returned")
		}
		for _, sampleVal := range s.Value {
			if len(sampleVal.Value) > 0 {
				switch sampleVal.Name {
				case "net.bytesRx.average":
					result.BytesRxAverage += sampleVal.Value[0]
				case "net.bytesTx.average":
					result.BytesTxAverage += sampleVal.Value[0]
				case "cpu.usage.average":
					result.CpuUsagePercent = float64(sampleVal.Value[0]) / 100
				case "mem.active.average":
					// mem.active.average is in KB, convert to bytes
					result.MemUsageBytes = sampleVal.Value[0] * 1024
				}
			}
		}
	}
	return &result, nil
}

func (v *VSpherePlatform) CreateTemplateFolder(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelMetrics, "CreateTemplateFolder")

	dcName := v.GetDatacenterName(ctx)
	folderPath := fmt.Sprintf("/%s/vm/%s", dcName, v.GetTemplateFolder())
	out, err := v.TimedGovcCommand(ctx, "govc", "folder.create", "-dc", dcName, folderPath)
	if err != nil {
		if strings.Contains(string(out), "already exists") {
			log.SpanLog(ctx, log.DebugLevelInfra, "Template folder already exists", "folderPath", folderPath)
			return nil
		}
		return fmt.Errorf("unable to create template folder: %s", folderPath)
	}
	return nil
}
