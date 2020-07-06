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

	"github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/log"
)

var maxGuestWait = time.Minute * 2

const VMMatchAny = "*"

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

type DistributedPortGroup struct {
	Name string
	Path string
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

type GovcVMHardware struct {
	MemoryMB uint64
	NumCPU   uint64
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
	newSh := sh.NewSession()
	for key, val := range v.vcenterVars {
		newSh.SetEnv(key, val)
	}

	out, err := newSh.Command(name, a).CombinedOutput()
	if err != nil {
		log.InfoLog("Govc command returned error", "parms", parmstr, "out", string(out), "err", err, "elapsed time", time.Since(start))
		return out, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Govc Command Done", "parmstr", parmstr, "elapsed time", time.Since(start))
	return out, nil
}

func (v *VSpherePlatform) GetDistributedPortGroups(ctx context.Context) ([]DistributedPortGroup, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetDistributedPortGroups")

	var pgrps []DistributedPortGroup
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

			if strings.Contains(element.Object.Summary.Name, "subnet") {
				var pgrp DistributedPortGroup
				pgrp.Name = element.Object.Summary.Name
				pgrp.Path = networkSearchPath + "/" + pgrp.Name
				pgrps = append(pgrps, pgrp)
			}
		}
	}
	return pgrps, nil
}

func (v *VSpherePlatform) GetResourcePools(ctx context.Context) (*GovcPools, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetResourcePools")

	dcName := v.GetDatacenterName(ctx)
	computeCluster := v.GetComputeCluster()
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
	computeCluster := v.GetComputeCluster()
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
	tags, err := v.getTagsForCategory(ctx, v.GetSubnetTagCategory(ctx))
	if err != nil {
		return nil, err
	}
	for _, t := range tags {
		// tags are format subnet__cidr
		ts := strings.Split(t.Name, vmlayer.TagDelimiter)
		if len(ts) != 2 {
			log.SpanLog(ctx, log.DebugLevelInfra, "incorrect subnet tag format", "tag", t)
			return nil, fmt.Errorf("incorrect subnet tag format %s", t)
		}
		sn := ts[0]
		cidr := ts[1]
		cidrUsed[cidr] = sn
	}

	return cidrUsed, nil
}

func (v *VSpherePlatform) GetTags(ctx context.Context) ([]GovcTag, error) {
	out, err := v.TimedGovcCommand(ctx, "govc", "tags.ls", "-json")
	var tags []GovcTag
	err = json.Unmarshal(out, &tags)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetTags unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal govc subnet tags, %v", err)
		return nil, err
	}
	return tags, nil
}

func (v *VSpherePlatform) getTagsForCategory(ctx context.Context, category string) ([]GovcTag, error) {
	out, err := v.TimedGovcCommand(ctx, "govc", "tags.ls", "-c", category, "-json")

	var tags []GovcTag
	err = json.Unmarshal(out, &tags)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "getTagsForCategory unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal govc subnet tags, %v", err)
		return nil, err
	}
	return tags, nil
}

func (v *VSpherePlatform) GetTagCategories(ctx context.Context) ([]GovcTagCategory, error) {
	dcName := v.GetDatacenterName(ctx)

	out, err := v.TimedGovcCommand(ctx, "govc", "tags.category.ls", "-json")
	if err != nil {
		return nil, err
	}

	var foundcats []GovcTagCategory
	var returnedcats []GovcTagCategory
	err = json.Unmarshal(out, &foundcats)
	if err != nil {
		return nil, err

	}
	// exclude the ones not in our datacenter
	for _, c := range foundcats {
		if strings.HasPrefix(c.Name, dcName) {
			returnedcats = append(returnedcats, c)
		}
	}
	return returnedcats, err
}

func (v *VSpherePlatform) GetIpFromTagsForVM(ctx context.Context, vmName, netname string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetIpFromTagsForVM", "vmName", vmName, "netname", netname)
	tags, err := v.getTagsForCategory(ctx, v.GetVmIpTagCategory(ctx))
	if err != nil {
		return "", err
	}
	for _, t := range tags {
		// vmtags are format vm__network__cidr
		ts := strings.Split(t.Name, vmlayer.TagDelimiter)
		if len(ts) != 3 {
			log.SpanLog(ctx, log.DebugLevelInfra, "incorrect tag format", "tag", t)
			continue
		}
		vm := ts[0]
		net := ts[1]
		ip := ts[2]
		if vm == vmName && net == netname {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no ip found from tags for %s", vmName)
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

	tags, err := v.getTagsForCategory(ctx, v.GetVmIpTagCategory(ctx))
	if err != nil {
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetUsedExternalIPs tags found", "tags", tags)

	for _, t := range tags {
		// tags are format vm__network__ip
		ts := strings.Split(t.Name, vmlayer.TagDelimiter)
		if len(ts) != 3 {
			return nil, fmt.Errorf("notice: incorrect tag format for tag: %s", t)
		}
		if ts[1] == extNetId {
			log.SpanLog(ctx, log.DebugLevelInfra, "Found external ip", "server", ts[0], "ip", ts[2])
			ipsUsed[ts[2]] = ts[0]
		}
	}
	return ipsUsed, nil
}

func (v *VSpherePlatform) getServerDetailFromGovcVm(ctx context.Context, govcVm *GovcVM) *vmlayer.ServerDetail {
	log.SpanLog(ctx, log.DebugLevelInfra, "getServerDetailFromGovcVm", "name", govcVm.Name, "guest state", govcVm.Guest.GuestState)

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
	/*  The below code works but not in the following cases:
	1) the VM is powered off
	2) the VM has not yet reported the IPs to VC after startup
	*/
	netlist, err := v.GetNetworkListForGovcVm(ctx, sd.Name)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Unable to get network list for VM", "name", govcVm.Name, "err", err)
	}
	for i, net := range govcVm.Guest.Net {
		var sip vmlayer.ServerIP
		// sip.Network = net.Network -- prior to vSphere 7 this worked, TODO: check in future if this is fixed
		sip.MacAddress = net.MacAddress
		sip.PortName = vmlayer.GetPortName(govcVm.Name, net.Network)
		if i < len(netlist) {
			sip.Network = netlist[i]
		}
		if net.Network == "" {
			continue
		}
		if len(net.IpAddress) > 0 {
			sip.ExternalAddr = net.IpAddress[0]
			sip.InternalAddr = net.IpAddress[0]
		} else {
			ip, err := v.GetIpFromTagsForVM(ctx, sd.Name, sip.Network)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetIpFromTagsForVM failed", "net", sip.Network, "err", err)
			} else {
				sip.ExternalAddr = ip
				sip.InternalAddr = ip
			}
		}
		sd.Addresses = append(sd.Addresses, sip)
	}
	// if there is not guest net info, populate what is available from tags for the external network
	// this can happen for VMs which do not have vmtools installed
	if len(govcVm.Guest.Net) == 0 {
		var sip vmlayer.ServerIP
		sip.Network = v.vmProperties.GetCloudletExternalNetwork()
		sip.PortName = vmlayer.GetPortName(govcVm.Name, sip.Network)
		ip, err := v.GetIpFromTagsForVM(ctx, sd.Name, sip.Network)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetIpFromTagsForVM failed", "net", sip.Network, "err", err)
		} else {
			sip.ExternalAddr = ip
			sip.InternalAddr = ip
			sd.Addresses = append(sd.Addresses, sip)
		}
	}
	return &sd
}

// a vSphere7/Govc interaction problem in which vm.info does not return port group names, but
// only UUIDs for the vswitch which is not one to one with a portgroup.  The non-json output
func (v *VSpherePlatform) GetNetworkListForGovcVm(ctx context.Context, vmname string) ([]string, error) {
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
			networks := strings.TrimSpace(matches[1])
			return strings.Split(networks, ","), nil
		}
	}
	return nil, fmt.Errorf("no networks found for vm: %s", vmname)
}

func (v *VSpherePlatform) GetServerDetail(ctx context.Context, vmname string) (*vmlayer.ServerDetail, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetail", "vmname", vmname)
	var sd *vmlayer.ServerDetail
	dcName := v.GetDatacenterName(ctx)
	vmPath := "/" + dcName + "/vm/" + vmname
	var err error
	start := time.Now()
	for {
		out, err := v.TimedGovcCommand(ctx, "govc", "vm.info", "-dc", dcName, "-json", vmPath)
		if err != nil {
			return nil, err
		}
		var vms GovcVMs
		err = json.Unmarshal(out, &vms)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetVSphereServer unmarshal fail", "vmname", vmname, "out", string(out), "err", err)
			err = fmt.Errorf("cannot unmarshal, %v", err)
			return nil, err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetail num vms found", "numVMs", len(vms.VirtualMachines))
		if len(vms.VirtualMachines) == 0 {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetail not found", "vmname", vmname)
			return nil, fmt.Errorf(vmlayer.ServerDoesNotExistError)
		}
		if len(vms.VirtualMachines) > 1 {
			log.SpanLog(ctx, log.DebugLevelInfra, "unexpected number of VM found", "vmname", vmname, "vms", vms, "out", string(out), "err", err)
			return nil, fmt.Errorf("unexpected number of VM found: %d", len(vms.VirtualMachines))
		}

		sd = v.getServerDetailFromGovcVm(ctx, &vms.VirtualMachines[0])
		if len(vms.VirtualMachines[0].Guest.Net) > 0 || sd.Status == vmlayer.ServerShutoff {
			break
		}
		if vms.VirtualMachines[0].Guest.ToolsStatus == "toolsNotInstalled" && len(sd.Addresses) > 0 {
			// indicates we got an IP from tags
			break
		}
		elapsed := time.Since(start)
		if elapsed >= (maxGuestWait) {
			log.SpanLog(ctx, log.DebugLevelInfra, "max guest wait time expired")
			err = fmt.Errorf("max guest wait time expired for VM: %s", vms.VirtualMachines[0].Name)
			break
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "VM powered on but guest net is not ready, sleep 5 seconds and retry", "elaspsed", elapsed)
		time.Sleep(5 * time.Second)
	}
	return sd, err
}

func getVmNamesForDomain(ctx context.Context, domainMatch vmlayer.VMDomain, tags []GovcTag) (map[string]string, error) {
	names := make(map[string]string)
	for _, tag := range tags {
		ts := strings.Split(tag.Name, vmlayer.TagDelimiter)
		if len(ts) != 2 {
			return nil, fmt.Errorf("Incorrect VM Domain tag format %s", ts)
		}
		vmname := ts[0]
		domain := ts[1]
		if domainMatch == vmlayer.VMDomainAny || domain == string(domainMatch) {
			names[vmname] = vmname
		}
	}
	return names, nil
}

func (v *VSpherePlatform) GetVMs(ctx context.Context, vmNameMatch string, domainMatch vmlayer.VMDomain) (*GovcVMs, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVMs", "vmNameMatch", vmNameMatch, "domainMatch", domainMatch)
	var vms GovcVMs
	dcName := v.GetDatacenterName(ctx)

	vmtags, err := v.getTagsForCategory(ctx, v.GetVMDomainTagCategory(ctx))
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
	namematch, err := getVmNamesForDomain(ctx, domainMatch, vmtags)
	if err != nil {
		return nil, err
	}
	// filter the list
	var matchedVms GovcVMs
	for _, vm := range vms.VirtualMachines {
		_, ok := namematch[vm.Name]
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
		_, err = v.TimedGovcCommand(ctx, "govc", "-dc", dcName, "vm.power", "-off", vmPath)
	case vmlayer.ActionStart:
		_, err = v.TimedGovcCommand(ctx, "govc", "-dc", dcName, "vm.power", "-on", vmPath)
	case vmlayer.ActionReboot:
		_, err = v.TimedGovcCommand(ctx, "govc", "-dc", dcName, "vm.power", "-reset", vmPath)
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

func (v *VSpherePlatform) CreateTemplateFromImage(ctx context.Context, imageFolder string, imageFile string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateTemplateFromImage", "imageFile", imageFile)
	ds := v.GetDataStore()
	dcName := v.GetDatacenterName(ctx)
	templateName := imageFile
	folder := v.GetTemplateFolder()
	extNet := v.vmProperties.GetCloudletExternalNetwork()
	pool := fmt.Sprintf("/%s/host/%s/Resources", v.GetDatacenterName(ctx), v.GetComputeCluster())

	// create the VM which will become our template
	out, err := v.TimedGovcCommand(ctx, "govc", "vm.create", "-g", "ubuntu64Guest", "-pool", pool, "-ds", ds, "-dc", dcName, "-folder", folder, "-disk", imageFolder+"/"+imageFile+".vmdk", "-net", extNet, templateName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to create template VM", "out", string(out), "err", err)
		return fmt.Errorf("Failed to create template VM: %v", err)
	}

	// try to get server detail which will ensure vmtools is running which needs to be set in the template's data
	_, err = v.GetServerDetail(ctx, folder+"/"+templateName)
	if err != nil {
		return err
	}
	// shut off the VM
	err = v.SetPowerState(ctx, folder+"/"+templateName, vmlayer.ActionStop)
	if err != nil {
		return err
	}
	// mark the VM as a template
	out, err = v.TimedGovcCommand(ctx, "govc", "vm.markastemplate", "-dc", dcName, templateName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to mark VM as template", "out", string(out), "err", err)
		return fmt.Errorf("Failed to mark VM as template: %v", err)
	}
	return nil
}

func (v *VSpherePlatform) ImportImage(ctx context.Context, folder, imageFile string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ImportImage", "imageFile", imageFile)
	ds := v.GetDataStore()
	dcName := v.GetDatacenterName(ctx)

	// first delete anything that may be there for this image
	v.DeleteImage(ctx, folder, imageFile)

	pool := fmt.Sprintf("/%s/host/%s/Resources", v.GetDatacenterName(ctx), v.GetComputeCluster())
	out, err := v.TimedGovcCommand(ctx, "govc", "import.vmdk", "-force", "-pool", pool, "-ds", ds, "-dc", dcName, imageFile, folder)

	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "ImportImage fail", "out", string(out), "err", err)
		return fmt.Errorf("Import Image Fail: %v", err)
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "ImportImage OK", "out", string(out))
	}
	return nil
}

func (v *VSpherePlatform) DeleteImage(ctx context.Context, folder, image string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteImage", "image", image)
	ds := v.GetDataStore()
	dcName := v.GetDatacenterName(ctx)

	out, err := v.TimedGovcCommand(ctx, "govc", "datastore.rm", "-ds", ds, "-dc", dcName, folder)
	if err != nil {
		if strings.Contains(string(out), "not found") {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteImage -- dir does not exist", "out", string(out), "err", err)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteImage fail", "out", string(out), "err", err)
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteImage OK", "out", string(out))
	}

	return err
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
