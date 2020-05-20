package vsphere

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/log"
)

var maxGuestWait = time.Minute * 2

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

type GovcRuntime struct {
	PowerState string
}

type GovcVMGuest struct {
	GuestState string
	Net        []GovcVMNet
}

type GovcVM struct {
	Name    string
	Runtime GovcRuntime
	Guest   GovcVMGuest
	Path    string
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

type GovcPool struct {
	Name string
	Path string
}
type GovcPools struct {
	ResourcePools []GovcPool
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
	out, err := v.TimedGovcCommand(ctx, "govc", "ls", "-json", networkSearchPath)
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

func (v *VSpherePlatform) GetUsedSubnetCIDRs(ctx context.Context) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetUsedSubnetCIDRs")

	cidrUsed := make(map[string]string)
	tags, err := v.getTagsForCategory(ctx, v.GetSubnetTagCategory(ctx))
	if err != nil {
		return nil, err
	}
	for _, t := range tags {
		// tags are format subnet__cidr
		ts := strings.Split(t.Name, TagDelimiter)
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
		ts := strings.Split(t.Name, TagDelimiter)
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
		ts := strings.Split(t.Name, TagDelimiter)
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
	for _, net := range govcVm.Guest.Net {
		var sip vmlayer.ServerIP

		sip.Network = net.Network
		sip.MacAddress = net.MacAddress
		sip.PortName = vmlayer.GetPortName(govcVm.Name, net.Network)
		if len(net.IpAddress) > 0 {
			sip.ExternalAddr = net.IpAddress[0]
			sip.InternalAddr = net.IpAddress[0]
		} else {
			ip, err := v.GetIpFromTagsForVM(ctx, sd.Name, sip.Network)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetIpFromTagsForVM failed", "err", err)
			} else {
				sip.ExternalAddr = ip
				sip.InternalAddr = ip
			}
		}
		sd.Addresses = append(sd.Addresses, sip)
	}
	return &sd

}

func (v *VSpherePlatform) GetServerDetail(ctx context.Context, vmname string) (*vmlayer.ServerDetail, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetail", "vmname", vmname)
	var sd *vmlayer.ServerDetail
	dcName := v.GetDatacenterName(ctx)
	vmPath := "/" + dcName + "/vm/" + vmname
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
		elapsed := time.Since(start)
		if elapsed >= (maxGuestWait) {
			log.SpanLog(ctx, log.DebugLevelInfra, "max guest wait time expired")
			break
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "VM powered on but guest net is not ready, sleep 5 seconds and retry", "elaspsed", elapsed)
		time.Sleep(5 * time.Second)
	}

	return sd, nil
}

func (v *VSpherePlatform) GetVMs(ctx context.Context) (*GovcVMs, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVMs")
	var vms GovcVMs
	dcName := v.GetDatacenterName(ctx)

	vmPath := "/" + dcName + "/vm/"
	out, err := v.TimedGovcCommand(ctx, "govc", "vm.info", "-json", vmPath+"*")
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
	return &vms, nil
}

func (v *VSpherePlatform) SetPowerState(ctx context.Context, serverName, serverAction string) error {
	return fmt.Errorf("SetPowerState TODO")
}
