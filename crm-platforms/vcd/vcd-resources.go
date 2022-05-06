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

package vcd

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	prototypes "github.com/gogo/protobuf/types"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"

	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
	vcdtypes "github.com/vmware/go-vcloud-director/v2/types/v56"
)

type VcdResources struct {
	VmsUsed uint64
}

const CurrentVmMetrics string = "application/vnd.vmware.vcloud.metrics.currentUsageSpec+xml"

type GovcdMetric struct {
	Name  string `xml:"name,attr,omitempty"`
	Unit  string `xml:"unit,attr,omitempty"`
	Value string `xml:"value,attr,omitempty"`
}
type GovcdMetricList []*GovcdMetric
type GovcdMetricsResponse struct {
	Link   types.LinkList  `xml:"Link,omitempty"`
	Metric GovcdMetricList `xml:"Metric,omitempty"`
}

func (v *VcdPlatform) GetPlatformResourceInfo(ctx context.Context) (*vmlayer.PlatformResources, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetPlatformResourceInfo")

	var resources = vmlayer.PlatformResources{}
	resources.CollectTime, _ = prototypes.TimestampProto(time.Now())
	resinfo, err := v.GetCloudletInfraResourcesInfo(ctx)
	if err != nil {
		return nil, err
	}
	// TODO, 2 similar structs for the same concept should be revisited
	for _, r := range resinfo {
		switch r.Name {
		case cloudcommon.ResourceVcpus:
			resources.VCpuMax = r.InfraMaxValue
			resources.VCpuUsed = r.Value
		case cloudcommon.ResourceRamMb:
			resources.MemMax = r.InfraMaxValue
			resources.MemUsed = r.Value
		case cloudcommon.ResourceExternalIPs:
			resources.Ipv4Max = r.InfraMaxValue
			resources.Ipv4Used = r.Value
		case cloudcommon.ResourceDiskGb:
			resources.DiskMax = r.InfraMaxValue
			resources.DiskUsed = r.Value
		}
	}
	return &resources, nil
}

func (v *VcdPlatform) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletInfraResourcesInfo")
	resInfo := []edgeproto.InfraResource{}
	vcdClient := v.GetVcdClientFromContext(ctx)

	if vcdClient == nil {
		return nil, fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdcFromContext(ctx, vcdClient)
	if err != nil {
		return nil, err
	}

	org, err := v.GetOrg(ctx, vcdClient)
	if err != nil {
		return nil, fmt.Errorf("Error getting VDC Org: %v", err)
	}

	// get the cpu speed to calculate number of VMs used.  When we create VMs we specify the number of VCPUs, but
	// to find the quotas and numbers used, we have to search for the CPU speed and calculate.
	cpuSpeed := v.GetVcpuSpeedOverride(ctx)
	var storageLimit int64 = 0
	var storageUsed int64 = 0
	if cpuSpeed == 0 {
		// retrieve from admin org
		adminOrg, err := govcd.GetAdminOrgByName(vcdClient, org.Org.Name)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Unable to get AdminOrg", "orgName", "org.Org.Name", "error", err)
			return nil, fmt.Errorf("Unable to get AdminOrg named: %s - %v", org.Org.Name, err)
		}
		adminVdc, err := adminOrg.GetAdminVdcByName(v.GetVDCName())
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Unable to get AdminVdc", "adminOrgName", "adminOrg.Org.Name", "error", err)
			return nil, fmt.Errorf("Unable to get AdminVcd named: %s - %v", v.GetVDCName(), err)
		}
		if len(adminVdc.AdminVdc.VdcStorageProfiles.VdcStorageProfile) > 0 {
			foundStorageProfile, err := govcd.GetStorageProfileByHref(vcdClient, adminVdc.AdminVdc.VdcStorageProfiles.VdcStorageProfile[0].HREF)
			if err != nil {
				return nil, fmt.Errorf("Unable to get storage profile - %v", err)
			}
			storageLimit = foundStorageProfile.Limit / 1024
			storageUsed = foundStorageProfile.StorageUsedMB / 1024
		}
		// VMW stores the speed in 2 different places, the first of which is generally nil in our testing
		if adminVdc.AdminVdc.VCpuInMhz != nil && *adminVdc.AdminVdc.VCpuInMhz != 0 {
			cpuSpeed = *adminVdc.AdminVdc.VCpuInMhz
			log.SpanLog(ctx, log.DebugLevelInfra, "Using cpu speed from admin VCpuInMhz", "cpuSpeed", cpuSpeed)
		} else {
			if adminVdc.AdminVdc.VCpuInMhz2 != nil && *adminVdc.AdminVdc.VCpuInMhz2 != 0 {
				cpuSpeed = *adminVdc.AdminVdc.VCpuInMhz2
				log.SpanLog(ctx, log.DebugLevelInfra, "Using cpu speed from admin VCpuInMhz2", "cpuSpeed", cpuSpeed)
			} else {
				return nil, fmt.Errorf("No cpu speed in organization")
			}
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "Using cpu speed from properties", "cpuSpeed", cpuSpeed)
	}

	vmlist, err := vcdClient.Client.QueryVmList(vcdtypes.VmQueryFilterOnlyDeployed)
	if err != nil {
		return nil, fmt.Errorf("Failed to query VmList: %v", err)
	}
	extNet, err := v.GetExtNetwork(ctx, vcdClient, v.vmProperties.GetCloudletExternalNetwork())
	if err != nil {
		return nil, err
	}
	ipScopes := extNet.OrgVDCNetwork.Configuration.IPScopes.IPScope
	ranges := []string{}
	for _, ips := range ipScopes {
		mask, err := MaskToCidr(ips.Netmask)
		if err != nil {
			return nil, fmt.Errorf("MaskToCidr failed - %s - %v", ips.Netmask, err)
		}
		for _, ipr := range ips.IPRanges.IPRange {
			ranges = append(ranges, fmt.Sprintf("%s/%s-%s/%s", ipr.StartAddress, mask, ipr.EndAddress, mask))
		}
	}
	iprangeString := strings.Join(ranges, ",")
	availIps, err := infracommon.ParseIpRanges(iprangeString)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse ip ranges from org vcd network ranges: %s - %v", iprangeString, err)
	}
	var usedIps uint64 = 0
	extNetName := v.vmProperties.GetCloudletExternalNetwork()
	for _, vm := range vmlist {
		if vm.NetworkName == extNetName {
			usedIps++
		}
	}

	resInfo = append(resInfo, edgeproto.InfraResource{
		Name:          cloudcommon.ResourceExternalIPs,
		InfraMaxValue: uint64(len(availIps)),
		Value:         usedIps,
	})
	resInfo = append(resInfo, edgeproto.InfraResource{
		Name:          cloudcommon.ResourceInstances,
		InfraMaxValue: uint64(vdc.Vdc.VMQuota),
		Value:         uint64(len(vmlist)),
	})
	resInfo = append(resInfo, edgeproto.InfraResource{
		Name:          cloudcommon.ResourceDiskGb,
		InfraMaxValue: uint64(storageLimit),
		Value:         uint64(storageUsed),
	})
	for _, cap := range vdc.Vdc.ComputeCapacity {
		resInfo = append(resInfo, edgeproto.InfraResource{
			Name:          cloudcommon.ResourceVcpus,
			Value:         uint64((cap.CPU.Used) / cpuSpeed),
			InfraMaxValue: uint64((cap.CPU.Limit) / cpuSpeed),
		})
		resInfo = append(resInfo, edgeproto.InfraResource{
			Name:          cloudcommon.ResourceRamMb,
			Value:         uint64(cap.Memory.Used),
			InfraMaxValue: uint64(cap.Memory.Limit),
		})
	}
	return resInfo, nil
}

func (v *VcdPlatform) GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletResourceQuotaProps")

	return &edgeproto.CloudletResourceQuotaProps{
		Properties: []edgeproto.InfraResource{
			{
				Name:        cloudcommon.ResourceInstances,
				Description: cloudcommon.ResourceQuotaDesc[cloudcommon.ResourceInstances],
			},
		},
	}, nil

}

func getVcdResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, resources []edgeproto.VMResource) *VcdResources {
	log.SpanLog(ctx, log.DebugLevelInfra, "getVcdResources", "vmRes count", len(resources))
	var vRes VcdResources
	for _, vmRes := range resources {
		log.SpanLog(ctx, log.DebugLevelInfra, "getVcdResources", "vmRes", vmRes)

		// Number of Instances = Number of resources
		vRes.VmsUsed += 1
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "getVcdResources", "vRes", vRes)
	return &vRes
}

// called by controller, make sure it doesn't make any calls to infra API
func (v *VcdPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	// resource name -> resource units
	cloudletRes := map[string]string{
		cloudcommon.ResourceInstances: "",
	}
	resInfo := make(map[string]edgeproto.InfraResource)
	for resName, resUnits := range cloudletRes {
		resMax := uint64(0)
		if infraRes, ok := infraResMap[resName]; ok {
			resMax = infraRes.InfraMaxValue
		}
		resInfo[resName] = edgeproto.InfraResource{
			Name:          resName,
			InfraMaxValue: resMax,
			Units:         resUnits,
		}
	}
	vRes := getVcdResources(ctx, cloudlet, vmResources)
	outInfo, ok := resInfo[cloudcommon.ResourceInstances]
	if ok {
		outInfo.Value += vRes.VmsUsed
		resInfo[cloudcommon.ResourceInstances] = outInfo
	}
	return resInfo
}

func (v *VcdPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetClusterAdditionalResourceMetric ")
	vRes := getVcdResources(ctx, cloudlet, resources)
	resMetric.AddIntVal(cloudcommon.ResourceMetricInstances, vRes.VmsUsed)
	log.SpanLog(ctx, log.DebugLevelInfra, "GetClusterAdditionalResourceMetric Reports", "numVmsUsed", vRes.VmsUsed)
	return nil
}

func (v *VcdPlatform) VmAppChangedCallback(ctx context.Context, appInst *edgeproto.AppInst, newState edgeproto.TrackedState) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "VmAppChangedCallback", "appInstKey", appInst.Key, "newState", newState)
	if v.GetHrefCacheEnabled() && newState != edgeproto.TrackedState_READY {
		vmName := appInst.Uri
		v.DeleteVmHrefFromCache(ctx, vmName)
		// delete using old format also
		altVmName := oldGetAppFQN(&appInst.Key.AppKey)
		v.DeleteVmHrefFromCache(ctx, altVmName)
	}
}

func oldGetAppFQN(key *edgeproto.AppKey) string {
	app := util.DNSSanitize(key.Name)
	dev := util.DNSSanitize(key.Organization)
	ver := util.DNSSanitize(key.Version)
	return fmt.Sprintf("%s%s%s", dev, app, ver)
}

func (v *VcdPlatform) GetVMStats(ctx context.Context, appInst *edgeproto.AppInst) (*vmlayer.VMMetrics, error) {
	key := &appInst.Key
	log.SpanLog(ctx, log.DebugLevelMetrics, "GetVMStats", "key", key)

	vm := &govcd.VM{}
	metrics := vmlayer.VMMetrics{}
	var err error

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return nil, fmt.Errorf(NoVCDClientInContext, err)
	}
	vdc, err := v.GetVdcFromContext(ctx, vcdClient)
	if err != nil {
		return nil, fmt.Errorf("GetVdcFromCacheForVmStats Failed - %v", err)
	}

	// we need the flavor to do RAM conversion
	flavor := edgeproto.Flavor{}
	flavorKey := edgeproto.FlavorKey{
		Name: appInst.Flavor.Name,
	}
	if !v.caches.FlavorCache.Get(&flavorKey, &flavor) {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Flavor not in cache", "appkey", key, "flavorKey", flavorKey)
		return nil, fmt.Errorf("GetVMStats failed to find flavor in cache for AppInst %s", key)
	}
	vmName := appInst.UniqueId
	vm, err = v.FindVMByName(ctx, vmName, vcdClient, vdc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "VM not found", "vnname", vmName, "err", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "GetVMStats for", "vm", vmName)
	link := vm.VM.Link.ForType(CurrentVmMetrics, types.RelMetrics)
	if link == nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to get metrics for VM", "vmName", vmName)
		return nil, fmt.Errorf("Unable to get metrics for VM: %s", vmName)
	}
	var metricsResponse GovcdMetricsResponse
	response, err := vcdClient.Client.ExecuteRequest(link.HREF, http.MethodGet, "", "error GET retriving metrics link: %s", nil, &metricsResponse)
	log.SpanLog(ctx, log.DebugLevelMetrics, "VCD Get VM Metrics results", "statusCode", response.StatusCode, "metricsResponse", metricsResponse, "err", err)
	if err != nil {
		log.ForceLogSpan(log.SpanFromContext(ctx))
		log.SpanLog(ctx, log.DebugLevelMetrics, "Error getting VCD metrics", "err", err)
		return &metrics, err
	}
	if response.StatusCode != http.StatusOK {
		log.ForceLogSpan(log.SpanFromContext(ctx))
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failure getting VCD metrics", "StatusCode", response.StatusCode)
		return &metrics, fmt.Errorf("Failure getting VCD metrics code: %d", response.StatusCode)
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "VCD Get VM Metrics results", "metricsResponse", metricsResponse)
	ts, _ := prototypes.TimestampProto(time.Now())

	for _, m := range metricsResponse.Metric {
		switch m.Name {
		case "cpu.usage.average":
			f, err := strconv.ParseFloat(m.Value, 64)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelMetrics, "GetVMStats error parse float for cpu usage", "value", m.Value, "err", err)
				continue
			}
			metrics.Cpu = f
			metrics.CpuTS = ts
		case "mem.usage.average":
			f, err := strconv.ParseFloat(m.Value, 64)
			if err != nil {
				log.ForceLogSpan(log.SpanFromContext(ctx))
				log.SpanLog(ctx, log.DebugLevelMetrics, "GetVMStats error parse float for mem usage", "value", m.Value, "err", err)
				continue
			}
			// mem.usage.average is a percent 0-100.  Multiply this by the flavor memory to get the results in bytes
			metrics.Mem = uint64(math.Round(f / 100 * float64(flavor.Ram*1024*1024)))
			metrics.MemTS = ts
		}
		// note disk stats are available in vmware, but they are useless for our purposes, as they do not reflect
		// OS usage inside the VM, rather the disk metrics measure the size of various VM files on the datastore
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "GetVMStats returns", "metrics", metrics)
	return &metrics, nil
}
