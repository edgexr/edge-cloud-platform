package vsphere

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type VSpherePlatform struct {
	vcenterVars  map[string]string
	vmProperties *vmlayer.VMProperties
	TestMode     bool
	caches       *platform.Caches
}

func (v *VSpherePlatform) GetType() string {
	return "vsphere"
}

func (v *VSpherePlatform) SetVMProperties(vmProperties *vmlayer.VMProperties) {
	v.vmProperties = vmProperties
}

func (v *VSpherePlatform) SetCaches(ctx context.Context, caches *platform.Caches) {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetCaches")
	v.caches = caches
}

func (v *VSpherePlatform) InitProvider(ctx context.Context, caches *platform.Caches, stage vmlayer.ProviderInitStage, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider for VSphere", "stage", stage)
	v.SetCaches(ctx, caches)
	if stage == vmlayer.ProviderInitPlatformStart {
		v.initDebug(v.vmProperties.CommonPf.PlatformConfig.NodeMgr)
	}
	if stage != vmlayer.ProviderInitDeleteCloudlet {
		err := v.CreateTemplateFolder(ctx)
		if err != nil {
			return err
		}
		return v.CreateTagCategories(ctx)
	}
	return nil
}

func (v *VSpherePlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo ")
	var err error
	info.Flavors, err = v.GetFlavorList(ctx)
	return err
}

func (v *VSpherePlatform) GetDatacenterName(ctx context.Context) string {
	return v.NameSanitize(v.vmProperties.CommonPf.PlatformConfig.CloudletKey.Organization + "-" + v.vmProperties.CommonPf.PlatformConfig.CloudletKey.Name)
}

// alphanumeric plus -_. first char must be alpha, <= 255 chars.
func (v *VSpherePlatform) NameSanitize(name string) string {
	r := strings.NewReplacer(
		" ", "",
		"&", "",
		",", "_",
		"/", "_",
		"!", "")
	str := r.Replace(name)
	if str == "" {
		return str
	}
	if !unicode.IsLetter(rune(str[0])) {
		// first character must be alpha
		str = "a" + str
	}
	if len(str) > 255 {
		str = str[:254]
	}
	return str
}

// IdSanitize is NameSanitize plus removing "."
func (v *VSpherePlatform) IdSanitize(name string) string {
	str := v.NameSanitize(name)
	str = strings.ReplaceAll(str, ".", "-")
	str = strings.ReplaceAll(str, "=", "-")
	return str
}

func (v *VSpherePlatform) GetResourceID(ctx context.Context, resourceType vmlayer.ResourceType, resourceName string) (string, error) {
	if v.TestMode {
		return resourceName + "-testingID", nil
	}
	switch resourceType {
	case vmlayer.ResourceTypeSecurityGroup:
		return resourceName + "-id", nil
	}
	return "", fmt.Errorf("GetResourceID not implemented for resource type: %s ", resourceType)
}

func (v *VSpherePlatform) GetVMStats(ctx context.Context, key *edgeproto.AppInstKey) (*vmlayer.VMMetrics, error) {
	log.DebugLog(log.DebugLevelSampled, "GetVMStats")
	vmName := cloudcommon.GetAppFQN(&key.AppKey)
	vmMetrics := vmlayer.VMMetrics{}

	cr := MetricsCollectionRequestType{CollectNetworkStats: true, CollectCPUStats: true, CollectMemStats: true}
	mets, err := v.GetMetrics(ctx, vmName, &cr)
	if err != nil {
		return &vmMetrics, err
	}
	time, err := time.Parse(time.RFC3339, mets.Timestamp)
	if err != nil {
		return &vmMetrics, err
	}
	ts, err := types.TimestampProto(time)
	if err != nil {
		return &vmMetrics, err

	}
	vmMetrics.CpuTS = ts
	vmMetrics.NetRecv = mets.BytesRxAverage
	vmMetrics.NetRecvTS = ts
	vmMetrics.NetSent = mets.BytesTxAverage
	vmMetrics.NetSentTS = ts
	vmMetrics.Cpu = mets.CpuUsagePercent
	vmMetrics.CpuTS = ts
	vmMetrics.Mem = mets.MemUsageBytes
	vmMetrics.MemTS = ts

	vms, err := v.GetVMs(ctx, vmName, vmlayer.VMDomainAny)
	if err != nil || vms == nil || len(vms.VirtualMachines) != 1 {
		return &vmMetrics, fmt.Errorf("unable to get VMs - %v", err)
	}
	for _, f := range vms.VirtualMachines[0].LayoutEx.File {
		vmMetrics.Disk += f.Size
	}
	vmMetrics.DiskTS = ts
	return &vmMetrics, nil
}

func (v *VSpherePlatform) GetPlatformResourceInfo(ctx context.Context) (*vmlayer.PlatformResources, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetPlatformResourceInfo")
	platformRes := vmlayer.PlatformResources{}
	platformRes.CollectTime, _ = types.TimestampProto(time.Now())

	hosts, err := v.GetHosts(ctx)
	if err != nil {
		return &platformRes, err
	}

	for _, hs := range hosts.HostSystems {
		platformRes.MemMax = platformRes.MemMax + hs.Hardware.MemorySize
		platformRes.VCpuMax = platformRes.VCpuMax + hs.Hardware.CpuInfo.NumCpuThreads
	}
	// convert to MB
	if platformRes.MemMax > 0 {
		platformRes.MemMax = uint64(platformRes.MemMax / (1024 * 1024))
	}

	vms, err := v.GetVMs(ctx, VMMatchAny, vmlayer.VMDomainAny)
	if err != nil {
		return &platformRes, err
	}
	for _, vm := range vms.VirtualMachines {
		platformRes.VCpuUsed = platformRes.VCpuUsed + vm.Config.Hardware.NumCPU
		platformRes.MemUsed = platformRes.VCpuUsed + vm.Config.Hardware.MemoryMB
	}

	ds, err := v.GetDataStoreInfo(ctx)
	if err != nil {
		return &platformRes, err
	}
	// we only have 1 DS right now and maybe forever but in theory could be aggregated
	var totalDs uint64
	var freeDs uint64
	var usedDs uint64

	for _, ds := range ds.Datastores {
		totalDs = totalDs + ds.Summary.Capacity
		freeDs = usedDs + ds.Summary.FreeSpace
	}
	usedDs = totalDs - freeDs

	// convert to GB
	if usedDs > 0 {
		platformRes.DiskUsed = uint64(usedDs / (1024 * 1024 * 1024))
	}
	if totalDs > 0 {
		platformRes.DiskMax = uint64(totalDs / (1024 * 1024 * 1024))
	}

	ipMax, ipUsed, err := v.GetExternalIPCounts(ctx)
	if err != nil {
		return &platformRes, err
	}
	platformRes.Ipv4Max = ipMax
	platformRes.Ipv4Used = ipUsed

	cr := MetricsCollectionRequestType{CollectNetworkStats: true}
	mets, err := v.GetMetrics(ctx, VMMatchAny, &cr)
	if err != nil {
		return &platformRes, err
	}
	platformRes.NetRecv = mets.BytesRxAverage * mets.Interval
	platformRes.NetSent = mets.BytesTxAverage * mets.Interval
	return &platformRes, nil
}

func (s *VSpherePlatform) CheckServerReady(ctx context.Context, client ssh.Client, serverName string) error {
	// for vSphere in the current baseimage, there is a second reboot performed by vCenter after the initial
	// guest customization.  This generally happens a few seconds after the VM is reachable so just checking that
	// the VM is up is not sufficient as it may go back down.  Checking that the VM is ready relies on the fact that the
	// mobiledgex init script will be executed a second time after it has finished its job with the init-done flag set.  When
	// this happens, the mobiledgex service exits with exitcode = 2
	out, err := client.Output("systemctl status mobiledgex.service|grep status=2")
	log.SpanLog(ctx, log.DebugLevelInfra, "CheckServerReady Mobiledgex service status", "serverName", serverName, "out", out, "err", err)
	return err
}
