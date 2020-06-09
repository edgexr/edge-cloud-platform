package vsphere

import (
	"context"
	"fmt"
	"sync"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer/terraform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var clusterLock sync.Mutex
var appLock sync.Mutex

var flavors []*edgeproto.FlavorInfo

func (o *VSpherePlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("SaveCloudletAccessVars not implemented for vsphere")
}

func (v *VSpherePlatform) AddCloudletImageIfNotPresent(ctx context.Context, imgPathPrefix, imgVersion string, updateCallback edgeproto.CacheUpdateCallback) (string, error) {
	// we don't currently have the ability to download and setup the template, but we will verify it is there
	//imgPath := v.GetTemplateFolder() + "/" + v.vmProperties.GetCloudletOSImage()
	img := v.vmProperties.GetCloudletOSImage()
	imgPath := v.GetTemplateFolder() + "/" + img
	_, err := v.GetServerDetail(ctx, imgPath)
	if err != nil {
		return "", fmt.Errorf("Vsphere base image template not present: %s", imgPath)
	}
	return img, nil
}

func (v *VSpherePlatform) GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	// we just send the controller back the same list of flavors it gave us, because VSphere has no flavor concept

	flavorkeys := make(map[edgeproto.FlavorKey]struct{})
	v.caches.FlavorCache.GetAllKeys(ctx, func(k *edgeproto.FlavorKey, modRev int64) {
		flavorkeys[*k] = struct{}{}
	})
	for k := range flavorkeys {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList found flavor", "key", k)
		var flav edgeproto.Flavor
		if v.caches.FlavorCache.Get(&k, &flav) {
			var flavInfo edgeproto.FlavorInfo
			flavInfo.Name = flav.Key.Name
			flavInfo.Disk = flav.Disk
			flavInfo.Ram = flav.Ram
			flavInfo.Vcpus = flav.Vcpus
			flavors = append(flavors, &flavInfo)
		} else {
			return nil, fmt.Errorf("fail to fetch flavor %s", k)
		}
	}
	return flavors, nil
}

func (v *VSpherePlatform) ImportDataFromInfra(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ImportDataFromInfra")
	// first import existing resources
	pools, err := v.GetResourcePools(ctx)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Import Resource Pools")
	for _, p := range pools.ResourcePools {
		err = v.ImportTerraformResourcePool(ctx, p.Name, p.Path)
		if err != nil {
			return err
		}
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "Import Tags")
	tags, err := v.GetTags(ctx)
	if err != nil {
		return err
	}
	for _, c := range tags {
		err = v.ImportTerraformTag(ctx, c.Name, c.Category)
		if err != nil {
			return err
		}
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "Import Distributed Port Groups")
	pgrps, err := v.GetDistributedPortGroups(ctx)
	if err != nil {
		return err
	}
	for _, p := range pgrps {
		err = v.ImportTerraformDistributedPortGrp(ctx, p.Name, p.Path)
		if err != nil {
			return err
		}
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "Import VMs")
	vms, err := v.GetVMs(ctx)
	if err != nil {
		return err
	}
	for _, vm := range vms.VirtualMachines {
		err = v.ImportTerraformVirtualMachine(ctx, vm.Name, vm.Path)
		if err != nil {
			return err
		}
	}
	return terraform.RunTerraformApply(ctx, terraform.WithRetries(NumTerraformRetries))
}

func (v *VSpherePlatform) GetApiEndpointAddr(ctx context.Context) (string, error) {
	vcaddr := v.vcenterVars["VCENTER_ADDR"]
	log.SpanLog(ctx, log.DebugLevelInfra, "GetApiEndpointAddr", "vcaddr", vcaddr)
	if vcaddr == "" {
		return "", fmt.Errorf("unable to find VCENTER_ADDR")
	}
	return vcaddr, nil
}

func (v *VSpherePlatform) GetCloudletManifest(ctx context.Context, name string, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletManifest", "name", name, "VMGroupOrchestrationParams", VMGroupOrchestrationParams)
	// because we look for free IPs when defining the orchestration parms which are not reserved
	// until the plan is created, we need to lock this whole function
	vmOrchestrateLock.Lock()
	defer vmOrchestrateLock.Unlock()

	planName := v.NameSanitize(VMGroupOrchestrationParams.GroupName)
	var vgp VSphereGeneralParams
	err := v.populateGeneralParams(ctx, planName, &vgp, terraformCreate)
	if err != nil {
		return "", err
	}
	err = v.populateVMOrchParams(ctx, VMGroupOrchestrationParams, &vgp, terraformCreate)
	if err != nil {
		return "", err
	}

	buf, err := vmlayer.ExecTemplate(name, vmGroupTemplate, VMGroupOrchestrationParams)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
