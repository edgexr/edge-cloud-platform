package vsphere

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer/terraform"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var clusterLock sync.Mutex
var appLock sync.Mutex

func (o *VSpherePlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("SaveCloudletAccessVars not implemented for vsphere")
}

func (v *VSpherePlatform) GetCloudletImageSuffix(ctx context.Context) string {
	return "-vsphere.qcow2"
}

//CreateImageFromUrl downloads image from URL and then imports to the datastore
func (v *VSpherePlatform) CreateImageFromUrl(ctx context.Context, imageName, imageUrl, md5Sum string) error {

	filePath, err := vmlayer.DownloadVMImage(ctx, v.vmProperties.CommonPf.VaultConfig, imageName, imageUrl, md5Sum)
	if err != nil {
		return err
	}
	defer func() {
		// Stale file might be present if download fails/succeeds, deleting it
		if delerr := infracommon.DeleteFile(filePath); delerr != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "delete file failed", "filePath", filePath)
		}
	}()

	vmdkFile, err := v.ConvertQcowToVmdk(ctx, filePath, vmlayer.MINIMUM_DISK_SIZE)
	if err != nil {
		return err
	}
	return v.ImportImage(ctx, imageName, vmdkFile)
}

func (v *VSpherePlatform) AddCloudletImageIfNotPresent(ctx context.Context, imgPathPrefix, imgVersion string, updateCallback edgeproto.CacheUpdateCallback) (string, error) {
	// we don't currently have the ability to download and setup the template, but we will verify it is there
	log.SpanLog(ctx, log.DebugLevelInfra, "AddCloudletImageIfNotPresent", "imgPathPrefix", imgPathPrefix, "imgVersion", imgVersion)

	imgPath := vmlayer.GetCloudletVMImagePath(imgPathPrefix, imgVersion, v.GetCloudletImageSuffix(ctx))
	// Fetch platform base image name
	pfImageName, err := cloudcommon.GetFileName(imgPath)
	if err != nil {
		return "", err
	}
	// see if a template already exists based on this image
	templatePath := v.GetTemplateFolder() + "/" + pfImageName
	_, err = v.GetServerDetail(ctx, templatePath)

	if err != nil {
		if !strings.Contains(err.Error(), vmlayer.ServerDoesNotExistError) {
			return "", err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "template not present", "pfImageName", pfImageName, "err", err)

		// Validate if pfImageName is same as we expected
		_, md5Sum, err := infracommon.GetUrlInfo(ctx, v.vmProperties.CommonPf.VaultConfig, imgPath)
		if err != nil {
			return "", err
		}
		// Download platform image and create a vsphere template from it
		updateCallback(edgeproto.UpdateTask, "Downloading platform base image: "+pfImageName)
		err = v.CreateImageFromUrl(ctx, pfImageName, imgPath, md5Sum)
		if err != nil {
			return "", fmt.Errorf("Error downloading platform base image %s: %v", pfImageName, err)
		}
		err = v.CreateTemplateFromImage(ctx, pfImageName, pfImageName)
		if err != nil {
			return "", fmt.Errorf("Error in creating baseimage template: %v", err)
		}
	}
	return pfImageName, nil
}

func (v *VSpherePlatform) GetFlavor(ctx context.Context, flavorName string) (*edgeproto.FlavorInfo, error) {
	flavs, err := v.GetFlavorList(ctx)
	if err != nil {
		return nil, err
	}
	for _, f := range flavs {
		if f.Name == flavorName {
			return f, nil
		}
	}
	return nil, fmt.Errorf("no flavor found named: %s", flavorName)
}

func (v *VSpherePlatform) GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	// we just send the controller back the same list of flavors it gave us, because VSphere has no flavor concept.
	// Make sure each flavor is at least a minimum size to run the platform
	var flavors []*edgeproto.FlavorInfo
	if v.caches == nil {
		log.WarnLog("flavor cache is nil")
		return nil, fmt.Errorf("Flavor cache is nil")
	}
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
			if flav.Ram >= vmlayer.MINIMUM_RAM_SIZE {
				flavInfo.Ram = flav.Ram
			} else {
				flavInfo.Ram = vmlayer.MINIMUM_RAM_SIZE
			}
			if flav.Vcpus >= vmlayer.MINIMUM_VCPUS {
				flavInfo.Vcpus = flav.Vcpus
			} else {
				flavInfo.Vcpus = vmlayer.MINIMUM_VCPUS
			}
			if flav.Disk >= vmlayer.MINIMUM_DISK_SIZE {
				flavInfo.Disk = flav.Disk
			} else {
				flavInfo.Disk = vmlayer.MINIMUM_DISK_SIZE
			}
			flavors = append(flavors, &flavInfo)
		} else {
			return nil, fmt.Errorf("fail to fetch flavor %s", k)
		}
	}

	// add the default platform flavor as well
	var rlbFlav edgeproto.Flavor
	err := v.vmProperties.GetCloudletSharedRootLBFlavor(&rlbFlav)
	if err != nil {
		return nil, err
	}
	rootlbFlavorInfo := edgeproto.FlavorInfo{
		Name:  "mex-rootlb-flavor",
		Vcpus: rlbFlav.Vcpus,
		Ram:   rlbFlav.Ram,
		Disk:  rlbFlav.Disk,
	}
	flavors = append(flavors, &rootlbFlavorInfo)
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
		if strings.HasSuffix(p.Name, string(vmlayer.VMDomainCompute)) {
			err = v.ImportTerraformResourcePool(ctx, p.Name, p.Path)
			if err != nil {
				return err
			}
		}
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "Import Tags")
	tags, err := v.GetTags(ctx)
	if err != nil {
		return err
	}
	dcName := v.GetDatacenterName(ctx)
	for _, c := range tags {
		if strings.HasPrefix(c.Category, dcName) {
			err = v.ImportTerraformTag(ctx, c.Name, c.Category)
			if err != nil {
				return err
			}
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
	// filter on compute VMs so we don't delete anything else
	vms, err := v.GetVMs(ctx, VMMatchAny, vmlayer.VMDomainCompute)
	if err != nil {
		return err
	}
	for _, vm := range vms.VirtualMachines {
		err = v.ImportTerraformVirtualMachine(ctx, vm.Name, vm.Path)
		if err != nil {
			return err
		}
	}
	return terraform.RunTerraformApply(ctx, v.getTerraformDir(ctx), terraform.WithRetries(NumTerraformRetries))
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
	err := v.populateGeneralParams(ctx, planName, "", &vgp, terraformCreate)
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
