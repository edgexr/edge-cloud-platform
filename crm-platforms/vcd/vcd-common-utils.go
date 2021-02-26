package vcd

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// This functions could be shared across non-openstack platforms, and were basicly hijacked from vsphere
// While in VcdPlatform currently, if approved, move into vm-common-mumble package
func (v *VcdPlatform) GetFlavor(ctx context.Context, flavorName string) (*edgeproto.FlavorInfo, error) {
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

func (v *VcdPlatform) GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList")
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
		if v.Verbose {
			//log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList found flavor", "key", k)
		}
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

// Here, we're implementing AddCloudletImageIfNotPresent
// We'll lift CreateImageFromUrl, but leave out the return v.ImportImage
// Really, it could have the platform passed in, and we could return p.ImportImage
// but not yet, just let the caller do the ImportImage
//
//CreateImageFromUrl downloads image from URL and then imports to the datastore
//func (v *VSpherePlatform) CreateImageFromUrl(ctx context.Context, imageName, imageUrl, md5Sum string) error {

func (v *VcdPlatform) AddCloudletImageIfNotPresent(ctx context.Context, imgPathPrefix, imgVersion string, updateCallback edgeproto.CacheUpdateCallback) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddCloudletImageIfNotPresent", "imgPathPrefix", imgPathPrefix, "ImgVersion", imgVersion)
	//	filePath, err := vmlayer.DownloadVMImage(ctx, v.vmProperties.CommonPf.VaultConfig, imageName, imageUrl, md5Sum)
	return "", nil
}

func (v *VcdPlatform) CreateImageFromUrl(ctx context.Context, imageName, imageUrl, md5Sum string) (string, error) {

	// dne	filePath, err := vmlayer.DownloadVMImage(ctx, v.vmProperties.CommonPf.VaultConfig, imageName, imageUrl, md5Sum)
	filePath := ""
	defer func() {
		// Stale file might be present if download fails/succeeds, deleting it
		if delerr := infracommon.DeleteFile(filePath); delerr != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "delete file failed", "filePath", filePath)
		}
	}()

	vmdkFile, err := vmlayer.ConvertQcowToVmdk(ctx, filePath, vmlayer.MINIMUM_DISK_SIZE)
	if err != nil {
		return "", err
	}
	return vmdkFile, nil
	// return v.ImportImage(ctx, imageName, vmdkFile)
}

func (v *VcdPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo ")
	var err error
	info.Flavors, err = v.GetFlavorList(ctx)
	if err != nil {
		return err
	}
	return nil
}

// convenience routines for SDK objects
func TakeBoolPointer(value bool) *bool {
	return &value
}

// takeIntAddress is a helper that returns the address of an `int`
func TakeIntAddress(x int) *int {
	return &x
}

// takeStringPointer is a helper that returns the address of a `string`
func TakeStringPointer(x string) *string {
	return &x
}

// takeFloatAddress is a helper that returns the address of an `float64`
func TakeFloatAddress(x float64) *float64 {
	return &x
}

func TakeIntPointer(x int) *int {
	return &x
}

func TakeUint64Pointer(x uint64) *uint64 {
	return &x
}
