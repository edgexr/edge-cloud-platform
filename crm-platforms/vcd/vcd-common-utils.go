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

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/crmutil"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

func (v *VcdPlatform) GetFlavor(ctx context.Context, flavorName string) (*edgeproto.FlavorInfo, error) {

	flavs, err := v.vmProperties.GetFlavorListInternal(ctx, v.caches)
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
	var flavors []*edgeproto.FlavorInfo
	// by returning no flavors, we signal to the controller this platform supports no native flavors
	log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList return empty", "len", len(flavors))
	return flavors, nil
}

func (v *VcdPlatform) CreateImageFromUrl(ctx context.Context, imageName, imageUrl, md5Sum string) (string, error) {

	// dne	filePath, err := vmlayer.DownloadVMImage(ctx, v.vmProperties.CommonPf.VaultConfig, imageName, imageUrl, md5Sum)
	filePath := ""
	defer func() {
		// Stale file might be present if download fails/succeeds, deleting it
		if delerr := cloudcommon.DeleteFile(filePath); delerr != nil {
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

func (v *VcdPlatform) GetCloudletTrustPolicy(ctx context.Context) (*edgeproto.TrustPolicy, error) {

	cldlet := edgeproto.Cloudlet{}
	trustcache := v.caches.TrustPolicyCache
	key := v.vmProperties.CommonPf.PlatformConfig.CloudletKey

	if !v.caches.CloudletCache.Get(key, &cldlet) {
		log.SpanLog(ctx, log.DebugLevelInfra, "vcd:GetCloudletTrustPolicy unable to retrieve cloudlet from cache", "cloudlet", cldlet.Key.Name, "cloudletOrg", key.Organization)
		return nil, fmt.Errorf("Cloudlet Not Found")
	}
	tpol, err := crmutil.GetCloudletTrustPolicy(ctx, cldlet.TrustPolicy, key.Organization, trustcache)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "vcd:GetCloudletTrustPolicy crmutil failed", "cloudlet", cldlet.Key.Name, "cloudletOrg", key.Organization, "error", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "vcd:GetCloudletTrustPolicy fetched", "TrustPolicy", tpol.Key.Name, "cloudlet", cldlet.Key.Name)
	return tpol, nil
}
