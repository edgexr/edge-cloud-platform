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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

func (v *VSpherePlatform) AddImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddImageIfNotPresent", "imageInfo", imageInfo)

	templatePath := v.GetTemplateFolder() + "/" + imageInfo.LocalImageName
	_, err := v.GetServerDetail(ctx, templatePath)

	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "image template already present")
		return nil
	}
	if !strings.Contains(err.Error(), vmlayer.ServerDoesNotExistError) {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "template not present", "LocalImageName", imageInfo.LocalImageName)

	diskSize := vmlayer.MINIMUM_DISK_SIZE
	if imageInfo.ImageCategory == infracommon.ImageCategoryVmApp {
		// vm apps are imported directly as a VM disk not a template and so need a flavor
		f, err := v.GetFlavor(ctx, imageInfo.Flavor)
		if err != nil {
			return err
		}
		diskSize = f.Disk
	}

	updateCallback(edgeproto.UpdateTask, "Downloading VM Image")
	filePath, err := vmlayer.DownloadVMImage(ctx, v.vmProperties.CommonPf.PlatformConfig.AccessApi, imageInfo.LocalImageName, imageInfo.ImagePath, imageInfo.Md5sum)
	if err != nil {
		return err
	}
	filesToCleanup := []string{}
	defer func() {
		for _, file := range filesToCleanup {
			log.SpanLog(ctx, log.DebugLevelInfra, "delete file", "file", file)
			if delerr := cloudcommon.DeleteFile(file); delerr != nil {
				if !os.IsNotExist(delerr) {
					log.SpanLog(ctx, log.DebugLevelInfra, "delete file failed", "file", file, "error", delerr)
				}
			}
		}
	}()

	log.SpanLog(ctx, log.DebugLevelInfra, "downloaded file", "filePath", filePath)
	// rename to match localImageName
	dirName := filepath.Dir(filePath)
	extension := filepath.Ext(filePath)
	newName := dirName + "/" + imageInfo.LocalImageName + extension
	log.SpanLog(ctx, log.DebugLevelInfra, "renaming", "old name", filePath, "new name", newName)
	err = os.Rename(filePath, newName)
	if err != nil {
		filesToCleanup = append(filesToCleanup, filePath)
		return fmt.Errorf("Failed to rename image file - %v", err)
	}
	filesToCleanup = append(filesToCleanup, newName)
	vmdkFile := newName
	if imageInfo.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW {
		updateCallback(edgeproto.UpdateTask, "Converting Image to VMDK")
		vmdkFile, err = vmlayer.ConvertQcowToVmdk(ctx, newName, diskSize)
		filesToCleanup = append(filesToCleanup, vmdkFile)
		if err != nil {
			return err
		}
	}
	folder := imageInfo.LocalImageName
	if imageInfo.VmName != "" {
		folder = imageInfo.VmName
	}
	if imageInfo.ImageCategory == infracommon.ImageCategoryVmApp {
		// for VM images, first delete anything that may be there for this image
		err := v.DeleteImage(ctx, folder, imageInfo.LocalImageName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteImage error", "err", err)
		}
	}
	err = v.ImportImage(ctx, folder, vmdkFile)
	if err != nil {
		return err
	}
	if imageInfo.ImageCategory == infracommon.ImageCategoryPlatform {
		err = v.CreateTemplateFromImage(ctx, folder, imageInfo.LocalImageName)
		if err != nil {
			return fmt.Errorf("Error in creating baseimage template: %v", err)
		}
	}
	return nil
}

// DeleteImage deletes the image folder and any contents from the datastore
func (v *VSpherePlatform) DeleteImage(ctx context.Context, folder, image string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteFolder", "folder", folder)
	ds := v.GetDataStore()
	dcName := v.GetDatacenterName(ctx)

	out, err := v.TimedGovcCommand(ctx, "govc", "datastore.rm", "-ds", ds, "-dc", dcName, folder)
	if err != nil {
		if strings.Contains(string(out), "not found") {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteImage -- dir does not exist", "out", string(out), "err", err)
			err = nil
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteImage fail", "out", string(out), "err", err)
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteImage OK", "out", string(out))
	}

	return err
}
