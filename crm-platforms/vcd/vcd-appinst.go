package vcd

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// appinst related functionality
// TBI
func (v *VcdPlatform) AddAppImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, app *edgeproto.App, flavor string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddAppImageIfNotPresent", "app.ImagePath", app.ImagePath, "flavor", flavor)

	return fmt.Errorf("AddAppImageIfNotPresent TBI")
	/*
	   	f, err := v.GetFlavor(ctx, flavor)
	   	if err != nil {
	   		return err
	   	}
	           imageName, err = cloudcommon.GetFileName(app.ImagePath)
	   	if err != nil {
	   		return err
	   	}
	   	// DNE	_, md5Sum, err := infracommon.GetUrlInfo(ctx, v.vmProperties.CommonPf.VaultConfig, app.ImagePath)

	   	// 	filePath, err := vmlayer.DownloadVMImage(ctx, v.vmProperties.CommonPf.VaultConfig, imageName, app.ImagePath, md5Sum)
	   	if err != nil {
	   		return err
	   	}
	   	filePath := ""
	   	log.SpanLog(ctx, log.DebugLevelInfra, "downloaded file", "filePath", filePath)

	   	vmdkFile := filePath
	   	if app.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW {
	   		vmdkFile, err = v.ConvertQcowToVmdk(ctx, filePath, f.Disk)
	   		if err != nil {
	   			return err
	   		}
	   	}

	   	defer func() {
	   		// Stale file might be present if download fails/succeeds, deleting it
	   		if delerr := infracommon.DeleteFile(filePath); delerr != nil {
	   			log.SpanLog(ctx, log.DebugLevelInfra, "delete file failed", "filePath", filePath)
	   		}
	   		if app.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW {
	   			if delerr := infracommon.DeleteFile(vmdkFile); delerr != nil {
	   				log.SpanLog(ctx, log.DebugLevelInfra, "delete file failed", "vmdkFile", vmdkFile)
	   			}
	   		}
	   	}()
	   	return v.ImportImage(ctx, cloudcommon.GetAppFQN(&app.Key), vmdkFile)
	*/
}
