package vsphere

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (v *VSpherePlatform) AddAppImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, app *edgeproto.App, flavor string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddAppImageIfNotPresent", "app.ImagePath", app.ImagePath, "imageInfo", imageInfo, "flavor", flavor)

	f, err := v.GetFlavor(ctx, flavor)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Downloading VM Image")
	filePath, err := vmlayer.DownloadVMImage(ctx, v.vmProperties.CommonPf.PlatformConfig.AccessApi, imageInfo.LocalImageName, app.ImagePath, imageInfo.Md5sum)
	if err != nil {
		return err
	}
	filesToCleanup := []string{}
	defer func() {
		for _, file := range filesToCleanup {
			log.SpanLog(ctx, log.DebugLevelInfra, "delete file", "file", file)
			if delerr := infracommon.DeleteFile(file); delerr != nil {
				if !os.IsNotExist(delerr) {
					log.SpanLog(ctx, log.DebugLevelInfra, "delete file failed", "file", file)
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
	if app.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW {
		updateCallback(edgeproto.UpdateTask, "Converting Image to VMDK")
		vmdkFile, err = vmlayer.ConvertQcowToVmdk(ctx, newName, f.Disk)
		filesToCleanup = append(filesToCleanup, vmdkFile)
		if err != nil {
			return err
		}
	}
	return v.ImportImage(ctx, cloudcommon.GetAppFQN(&app.Key), vmdkFile)
}
