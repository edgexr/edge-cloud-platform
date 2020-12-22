package vsphere

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var qcowConvertTimeout = 10 * time.Minute

func (v *VSpherePlatform) AddAppImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, app *edgeproto.App, flavor string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddAppImageIfNotPresent", "app.ImagePath", app.ImagePath, "flavor", flavor)

	f, err := v.GetFlavor(ctx, flavor)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Downloading VM Image")
	filePath, err := vmlayer.DownloadVMImage(ctx, v.vmProperties.CommonPf.PlatformConfig.AccessApi, imageInfo.LocalImageName, app.ImagePath, imageInfo.Md5sum)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "downloaded file", "filePath", filePath)

	vmdkFile := filePath
	if app.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW {
		updateCallback(edgeproto.UpdateTask, "Converting Image to VMDK")
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
}

func (v *VSpherePlatform) ConvertQcowToVmdk(ctx context.Context, sourceFile string, size uint64) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ConvertQcowToVmdk", "sourceFile", sourceFile, "size", size)
	destFile := strings.TrimSuffix(sourceFile, filepath.Ext(sourceFile))
	destFile = destFile + ".vmdk"

	convertChan := make(chan string, 1)
	var convertErr string
	go func() {
		//resize to the correct size
		sizeInGB := fmt.Sprintf("%dG", size)
		log.SpanLog(ctx, log.DebugLevelInfra, "Resizing to", "size", sizeInGB)
		out, err := sh.Command("qemu-img", "resize", sourceFile, "--shrink", sizeInGB).CombinedOutput()

		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "qemu-img resize failed", "out", string(out), "err", err)
			convertChan <- fmt.Sprintf("qemu-img resize failed: %s %v", out, err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "doing qemu-img convert", "destFile", destFile)
		out, err = sh.Command("qemu-img", "convert", "-O", "vmdk", "-o", "subformat=streamOptimized", sourceFile, destFile).CombinedOutput()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "qemu-img convert failed", "out", string(out), "err", err)
			convertChan <- fmt.Sprintf("qemu-img convert failed: %s %v", out, err)
		} else {
			convertChan <- ""

		}
	}()
	select {
	case convertErr = <-convertChan:
	case <-time.After(qcowConvertTimeout):
		return "", fmt.Errorf("ConvertQcowToVmdk timed out")
	}
	if convertErr != "" {
		return "", errors.New(convertErr)
	}
	return destFile, nil
}
