package vsphere

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var qcowConvertTimeout = 5 * time.Minute

func (v *VSpherePlatform) AddAppImageIfNotPresent(ctx context.Context, app *edgeproto.App, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddAppImageIfNotPresent", "app.ImagePath", app.ImagePath)

	imageName, err := cloudcommon.GetFileName(app.ImagePath)
	if err != nil {
		return err
	}
	_, md5Sum, err := infracommon.GetUrlInfo(ctx, v.vmProperties.CommonPf.VaultConfig, app.ImagePath)

	filePath, err := vmlayer.DownloadVMImage(ctx, v.vmProperties.CommonPf.VaultConfig, imageName, app.ImagePath, md5Sum)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "downloaded file", "filePath", filePath)

	vmdkFile := filePath
	if app.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW {
		vmdkFile, err = v.ConvertQcowToVmdk(ctx, filePath)
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
	return v.ImportImage(ctx, vmdkFile)
}

func (v *VSpherePlatform) ConvertQcowToVmdk(ctx context.Context, sourceFile string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ConvertQcowToVmdk", "sourceFile", sourceFile)
	destFile := strings.ReplaceAll(sourceFile, ".qcow2", "")
	destFile = destFile + ".vmdk"

	convertChan := make(chan string, 1)
	var convertErr string
	go func() {
		out, err := sh.Command("qemu-img", "convert", "-O", "vmdk", "-o", "subformat=streamOptimized", sourceFile, destFile).CombinedOutput()
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
