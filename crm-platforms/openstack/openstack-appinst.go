package openstack

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (o *OpenstackPlatform) GetConsoleUrl(ctx context.Context, serverName string) (string, error) {
	consoleUrl, err := o.OSGetConsoleUrl(ctx, serverName)
	if err != nil {
		return "", err
	}
	return consoleUrl.Url, nil
}

func (o *OpenstackPlatform) AddAppImageIfNotPresent(ctx context.Context, app *edgeproto.App, updateCallback edgeproto.CacheUpdateCallback) error {
	imageName, err := cloudcommon.GetFileName(app.ImagePath)
	if err != nil {
		return err
	}
	sourceImageTime, md5Sum, err := infracommon.GetUrlInfo(ctx, o.VMProperties.CommonPf.VaultConfig, app.ImagePath)
	imageDetail, err := o.GetImageDetail(ctx, imageName)
	createImage := false
	if err != nil {
		if strings.Contains(err.Error(), "Could not find resource") {
			// Add image to Glance
			log.SpanLog(ctx, log.DebugLevelInfra, "image is not present in glance, add image")
			createImage = true
		} else {
			return err
		}
	} else {
		if imageDetail.Status != "active" {
			return fmt.Errorf("image in store %s is not active", imageName)
		}
		if imageDetail.Checksum != md5Sum {
			if app.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW && imageDetail.DiskFormat == vmlayer.ImageFormatVmdk {
				log.SpanLog(ctx, log.DebugLevelInfra, "image was imported as vmdk, checksum match not possible")
			} else {
				return fmt.Errorf("mismatch in md5sum for image in glance: %s", imageName)
			}
		}
		glanceImageTime, err := time.Parse(time.RFC3339, imageDetail.UpdatedAt)
		if err != nil {
			return err
		}
		if !sourceImageTime.IsZero() {
			if sourceImageTime.Sub(glanceImageTime) > 0 {
				// Update the image in Glance
				updateCallback(edgeproto.UpdateTask, "Image in store is outdated, deleting old image")
				err = o.DeleteImage(ctx, imageName)
				if err != nil {
					return err
				}
				createImage = true
			}
		}
	}
	if createImage {
		updateCallback(edgeproto.UpdateTask, "Creating VM Image from URL")
		err = o.CreateImageFromUrl(ctx, imageName, app.ImagePath, md5Sum)
		if err != nil {
			return err
		}
	}
	return nil
}
