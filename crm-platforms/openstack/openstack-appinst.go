package openstack

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
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

func (o *OpenstackPlatform) AddAppImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, app *edgeproto.App, flavor string, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddAppImageIfNotPresent", "imageInfo", imageInfo, "imagePath", app.ImagePath)

	imageDetail, err := o.GetImageDetail(ctx, imageInfo.LocalImageName)
	createImage := false
	if err != nil {
		if strings.Contains(err.Error(), ResourceNotFound) {
			// Add image to Glance
			log.SpanLog(ctx, log.DebugLevelInfra, "image is not present in glance, add image")
			createImage = true
		} else {
			return err
		}
	} else {
		if imageDetail.Status != "active" {
			return fmt.Errorf("image in store %s is not active", imageInfo.LocalImageName)
		}
		if imageDetail.Checksum != imageInfo.Md5sum {
			if app.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW && imageDetail.DiskFormat == vmlayer.ImageFormatVmdk {
				log.SpanLog(ctx, log.DebugLevelInfra, "image was imported as vmdk, checksum match not possible")
			} else {
				return fmt.Errorf("mismatch in md5sum for image in glance: %s", imageInfo.LocalImageName)
			}
		}
		glanceImageTime, err := time.Parse(time.RFC3339, imageDetail.UpdatedAt)
		if err != nil {
			return err
		}
		if !imageInfo.SourceImageTime.IsZero() {
			if imageInfo.SourceImageTime.Sub(glanceImageTime) > 0 {
				// Update the image in Glance
				updateCallback(edgeproto.UpdateTask, "Image in store is outdated, deleting old image")
				err = o.DeleteImage(ctx, "", imageInfo.LocalImageName)
				if err != nil {
					return err
				}
				createImage = true
			}
		}
	}
	if createImage {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Creating VM Image from URL: %s", imageInfo.LocalImageName))
		err = o.CreateImageFromUrl(ctx, imageInfo.LocalImageName, app.ImagePath, imageInfo.Md5sum)
		if err != nil {
			return err
		}
	}
	return nil
}
