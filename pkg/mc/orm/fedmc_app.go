package orm

import (
	fmt "fmt"
	"strings"

	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/labstack/echo/v4"
)

func CreateConsumerApp(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	in := ormapi.ConsumerApp{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	if in.Region == "" {
		return fmt.Errorf("Missing region")
	}
	if in.App.Key.Name == "" {
		return fmt.Errorf("Missing App name")
	}
	if in.App.Key.Organization == "" {
		return fmt.Errorf("Missing App organization")
	}
	if in.App.Key.Version == "" {
		return fmt.Errorf("Missing App version")
	}

	// check that user has perms for the developer organization
	if err = authorized(ctx, claims.Username, in.App.Key.Organization, ResourceApps, ActionManage); err != nil {
		return err
	}

	// lookup App
	rc := ormutil.RegionContext{
		Region:    in.Region,
		SkipAuthz: true,
		Database:  loggedDB(ctx),
	}
	var app *edgeproto.App
	err = ctrlclient.ShowAppStream(ctx, &rc, &in.App, connCache, nil, func(retApp *edgeproto.App) error {
		app = retApp
		return nil
	})
	if err != nil {
		return fmt.Errorf("Failure looking up App: %s", err)
	}
	if app == nil {
		return fmt.Errorf("App not found")
	}

	// create images from App info
	images, err := getImagesForApp(in.FederationName, app)
	if err != nil {
		return err
	}
	for _, image := range images {
		err := createFederatedImageObj(ctx, image)
		if err == ErrExactDuplicate {
			// ignore duplicate errors
			err = nil
		}
		if err != nil {
			return err
		}
	}

	// TODO: create artifact with ComponentSpec
	// TODO: onboard App
	return nil
}

func getImagesForApp(fedName string, app *edgeproto.App) ([]*ormapi.ConsumerImage, error) {
	images := []*ormapi.ConsumerImage{}
	if app.ImagePath != "" {
		image := ormapi.ConsumerImage{
			Organization:   app.Key.Organization,
			FederationName: fedName,
			SourcePath:     app.ImagePath,
			Checksum:       app.Md5Sum,
		}
		switch app.ImageType {
		case edgeproto.ImageType_IMAGE_TYPE_DOCKER:
			image.Type = string(fedewapi.VIRTIMAGETYPE_DOCKER)
		case edgeproto.ImageType_IMAGE_TYPE_QCOW:
			image.Type = string(fedewapi.VIRTIMAGETYPE_QCOW2)
		case edgeproto.ImageType_IMAGE_TYPE_OVA:
			image.Type = string(fedewapi.VIRTIMAGETYPE_OVA)
		case edgeproto.ImageType_IMAGE_TYPE_HELM:
			// TODO: waiting on EWBI API changes, not clear how to handle
			fallthrough
		case edgeproto.ImageType_IMAGE_TYPE_OVF:
			return nil, fmt.Errorf("federation does not support image type %s", app.ImageType.String())
		default:
			return nil, fmt.Errorf("Unknown App ImageType %d", app.ImageType)
		}

		parts := strings.Split(app.ImagePath, "#md5:")
		if len(parts) == 2 {
			image.SourcePath = parts[0]
			image.Checksum = parts[1]
		}
		images = append(images, &image)
	}
	if app.DeploymentManifest != "" && app.Deployment == cloudcommon.DeploymentTypeDocker {
		// TODO: parse docker-compose for containers and
		// replace later with uploaded image paths
		return nil, fmt.Errorf("custom docker deployment manifest not supported yet")

	}
	if app.DeploymentManifest != "" && app.Deployment == cloudcommon.DeploymentTypeKubernetes && app.DeploymentGenerator == "" {
		// User-supplied manifest
		// TODO: parse manifest to get images and replace later
		// with uploaded image paths
		return nil, fmt.Errorf("custom kubernetes deployment manifest not supported yet")
	}
	return images, nil
}
