package orm

import (
	"context"
	"errors"
	fmt "fmt"
	"net/http"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/federation"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

var ErrExactDuplicate = errors.New("exact duplicate")

func CreateConsumerImage(c echo.Context) (reterr error) {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	image := ormapi.ConsumerImage{}
	if err := c.Bind(&image); err != nil {
		return ormutil.BindErr(err)
	}
	if image.Organization == "" {
		return fmt.Errorf("Missing developer organization")
	}
	if image.FederationName == "" {
		return fmt.Errorf("Missing federation name to copy to")
	}
	if image.SourcePath == "" {
		return fmt.Errorf("Missing image source path")
	}
	if image.Type == "" {
		return fmt.Errorf("Missing image type")
	}
	// check that user has perms for the developer organization
	if err = authorized(ctx, claims.Username, image.Organization, ResourceApps, ActionManage); err != nil {
		return err
	}
	err = createFederatedImageObj(ctx, &image)
	if err != nil && err == ErrExactDuplicate {
		return ormutil.SetReply(c, ormutil.Msg("Exact duplicate of image already exists"))
	} else if err != nil {
		return err
	}
	return ormutil.SetReply(c, ormutil.Msg(fmt.Sprintf("Image %s created", image.ID)))
}

func createFederatedImageObj(ctx context.Context, image *ormapi.ConsumerImage) (reterr error) {
	if image.ID != "" {
		return fmt.Errorf("ID cannot be specified")
	}

	if err := federation.CheckFileType(image.Type); err != nil {
		return err
	}

	// if the image path refers to our registry, verify the user has
	// permissions to the organization
	err := checkImagePathStrings(ctx, image.Organization, image.SourcePath)
	if err != nil {
		return err
	}

	// get image name
	if image.Name == "" {
		parts := strings.Split(image.SourcePath, "/")
		image.Name = parts[len(parts)-1]
	}
	consumer, err := lookupFederationConsumer(ctx, 0, image.FederationName)
	if err != nil {
		return err
	}

	// get auth information so we can determine container checksum
	var auth *cloudcommon.RegistryAuth
	inVmReg := false
	inHarbor := false
	if serverConfig.VmRegistryAddr != "" && strings.Contains(image.SourcePath, serverConfig.VmRegistryAddr) {
		auth, err = cloudcommon.GetRegistryAuth(ctx, serverConfig.VmRegistryAddr, cloudcommon.AllOrgs, serverConfig.vaultConfig)
		if err != nil {
			return err
		}
		inVmReg = true
	} else if serverConfig.HarborAddr != "" && strings.Contains(image.SourcePath, util.TrimScheme(serverConfig.HarborAddr)) {
		// add harbor credentials
		auth, err = cloudcommon.GetRegistryAuth(ctx, serverConfig.HarborAddr, image.Organization, serverConfig.vaultConfig)
		if err != nil {
			return err
		}
		inHarbor = true
	}

	if image.Type == string(fedewapi.VIRTIMAGETYPE_DOCKER) {
		if strings.Index(image.SourcePath, "://") != -1 {
			return fmt.Errorf("docker container image path should be without scheme://")
		}
	}

	// We use the checksum to ensure the file was transferred correctly
	// and to allow already exists checks
	if image.Type == string(fedewapi.VIRTIMAGETYPE_DOCKER) && image.Checksum == "" {
		// easy to retreive checksum
		checksum, err := cloudcommon.GetDockerImageChecksum(ctx, image.SourcePath, auth)
		if err != nil {
			return err
		}
		image.Checksum = checksum
	} else if image.Checksum == "" {
		// we could technically calculate checksum for local files,
		// but for large remote files we'd have to download it
		// first which is inefficient.
		// TODO: for our own vm-registry we can do a HEAD request
		// to get the checksum.
		return fmt.Errorf("Checksum missing, please specify md5 checksum for image %s", image.SourcePath)
	}

	// check if image already exists, this allows
	// multiple applies of "createImagesForApp" to be idempotent
	db := loggedDB(ctx)
	lookup := ormapi.ConsumerImage{
		Organization:   image.Organization,
		FederationName: image.FederationName,
		Name:           image.Name,
	}
	dup := ormapi.ConsumerImage{}
	res := db.Where(&lookup).First(&dup)
	if res.Error == nil && !res.RecordNotFound() {
		if image.SourcePath == dup.SourcePath && image.Type == dup.Type && image.Checksum == dup.Checksum {
			// exact match
			log.SpanLog(ctx, log.DebugLevelApi, "create consumer image already exists with exact match", "image", dup)
			return ErrExactDuplicate
		}
	}

	// save first before we upload
	image.ID = uuid.New().String()
	image.Status = federation.ImageStatusSending
	err = db.Create(&image).Error
	if err != nil {
		if strings.Contains(err.Error(), `duplicate key value violates unique constraint "consumer_images_pkey"`) {
			return fmt.Errorf("Internal UUID conflict, please try again")
		}
		if strings.Contains(err.Error(), `duplicate key value violates unique constraint "consumerimageindex"`) {
			return fmt.Errorf("Image with Organization %q, FederationName %q, and Name %q combination already exists; please choose a different Name", image.Organization, image.FederationName, image.Name)
		}
		return err
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := db.Delete(&image).Error
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to undo image create", "image", image, "err", undoErr)
		}
	}()

	// multipart/form-data
	data := ormclient.NewMultiPartFormData()
	data.AddField(federation.FileFieldFileId, image.ID)
	data.AddField(federation.FileFieldAppProviderId, image.Organization)
	data.AddField(federation.FileFieldFileName, image.Name)
	data.AddField(federation.FileFieldFileType, image.Type)
	if image.Checksum != "" {
		data.AddField(federation.FileFieldChecksum, image.Checksum)
	}

	repoLocation := &fedewapi.ObjectRepoLocation{
		RepoURL: &image.SourcePath,
	}
	if inVmReg {
		// generate a short-lived cookie that is only good
		// for reading this specific image
		idx := strings.Index(image.SourcePath, cloudcommon.VmRegPath)
		orgpath := image.SourcePath[idx+len(cloudcommon.VmRegPath):]
		orgpath = strings.TrimLeft(orgpath, "/")
		parts := strings.SplitN(orgpath, "/", 2)
		if len(parts) != 2 {
			return fmt.Errorf("bad image path, expected org/path but was %s", orgpath)
		}
		user := ormapi.User{
			Name: auth.Username,
		}
		config, err := getConfig(ctx)
		if err != nil {
			return err
		}
		cookie, err := GenerateCookie(&user, "", serverConfig.HTTPCookieDomain, config, WithObjectRestriction(parts[1]), WithValidDuration(time.Hour))
		// add vmreg credentials
		repoLocation.Token = &cookie.Value
		data.AddField(federation.FileFieldRepoType, federation.RepoTypeUpload)
		log.SpanLog(ctx, log.DebugLevelApi, "upload file request added vm-registry auth token", "object-restriction", parts[1])
	} else if inHarbor {
		// add harbor credentials
		repoLocation.UserName = &auth.Username
		repoLocation.Password = &auth.Password
		data.AddField(federation.FileFieldRepoType, federation.RepoTypeUpload)
		log.SpanLog(ctx, log.DebugLevelApi, "upload file request added harbor basic credentials")
	} else {
		data.AddField(federation.FileFieldRepoType, federation.RepoTypePublic)
	}
	data.AddField(federation.FileFieldRepoLocation, repoLocation)

	fedClient, err := partnerApi.ConsumerPartnerClient(ctx, consumer)
	if err != nil {
		return err
	}
	apiPath := fmt.Sprintf("/%s/%s/files", federation.ApiRoot, consumer.FederationContextId)
	_, err = fedClient.SendRequest(ctx, http.MethodPost, apiPath, data, nil, nil)
	if err != nil {
		return err
	}

	// save uploaded status
	image.Status = federation.ImageStatusReady
	err = db.Save(image).Error
	if err != nil {
		// just log it, since it's just the status that we're missing
		log.SpanLog(ctx, log.DebugLevelApi, "failed to save uploaded status", "image", image, "err", err)
	}
	return nil
}

func DeleteConsumerImage(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	image := ormapi.ConsumerImage{}
	if err := c.Bind(&image); err != nil {
		return ormutil.BindErr(err)
	}
	if image.ID == "" && (image.Organization == "" || image.FederationName == "" || image.Name == "") {
		return fmt.Errorf("Either ID, or the triplet of Organization, FederationName, and Name must be specified to uniquely identify the image")
	}

	db := loggedDB(ctx)
	res := db.Where(&image).First(&image)
	if res.RecordNotFound() {
		return fmt.Errorf("Image not found")
	}
	if res.Error != nil {
		return ormutil.DbErr(err)
	}
	if err = authorized(ctx, claims.Username, image.Organization, ResourceApps, ActionManage); err != nil {
		return err
	}
	consumer, err := lookupFederationConsumer(ctx, 0, image.FederationName)
	if err != nil {
		return err
	}

	fedClient, err := partnerApi.ConsumerPartnerClient(ctx, consumer)
	if err != nil {
		return err
	}
	apiPath := fmt.Sprintf("/%s/%s/files/%s", federation.ApiRoot, consumer.FederationContextId, image.ID)
	_, err = fedClient.SendRequest(ctx, http.MethodDelete, apiPath, nil, nil, nil)
	if err != nil {
		return err
	}
	err = db.Delete(&image).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	return ormutil.SetReply(c, ormutil.Msg(fmt.Sprintf("Image %s deleted", image.ID)))
}

func ShowConsumerImage(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.ConsumerImage{})
	if err != nil {
		return err
	}
	images := []ormapi.ConsumerImage{}
	db := loggedDB(ctx)
	err = db.Where(filter).Find(&images).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	showAuth, err := newShowAuthz(ctx, "", claims.Username, ResourceApps, ActionView)
	if err != nil {
		return err
	}
	if showAuth.allowAll {
		// admin
		return ormutil.SetReply(c, images)
	}
	allowedImages := []ormapi.ConsumerImage{}
	for _, image := range images {
		if showAuth.Ok(image.Organization) {
			allowedImages = append(allowedImages, image)
		} else if showAuth.Ok(image.FederationName) {
			// consumer fed needs to be able to see images to
			// ask developers to delete them in order to be able
			// to delete the federation consumer.
			// Show only id and org.
			redactedImage := ormapi.ConsumerImage{
				ID:             image.ID,
				Organization:   image.Organization,
				FederationName: image.FederationName,
			}
			allowedImages = append(allowedImages, redactedImage)
		}
	}
	return ormutil.SetReply(c, allowedImages)
}

func ShowProviderImage(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.ProviderImage{})
	if err != nil {
		return err
	}
	images := []ormapi.ProviderImage{}
	db := loggedDB(ctx)
	err = db.Where(filter).Find(&images).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	showAuth, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}
	if showAuth.allowAll {
		// admin
		return ormutil.SetReply(c, images)
	}
	allowedImages := []ormapi.ProviderImage{}
	for _, image := range images {
		if showAuth.Ok(image.FederationName) {
			allowedImages = append(allowedImages, image)
		}
	}
	return ormutil.SetReply(c, allowedImages)
}
