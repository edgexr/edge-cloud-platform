package orm

import (
	"context"
	fmt "fmt"
	"net/http"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/federation"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/labstack/echo/v4"
)

const AppCreateTimeout = 10 * time.Minute

func OnboardConsumerApp(c echo.Context) (reterr error) {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Mark stream API
	in := ormapi.ConsumerApp{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	if in.Region == "" {
		return fmt.Errorf("Missing region")
	}
	if in.AppName == "" {
		return fmt.Errorf("Missing App name")
	}
	if in.AppOrg == "" {
		return fmt.Errorf("Missing App organization")
	}
	if in.AppVers == "" {
		return fmt.Errorf("Missing App version")
	}
	if in.FederationName == "" {
		return fmt.Errorf("Missing federation name")
	}
	if in.ID != "" {
		return fmt.Errorf("ID cannot be specified")
	}

	// check that user has perms for the developer organization
	if err = authorized(ctx, claims.Username, in.AppOrg, ResourceApps, ActionManage); err != nil {
		return err
	}

	consumer, err := lookupFederationConsumer(ctx, 0, in.FederationName)
	if err != nil {
		return err
	}

	// lookup App
	log.SpanLog(ctx, log.DebugLevelApi, "create ConsumerApp, look up app")
	rc := ormutil.RegionContext{
		Region:    in.Region,
		SkipAuthz: true,
		Database:  loggedDB(ctx),
	}
	appKey := edgeproto.AppKey{
		Name:         in.AppName,
		Version:      in.AppVers,
		Organization: in.AppOrg,
	}
	app, flavor, err := federation.LookupRegionApp(ctx, &rc, connCache, &appKey)
	if err != nil {
		return err
	}

	// ID is set to the app's federation id.
	// The ID should be unique across all regions, as it contains the
	// region name.
	in.ID = app.GlobalId

	// create database object so we can check for duplicates
	db := loggedDB(ctx)
	err = db.Create(&in).Error
	if err != nil {
		if strings.Contains(err.Error(), `duplicate key value`) {
			log.SpanLog(ctx, log.DebugLevelApi, "duplicate key value", "err", err)
			return fmt.Errorf("ConsumerApp %s already exists", in.ID)
		}
		log.SpanLog(ctx, log.DebugLevelApi, "failed create consumer app", "app", in, "err", err)
		return err
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := db.Delete(&in).Error
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to undo consumer app create", "app", in, "err", undoErr)
		}
	}()

	err = streamCb(c, 200, "Creating images")
	if err != nil {
		return err
	}

	// create images from App info
	log.SpanLog(ctx, log.DebugLevelApi, "create ConsumerApp, get images for app")
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

	err = streamCb(c, 200, "Creating artefact")
	if err != nil {
		return err
	}

	imageIds := []string{}
	for _, image := range images {
		imageIds = append(imageIds, image.ID)
	}
	in.ImageIds = imageIds
	err = db.Save(&in).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	// create artefact for app with component spec
	log.SpanLog(ctx, log.DebugLevelApi, "create ConsumerApp, create artefact")
	err = createAppArtefact(ctx, consumer, &in, app, imageIds, flavor)
	if err != nil {
		return fmt.Errorf("failed to create federation artefact for app: %s", err)
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := deleteAppArtefact(ctx, consumer, &in)
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to undo artefact create", "app", in, "err", undoErr)
		}
	}()

	err = streamCb(c, 200, "Creating app")
	if err != nil {
		return err
	}

	// create federated app
	log.SpanLog(ctx, log.DebugLevelApi, "create ConsumerApp, create app")
	err = createConsumerApp(ctx, consumer, &in, app)
	if err != nil {
		return err
	}

	err = streamCb(c, 200, "App created successfully")
	if err != nil {
		return err
	}
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

func createAppArtefact(ctx context.Context, consumer *ormapi.FederationConsumer, cApp *ormapi.ConsumerApp, app *edgeproto.App, imageIds []string, defaultFlavor *edgeproto.Flavor) (reterr error) {
	var virtType string
	if app.Deployment == cloudcommon.DeploymentTypeVM {
		virtType = federation.ArtefactVirtTypeVM
	} else {
		virtType = federation.ArtefactVirtTypeContainer
	}

	spec, err := partnerApi.GenerateComponentSpec(ctx, app, imageIds, defaultFlavor)
	if err != nil {
		return err
	}

	// multipart/form-data
	data := ormclient.NewMultiPartFormData()
	data.AddField(federation.ArtefactFieldId, cApp.ID)
	data.AddField(federation.ArtefactFieldAppProviderId, util.DNSSanitize(cApp.AppOrg))
	data.AddField(federation.ArtefactFieldName, cApp.AppName)
	data.AddField(federation.ArtefactFieldVersionInfo, cApp.AppVers)
	data.AddField(federation.ArtefactFieldVirtType, virtType)
	data.AddField(federation.ArtefactFieldDescriptorType, federation.ArtefactDescTypeCompSpec)
	specs := []fedewapi.ComponentSpec{*spec}
	data.AddField(federation.ArtefactFieldComponentSpec, specs)

	fedClient, err := partnerApi.ConsumerPartnerClient(ctx, consumer)
	if err != nil {
		return err
	}
	apiPath := fmt.Sprintf("/%s/%s/artefact", federationmgmt.ApiRoot, consumer.FederationContextId)
	_, _, err = fedClient.SendRequest(ctx, http.MethodPost, apiPath, data, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func createConsumerApp(ctx context.Context, consumer *ormapi.FederationConsumer, cApp *ormapi.ConsumerApp, app *edgeproto.App) error {

	appReq := fedewapi.OnboardApplicationRequest{
		AppId:         cApp.ID,
		AppProviderId: util.DNSSanitize(cApp.AppOrg),
		AppMetaData: fedewapi.AppMetaData{
			AppName:     cApp.AppName,
			Version:     cApp.AppVers,
			AccessToken: app.AuthPublicKey,
		},
		AppQoSProfile: fedewapi.AppQoSProfile{
			LatencyConstraints: federation.AppQosLatencyNone,
		},
		AppComponentSpecs: []fedewapi.AppComponentSpecsInner{{
			ArtefactId: cApp.ID,
		}},
		AppStatusCallbackLink: serverConfig.FederationExternalAddr + "/" + federationmgmt.PartnerAppOnboardStatusEventPath,
	}
	if appReq.AppMetaData.AccessToken == "" {
		appReq.AppMetaData.AccessToken = "nonenonenonenonenonenonenonenone11"
	}

	fedClient, err := partnerApi.ConsumerPartnerClient(ctx, consumer)
	if err != nil {
		return err
	}
	apiPath := fmt.Sprintf("/%s/%s/application/onboarding", federationmgmt.ApiRoot, consumer.FederationContextId)
	_, _, err = fedClient.SendRequest(ctx, http.MethodPost, apiPath, appReq, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func DeboardConsumerApp(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Mark stream API
	in := ormapi.ConsumerApp{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}
	if in.ID == "" && (in.AppName == "" || in.AppOrg == "" || in.AppVers == "") {
		return fmt.Errorf("Either appname, apporg, and appvers must be specified, or ID must be specified")
	}
	if in.FederationName == "" {
		return fmt.Errorf("Federation name must be specified")
	}
	fedQueryParams := federation.GetFedQueryParams(c)

	db := loggedDB(ctx)
	res := db.Where(&in).First(&in)
	if res.RecordNotFound() {
		return fmt.Errorf("ConsumerApp not found")
	}

	// check that user has perms for the developer organization
	if err = authorized(ctx, claims.Username, in.AppOrg, ResourceApps, ActionManage); err != nil {
		return err
	}

	consumer, err := lookupFederationConsumer(ctx, 0, in.FederationName)
	if err != nil {
		return err
	}

	// check if AppInsts exist that reference edgeproto App
	rc := ormutil.RegionContext{
		Region:    in.Region,
		SkipAuthz: true,
		Database:  database,
	}
	appInstFilter := edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			AppKey: edgeproto.AppKey{
				Name:         in.AppName,
				Organization: in.AppOrg,
				Version:      in.AppVers,
			},
		},
	}
	inUseKeys := []string{}
	err = ctrlclient.ShowAppInstStream(ctx, &rc, &appInstFilter, connCache, nil, func(ai *edgeproto.AppInst) error {
		inUseKeys = append(inUseKeys, ai.Key.GetKeyString())
		return nil
	})
	if err != nil {
		return err
	}
	if len(inUseKeys) > 0 {
		return fmt.Errorf("App still in use by %d AppInsts: %v", len(inUseKeys), strings.Join(inUseKeys, ", "))
	}

	if fedQueryParams.IgnorePartner {
		log.SpanLog(ctx, log.DebugLevelApi, "skipping federation api calls to delete app and artefact")
		if err := streamCb(c, 200, "Skipping partner API calls"); err != nil {
			return err
		}
	} else {
		if err := streamCb(c, 200, "Deleting App"); err != nil {
			return err
		}
		// delete remote app
		err = deleteApp(ctx, consumer, &in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "not found") {
			err = nil
		}
		if err != nil {
			return fmt.Errorf("failed to delete app, %s", err)
		}

		if err := streamCb(c, 200, "Deleting Artefact"); err != nil {
			return err
		}
		// delete remote artefact
		err = deleteAppArtefact(ctx, consumer, &in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "not found") {
			err = nil
		}
		if err != nil {
			return fmt.Errorf("failed to delete artefact for app, %s", err)
		}
	}

	// delete consumerapp
	err = db.Delete(&in).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	if err := streamCb(c, 200, "Deleted App successfully"); err != nil {
		return err
	}
	return nil
}

func deleteApp(ctx context.Context, consumer *ormapi.FederationConsumer, cApp *ormapi.ConsumerApp) error {
	fedClient, err := partnerApi.ConsumerPartnerClient(ctx, consumer)
	if err != nil {
		return err
	}
	apiPath := fmt.Sprintf("/%s/%s/application/onboarding/app/%s", federationmgmt.ApiRoot, consumer.FederationContextId, cApp.ID)
	_, _, err = fedClient.SendRequest(ctx, http.MethodDelete, apiPath, nil, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func deleteAppArtefact(ctx context.Context, consumer *ormapi.FederationConsumer, cApp *ormapi.ConsumerApp) error {
	fedClient, err := partnerApi.ConsumerPartnerClient(ctx, consumer)
	if err != nil {
		return err
	}
	apiPath := fmt.Sprintf("/%s/%s/artefact/%s", federationmgmt.ApiRoot, consumer.FederationContextId, cApp.ID)
	_, _, err = fedClient.SendRequest(ctx, http.MethodDelete, apiPath, nil, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func guestAppOnboarded(ctx context.Context, fedName, region string, key edgeproto.AppKey) (bool, error) {
	db := loggedDB(ctx)
	app := ormapi.ConsumerApp{
		FederationName: fedName,
		Region:         region,
		AppName:        key.Name,
		AppVers:        key.Version,
		AppOrg:         key.Organization,
	}
	res := db.Where(&app).First(&app)
	if res.RecordNotFound() {
		return false, nil
	}
	if res.Error != nil {
		return false, res.Error
	}
	return true, nil
}

func ShowConsumerApp(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.ConsumerApp{})
	if err != nil {
		return err
	}
	db := loggedDB(ctx)

	apps := []ormapi.ConsumerApp{}
	err = db.Where(filter).Find(&apps).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	authz, err := newShowAppAuthz(ctx, "", claims.Username, ResourceApps, ActionView)
	if err != nil {
		return err
	}
	showApps := []ormapi.ConsumerApp{}
	for _, app := range apps {
		if ok, _ := authz.OkOrg(app.AppOrg); ok {
			showApps = append(showApps, app)
		}
	}
	return ormutil.SetReply(c, showApps)
}

func ShowProviderArtefact(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.ProviderArtefact{})
	if err != nil {
		return err
	}
	db := loggedDB(ctx)

	arts := []ormapi.ProviderArtefact{}
	err = db.Where(filter).Find(&arts).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	orgs, err := enforcer.GetAuthorizedOrgs(ctx, claims.Username, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}
	if _, ok := orgs[""]; ok {
		// admin
		return ormutil.SetReply(c, arts)
	}
	showArts := []ormapi.ProviderArtefact{}
	for _, art := range arts {
		if _, ok := orgs[art.FederationName]; ok {
			showArts = append(showArts, art)
		}
	}
	return ormutil.SetReply(c, showArts)
}

func ShowProviderApp(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.ProviderApp{})
	if err != nil {
		return err
	}
	db := loggedDB(ctx)

	apps := []ormapi.ProviderApp{}
	err = db.Where(filter).Find(&apps).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	orgs, err := enforcer.GetAuthorizedOrgs(ctx, claims.Username, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}
	if _, ok := orgs[""]; ok {
		// admin
		return ormutil.SetReply(c, apps)
	}
	showApps := []ormapi.ProviderApp{}
	for _, art := range apps {
		if _, ok := orgs[art.FederationName]; ok {
			showApps = append(showApps, art)
		}
	}
	return ormutil.SetReply(c, showApps)
}

func ShowProviderAppInst(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.ProviderAppInst{})
	if err != nil {
		return err
	}
	db := loggedDB(ctx)

	insts := []ormapi.ProviderAppInst{}
	err = db.Where(filter).Find(&insts).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	orgs, err := enforcer.GetAuthorizedOrgs(ctx, claims.Username, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}
	if _, ok := orgs[""]; ok {
		// admin
		return ormutil.SetReply(c, insts)
	}
	showAppInsts := []ormapi.ProviderAppInst{}
	for _, inst := range insts {
		if _, ok := orgs[inst.FederationName]; ok {
			showAppInsts = append(showAppInsts, inst)
		}
	}
	return ormutil.SetReply(c, showAppInsts)
}

func isProviderApp(ctx context.Context, app *edgeproto.App) (bool, error) {
	art := ormapi.ProviderArtefact{}
	art.SetAppKey(&app.Key)
	db := loggedDB(ctx)
	res := db.Where(&art).First(&art)
	if res.RecordNotFound() {
		return false, nil
	}
	if res.Error != nil {
		return false, res.Error
	}
	return true, nil
}

func isProviderAppInst(ctx context.Context, appInst *edgeproto.AppInst) (bool, error) {
	ai := ormapi.ProviderAppInst{}
	ai.SetAppInstKey(&appInst.Key)
	db := loggedDB(ctx)
	res := db.Where(&ai).First(&ai)
	if res.RecordNotFound() {
		return false, nil
	}
	if res.Error != nil {
		return false, res.Error
	}
	return true, nil
}

func UnsafeDeleteProviderArtefact(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	in := ormapi.ProviderArtefact{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	if in.ArtefactID == "" {
		return fmt.Errorf("ArtefactID must be specified")
	}
	if in.FederationName == "" {
		return fmt.Errorf("Federation name must be specified")
	}

	provider, err := lookupFederationProvider(ctx, 0, in.FederationName)
	if err != nil {
		return err
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, provider.GetTags())
	if err := fedAuthorized(ctx, claims.Username, provider.OperatorId); err != nil {
		return err
	}

	return partnerApi.RemoveArtefactInternal(c, provider, in.ArtefactID)
}

func UnsafeDeleteProviderApp(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	in := ormapi.ProviderApp{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	if in.AppID == "" {
		return fmt.Errorf("AppID must be specified")
	}
	if in.FederationName == "" {
		return fmt.Errorf("Federation name must be specified")
	}

	provider, err := lookupFederationProvider(ctx, 0, in.FederationName)
	if err != nil {
		return err
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, provider.GetTags())
	if err := fedAuthorized(ctx, claims.Username, provider.OperatorId); err != nil {
		return err
	}

	return partnerApi.DeleteAppInternal(c, provider, in.AppID)
}

func UnsafeDeleteProviderAppInst(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	in := ormapi.ProviderAppInst{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	if in.AppInstID == "" {
		return fmt.Errorf("AppInstID must be specified")
	}
	if in.FederationName == "" {
		return fmt.Errorf("Federation name must be specified")
	}

	provider, err := lookupFederationProvider(ctx, 0, in.FederationName)
	if err != nil {
		return err
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, provider.GetTags())
	if err := fedAuthorized(ctx, claims.Username, provider.OperatorId); err != nil {
		return err
	}

	return partnerApi.RemoveAppInstInternal(c, provider, in.AppInstID)
}
