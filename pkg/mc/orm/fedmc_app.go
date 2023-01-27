package orm

import (
	"context"
	fmt "fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	dmeproto "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/federation"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/labstack/echo/v4"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
)

const AppCreateTimeout = 10 * time.Minute

func OnboardConsumerApp(c echo.Context) (reterr error) {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Mark stream API
	c.Set(StreamAPITag, true)

	in := ormapi.ConsumerApp{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
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
	lookup := edgeproto.App{
		Key: edgeproto.AppKey{
			Name:         in.AppName,
			Organization: in.AppOrg,
			Version:      in.AppVers,
		},
	}
	var app *edgeproto.App
	err = ctrlclient.ShowAppStream(ctx, &rc, &lookup, connCache, nil, func(retApp *edgeproto.App) error {
		app = retApp
		return nil
	})
	if err != nil {
		return fmt.Errorf("Failure looking up App: %s", err)
	}
	if app == nil {
		return fmt.Errorf("App not found")
	}

	if app.DefaultFlavor.Name == "" && app.ServerlessConfig == nil {
		return fmt.Errorf("App has no default flavor and no serverless config to specify compute resources")
	}

	var flavor *edgeproto.Flavor
	if app.DefaultFlavor.Name != "" {
		log.SpanLog(ctx, log.DebugLevelApi, "create ConsumerApp, look up flavors")
		flavorLookup := edgeproto.Flavor{
			Key: app.DefaultFlavor,
		}
		err = ctrlclient.ShowFlavorStream(ctx, &rc, &flavorLookup, connCache, func(retFlavor *edgeproto.Flavor) error {
			flavor = retFlavor
			return nil
		})
		if err != nil {
			return fmt.Errorf("Failure looking up Flavor %s: %s", app.DefaultFlavor.Name, err)
		}
		if flavor == nil {
			return fmt.Errorf("App DefaultFlavor %s not found", app.DefaultFlavor.Name)
		}
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
			return fmt.Errorf("ConsumerApp already exists")
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

	// create artefact for app with component spec
	log.SpanLog(ctx, log.DebugLevelApi, "create ConsumerApp, create artefact")
	err = createAppArtefact(ctx, consumer, &in, app, images, flavor)
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

func createAppArtefact(ctx context.Context, consumer *ormapi.FederationConsumer, cApp *ormapi.ConsumerApp, app *edgeproto.App, images []*ormapi.ConsumerImage, defaultFlavor *edgeproto.Flavor) (reterr error) {
	var virtType string
	if app.Deployment == cloudcommon.DeploymentTypeVM {
		virtType = federation.ArtefactVirtTypeVM
	} else {
		virtType = federation.ArtefactVirtTypeContainer
	}

	// Create ComponentSpec
	spec := fedewapi.ComponentSpec{}
	spec.ComponentName = app.Key.Name
	spec.Images = []string{}
	for _, image := range images {
		spec.Images = append(spec.Images, image.ID)
	}
	if app.ScaleWithCluster {
		spec.NumOfInstances = -1
	} else {
		spec.NumOfInstances = 1
	}
	spec.RestartPolicy = federation.RestartPolicyAlways
	commandLineParams := fedewapi.CommandLineParams{}
	envVars := []v1.EnvVar{}
	if app.Command != "" {
		commandLineParams.Command = []string{app.Command}
	}
	for _, cfg := range app.Configs {
		switch cfg.Kind {
		case edgeproto.AppConfigHelmYaml:
			// TODO: spec doesn't have any place for this yet
		case edgeproto.AppConfigEnvYaml:
			err := yaml.Unmarshal([]byte(cfg.Config), &envVars)
			if err != nil {
				return fmt.Errorf("Failed to unmarshal ConfigFile for env vars: %s", err)
			}
		case edgeproto.AppConfigPodArgs:
			args := []string{}
			err := yaml.Unmarshal([]byte(cfg.Config), &args)
			if err != nil {
				return err
			}
			commandLineParams.CommandArgs = args
		}
	}
	if len(commandLineParams.Command) > 0 || len(commandLineParams.CommandArgs) > 0 {
		spec.CommandLineParams = &commandLineParams
	}
	for _, envVar := range envVars {
		env := fedewapi.CompEnvParams{
			EnvVarName:   envVar.Name,
			EnvVarValue:  &envVar.Value,
			EnvValueType: federation.EnvVarTypeUser,
		}
		spec.CompEnvParams = append(spec.CompEnvParams, env)
	}

	ports, err := edgeproto.ParseAppPorts(app.AccessPorts)
	if err != nil {
		return err
	}
	interfaces := []fedewapi.InterfaceDetails{}
	for _, port := range ports {
		portStart := port.InternalPort
		portEnd := port.EndPort
		if portEnd == 0 {
			portEnd = portStart
		}
		for portVal := portStart; portVal <= portEnd; portVal++ {
			intf := fedewapi.InterfaceDetails{}
			intf.InterfaceId = partnerApi.GetInterfaceId(port, portVal)
			if port.Proto == dmeproto.LProto_L_PROTO_UDP {
				intf.CommProtocol = federation.CommProtoUDP
			} else {
				intf.CommProtocol = federation.CommProtoTCP
			}
			intf.CommPort = portVal
			if app.InternalPorts {
				intf.VisibilityType = federation.CommPortVisInt
			} else {
				intf.VisibilityType = federation.CommPortVisExt
			}
			interfaces = append(interfaces, intf)
		}
	}
	if len(interfaces) > 0 {
		spec.ExposedInterfaces = interfaces
	}

	resources := fedewapi.ComputeResourceInfo{}
	if defaultFlavor == nil && app.ServerlessConfig == nil {
		return fmt.Errorf("Cannot specify compute resource info, one of default flavor or serverless config must be set")
	}
	if app.ServerlessConfig != nil {
		resources.NumCPU = app.ServerlessConfig.Vcpus.DecString()
		resources.Memory = int64(app.ServerlessConfig.Ram)
	} else {
		disk := int32(defaultFlavor.Disk)
		resources.NumCPU = strconv.Itoa(int(defaultFlavor.Vcpus))
		resources.Memory = int64(defaultFlavor.Ram)
		if disk > 0 {
			resources.DiskStorage = &disk
		}
	}
	// TODO: resources.Gpu
	spec.ComputeResourceProfile = resources

	// multipart/form-data
	data := ormclient.NewMultiPartFormData()
	data.AddField(federation.ArtefactFieldId, cApp.ID)
	data.AddField(federation.ArtefactFieldAppProviderId, cApp.AppOrg)
	data.AddField(federation.ArtefactFieldName, cApp.AppName)
	data.AddField(federation.ArtefactFieldVersionInfo, cApp.AppVers)
	data.AddField(federation.ArtefactFieldVirtType, virtType)
	data.AddField(federation.ArtefactFieldDescriptorType, federation.ArtefactDescTypeCompSpec)
	specs := []fedewapi.ComponentSpec{spec}
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
		AppProviderId: cApp.AppOrg,
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
		appReq.AppMetaData.AccessToken = "none"
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
	c.Set(StreamAPITag, true)

	in := ormapi.ConsumerApp{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	if in.ID == "" && (in.AppName == "" || in.AppOrg == "" || in.AppVers == "") {
		return fmt.Errorf("Either appname, apporg, and appvers must be specified, or ID must be specified")
	}
	if in.FederationName == "" {
		return fmt.Errorf("Federation name must be specified")
	}

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

	// TODO: check if AppInsts exist that reference edgeproto App

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
