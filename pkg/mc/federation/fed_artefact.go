package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	dmeproto "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/labstack/echo/v4"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
)

const (
	// Artefact
	ArtefactFieldId             = "artefactId"
	ArtefactFieldAppProviderId  = "appProviderId"
	ArtefactFieldName           = "artefactName"
	ArtefactFieldVersionInfo    = "artefactVersionInfo"
	ArtefactFieldDescription    = "artefactDescription"
	ArtefactFieldVirtType       = "artefactVirtType"
	ArtefactFieldFileName       = "artefactFileName"
	ArtefactFieldFileFormat     = "artefactFileFormat"
	ArtefactFieldDescriptorType = "artefactDescriptorType"
	ArtefactFieldRepoType       = "repoType"
	ArtefactFieldRepoLocation   = "artefactRepoLocation"
	ArtefactFieldFile           = "artefactFile"
	ArtefactFieldComponentSpec  = "componentSpec"

	ArtefactVirtTypeVM        = "VM_TYPE"
	ArtefactVirtTypeContainer = "CONTAINER_TYPE"

	ArtefactDescTypeCompSpec = "COMPONENTSPEC"

	// ComponentSpec
	RestartPolicyAlways = "RESTART_POLICY_ALWAYS"
	RestartPolicyNever  = "RESTART_POLICY_NEVER"

	CommProtoUDP   = "UDP"
	CommProtoTCP   = "TCP"
	CommProtoHTTP  = "HTTP_HTTPS"
	CommPortVisExt = "VISIBILITY_EXTERNAL"
	CommPortVisInt = "VISIBILITY_INTERNAL"

	EnvVarTypeUser = "USER_DEFINED"

	ConfigTypeDockerCompose = "DOCKER_COMPOSE"
	ConfigTypeK8sManifest   = "KUBERNETES_MANIFEST"
	ConfigTypeCloudInit     = "CLOUD_INIT"
	ConfigTypeHelmValues    = "HELM_VALUES"
)

func (p *PartnerApi) lookupArtefact(c echo.Context, provider *ormapi.FederationProvider, artefactId string) (*ormapi.ProviderArtefact, error) {
	ctx := ormutil.GetContext(c)
	db := p.loggedDB(ctx)
	provArt := ormapi.ProviderArtefact{}
	provArt.FederationName = provider.Name
	provArt.ArtefactID = artefactId
	res := db.Where(&provArt).First(&provArt)
	if res.RecordNotFound() {
		return nil, fmt.Errorf("Artefact %s not found", artefactId)
	}
	if res.Error != nil {
		return nil, fedError(http.StatusInternalServerError, fmt.Errorf("Failed to look up artefact, %s", res.Error.Error()))
	}
	return &provArt, nil
}

func (p *PartnerApi) UploadArtefact(c echo.Context, fedCtxId FederationContextId) (reterr error) {
	ctx := ormutil.GetContext(c)
	log.SpanLog(ctx, log.DebugLevelApi, "Fed EWBI UploadArtefact", "fedCtxId", fedCtxId)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	req := c.Request()
	// 1 megabyte in memory storage, we don't allow inline data upload
	maxMemBytes := int64(1024 * 1024)
	req.ParseMultipartForm(maxMemBytes)

	provArt := ormapi.ProviderArtefact{}
	provArt.FederationName = provider.Name
	provArt.ArtefactID = req.PostFormValue(ArtefactFieldId)
	provArt.ArtefactName = req.PostFormValue(ArtefactFieldName)
	provArt.AppProviderId = req.PostFormValue(ArtefactFieldAppProviderId)
	provArt.ArtefactVersion = req.PostFormValue(ArtefactFieldVersionInfo)
	provArt.VirtType = req.PostFormValue(ArtefactFieldVirtType)
	provArt.DescType = req.PostFormValue(ArtefactFieldDescriptorType)
	if val := req.PostFormValue(ArtefactFieldRepoLocation); val != "" {
		return fmt.Errorf("Artefact repo location not supported, only component spec is supported")
	}
	if val := req.PostFormValue(ArtefactFieldFile); val != "" {
		return fmt.Errorf("Artefact file not supported, only component spec is supported")
	}
	specData := req.PostFormValue(ArtefactFieldComponentSpec)

	log.SpanLog(ctx, log.DebugLevelApi, "create artefact request", "provArt", provArt, "specData", specData)

	// for validation
	artReq := fedewapi.UploadArtefactRequest{
		ArtefactId:             provArt.ArtefactID,
		AppProviderId:          provArt.AppProviderId,
		ArtefactName:           provArt.ArtefactName,
		ArtefactVersionInfo:    provArt.ArtefactVersion,
		ArtefactVirtType:       provArt.VirtType,
		ArtefactDescriptorType: provArt.DescType,
	}
	if err := artReq.Validate(); err != nil {
		return err
	}
	if provArt.VirtType != ArtefactVirtTypeVM && provArt.VirtType != ArtefactVirtTypeContainer {
		return fmt.Errorf("%s invalid value %s, valid values are %s and %s", ArtefactFieldVirtType, provArt.VirtType, ArtefactVirtTypeVM, ArtefactVirtTypeContainer)
	}
	if provArt.DescType != ArtefactDescTypeCompSpec {
		log.SpanLog(ctx, log.DebugLevelApi, "artefact does not support descriptor type", "type", provArt.DescType)
		return fmt.Errorf("%s does not support %s, only supports %s", ArtefactFieldDescriptorType, provArt.DescType, ArtefactDescTypeCompSpec)
	}
	if specData == "" {
		return fmt.Errorf("%s not specified", ArtefactFieldComponentSpec)
	}
	specs := []fedewapi.ComponentSpec{}
	err = json.Unmarshal([]byte(specData), &specs)
	if err != nil {
		return fmt.Errorf("failed to unmarshal component spec, %s", err)
	}
	if len(specs) == 0 {
		return fmt.Errorf("component specs cannot be empty array")
	}
	if len(specs) > 1 {
		return fmt.Errorf("only one component spec is supported, but found %d", len(specs))
	}
	spec := specs[0]
	if err := spec.Validate(); err != nil {
		return err
	}
	if len(spec.Images) == 0 {
		return fmt.Errorf("ComponentSpec missing at least 1 image")
	}

	// decide on fields used for AppKey
	provArt.AppName = provArt.ArtefactID
	provArt.AppVers = provArt.ArtefactVersion

	db := p.loggedDB(ctx)

	// build app from spec
	app := edgeproto.App{}
	app.Key = provArt.GetAppKey()
	if spec.NumOfInstances == -1 {
		app.ScaleWithCluster = true
	}
	if len(spec.Images) != 1 {
		return fmt.Errorf("only one image is supported for ComponentSpec, but it has %d", len(spec.Images))
	}
	// look up image
	log.SpanLog(ctx, log.DebugLevelApi, "lookup image", "fileID", spec.Images[0])
	provImage := ormapi.ProviderImage{
		FederationName: provider.Name,
		FileID:         spec.Images[0],
	}
	res := db.Find(&provImage).First(&provImage)
	if res.RecordNotFound() {
		return fmt.Errorf("Image ID %s in component spec not found, please ensure it has been created", spec.Images[0])
	}
	if res.Error != nil {
		return fedError(http.StatusInternalServerError, res.Error)
	}
	app.ImagePath = provImage.Path
	switch provImage.Type {
	case string(fedewapi.VIRTIMAGETYPE_DOCKER):
		app.ImageType = edgeproto.ImageType_IMAGE_TYPE_DOCKER
	case string(fedewapi.VIRTIMAGETYPE_QCOW2):
		app.ImageType = edgeproto.ImageType_IMAGE_TYPE_QCOW
	case string(fedewapi.VIRTIMAGETYPE_OVA):
		app.ImageType = edgeproto.ImageType_IMAGE_TYPE_OVA
	default:
		return fmt.Errorf("Unknown image type %s for image %s", provImage.Type, provImage.FileID)
	}
	switch provArt.VirtType {
	case ArtefactVirtTypeVM:
		if provImage.Type != string(fedewapi.VIRTIMAGETYPE_QCOW2) && provImage.Type != string(fedewapi.VIRTIMAGETYPE_OVA) {
			return fmt.Errorf("virtType is %s but image %s type is %s, which is inconsistent", provArt.VirtType, provImage.FileID, provImage.Type)
		}
		app.Deployment = cloudcommon.DeploymentTypeVM
		if provImage.Checksum == "" {
			return fmt.Errorf("Checksum missing for VM image %s", provImage.FileID)
		}
		app.ImagePath += "#md5:" + provImage.Checksum
	case ArtefactVirtTypeContainer:
		if provImage.Type != string(fedewapi.VIRTIMAGETYPE_DOCKER) {
			return fmt.Errorf("virtType is %s but image %s type is %s, which is inconsistent", provArt.VirtType, provImage.FileID, provImage.Type)
		}
		if provider.DefaultContainerDeployment == "" {
			// TODO: remove this later, this is only for
			// backwards compatability before the
			// DefaultContainerDeployment field was added.
			app.Deployment = cloudcommon.DeploymentTypeDocker
		} else {
			app.Deployment = provider.DefaultContainerDeployment
		}
	}
	if spec.DeploymentConfig != nil {
		badConfigErr := func() error {
			return fmt.Errorf("Cannot use deployment config type %s for virtType %s", spec.DeploymentConfig.ConfigType, provArt.VirtType)
		}

		switch spec.DeploymentConfig.ConfigType {
		case ConfigTypeDockerCompose:
			if provArt.VirtType != ArtefactVirtTypeContainer {
				return badConfigErr()
			}
			app.Deployment = cloudcommon.DeploymentTypeDocker
			app.DeploymentManifest = spec.DeploymentConfig.Contents
		case ConfigTypeK8sManifest:
			if provArt.VirtType != ArtefactVirtTypeContainer {
				return badConfigErr()
			}
			app.Deployment = cloudcommon.DeploymentTypeKubernetes
			app.DeploymentManifest = spec.DeploymentConfig.Contents
		case ConfigTypeCloudInit:
			if provArt.VirtType != ArtefactVirtTypeVM {
				return badConfigErr()
			}
			app.Deployment = cloudcommon.DeploymentTypeVM
			app.DeploymentManifest = spec.DeploymentConfig.Contents
		case ConfigTypeHelmValues:
			if provArt.VirtType != ArtefactVirtTypeContainer {
				return badConfigErr()
			}
			app.Deployment = cloudcommon.DeploymentTypeHelm
			app.DeploymentManifest = spec.DeploymentConfig.Contents
		}
	}
	if spec.CommandLineParams != nil && app.Deployment == cloudcommon.DeploymentTypeKubernetes {
		if len(spec.CommandLineParams.Command) > 0 {
			app.Command = strings.Join(spec.CommandLineParams.Command, " ")
		}
		app.CommandArgs = spec.CommandLineParams.CommandArgs
	}
	if spec.CommandLineParams != nil && app.Deployment == cloudcommon.DeploymentTypeDocker {
		if len(spec.CommandLineParams.Command) > 1 {
			return fmt.Errorf("Only one command supported")
		}
		if len(spec.CommandLineParams.Command) == 1 {
			app.Command = spec.CommandLineParams.Command[0]
		}
		app.CommandArgs = spec.CommandLineParams.CommandArgs
	}
	envVars := []v1.EnvVar{}
	for _, param := range spec.CompEnvParams {
		if param.EnvVarValue == nil {
			log.SpanLog(ctx, log.DebugLevelApi, "skipping env var %s with nil value", param.EnvVarName)
			continue
		}
		if param.EnvValueType != EnvVarTypeUser {
			return fmt.Errorf("env var %s has unsupported value type %s", param.EnvVarName, param.EnvValueType)
		}
		envVar := v1.EnvVar{
			Name:  param.EnvVarName,
			Value: *param.EnvVarValue,
		}
		envVars = append(envVars, envVar)
	}
	if len(envVars) > 0 {
		dat, err := yaml.Marshal(envVars)
		if err != nil {
			return fmt.Errorf("failed to marshal env vars to yaml ConfigFile for app, %s", err)
		}
		cfg := edgeproto.ConfigFile{
			Kind:   edgeproto.AppConfigEnvYaml,
			Config: string(dat),
		}
		app.Configs = append(app.Configs, &cfg)
	}
	intPorts := []string{}
	extPorts := []string{}
	for ii, port := range spec.ExposedInterfaces {
		if port.InterfaceId == "" {
			return fmt.Errorf("ExposedInterface[%d] missing InterfaceId", ii)
		}
		if port.CommProtocol == "" {
			return fmt.Errorf("ExposedInterface %s missing CommProtocol", port.InterfaceId)
		}
		if port.CommPort == 0 {
			return fmt.Errorf("ExposedInterface %s missing CommPort", port.InterfaceId)
		}
		if port.VisibilityType == "" {
			return fmt.Errorf("ExposedInterface %s missing VisibilityType", port.InterfaceId)
		}

		proto := ""
		switch port.CommProtocol {
		case CommProtoHTTP:
		case CommProtoTCP:
			proto = "tcp"
		case CommProtoUDP:
			proto = "udp"
		default:
			return fmt.Errorf("Unsupported protocol %q for exposed interface %d", port.CommProtocol, port.CommPort)
		}
		pspec := fmt.Sprintf("%s:%d", proto, port.CommPort)
		if port.VisibilityType == CommPortVisInt {
			intPorts = append(intPorts, pspec)
		} else {
			extPorts = append(extPorts, pspec)
		}
	}
	if len(extPorts) == 0 && len(intPorts) > 0 {
		app.AccessPorts = strings.Join(intPorts, ",")
		app.InternalPorts = true
	} else if len(extPorts) > 0 {
		app.AccessPorts = strings.Join(extPorts, ",")
		log.SpanLog(ctx, log.DebugLevelApi, "ignoring internal ports in mix of internal and external ports", "intPorts", intPorts)
	}
	vcpus, err := edgeproto.ParseUdec64(spec.ComputeResourceProfile.NumCPU)
	if err != nil {
		return fmt.Errorf("Failed to parse ComponentSpec ComputeResourceProfile NumCPU %s, %s", spec.ComputeResourceProfile.NumCPU, err)
	}
	// handle resource requirements
	if vcpus.IsZero() {
		return fmt.Errorf("ComponentSpec computeResourceProfile num CPU must be greater than 0")
	}
	if spec.ComputeResourceProfile.Memory < 0 {
		return fmt.Errorf("ComponentSpec computeResourceProfile memory must be greater than 0")
	}
	if spec.ComputeResourceProfile.DiskStorage != nil && *spec.ComputeResourceProfile.DiskStorage < 0 {
		return fmt.Errorf("ComponentSpec computeResourceProfile disk storage must be greater than 0")
	}
	serverlessConfig := edgeproto.ServerlessConfig{
		Vcpus: *vcpus,
		Ram:   uint64(spec.ComputeResourceProfile.Memory),
	}
	gpu := spec.ComputeResourceProfile.Gpu
	if gpu != nil && len(gpu) > 1 {
		return fmt.Errorf("Only one gpu supported for ComponentSpec Compute Resource Profile, but has %d", len(gpu))
	}
	if gpu != nil && len(gpu) == 1 {
		gpuConfig := edgeproto.GpuConfig{}
		// Spec does not indicate PCI vs VGPU, assume VGPU for now
		gpuConfig.Type = edgeproto.GpuType_GPU_TYPE_VGPU
		gpuConfig.NumGpu = gpu[0].NumGPU
	}
	app.ServerlessConfig = &serverlessConfig

	// create the provider artefact to track the association between the
	// artefact id and the app key.
	log.SpanLog(ctx, log.DebugLevelApi, "save providerArtefact", "provArt", provArt)
	err = db.Create(&provArt).Error
	if err != nil {
		return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to save artefact, %s", err.Error()))
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := db.Delete(&provArt).Error
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to undo artefact create", "providerArtefact", provArt, "err", undoErr)
		}
	}()

	createdRegions := []string{}
	defer func() {
		if reterr == nil {
			return
		}
		for _, region := range createdRegions {
			rc := ormutil.RegionContext{
				Region:    region,
				SkipAuthz: true,
				Database:  p.database,
			}
			_, undoErr := ctrlclient.DeleteAppObj(ctx, &rc, &app, p.connCache)
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "failed to undo app create for artefact", "provArt", provArt, "region", region, "err", undoErr)
			}
		}
	}()

	// create App in all regions associated with the Provider
	log.SpanLog(ctx, log.DebugLevelApi, "create region apps for artefact", "app", app)
	for _, region := range provider.Regions {
		rc := ormutil.RegionContext{
			Region:    region,
			SkipAuthz: true,
			Database:  p.database,
		}
		_, err = ctrlclient.CreateAppObj(ctx, &rc, &app, p.connCache)
		if err != nil {
			return fmt.Errorf("failed to create App for Artefact in region %s: %s", region, err)
		}
		createdRegions = append(createdRegions, region)
	}
	return nil
}

func (p *PartnerApi) RemoveArtefact(c echo.Context, fedCtxId FederationContextId, artefactId ArtefactId) error {
	ctx := ormutil.GetContext(c)
	log.SpanLog(ctx, log.DebugLevelApi, "Fed EWBI RemoveArtefact", "fedCtxId", fedCtxId, "artefactId", artefactId)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}
	return p.RemoveArtefactInternal(c, provider, string(artefactId))
}

func (p *PartnerApi) RemoveArtefactInternal(c echo.Context, provider *ormapi.FederationProvider, artefactId string) error {
	ctx := ormutil.GetContext(c)

	provArt, err := p.lookupArtefact(c, provider, string(artefactId))
	if err != nil {
		return err
	}
	db := p.loggedDB(ctx)

	// check if artefact is being used by any app
	provApp := ormapi.ProviderApp{
		FederationName: provider.Name,
	}
	provApps := []ormapi.ProviderApp{}
	err = db.Where(&provApp).Find(&provApps).Error
	if err != nil {
		return fedError(http.StatusInternalServerError, fmt.Errorf("Failed looking up Apps that may depend on Artefact, %s", err.Error()))
	}
	for _, papp := range provApps {
		for _, af := range papp.ArtefactIds {
			if af == string(artefactId) {
				return fmt.Errorf("cannot delete Artefact %s which is referenced by App %s", af, papp.AppID)
			}
		}
	}

	app := edgeproto.App{}
	app.Key = provArt.GetAppKey()

	// make sure App can be deleted from each region
	log.SpanLog(ctx, log.DebugLevelApi, "delete apps for artefact", "app", provApp)
	for _, region := range provider.Regions {
		rc := ormutil.RegionContext{
			Region:    region,
			SkipAuthz: true,
			Database:  p.database,
		}
		_, err = ctrlclient.DeleteAppObj(ctx, &rc, &app, p.connCache)
		if err != nil && strings.Contains(err.Error(), app.Key.NotFoundError().Error()) {
			// ok if not found
			err = nil
		}
		if err != nil {
			return fmt.Errorf("failed to delete App for Artefact in region %s: %s", region, err)
		}
	}

	// delete artefact
	err = db.Delete(&provArt).Error
	if err != nil {
		return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to delete artefact from database, %s", err.Error()))
	}
	return nil
}

func (p *PartnerApi) GetArtefact(c echo.Context, fedCtxId FederationContextId, artefactId ArtefactId) error {
	ctx := ormutil.GetContext(c)
	log.SpanLog(ctx, log.DebugLevelApi, "Fed EWBI GetArtefact", "fedCtxId", fedCtxId, "artefactId", artefactId)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}
	provArt, err := p.lookupArtefact(c, provider, string(artefactId))
	if err != nil {
		return err
	}

	// look up app
	rc := ormutil.RegionContext{
		Region:    provider.Regions[0],
		SkipAuthz: true,
		Database:  p.loggedDB(ctx),
	}
	appKey := provArt.GetAppKey()
	app, flavor, err := LookupRegionApp(ctx, &rc, p.connCache, &appKey)
	if err != nil {
		return fedError(http.StatusInternalServerError, err)
	}
	imageIds, err := p.getProviderImageIdsForApp(ctx, provider.Name, app)
	if err != nil {
		return fedError(http.StatusInternalServerError, err)
	}
	spec, err := p.GenerateComponentSpec(ctx, app, imageIds, flavor)
	if err != nil {
		return fedError(http.StatusInternalServerError, err)
	}

	resp := fedewapi.GetArtefact200Response{}
	resp.ArtefactId = provArt.ArtefactID
	resp.AppProviderId = provArt.AppProviderId
	resp.ArtefactName = provArt.ArtefactName
	resp.ArtefactVersionInfo = provArt.ArtefactVersion
	resp.ArtefactVirtType = provArt.VirtType
	resp.ArtefactDescriptorType = provArt.DescType
	resp.ComponentSpec = append(resp.ComponentSpec, *spec)
	return c.JSON(http.StatusOK, resp)
}

func LookupRegionApp(ctx context.Context, rc *ormutil.RegionContext, connCache ctrlclient.ClientConnMgr, appKey *edgeproto.AppKey) (*edgeproto.App, *edgeproto.Flavor, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "lookup region app", "appkey", *appKey)
	lookup := edgeproto.App{
		Key: *appKey,
	}
	var app *edgeproto.App
	err := ctrlclient.ShowAppStream(ctx, rc, &lookup, connCache, nil, func(retApp *edgeproto.App) error {
		app = retApp
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("Failure looking up App: %s", err)
	}
	if app == nil {
		return nil, nil, fmt.Errorf("App not found")
	}

	if app.DefaultFlavor.Name == "" && app.ServerlessConfig == nil {
		return nil, nil, fmt.Errorf("App has no default flavor and no serverless config to specify compute resources")
	}

	var flavor *edgeproto.Flavor
	if app.DefaultFlavor.Name != "" {
		log.SpanLog(ctx, log.DebugLevelApi, "create ConsumerApp, look up flavors")
		flavorLookup := edgeproto.Flavor{
			Key: app.DefaultFlavor,
		}
		err = ctrlclient.ShowFlavorStream(ctx, rc, &flavorLookup, connCache, func(retFlavor *edgeproto.Flavor) error {
			flavor = retFlavor
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("Failure looking up Flavor %s: %s", app.DefaultFlavor.Name, err)
		}
		if flavor == nil {
			return nil, nil, fmt.Errorf("App DefaultFlavor %s not found", app.DefaultFlavor.Name)
		}
	}
	return app, flavor, nil
}

func (p *PartnerApi) getProviderImageIdsForApp(ctx context.Context, fedName string, app *edgeproto.App) ([]string, error) {
	if app.ImagePath != "" {
		image := ormapi.ProviderImage{
			FederationName: fedName,
			Path:           app.ImagePath,
		}
		// lookup image
		db := p.loggedDB(ctx)
		images := []ormapi.ProviderImage{}
		res := db.Where(&image).Find(&images)
		if res.RecordNotFound() {
			return []string{}, nil
		}
		if res.Error != nil {
			return []string{}, res.Error
		}
		imageIds := []string{}
		for _, img := range images {
			imageIds = append(imageIds, img.FileID)
		}
		return imageIds, nil
	}
	return []string{}, nil
}

func (p *PartnerApi) GenerateComponentSpec(ctx context.Context, app *edgeproto.App, imageIds []string, defaultFlavor *edgeproto.Flavor) (*fedewapi.ComponentSpec, error) {
	// Create ComponentSpec
	spec := fedewapi.ComponentSpec{}
	spec.ComponentName = app.Key.Name
	spec.Images = imageIds
	if app.ScaleWithCluster {
		spec.NumOfInstances = -1
	} else {
		spec.NumOfInstances = 1
	}
	spec.RestartPolicy = RestartPolicyAlways
	commandLineParams := fedewapi.CommandLineParams{}
	envVars := []v1.EnvVar{}
	if app.Command != "" {
		commandLineParams.Command = []string{app.Command}
	}
	commandLineParams.CommandArgs = app.CommandArgs

	for _, cfg := range app.Configs {
		switch cfg.Kind {
		case edgeproto.AppConfigHelmYaml:
			// TODO: spec doesn't have any place for this yet
		case edgeproto.AppConfigEnvYaml:
			err := yaml.Unmarshal([]byte(cfg.Config), &envVars)
			if err != nil {
				return nil, fmt.Errorf("Failed to unmarshal ConfigFile for env vars: %s", err)
			}
		}
	}
	if len(commandLineParams.Command) > 0 || len(commandLineParams.CommandArgs) > 0 {
		spec.CommandLineParams = &commandLineParams
	}
	for _, envVar := range envVars {
		env := fedewapi.CompEnvParams{
			EnvVarName:   envVar.Name,
			EnvVarValue:  &envVar.Value,
			EnvValueType: EnvVarTypeUser,
		}
		spec.CompEnvParams = append(spec.CompEnvParams, env)
	}

	ports, err := edgeproto.ParseAppPorts(app.AccessPorts)
	if err != nil {
		return nil, err
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
			intf.InterfaceId = p.GetInterfaceId(port, portVal)
			if port.Proto == dmeproto.LProto_L_PROTO_UDP {
				intf.CommProtocol = CommProtoUDP
			} else {
				intf.CommProtocol = CommProtoTCP
			}
			intf.CommPort = portVal
			if app.InternalPorts {
				intf.VisibilityType = CommPortVisInt
			} else {
				intf.VisibilityType = CommPortVisExt
			}
			interfaces = append(interfaces, intf)
		}
	}
	if len(interfaces) > 0 {
		spec.ExposedInterfaces = interfaces
	}

	resources := fedewapi.ComputeResourceInfo{
		CpuArchType: CPUArchTypeX8664,
	}
	if defaultFlavor == nil && app.ServerlessConfig == nil {
		return nil, fmt.Errorf("Cannot specify compute resource info, one of default flavor or serverless config must be set")
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
	return &spec, nil
}
