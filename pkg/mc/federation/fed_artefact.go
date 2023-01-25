package federation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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
	provArt.AppName = req.PostFormValue(ArtefactFieldName)
	provArt.AppProviderId = req.PostFormValue(ArtefactFieldAppProviderId)
	provArt.AppVers = req.PostFormValue(ArtefactFieldVersionInfo)
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

	if provArt.ArtefactID == "" {
		return fmt.Errorf("%s not specified", ArtefactFieldId)
	}
	if provArt.AppName == "" {
		return fmt.Errorf("%s not specified", ArtefactFieldName)
	}
	if provArt.AppProviderId == "" {
		return fmt.Errorf("%s not specified", ArtefactFieldAppProviderId)
	}
	if provArt.AppVers == "" {
		return fmt.Errorf("%s not specified", ArtefactFieldVersionInfo)
	}
	if provArt.VirtType == "" {
		return fmt.Errorf("%s not specified", ArtefactFieldVirtType)
	}
	if provArt.VirtType != ArtefactVirtTypeVM && provArt.VirtType != ArtefactVirtTypeContainer {
		return fmt.Errorf("%s invalid value %s, valid values are %s and %s", ArtefactFieldVirtType, provArt.VirtType, ArtefactVirtTypeVM, ArtefactVirtTypeContainer)
	}
	if provArt.DescType == "" {
		return fmt.Errorf("%s not specified", ArtefactFieldDescriptorType)
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
	// check spec fields are set
	if spec.ComponentName == "" {
		return fmt.Errorf("ComponentSpec component name missing")
	}
	if len(spec.Images) == 0 {
		return fmt.Errorf("ComponentSpec missing at least 1 image")
	}
	if spec.RestartPolicy == "" {
		return fmt.Errorf("ComponentSpec restart policy missing")
	}

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
		// TODO: need a way to distinguish docker from k8s
		app.Deployment = cloudcommon.DeploymentTypeKubernetes
	}
	if spec.CommandLineParams != nil {
		if len(spec.CommandLineParams.Command) > 0 {
			app.Command = strings.Join(spec.CommandLineParams.Command, " ")
		}
		if len(spec.CommandLineParams.CommandArgs) > 0 {
			dat, err := yaml.Marshal(spec.CommandLineParams.CommandArgs)
			if err != nil {
				return fmt.Errorf("failed to marshal command line args %v to yaml ConfigFile for app, %s", spec.CommandLineParams.CommandArgs, err)
			}
			cfg := edgeproto.ConfigFile{
				Kind:   edgeproto.AppConfigPodArgs,
				Config: string(dat),
			}
			app.Configs = append(app.Configs, &cfg)
		}
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
	// handle resource requirements
	if spec.ComputeResourceProfile.NumCPU < 0 {
		return fmt.Errorf("ComponentSpec computeResourceProfile num CPU must be greater than 0")
	}
	if spec.ComputeResourceProfile.Memory < 0 {
		return fmt.Errorf("ComponentSpec computeResourceProfile memory must be greater than 0")
	}
	if spec.ComputeResourceProfile.DiskStorage < 0 {
		return fmt.Errorf("ComponentSpec computeResourceProfile disk storage must be greater than 0")
	}
	serverlessConfig := edgeproto.ServerlessConfig{
		Vcpus: *edgeproto.NewUdec64(uint64(spec.ComputeResourceProfile.NumCPU), 0),
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
	log.SpanLog(ctx, log.DebugLevelApi, "Fed EWBI RemoveArtefact", "fedCtxId", fedCtxId, "artefactId", artefactId)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}
	provArt, err := p.lookupArtefact(c, provider, string(artefactId))
	if err != nil {
		return err
	}

	resp := fedewapi.GetArtefact200Response{}
	resp.ArtefactId = provArt.ArtefactID
	resp.AppProviderId = provArt.AppProviderId
	resp.ArtefactName = provArt.AppName
	resp.ArtefactVersionInfo = provArt.AppVers
	resp.ArtefactVirtType = provArt.VirtType
	resp.ArtefactDescriptorType = provArt.DescType
	return c.JSON(http.StatusOK, resp)
}
