package federation

import (
	"fmt"
	"net/http"
	"strings"

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/labstack/echo/v4"
)

const (
	AppQosLatencyNone     = "NONE"
	AppQosLatencyLow      = "LOW"
	AppQosLatencyUltraLow = "ULTRALOW"

	AppStatusPending    = "PENDING"
	AppStatusOnboarded  = "ONBOARDED"
	AppStatusDeboarding = "DEBOARDING"
	AppStatusRemoved    = "REMOVED"
	AppStatusFailed     = "FAILED"
)

func (p *PartnerApi) lookupApp(c echo.Context, provider *ormapi.FederationProvider, appId string) (*ormapi.ProviderApp, error) {
	ctx := ormutil.GetContext(c)
	db := p.loggedDB(ctx)

	provApp := ormapi.ProviderApp{
		FederationName: provider.Name,
		AppID:          appId,
	}
	res := db.Where(&provApp).First(&provApp)
	if res.RecordNotFound() {
		return nil, fedError(http.StatusNotFound, fmt.Errorf("Application %s not found", appId))
	}
	if res.Error != nil {
		return nil, fedError(http.StatusInternalServerError, fmt.Errorf("Failed to look up application, %s", res.Error.Error()))
	}
	return &provApp, nil
}

func (p *PartnerApi) lookupConsumerApp(c echo.Context, consumer *ormapi.FederationConsumer, appId string) (*ormapi.ConsumerApp, error) {
	ctx := ormutil.GetContext(c)
	db := p.loggedDB(ctx)

	consApp := ormapi.ConsumerApp{
		ID:             appId,
		FederationName: consumer.Name,
	}
	res := db.Where(&consApp).First(&consApp)
	if res.RecordNotFound() {
		return nil, fmt.Errorf("Consumer Application " + appId + " not found")
	}
	if res.Error != nil {
		return nil, fmt.Errorf("Failed to look up application, %s", res.Error)
	}
	return &consApp, nil
}

// Remote partner federator sends this request to us to onboard an application
func (p *PartnerApi) OnboardApplication(c echo.Context, fedCtxId FederationContextId) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	req := fedewapi.OnboardApplicationRequest{}
	if err := c.Bind(&req); err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelApi, "Federation app onboarding", "fedName", provider.Name, "request", req)
	if req.AppId == "" {
		return fmt.Errorf("Missing application ID")
	}
	if req.AppProviderId == "" {
		return fmt.Errorf("Missing app provider ID")
	}
	if req.AppMetaData.AppName == "" {
		return fmt.Errorf("Missing app name")
	}
	if req.AppMetaData.Version == "" {
		return fmt.Errorf("Missing app version")
	}
	if req.AppMetaData.AccessToken == "" {
		return fmt.Errorf("Missing access token")
	}
	if len(req.AppComponentSpecs) == 0 {
		return fmt.Errorf("Missing app component details")
	}
	if err := p.validateCallbackLink(req.AppStatusCallbackLink); err != nil {
		return err
	}

	if len(req.AppComponentSpecs) > 1 {
		return fmt.Errorf("Only one component detail is supported, but %d are specified", len(req.AppComponentSpecs))
	}

	provArt := ormapi.ProviderArtefact{
		FederationName: provider.Name,
	}
	for _, spec := range req.AppComponentSpecs {
		if spec.ArtefactId == "" {
			return fmt.Errorf("AppComponentSpec missing Artefact ID")
		}
		provArt.ArtefactID = spec.ArtefactId
	}

	// look up artefact
	db := p.loggedDB(ctx)
	res := db.Where(&provArt).First(&provArt)
	if res.RecordNotFound() {
		return fmt.Errorf("Artefact %s not found", provArt.ArtefactID)
	}
	if err != nil {
		return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to look up Artefact, %s", err.Error()))
	}

	// TODO: handle onboarding. We do not have any way to explictly
	// onboard a zone beforehand. And managing where images are
	// onboarded can be difficult in the case of kubernetes, as it
	// has it's own mechanisms for cleaing up images.
	// check any specified zones
	zones := []string{}
	for _, depZone := range req.AppDeploymentZones {
		provZone := ormapi.ProviderZone{
			ProviderName: provider.Name,
			ZoneId:       depZone,
		}
		// look up zone
		res := db.Where(&provZone).First(&provZone)
		if res.RecordNotFound() {
			return fmt.Errorf("Deployment zone %s not found", provZone.ZoneId)
		}
		if err != nil {
			return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to look up deployment zone %s, %s", provZone.ZoneId, err.Error()))
		}
		if provZone.Status == StatusUnregistered {
			return fmt.Errorf("Deployment zone %s is not registered", provZone.ZoneId)
		}
		zones = append(zones, provZone.ZoneId)
	}

	// create provider App
	provApp := ormapi.ProviderApp{
		FederationName:        provider.Name,
		AppID:                 req.AppId,
		AppProviderId:         req.AppProviderId,
		AppName:               req.AppMetaData.AppName,
		AppVers:               req.AppMetaData.Version,
		ArtefactIds:           []string{provArt.ArtefactID},
		DeploymentZones:       zones,
		AppStatusCallbackLink: req.AppStatusCallbackLink,
	}
	err = db.Create(&provApp).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value") {
			return fmt.Errorf("Application with ID %s already exists", provApp.AppID)
		}
		return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to save app to database, %s", err.Error()))
	}

	// TODO: write req.AppMetaData.AccessToken to app.PublicKey or similar

	c.Response().WriteHeader(http.StatusAccepted)
	c.Response().After(func() {
		if req.AppStatusCallbackLink == "" {
			log.SpanLog(ctx, log.DebugLevelApi, "app create no callback", "app", provApp)
			return
		}
		cb := fedewapi.FederationContextIdApplicationOnboardingPostRequest{
			FederationContextId: provider.FederationContextId,
			AppId:               req.AppId,
		}
		for _, zone := range zones {
			status := fedewapi.FederationContextIdApplicationOnboardingPostRequestStatusInfoInner{
				ZoneId:            zone,
				OnboardStatusInfo: "ONBOARDED",
			}
			cb.StatusInfo = append(cb.StatusInfo, status)
		}
		fedClient, err := p.ProviderPartnerClient(ctx, provider, req.AppStatusCallbackLink)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to send app create callback", "url", req.AppStatusCallbackLink, "err", err)
			return
		}
		_, _, err = fedClient.SendRequest(ctx, "POST", "", &cb, nil, nil)
		log.SpanLog(ctx, log.DebugLevelApi, "sent app create callback", "url", req.AppStatusCallbackLink, "err", err)
	})
	return nil
}

func (p *PartnerApi) DeleteApp(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier) error {
	// lookup federation provider based on claims
	ctx := ormutil.GetContext(c)
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}
	provApp, err := p.lookupApp(c, provider, string(appId))
	if err != nil {
		return err
	}

	// TODO: check if there are any appinsts for App

	// Note that edgeproto.App object is tied to the ProviderArtefact,
	// so the only action here is to delete the ProviderApp.
	db := p.loggedDB(ctx)
	err = db.Delete(provApp).Error
	if err != nil {
		return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to delete App, %s", err.Error()))
	}
	return nil
}

// ViewApplication gets onboarded app
func (p *PartnerApi) ViewApplication(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier) error {
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}
	provApp, err := p.lookupApp(c, provider, string(appId))
	if err != nil {
		return err
	}

	app := fedewapi.ViewApplication200Response{
		AppId:         provApp.AppID,
		AppProviderId: provApp.AppProviderId,
		AppMetaData: fedewapi.AppMetaData{
			AppName: provApp.AppName,
			Version: provApp.AppVers,
		},
		AppQoSProfile: fedewapi.AppQoSProfile{
			LatencyConstraints: AppQosLatencyNone,
		},
	}
	specs := []fedewapi.AppComponentSpecsInner{}
	for _, artid := range provApp.ArtefactIds {
		spec := fedewapi.AppComponentSpecsInner{
			ArtefactId: artid,
		}
		specs = append(specs, spec)
	}
	app.AppComponentSpecs = specs
	zones := []fedewapi.ViewApplication200ResponseAppDeploymentZonesInner{}
	for _, zone := range provApp.DeploymentZones {
		dz := fedewapi.ViewApplication200ResponseAppDeploymentZonesInner{
			ZoneInfo: zone,
		}
		zones = append(zones, dz)
	}
	app.AppDeploymentZones = zones
	return c.JSON(http.StatusOK, app)
}

// Remote partner federator sends this request to us to deboard application
func (p *PartnerApi) DeboardApplication(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier, zoneId ZoneIdentifier) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}
	provApp, err := p.lookupApp(c, provider, string(appId))
	if err != nil {
		return err
	}
	found := false
	for ii, zone := range provApp.DeploymentZones {
		if zone == string(zoneId) {
			provApp.DeploymentZones = append(provApp.DeploymentZones[:ii], provApp.DeploymentZones[ii+1:]...)
			found = true
			break
		}
	}
	if !found {
		return fedError(http.StatusNotFound, fmt.Errorf("Zone %s not found", string(zoneId)))
	}
	db := p.loggedDB(ctx)
	err = db.Save(&provApp).Error
	if err != nil {
		return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to save App, %s", err.Error()))
	}

	c.Response().WriteHeader(http.StatusAccepted)
	return nil
}

func (p *PartnerApi) UpdateApplication(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) OnboardExistingAppNewZones(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}
	provApp, err := p.lookupApp(c, provider, string(appId))
	if err != nil {
		return err
	}
	in := []string{}
	if err := c.Bind(&in); err != nil {
		return err
	}
	if len(in) == 0 {
		return fmt.Errorf("No zones specified")
	}

	// ignore dups
	existing := map[string]struct{}{}
	nonDups := []string{}
	for _, zone := range provApp.DeploymentZones {
		existing[zone] = struct{}{}
	}
	for _, zone := range in {
		if _, ok := existing[zone]; ok {
			continue
		}
		nonDups = append(nonDups, zone)
	}
	if len(nonDups) == 0 {
		return fmt.Errorf("No new zones added")
	}

	// add new zones and save
	provApp.DeploymentZones = append(provApp.DeploymentZones, nonDups...)
	db := p.loggedDB(ctx)
	err = db.Save(&provApp).Error
	if err != nil {
		return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to save App, %s", err.Error()))
	}

	c.Response().WriteHeader(http.StatusAccepted)
	return nil
}

func (p *PartnerApi) LockUnlockApplicationZone(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier) error {
	return fmt.Errorf("not supported")
}

func (p *PartnerApi) PartnerAppOnboardStatusEvent(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	in := fedewapi.FederationContextIdApplicationOnboardingPostRequest{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	// lookup federation consumer based on claims
	consumer, err := p.lookupConsumer(c, in.FederationContextId)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "partner app onboard status event", "consumer", consumer.Name, "operatorid", consumer.OperatorId, "request", in)
	// Notification about app onboarding status
	// This notifies state per zone, but we don't explicitly onboard per zone.
	// Since we'll never specify zones to onboard, we should never get
	// this callback.
	c.Response().WriteHeader(http.StatusNoContent)
	return nil
}

func (p *PartnerApi) GetInterfaceId(port dme.AppPort, portVal int32) string {
	return fmt.Sprintf("%d", portVal)
}
