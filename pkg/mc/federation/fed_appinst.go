package federation

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func (p *PartnerApi) InstallApp(c echo.Context, fedCtxId FederationContextId) (reterr error) {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	in := fedewapi.InstallAppRequest{}
	if err := c.Bind(&in); err != nil {
		return err
	}

	// lookup zone base so we can figure out region
	base, err := p.lookupProviderZoneBase(ctx, in.ZoneInfo.ZoneId, provider.OperatorId)
	if err != nil {
		return err
	}
	if len(base.Cloudlets) != 1 {
		return fmt.Errorf("Provider base zone must only have 1 cloudlet but has %v", base.Cloudlets)
	}

	// lookup zone to make sure zone is shared
	zone, err := p.LookupProviderZone(ctx, provider.Name, in.ZoneInfo.ZoneId)
	if err != nil {
		return err
	}
	if zone.Status != StatusRegistered {
		return fmt.Errorf("Specified zone is not registered")
	}

	// lookup app
	provApp, err := p.lookupApp(c, provider, in.AppId)
	if err != nil {
		return err
	}
	if len(provApp.ArtefactIds) != 1 {
		return fmt.Errorf("Invalid App configuration, must only have one Artefact but has %v", provApp.ArtefactIds)
	}

	// lookup artefact
	provArt, err := p.lookupArtefact(c, provider, provApp.ArtefactIds[0])
	if err != nil {
		return err
	}

	// generate unique id for appInst
	provAppInst := ormapi.ProviderAppInst{
		FederationName: provider.Name,
		AppInstID:      uuid.New().String(),
	}
	db := p.loggedDB(ctx)
	err = db.Create(&provAppInst).Error
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to create new provider AppInst, "+err.Error())
	}

	callbackUrl := ""
	if in.AppInstCallbackLink != "" {
		notifyTmpl := ormutil.NewUriTemplate(in.AppInstCallbackLink + PartnerLcmNotifyPath)
		vars := map[string]string{
			PathVarFederationContextId: provider.FederationContextId,
			PathVarAppId:               in.AppId,
			PathVarAppInstId:           provAppInst.AppInstID,
			PathVarZoneId:              in.ZoneInfo.ZoneId,
		}
		callbackUrl = notifyTmpl.Eval(vars)
	}

	// Run the actual create after sending the response
	worker := AppInstWorker{
		parentCtx:   ctx,
		partner:     p,
		provider:    provider,
		base:        base,
		provArt:     provArt,
		provApp:     provApp,
		provAppInst: &provAppInst,
		callbackUrl: callbackUrl,
	}
	c.Response().After(func() {
		go worker.createAppInstJob()
	})

	// appInst.UniqueId is only unique within the region, so append region name
	resp := fedewapi.InstallApp202Response{
		ZoneId:            in.ZoneInfo.ZoneId,
		AppInstIdentifier: provAppInst.AppInstID,
	}
	return c.JSON(http.StatusAccepted, &resp)
}

type AppInstWorker struct {
	parentCtx   context.Context
	partner     *PartnerApi
	req         *fedewapi.InstallAppRequest // only for create
	provider    *ormapi.FederationProvider
	base        *ormapi.ProviderZoneBase
	provArt     *ormapi.ProviderArtefact
	provApp     *ormapi.ProviderApp
	provAppInst *ormapi.ProviderAppInst
	callbackUrl string // only for create
}

func (s *AppInstWorker) createAppInstJob() {
	span, ctx := log.ChildSpan(s.parentCtx, log.DebugLevelApi, "create provider AppInst job")
	defer span.Finish()
	err := s.createAppInst(ctx)
	if err != nil {
		s.sendCallback(ctx, "FAILED", nil)
		log.SpanLog(ctx, log.DebugLevelApi, "create provider AppInst failed", "appInst", s.provAppInst, "err", err)
	}
}

func (s *AppInstWorker) createAppInst(ctx context.Context) (reterr error) {
	log.SpanLog(ctx, log.DebugLevelApi, "creating AppInst", "provAppInst", s.provAppInst)
	defer func() {
		if reterr == nil {
			return
		}
		db := s.partner.loggedDB(ctx)
		undoErr := db.Delete(s.provAppInst).Error
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to undo providerAppInst create", "providerAppInst", s.provAppInst, "err", undoErr)
		}
	}()

	// Create AppInst
	rc := ormutil.RegionContext{
		Region:    s.base.Region,
		SkipAuthz: true,
		Database:  s.partner.database,
	}

	appInstIn := edgeproto.AppInst{
		Key: getAppInstKey(s.provider, s.provArt, s.provApp.AppID, s.base.Cloudlets[0]),
		//CloudletFlavor: s.req.ZoneInfo.FlavorId,
	}
	log.SpanLog(ctx, log.DebugLevelApi, "Federation create appinst", "appInst", appInstIn)
	cb := func(res *edgeproto.Result) error {
		return nil
	}
	err := ctrlclient.CreateAppInstStream(ctx, &rc, &appInstIn, s.partner.connCache, cb)
	if err != nil {
		return err
	}
	s.sendCallback(ctx, "READY", nil)
	return nil
}

func (s *AppInstWorker) sendCallback(ctx context.Context, state string, accesspointInfo []fedewapi.FederationContextIdApplicationLcmPostRequestAppInstanceInfoAccesspointInfoInner) {
	now := time.Now()
	req := fedewapi.FederationContextIdApplicationLcmPostRequest{
		AppInstanceInfo: fedewapi.FederationContextIdApplicationLcmPostRequestAppInstanceInfo{
			AppInstanceState: &state,
			AccesspointInfo:  accesspointInfo,
		},
		ModificationDate: &now,
	}

	log.SpanLog(ctx, log.DebugLevelApi, "appInst lcm create callback", "req", req, "path", s.callbackUrl)
	fedClient, err := s.partner.ProviderPartnerClient(ctx, s.provider, s.callbackUrl)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "appInstWorker sendCallback get fedClient failed", "err", err)
	}
	_, _, err = fedClient.SendRequest(ctx, "POST", "", &req, nil, nil)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "appInstWorker sendCallback failed", "err", err)
	}
}

func (p *PartnerApi) RemoveApp(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier, appInstId InstanceIdentifier, zoneId ZoneIdentifier) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}
	// lookup base to find region
	base, err := p.lookupProviderZoneBase(ctx, string(zoneId), provider.OperatorId)
	if err != nil {
		return err
	}
	if len(base.Cloudlets) != 1 {
		return fmt.Errorf("Provider base zone must only have 1 cloudlet but has %v", base.Cloudlets)
	}

	// lookup app
	provApp, err := p.lookupApp(c, provider, string(appId))
	if err != nil {
		return err
	}
	if len(provApp.ArtefactIds) != 1 {
		return fmt.Errorf("Invalid App configuration, must only have one Artefact but has %v", provApp.ArtefactIds)
	}

	// lookup artefact
	provArt, err := p.lookupArtefact(c, provider, provApp.ArtefactIds[0])
	if err != nil {
		return err
	}

	appInst := edgeproto.AppInst{
		Key: getAppInstKey(provider, provArt, string(appId), string(zoneId)),
	}
	rc := ormutil.RegionContext{
		Region:    base.Region,
		SkipAuthz: true,
		Database:  p.database,
	}

	log.SpanLog(ctx, log.DebugLevelApi, "Federation delete appinst", "appInst", appInst.Key)
	err = ctrlclient.DeleteAppInstStream(ctx, &rc, &appInst, p.connCache,
		func(res *edgeproto.Result) error {
			return nil
		},
	)
	if err != nil {
		return err
	}
	return nil
}

func getAppInstKey(provider *ormapi.FederationProvider, provArt *ormapi.ProviderArtefact, appId string, cloudletName string) edgeproto.AppInstKey {
	return edgeproto.AppInstKey{
		AppKey: getAppKey(provArt),
		ClusterInstKey: edgeproto.VirtualClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: cloudcommon.AutoClusterPrefix + appId,
			},
			CloudletKey: edgeproto.CloudletKey{
				Name:         cloudletName,
				Organization: provider.OperatorId,
			},
			Organization: provider.Name,
		},
	}
}

func getAppInstId(ai *edgeproto.AppInst, region string) string {
	return ai.UniqueId + "-" + region
}

func (p *PartnerApi) GetAllAppInstances(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier, appProviderId AppProviderId) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) GetAppInstanceDetails(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier, appInstId InstanceIdentifier, zoneId ZoneIdentifier) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) PartnerLcmNotify(c echo.Context) error {
	return nil
}
