package federation

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	dmeproto "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	gonanoid "github.com/matoous/go-nanoid/v2"
)

const clusterSuffixAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func (p *PartnerApi) lookupAppInst(c echo.Context, provider *ormapi.FederationProvider, appInstanceId string) (*ormapi.ProviderAppInst, error) {
	ctx := ormutil.GetContext(c)
	db := p.loggedDB(ctx)

	provAppInst := ormapi.ProviderAppInst{
		FederationName: provider.Name,
		AppInstID:      appInstanceId,
	}
	res := db.Where(&provAppInst).First(&provAppInst)
	if res.RecordNotFound() {
		return nil, fedError(http.StatusNotFound, fmt.Errorf("Application %s not found", appInstanceId))
	}
	if res.Error != nil {
		return nil, fedError(http.StatusInternalServerError, fmt.Errorf("Failed to look up application, %s", res.Error.Error()))
	}
	return &provAppInst, nil

}

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
	if in.AppId == "" {
		return fmt.Errorf("Missing application ID")
	}
	if in.AppVersion == "" {
		return fmt.Errorf("Missing app version")
	}
	if in.AppProviderId == "" {
		return fmt.Errorf("Missing app provider ID")
	}
	if in.ZoneInfo.ZoneId == "" {
		return fmt.Errorf("Missing zone id")
	}
	if err := p.validateCallbackLink(in.AppInstCallbackLink); err != nil {
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

	// Set AppInst key. Make sure to set all fields to defaults
	// so that CreateAppInst function doesn't need to change the key.
	var clusterName, clusterOrg string
	if provArt.VirtType == ArtefactVirtTypeVM {
		clusterName = cloudcommon.DefaultClust
		clusterOrg = provider.Name
	} else {
		// Generate random suffixes to append to autocluster names.
		// This just needs to be random enough to avoid collisions within
		// a cloudlet for that organization.
		// See https://zelark.github.io/nano-id-cc/
		suffix := gonanoid.MustGenerate(clusterSuffixAlphabet, 12)
		if os.Getenv("E2ETEST_FED") != "" {
			// allow for deterministic test output
			suffix = "abcdefABCDEF"
		}
		clusterName = cloudcommon.AutoClusterPrefix + suffix
		clusterOrg = edgeproto.OrganizationEdgeCloud
	}

	// generate unique id for appInst
	// we'll update the AppInstKey once the AppInst is created,
	// in case it updates some of the optional fields.
	provAppInst := ormapi.ProviderAppInst{
		FederationName:      provider.Name,
		AppInstID:           uuid.New().String(),
		AppInstCallbackLink: in.AppInstCallbackLink,
		Region:              base.Region,
		AppName:             provArt.AppName,
		AppVers:             provArt.AppVers,
		Cluster:             clusterName,
		ClusterOrg:          clusterOrg,
		Cloudlet:            base.Cloudlets[0],
		CloudletOrg:         provider.OperatorId,
	}
	db := p.loggedDB(ctx)
	err = db.Create(&provAppInst).Error
	if err != nil {
		return fedError(http.StatusInternalServerError, fmt.Errorf("Failed to create new provider AppInst, %s", err.Error()))
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
		callbackUrl: in.AppInstCallbackLink,
		flavor:      in.ZoneInfo.FlavourId,
	}
	c.Response().After(func() {
		go worker.createAppInstJob()
	})

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
	flavor      string
}

func (s *AppInstWorker) createAppInstJob() {
	span, ctx := log.ChildSpan(s.parentCtx, log.DebugLevelApi, "create provider AppInst job")
	defer span.Finish()
	err := s.createAppInst(ctx)
	if err != nil {
		s.sendCallback(ctx, "FAILED", err.Error(), nil)
		log.SpanLog(ctx, log.DebugLevelApi, "create provider AppInst failed", "appInst", s.provAppInst, "err", err)
	}
}

func (s *AppInstWorker) createAppInst(ctx context.Context) (reterr error) {
	log.SpanLog(ctx, log.DebugLevelApi, "federation provider creating AppInst", "provAppInst", s.provAppInst)
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
		Key: s.provAppInst.GetAppInstKey(),
	}
	if s.flavor != "NOT_SPECIFIED" {
		appInstIn.Flavor.Name = s.flavor
	}

	log.SpanLog(ctx, log.DebugLevelApi, "Federation provider create appinst", "appInst", appInstIn)
	cb := func(res *edgeproto.Result) error {
		log.SpanLog(ctx, log.DebugLevelApi, "controller create appinst callback", "res", *res)
		s.sendCallback(ctx, federationmgmt.AppInstStatePending, res.Message, nil)
		return nil
	}
	err := ctrlclient.CreateAppInstStream(ctx, &rc, &appInstIn, s.partner.connCache, cb)
	if err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelApi, "Federation provider check appinst ports", "appInst", appInstIn)
	filter := edgeproto.AppInst{
		Key: appInstIn.Key,
	}
	var appInstOut *edgeproto.AppInst
	err = ctrlclient.ShowAppInstStream(ctx, &rc, &filter, s.partner.connCache, nil, func(ai *edgeproto.AppInst) error {
		appInstOut = ai
		return nil
	})
	if appInstOut == nil {
		return fmt.Errorf("Unable to find created AppInst %s", filter.Key.GetKeyString())
	}
	accessPoints := []fedewapi.FederationContextIdApplicationLcmPostRequestAppInstanceInfoAccesspointInfoInner{}
	for _, port := range appInstOut.MappedPorts {
		portStart := port.InternalPort
		portEnd := port.EndPort
		if portEnd == 0 {
			portEnd = portStart
		}
		for portVal := portStart; portVal <= portEnd; portVal++ {
			ap := fedewapi.FederationContextIdApplicationLcmPostRequestAppInstanceInfoAccesspointInfoInner{}
			ap.InterfaceId = s.partner.GetInterfaceId(port, portVal)
			fqdn := appInstOut.Uri + port.FqdnPrefix
			ap.AccessPoints.Port = portVal
			ap.AccessPoints.Fqdn = &fqdn
			accessPoints = append(accessPoints, ap)
		}
	}
	s.sendCallback(ctx, federationmgmt.AppInstStateReady, "", accessPoints)
	return nil
}

func (s *AppInstWorker) sendCallback(ctx context.Context, state, message string, accesspointInfo []fedewapi.FederationContextIdApplicationLcmPostRequestAppInstanceInfoAccesspointInfoInner) {
	now := time.Now()
	req := fedewapi.FederationContextIdApplicationLcmPostRequest{
		FederationContextId: s.provider.FederationContextId,
		AppId:               s.provApp.AppID,
		AppInstanceId:       s.provAppInst.AppInstID,
		ZoneId:              s.base.ZoneId,
		AppInstanceInfo: fedewapi.FederationContextIdApplicationLcmPostRequestAppInstanceInfo{
			AppInstanceState: &state,
			AccesspointInfo:  accesspointInfo,
		},
		ModificationDate: &now,
	}
	if message != "" {
		req.AppInstanceInfo.Message = &message
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

	// lookup AppInst
	provAppInst, err := p.lookupAppInst(c, provider, string(appInstId))
	if err != nil {
		return err
	}

	appInst := edgeproto.AppInst{
		Key: provAppInst.GetAppInstKey(),
	}
	rc := ormutil.RegionContext{
		Region:    provAppInst.Region,
		SkipAuthz: true,
		Database:  p.database,
	}

	log.SpanLog(ctx, log.DebugLevelApi, "Federation delete appinst", "appInst", appInst.Key)
	err = ctrlclient.DeleteAppInstStream(ctx, &rc, &appInst, p.connCache,
		func(res *edgeproto.Result) error {
			return nil
		},
	)
	if err != nil && strings.Contains(err.Error(), appInst.Key.NotFoundError().Error()) {
		log.SpanLog(ctx, log.DebugLevelApi, "Federation delete appinst not found, continuing", "key", appInst.Key)
		err = nil
	}
	if err != nil {
		return err
	}

	// delete provAppInst
	db := p.loggedDB(ctx)
	err = db.Delete(provAppInst).Error
	if err != nil {
		return fedError(http.StatusInternalServerError, err)
	}
	return nil
}

func (p *PartnerApi) GetAllAppInstances(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier, appProviderId AppProviderId) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) GetAppInstanceDetails(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier, appInstId InstanceIdentifier, zoneId ZoneIdentifier) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) PartnerInstanceStatusEvent(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	uniqueId := c.Param(federationmgmt.PathVarAppInstUniqueId)
	in := fedewapi.FederationContextIdApplicationLcmPostRequest{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	// lookup federation consumer based on claims
	consumer, err := p.lookupConsumer(c, in.FederationContextId)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "partner app instance status event", "consumer", consumer.Name, "operatorid", consumer.OperatorId, "request", in)

	// lookup app
	app, err := p.lookupConsumerApp(c, consumer, in.AppId)
	if err != nil {
		return err
	}

	event := edgeproto.FedAppInstEvent{
		Key: edgeproto.FedAppInstKey{
			FederationName: consumer.Name,
			AppInstId:      in.AppInstanceId,
		},
		UniqueId: uniqueId,
	}
	info := &in.AppInstanceInfo
	if info.Message != nil {
		event.Message = *info.Message
	}
	if info.AppInstanceState != nil {
		switch *info.AppInstanceState {
		case federationmgmt.AppInstStatePending:
			event.State = edgeproto.TrackedState_CREATING
		case federationmgmt.AppInstStateReady:
			event.State = edgeproto.TrackedState_READY
		case federationmgmt.AppInstStateFailed:
			event.State = edgeproto.TrackedState_CREATE_ERROR
		case federationmgmt.AppInstStateTerminating:
			event.State = edgeproto.TrackedState_CREATE_ERROR
			event.Message = "Terminating"
			if info.Message != nil {
				event.Message += ", " + *info.Message
			}
		}
	}
	if len(info.AccesspointInfo) > 0 {
		for _, ap := range info.AccesspointInfo {
			port := dmeproto.AppPort{}
			portVal, err := strconv.Atoi(ap.InterfaceId)
			if err != nil {
				return fmt.Errorf("Invalid interfaceId %s, cannot convert to a port number, %s", ap.InterfaceId, err)
			}
			port.InternalPort = int32(portVal)
			// Note that baseURL will be empty, so FqdnPrefix
			// will be used as the whole Fqdn.
			// Note we do not support multiple IP addresses.
			if ap.AccessPoints.Fqdn != nil {
				port.FqdnPrefix = *ap.AccessPoints.Fqdn
			} else if len(ap.AccessPoints.Ipv4Addresses) > 0 {
				port.FqdnPrefix = ap.AccessPoints.Ipv4Addresses[0]
			} else if len(ap.AccessPoints.Ipv6Addresses) > 0 {
				port.FqdnPrefix = ap.AccessPoints.Ipv6Addresses[0]
			} else {
				return fmt.Errorf("No valid fqdn or ip address for interfaceId %s", ap.InterfaceId)
			}
			event.Ports = append(event.Ports, port)
		}
	}

	// make call to Controller
	rc := ormutil.RegionContext{
		Region:    app.Region,
		SkipAuthz: true,
		Database:  p.database,
	}
	_, err = ctrlclient.HandleFedAppInstEventObj(ctx, &rc, &event, p.connCache)
	if err != nil {
		return err
	}
	return nil
}
