package federation

import (
	"context"
	"fmt"
	"net/http"
	"os"
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
		return nil, fedError(http.StatusNotFound, fmt.Errorf("Application instance %s not found", appInstanceId))
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
	if in.AppInstCallbackLink == "" {
		in.AppInstCallbackLink = federationmgmt.CallbackNotSupported
	}
	if err := in.Validate(); err != nil {
		return err
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

	// we'll update the AppInstKey once the AppInst is created,
	// in case it updates some of the optional fields.
	appKey := provArt.GetAppKey()
	provAppInst := ormapi.ProviderAppInst{
		FederationName:      provider.Name,
		AppID:               in.AppId,
		AppInstID:           in.AppInstanceId,
		AppInstCallbackLink: in.AppInstCallbackLink,
		Region:              base.Region,
		AppName:             appKey.Name,
		AppVers:             appKey.Version,
		Cluster:             clusterName,
		ClusterOrg:          clusterOrg,
		Cloudlet:            base.Cloudlets[0],
		CloudletOrg:         provider.OperatorId,
	}
	db := p.loggedDB(ctx)
	err = db.Create(&provAppInst).Error
	if err != nil && strings.Contains(err.Error(), "pq: duplicate key value") {
		return fmt.Errorf("AppInst with ID %s already exists", in.AppInstanceId)
	} else if err != nil {
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

	return c.JSON(http.StatusAccepted, "")
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
		state := fedewapi.INSTANCESTATE_FAILED
		s.sendCallback(ctx, &state, err.Error(), nil)
		log.SpanLog(ctx, log.DebugLevelApi, "create provider AppInst failed", "appInst", s.provAppInst, "err", err)
	}
}

func (s *AppInstWorker) createAppInst(ctx context.Context) (reterr error) {
	log.SpanLog(ctx, log.DebugLevelApi, "federation provider creating AppInst", "provAppInst", s.provAppInst)
	defer func() {
		if reterr == nil {
			return
		}
		// log error in providerAppInst
		s.provAppInst.Error = reterr.Error()
		db := s.partner.loggedDB(ctx)
		intErr := db.Save(&s.provAppInst).Error
		if intErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to save providerAppInst on error", "provAppInst", s.provAppInst, "err", intErr)
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
		FedKey: edgeproto.FedAppInstKey{
			FederationName: s.provider.Name,
			AppInstId:      s.provAppInst.AppInstID,
		},
	}
	if s.flavor != "NOT_SPECIFIED" {
		appInstIn.CloudletFlavor = s.flavor
	}

	log.SpanLog(ctx, log.DebugLevelApi, "Federation provider create appinst", "appInst", appInstIn)
	cb := func(res *edgeproto.Result) error {
		log.SpanLog(ctx, log.DebugLevelApi, "controller create appinst callback", "res", *res)
		state := fedewapi.INSTANCESTATE_PENDING
		s.sendCallback(ctx, &state, res.Message, nil)
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
	accessPoints := s.partner.getAppInstAccessPointInfo(appInstOut)
	state := getInstanceState(appInstOut)
	s.sendCallback(ctx, state, "", accessPoints)
	return nil
}

func getInstanceState(appInst *edgeproto.AppInst) *fedewapi.InstanceState {
	var state fedewapi.InstanceState
	switch appInst.State {
	case edgeproto.TrackedState_CREATE_REQUESTED:
		fallthrough
	case edgeproto.TrackedState_CREATING:
		fallthrough
	case edgeproto.TrackedState_UPDATE_REQUESTED:
		fallthrough
	case edgeproto.TrackedState_UPDATING:
		state = fedewapi.INSTANCESTATE_PENDING
	case edgeproto.TrackedState_DELETE_REQUESTED:
		fallthrough
	case edgeproto.TrackedState_DELETING:
		fallthrough
	case edgeproto.TrackedState_DELETE_PREPARE:
		state = fedewapi.INSTANCESTATE_TERMINATING
	case edgeproto.TrackedState_CREATE_ERROR:
		fallthrough
	case edgeproto.TrackedState_UPDATE_ERROR:
		fallthrough
	case edgeproto.TrackedState_DELETE_ERROR:
		state = fedewapi.INSTANCESTATE_FAILED
	case edgeproto.TrackedState_READY:
		state = fedewapi.INSTANCESTATE_READY
	default:
		return nil
	}
	return &state
}

func (s *PartnerApi) getAppInstAccessPointInfo(appInst *edgeproto.AppInst) []fedewapi.AccessPointInfoInner {
	accessPoints := []fedewapi.AccessPointInfoInner{}
	for _, port := range appInst.MappedPorts {
		portStart := port.InternalPort
		portEnd := port.EndPort
		if portEnd == 0 {
			portEnd = portStart
		}
		for portVal := portStart; portVal <= portEnd; portVal++ {
			ap := fedewapi.AccessPointInfoInner{}
			ap.InterfaceId = GetInterfaceId(port.Proto, portVal)
			fqdn := appInst.Uri + port.FqdnPrefix
			ap.AccessPoints.Port = port.PublicPort
			ap.AccessPoints.Fqdn = &fqdn
			accessPoints = append(accessPoints, ap)
		}
	}
	return accessPoints
}

func (s *AppInstWorker) sendCallback(ctx context.Context, state *fedewapi.InstanceState, message string, accesspointInfo []fedewapi.AccessPointInfoInner) {
	now := time.Now()
	req := fedewapi.FederationContextIdApplicationLcmPostRequest{
		FederationContextId: s.provider.FederationContextId,
		AppId:               s.provApp.AppID,
		AppInstanceId:       s.provAppInst.AppInstID,
		ZoneId:              s.base.ZoneId,
		AppInstanceInfo: fedewapi.FederationContextIdApplicationLcmPostRequestAppInstanceInfo{
			AppInstanceState: state,
			AccesspointInfo:  accesspointInfo,
		},
		ModificationDate: &now,
	}
	if message != "" {
		req.AppInstanceInfo.Message = &message
	}

	if s.callbackUrl == federationmgmt.CallbackNotSupported {
		log.SpanLog(ctx, log.DebugLevelApi, "appInst lcm skip callback", "req", req, "path", s.callbackUrl)
		return
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
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	return p.RemoveAppInstInternal(c, provider, string(appInstId))
}

func (p *PartnerApi) RemoveAppInstInternal(c echo.Context, provider *ormapi.FederationProvider, appInstId string) error {
	// lookup AppInst
	provAppInst, err := p.lookupAppInst(c, provider, string(appInstId))
	if err != nil {
		return err
	}

	ctx := ormutil.GetContext(c)
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
	ctx := ormutil.GetContext(c)
	log.SpanLog(ctx, log.DebugLevelApi, "Federation get appInstanceDetails", "fedCtxId", fedCtxId, "appInstId", appInstId)
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

	filter := edgeproto.AppInst{
		Key: provAppInst.GetAppInstKey(),
	}
	rc := ormutil.RegionContext{
		Region:    provAppInst.Region,
		SkipAuthz: true,
		Database:  p.database,
	}
	var appInstOut *edgeproto.AppInst
	err = ctrlclient.ShowAppInstStream(ctx, &rc, &filter, p.connCache, nil, func(ai *edgeproto.AppInst) error {
		appInstOut = ai
		return nil
	})

	state := fedewapi.INSTANCESTATE_PENDING
	resp := fedewapi.GetAppInstanceDetails200Response{
		AppInstanceState: &state,
	}
	if provAppInst.Error != "" {
		state = fedewapi.INSTANCESTATE_FAILED
		resp.AppInstanceState = &state
		resp.StateDescription = &provAppInst.Error
	}
	if appInstOut != nil {
		resp.AppInstanceState = getInstanceState(appInstOut)
		accessPoints := p.getAppInstAccessPointInfo(appInstOut)
		if len(accessPoints) > 0 {
			resp.AccesspointInfo = accessPoints
		}
	}
	return c.JSON(http.StatusOK, &resp)
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
	err = SetFedAppInstEvent(&event, info.AppInstanceState, info.Message, info.AccesspointInfo)
	if err != nil {
		return err
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

func SetFedAppInstEvent(event *edgeproto.FedAppInstEvent, instanceState *fedewapi.InstanceState, message *string, accessPointInfo []fedewapi.AccessPointInfoInner) error {
	if instanceState != nil {
		switch *instanceState {
		case fedewapi.INSTANCESTATE_PENDING:
			event.State = edgeproto.TrackedState_CREATING
		case fedewapi.INSTANCESTATE_READY:
			event.State = edgeproto.TrackedState_READY
		case fedewapi.INSTANCESTATE_FAILED:
			event.State = edgeproto.TrackedState_CREATE_ERROR
		case fedewapi.INSTANCESTATE_TERMINATING:
			event.State = edgeproto.TrackedState_CREATE_ERROR
			event.Message = "Terminating"
			if message != nil {
				event.Message += ", " + *message
			}
		}
	}
	if len(accessPointInfo) > 0 {
		for _, ap := range accessPointInfo {
			port := dmeproto.AppPort{}
			proto, internalPort, err := ParseInterfaceId(ap.InterfaceId)
			if err != nil {
				return err
			}
			port.Proto = proto
			port.InternalPort = internalPort
			port.PublicPort = int32(ap.AccessPoints.Port)
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
	return nil
}
