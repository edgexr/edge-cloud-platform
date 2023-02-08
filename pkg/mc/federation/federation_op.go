// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package federation

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/gormlog"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo/v4"
)

const (
	TokenUrl = "oauth2/token"

	StatusUnregistered = "Unregistered"
	StatusRegistered   = "Registered"

	// Path params
	PathVarFederationContextId = "federationContextId"
	PathVarZoneId              = "zoneId"
	PathVarAppId               = "appId"
	PathVarAppInstId           = "appInstanceId"
	PathVarAppProviderId       = "appProviderId"
	PathVarPoolId              = "poolId"

	BadAuthDelay   = 3 * time.Second
	AllAppsVersion = "1.0"
)

type FedQueryParams struct {
	IgnorePartner bool
}

func GetFedQueryParams(c echo.Context) FedQueryParams {
	qp := FedQueryParams{}
	if c.QueryParam("ignorepartner") == "true" {
		qp.IgnorePartner = true
	}
	return qp
}

type PartnerApi struct {
	database       *gorm.DB
	connCache      ctrlclient.ClientConnMgr
	nodeMgr        *node.NodeMgr
	vaultConfig    *vault.Config
	tokenSources   *federationmgmt.TokenSourceCache
	fedExtAddr     string
	vmRegistryAddr string
	harborAddr     string
	allowPlainHttp bool // for unit testing
}

func NewPartnerApi(db *gorm.DB, connCache ctrlclient.ClientConnMgr, nodeMgr *node.NodeMgr, vaultConfig *vault.Config, fedExtAddr, vmRegistryAddr, harborAddr string) *PartnerApi {
	p := &PartnerApi{
		database:       db,
		connCache:      connCache,
		nodeMgr:        nodeMgr,
		vaultConfig:    vaultConfig,
		fedExtAddr:     fedExtAddr,
		vmRegistryAddr: vmRegistryAddr,
		harborAddr:     harborAddr,
	}
	p.tokenSources = federationmgmt.NewTokenSourceCache(p)
	return p
}

func (p *PartnerApi) loggedDB(ctx context.Context) *gorm.DB {
	return gormlog.LoggedDB(ctx, p.database)
}

// unit testing only
func (p *PartnerApi) AllowPlainHttp() {
	p.allowPlainHttp = true
}

// E/W-BoundInterface APIs for Federation between multiple Operator Platforms (federators)
// These are the standard interfaces which are called by other federators for unified edge platform experience
func (p *PartnerApi) InitAPIs(e *echo.Echo) {
	RegisterHandlersWithBaseURL(e, p, federationmgmt.ApiRoot)
	e.POST(federationmgmt.PartnerStatusEventPath, p.PartnerStatusEvent)
	e.POST(federationmgmt.PartnerZoneResourceUpdatePath, p.PartnerZoneResourceUpdate)
	e.POST(federationmgmt.PartnerAppOnboardStatusEventPath, p.PartnerAppOnboardStatusEvent)
	e.POST(federationmgmt.PartnerInstanceStatusEventPath+"/:"+federationmgmt.PathVarAppInstUniqueId, p.PartnerInstanceStatusEvent)
	e.POST(federationmgmt.PartnerResourceStatusChangePath, p.PartnerResourceStatusChange)

}

func (p *PartnerApi) lookupProvider(c echo.Context, federationContextId FederationContextId) (*ormapi.FederationProvider, error) {
	claims, err := ormutil.GetClaims(c)
	if err != nil {
		return nil, err
	}
	ctx := ormutil.GetContext(c)
	db := p.loggedDB(ctx)
	// claims.ApiKeyUsername has the info to lookup provider
	typ, id, err := federationmgmt.ParseFedKeyUser(claims.ApiKeyUsername)
	if err != nil {
		return nil, err
	}
	if typ != federationmgmt.FederationTypeProvider {
		return nil, fmt.Errorf("expected owner %s but was %s", federationmgmt.FederationTypeProvider, typ)
	}

	provider := ormapi.FederationProvider{
		ID: id,
	}
	res := db.Where(&provider).First(&provider)
	if res.RecordNotFound() {
		return nil, fmt.Errorf("federation provider %q not found", claims.ApiKeyUsername)
	}
	if res.Error != nil {
		return nil, ormutil.DbErr(res.Error)
	}
	if federationContextId != "" && string(federationContextId) != provider.FederationContextId {
		return nil, fmt.Errorf("mismatch between access token and federation context id")
	}
	return &provider, nil
}

func (p *PartnerApi) lookupConsumer(c echo.Context, federationContextId string) (*ormapi.FederationConsumer, error) {
	claims, err := ormutil.GetClaims(c)
	if err != nil {
		return nil, err
	}
	ctx := ormutil.GetContext(c)
	db := p.loggedDB(ctx)
	// claims.ApiKeyUsername has the info to lookup consumer
	typ, id, err := federationmgmt.ParseFedKeyUser(claims.ApiKeyUsername)
	if err != nil {
		return nil, err
	}
	if typ != federationmgmt.FederationTypeConsumer {
		return nil, fmt.Errorf("expected owner %s but was %s", federationmgmt.FederationTypeConsumer, typ)
	}

	consumer := ormapi.FederationConsumer{
		ID: id,
	}
	res := db.Where(&consumer).First(&consumer)
	if res.RecordNotFound() {
		return nil, fmt.Errorf("federation consumer %q not found", claims.ApiKeyUsername)
	}
	if res.Error != nil {
		return nil, ormutil.DbErr(res.Error)
	}
	if federationContextId != "" && string(federationContextId) != consumer.FederationContextId {
		return nil, fmt.Errorf("mismatch between access token and federation context id")
	}
	return &consumer, nil
}

func (p *PartnerApi) auditCb(ctx context.Context, fedKey *federationmgmt.FedKey, data *ormclient.AuditLogData) {
	eventTags := data.GetEventTags()
	p.nodeMgr.TimedEvent(ctx, "federation client api", fedKey.Name, node.EventType, eventTags, data.Err, data.Start, data.End)
}

func (p *PartnerApi) GetFederationAPIKey(ctx context.Context, fedKey *federationmgmt.FedKey) (*federationmgmt.ApiKey, error) {
	return federationmgmt.GetFederationAPIKey(ctx, p.vaultConfig, fedKey)
}

func (p *PartnerApi) ProviderPartnerClient(ctx context.Context, provider *ormapi.FederationProvider, cbUrl string) (*federationmgmt.Client, error) {
	fedKey := ProviderFedKey(provider)
	return p.tokenSources.Client(ctx, cbUrl, fedKey, p.auditCb)
}

func (p *PartnerApi) ConsumerPartnerClient(ctx context.Context, consumer *ormapi.FederationConsumer) (*federationmgmt.Client, error) {
	fedKey := ConsumerFedKey(consumer)
	return p.tokenSources.Client(ctx, consumer.PartnerAddr, fedKey, p.auditCb)
}

func (p *PartnerApi) validateCallbackLink(link string) error {
	if link == "" || link == federationmgmt.CallbackNotSupported {
		return nil
	}
	_, err := url.ParseRequestURI(link)
	if err != nil {
		return fmt.Errorf("Invalid callback link %s, %s", link, err)
	}
	u, err := url.Parse(link)
	if err != nil {
		return fmt.Errorf("Invalid callback link %s, %s", link, err)
	}
	if p.allowPlainHttp {
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("Invalid scheme %q in callback link %s, must be http or https", u.Scheme, link)
		}
	} else {
		if u.Scheme != "https" {
			return fmt.Errorf("Invalid scheme %q in callback link %s, must be https", u.Scheme, link)
		}
	}
	if u.Host == "" {
		return fmt.Errorf("No host in callback link %s", link)
	}
	return nil
}

// Remote partner federator requests to create the federation, which
// allows its developers and subscribers to run their applications
// on our cloudlets
func (p *PartnerApi) CreateFederation(c echo.Context) (reterr error) {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, "")
	if err != nil {
		return err
	}

	req := fedewapi.FederationRequestData{}
	if err := c.Bind(&req); err != nil {
		return err
	}
	if req.PartnerStatusLink == "" {
		req.PartnerStatusLink = federationmgmt.CallbackNotSupported
	}
	if err := req.Validate(); err != nil {
		return err
	}
	if err := p.validateCallbackLink(req.PartnerStatusLink); err != nil {
		return err
	}

	// For convenience allow CreateFederation to be idempotent,
	// but only if it's the same requestor
	if provider.PartnerInfo.FederationId != "" {
		if req.OrigOPFederationId != provider.PartnerInfo.FederationId {
			return fmt.Errorf("Federation provider already in use by another consumer")
		}
	}

	// So we just overwrite existing partner data and reuse existing
	// federation context id.
	provider.PartnerInfo.FederationId = req.OrigOPFederationId
	provider.PartnerInfo.InitialDate = req.InitialDate
	provider.PartnerNotifyDest = req.PartnerStatusLink
	if req.OrigOPCountryCode != nil {
		provider.PartnerInfo.CountryCode = *req.OrigOPCountryCode
	}
	SetFixedNetworkIds(&provider.PartnerInfo, req.OrigOPFixedNetworkCodes)
	SetMobileNetworkIds(&provider.PartnerInfo, req.OrigOPMobileNetworkCodes)
	provider.Status = StatusRegistered

	out := fedewapi.FederationResponseData{}
	log.SpanLog(ctx, log.DebugLevelApi, "partner response fed ctx id", "id", provider.FederationContextId)
	out.FederationContextId = provider.FederationContextId
	log.SpanLog(ctx, log.DebugLevelApi, "partner response out", "id", out.FederationContextId, "out", out)
	out.PartnerOPFederationId = provider.MyInfo.FederationId
	if provider.MyInfo.CountryCode != "" {
		out.PartnerOPCountryCode = &provider.MyInfo.CountryCode
	}
	// TODO: Unclear how EdgeDiscoveryServiceEndpoint should work
	// TODO: Unclear how LcmServiceEndpoint should work
	out.PlatformCaps = []string{"homeRouting", "Anchoring"}
	out.PartnerOPMobileNetworkCodes = GetMobileNetworkIds(&provider.MyInfo)
	out.PartnerOPFixedNetworkCodes = GetFixedNetworkIds(&provider.MyInfo)

	zones, err := p.getAvailabilityZones(ctx, provider)
	if err != nil {
		return err
	}
	if len(zones) > 0 {
		out.OfferedAvailabilityZones = zones
	}

	var apiKey *federationmgmt.ApiKey
	if req.PartnerCallbackCredentials != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "got callback credentials in body")
		apiKey = &federationmgmt.ApiKey{
			TokenUrl: req.PartnerCallbackCredentials.TokenUrl,
			Id:       req.PartnerCallbackCredentials.ClientId,
			Key:      req.PartnerCallbackCredentials.ClientSecret,
		}
	}
	if apiKey != nil {
		fedKey := ProviderFedKey(provider)
		err := federationmgmt.PutAPIKeyToVault(ctx, p.vaultConfig, fedKey, apiKey)
		if err != nil {
			return err
		}
		provider.PartnerNotifyClientId = "***"
		provider.PartnerNotifyTokenUrl = apiKey.TokenUrl

		defer func() {
			if reterr == nil {
				return
			}
			undoErr := federationmgmt.DeleteAPIKeyFromVault(ctx, p.vaultConfig, fedKey)
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "undo: delete apikey failed", "err", undoErr)
			}
		}()
	}

	// Add federation with partner federator
	db := p.loggedDB(ctx)
	if err := db.Save(&provider).Error; err != nil {
		return ormutil.DbErr(err)
	}
	log.SpanLog(ctx, log.DebugLevelApi, "federation provider registered", "provider", provider, "response", out)

	// Return with list of zones to be shared
	return c.JSON(http.StatusOK, out)
}

func (p *PartnerApi) getAvailabilityZones(ctx context.Context, provider *ormapi.FederationProvider) ([]fedewapi.ZoneDetails, error) {
	// Get list of zones to be shared with partner federator
	opShZones := []ormapi.ProviderZone{}
	lookup := ormapi.ProviderZone{
		OperatorId:   provider.OperatorId,
		ProviderName: provider.Name,
	}
	db := p.loggedDB(ctx)
	err := db.Where(&lookup).Find(&opShZones).Error
	if err != nil {
		return nil, ormutil.DbErr(err)
	}

	zones := []fedewapi.ZoneDetails{}
	for _, opShZone := range opShZones {
		zoneBase := ormapi.ProviderZoneBase{
			ZoneId:     opShZone.ZoneId,
			OperatorId: provider.OperatorId,
		}
		err = db.Where(&zoneBase).First(&zoneBase).Error
		if err != nil {
			return nil, ormutil.DbErr(err)
		}
		details := fedewapi.ZoneDetails{
			GeographyDetails: zoneBase.GeographyDetails,
			Geolocation:      zoneBase.GeoLocation,
			ZoneId:           zoneBase.ZoneId,
		}
		if details.GeographyDetails == "" {
			details.GeographyDetails = GeographyDetailsNone
		}
		zones = append(zones, details)
	}
	return zones, nil
}

// Remote partner federator sends this request to us to notify about
// the change in its MNC, MCC or locator URL
func (p *PartnerApi) GetFederationDetails(c echo.Context, fedCtxId FederationContextId) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}
	out, err := p.getProviderDetails(ctx, provider)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, out)
}

func (p *PartnerApi) getProviderDetails(ctx context.Context, provider *ormapi.FederationProvider) (map[string]interface{}, error) {
	zones, err := p.getAvailabilityZones(ctx, provider)
	if err != nil {
		return nil, err
	}

	out := map[string]interface{}{
		"edgeDiscoveryServiceEndPoint": fedewapi.ServiceEndpoint{
			// TODO
		},
		"lcmServiceEndPoint": fedewapi.ServiceEndpoint{
			// TODO
		},
		"allowedMobileNetworkIds": GetMobileNetworkIds(&provider.MyInfo),
		"allowedFixedNetworkIds":  GetFixedNetworkIds(&provider.MyInfo),
	}
	if len(zones) > 0 {
		out["offeredAvailabilityZones"] = zones
	}
	return out, nil
}

func (p *PartnerApi) UpdateFederation(c echo.Context, fedCtxId FederationContextId) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	in := fedewapi.UpdateFederationRequest{}
	if err := c.Bind(&in); err != nil {
		return err
	}
	if err := in.Validate(); err != nil {
		return err
	}

	switch in.ObjectType {
	case "MOBILE_NETWORK_CODES":
		switch in.OperationType {
		case "ADD_CODES":
			if in.AddMobileNetworkIds == nil {
				return fmt.Errorf("Add mobile network codes specified but add codes not present")
			}
			if in.AddMobileNetworkIds.Mcc != nil {
				provider.MyInfo.MCC = *in.AddMobileNetworkIds.Mcc
			}
			if in.AddMobileNetworkIds.Mncs != nil {
				provider.MyInfo.MNC = util.AddStringSliceUniques(provider.MyInfo.MNC, in.AddMobileNetworkIds.Mncs)
			}
		case "REMOVE_CODES":
			if in.RemoveMobileNetworkIds == nil {
				return fmt.Errorf("Remove mobile network codes specified but remove codes not present")
			}
			if in.RemoveMobileNetworkIds.Mcc != nil && provider.MyInfo.MCC == *in.RemoveMobileNetworkIds.Mcc {
				provider.MyInfo.MCC = ""
			}
			if in.RemoveMobileNetworkIds.Mncs != nil {
				provider.MyInfo.MNC = util.RemoveStringSliceUniques(provider.MyInfo.MNC, in.RemoveMobileNetworkIds.Mncs)
			}
		case "UPDATE_CODES":
			if in.AddMobileNetworkIds == nil {
				return fmt.Errorf("Update mobile network codes specified but add codes not present")
			}
			SetMobileNetworkIds(&provider.MyInfo, in.AddMobileNetworkIds)
		default:
			return fmt.Errorf("Invalid OperationType %s", in.OperationType)
		}
	case "FIXED_NETWORK_CODES":
		switch in.OperationType {
		case "ADD_CODES":
			if in.AddFixedNetworkIds == nil {
				return fmt.Errorf("Add fixed network codes specified but add codes not present")
			}
			if in.AddFixedNetworkIds != nil {
				provider.MyInfo.FixedNetworkIds = util.AddStringSliceUniques(provider.MyInfo.FixedNetworkIds, in.AddFixedNetworkIds)
			}
		case "REMOVE_CODES":
			if in.RemoveFixedNetworkIds == nil {
				return fmt.Errorf("Remove fixed network codes specified but remove codes not present")
			}
			if in.RemoveFixedNetworkIds != nil {
				provider.MyInfo.FixedNetworkIds = util.RemoveStringSliceUniques(provider.MyInfo.FixedNetworkIds, in.RemoveFixedNetworkIds)
			}
		case "UPDATE_CODES":
			if in.AddFixedNetworkIds == nil {
				return fmt.Errorf("Update fixed network codes specified but add codes not present")
			}
			SetFixedNetworkIds(&provider.MyInfo, in.AddFixedNetworkIds)
		default:
			return fmt.Errorf("Invalid operationType %s", in.OperationType)
		}
	default:
		return fmt.Errorf("Invalid objectType %s", in.ObjectType)
	}

	db := p.loggedDB(ctx)
	err = db.Save(provider).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	out, err := p.getProviderDetails(ctx, provider)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, out)
}

// Remote partner federator requests to delete the federation, which
// disallows its developers and subscribers to run their applications
// on our cloudlets
func (p *PartnerApi) DeleteFederationDetails(c echo.Context, fedCtxId FederationContextId) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	// Check if all the provider zones are deregistered by partner federator
	db := p.loggedDB(ctx)
	lookup := ormapi.ProviderZone{
		OperatorId:   provider.OperatorId,
		ProviderName: provider.Name,
	}
	zones := []ormapi.ProviderZone{}
	err = db.Where(&lookup).Find(&zones).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	for _, pZone := range zones {
		if pZone.Status == StatusRegistered {
			return fmt.Errorf("Cannot delete partner federation as zone %q of federation %q is registered by partner federator. Please deregister it before deleting the federation", pZone.ZoneId, provider.FederationContextId)
		}
	}

	provider.PartnerInfo = ormapi.Federator{}
	provider.PartnerNotifyDest = ""
	provider.PartnerNotifyTokenUrl = ""
	provider.Status = StatusUnregistered

	err = db.Save(provider).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	return nil
}

func (p *PartnerApi) AddConsumerZones(ctx context.Context, consumer *ormapi.FederationConsumer, zones []fedewapi.ZoneDetails) (reterr error) {
	db := p.loggedDB(ctx)
	createdZones := []string{}
	defer func() {
		if reterr == nil {
			return
		}
		for _, id := range createdZones {
			delZone := ormapi.ConsumerZone{
				ZoneId:       id,
				ConsumerName: consumer.Name,
				OperatorId:   consumer.OperatorId,
			}
			undoErr := db.Delete(&delZone).Error
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "failed to clean up zone on register federation failure", "err", undoErr)
			}
		}
	}()

	// Store partner zones in DB
	for _, partnerZone := range zones {
		zoneObj := ormapi.ConsumerZone{}
		zoneObj.ZoneId = partnerZone.ZoneId
		zoneObj.ConsumerName = consumer.Name
		zoneObj.OperatorId = consumer.OperatorId
		zoneObj.GeoLocation = partnerZone.Geolocation
		zoneObj.GeographyDetails = partnerZone.GeographyDetails
		zoneObj.Status = StatusUnregistered
		if err := db.Create(&zoneObj).Error; err != nil {
			if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
				log.SpanLog(ctx, log.DebugLevelApi, "ignore zone already exists error", "err", err)
				continue
			} else {
				err = ormutil.DbErr(err)
			}
			log.SpanLog(ctx, log.DebugLevelApi, "register FederationConsumer failed", "err", err)
			return err
		}
		createdZones = append(createdZones, zoneObj.ZoneId)
	}

	if consumer.AutoRegisterZones {
		regErr := p.RegisterConsumerZones(ctx, consumer, consumer.AutoRegisterRegion, createdZones)
		if regErr != nil {
			// don't fail, just log that registration will need
			// to be done manually
			log.SpanLog(ctx, log.DebugLevelApi, "auto-registration of zones failed, some zones may need to be registered manually", "err", regErr)
		}
	}
	return nil
}

func (p *PartnerApi) RemoveConsumerZones(ctx context.Context, consumer *ormapi.FederationConsumer, zoneIds []string) (reterr error) {
	db := p.loggedDB(ctx)

	// Deregister zones automatically if they are registered.
	// This will fail if anything has been deployed to the cloudlet.
	err := p.DeregisterConsumerZones(ctx, consumer, zoneIds, FedQueryParams{})
	if err != nil {
		return fmt.Errorf("Some zones are registered and could not be automatically deregistered: %v", err)
	}

	// Remove partner zones from db
	for _, zoneId := range zoneIds {
		zoneObj := ormapi.ConsumerZone{}
		zoneObj.ZoneId = zoneId
		zoneObj.ConsumerName = consumer.Name
		zoneObj.OperatorId = consumer.OperatorId
		if err := db.Delete(&zoneObj).Error; err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "deregister FederationConsumer failed", "err", err)
			return err
		}
	}
	return nil
}

func (p *PartnerApi) SetConsumerZones(ctx context.Context, consumer *ormapi.FederationConsumer, zones []fedewapi.ZoneDetails) error {
	db := p.loggedDB(ctx)

	// get all existing zones
	lookup := ormapi.ConsumerZone{
		ConsumerName: consumer.Name,
		OperatorId:   consumer.OperatorId,
	}
	existingZones := []ormapi.ConsumerZone{}
	err := db.Where(&lookup).Find(&existingZones).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	// Add all new zones (no-op if already exists)
	err = p.AddConsumerZones(ctx, consumer, zones)
	if err != nil {
		return err
	}

	// Zones to keep
	keep := map[string]struct{}{}
	for _, zone := range zones {
		keep[zone.ZoneId] = struct{}{}
	}

	toDelete := []string{}
	for _, zone := range existingZones {
		if _, found := keep[zone.ZoneId]; !found {
			toDelete = append(toDelete, zone.ZoneId)
		}
	}
	// Remove zones to delete
	err = p.RemoveConsumerZones(ctx, consumer, toDelete)
	if err != nil {
		return err
	}
	return nil
}

func (p *PartnerApi) GetCandidateZones(c echo.Context, fedCtxId FederationContextId) error {
	return fmt.Errorf("not supported")
}

func (p *PartnerApi) AuthenticateDevice(c echo.Context, fedCtxId FederationContextId, deviceId DeviceId, authToken AuthorizationToken) error {
	return fmt.Errorf("not supported")
}

func GetFixedNetworkIds(fed *ormapi.Federator) []string {
	if len(fed.FixedNetworkIds) == 0 {
		return nil
	}
	ids := fed.FixedNetworkIds
	return ids
}

func SetFixedNetworkIds(fed *ormapi.Federator, ids []string) {
	if ids == nil {
		return
	}
	fed.FixedNetworkIds = ids
}

func GetMobileNetworkIds(fed *ormapi.Federator) *fedewapi.MobileNetworkIds {
	if fed.MCC == "" && len(fed.MNC) == 0 {
		return nil
	}
	ids := fedewapi.MobileNetworkIds{}
	if fed.MCC != "" {
		ids.Mcc = &fed.MCC
	}
	if len(fed.MNC) > 0 {
		ids.Mncs = fed.MNC
	}
	return &ids
}

func SetMobileNetworkIds(fed *ormapi.Federator, ids *fedewapi.MobileNetworkIds) {
	if ids == nil {
		return
	}
	if ids.Mcc != nil {
		fed.MCC = *ids.Mcc
	}
	if ids.Mncs != nil {
		fed.MNC = ids.Mncs
	}
}

func (p *PartnerApi) PartnerStatusEvent(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	in := fedewapi.PartnerPostRequest{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	if err := in.Validate(); err != nil {
		return err
	}

	// lookup federation consumer based on claims
	consumer, err := p.lookupConsumer(c, in.FederationContextId)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "partner notify", "consumer", consumer.Name, "operatorid", consumer.OperatorId)
	switch in.OperationType {
	case "ADD_ZONES":
		err = p.AddConsumerZones(ctx, consumer, in.AddZones)
	case "REMOVE_ZONES":
		err = p.RemoveConsumerZones(ctx, consumer, in.RemoveZones)
	case "UPDATE_ZONES":
		err = p.SetConsumerZones(ctx, consumer, in.AddZones)
	default:
		err = fmt.Errorf("Unsupported operationtype %q", in.OperationType)
	}
	return err
}

type FedError struct {
	Code    int
	Message string
}

func (s FedError) Error() string {
	return s.Message
}

// Use this to specify a particular error code
func fedError(code int, err error) error {
	return &FedError{
		Code:    code,
		Message: err.Error(),
	}
}
