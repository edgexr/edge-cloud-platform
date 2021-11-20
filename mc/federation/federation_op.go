package federation

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	"github.com/lib/pq"
	"github.com/mobiledgex/edge-cloud-infra/mc/ctrlclient"
	"github.com/mobiledgex/edge-cloud-infra/mc/gormlog"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormutil"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

const (
	// Federation APIs
	OperatorPartnerAPI    = "/operator/partner"
	OperatorZoneAPI       = "/operator/zone"
	OperatorNotifyZoneAPI = "/operator/notify/zone"

	BadAuthDelay = 3 * time.Second
)

type PartnerApi struct {
	Database  *gorm.DB
	ConnCache ctrlclient.ClientConnMgr
}

func (p *PartnerApi) loggedDB(ctx context.Context) *gorm.DB {
	return gormlog.LoggedDB(ctx, p.Database)
}

// E/W-BoundInterface APIs for Federation between multiple Operator Platforms (federators)
// These are the standard interfaces which are called by other federators for unified edge platform experience
func (p *PartnerApi) InitAPIs(e *echo.Echo) {
	// Create directed federation with partner federator
	e.POST(OperatorPartnerAPI, p.FederationOperatorPartnerCreate)
	// Update attributes of an existing federation with a partner federator
	e.PUT(OperatorPartnerAPI, p.FederationOperatorPartnerUpdate)
	// Remove existing federation with a partner federator
	e.DELETE(OperatorPartnerAPI, p.FederationOperatorPartnerDelete)
	// Partner registers self federator zones
	e.POST(OperatorZoneAPI, p.FederationOperatorZoneRegister)
	// Partner deregisters self federator zones
	e.DELETE(OperatorZoneAPI, p.FederationOperatorZoneDeRegister)
	// Notify partner federator about a new zone being added
	e.POST(OperatorNotifyZoneAPI, p.FederationOperatorZoneShare)
	// Notify partner federator about a zone being unshared
	e.DELETE(OperatorNotifyZoneAPI, p.FederationOperatorZoneUnShare)
}

func AuthAPIKey(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		auth := c.Request().Header.Get(echo.HeaderAuthorization)
		scheme := "Bearer"
		l := len(scheme)
		apiKey := ""
		if len(auth) > len(scheme) && strings.HasPrefix(auth, scheme) {
			apiKey = auth[l+1:]
		}
		if apiKey == "" {
			// Partner federator is using x-api-key for API key-based auth,
			// which will be changed in the future to use Authorization header.
			// So for now, we will support both.
			auth = c.Request().Header.Get("x-api-key")
			if len(auth) > 0 {
				apiKey = auth
			} else {
				// if no api key found, return a 400 err
				return &echo.HTTPError{
					Code:     http.StatusBadRequest,
					Message:  "api key not found in bearer token or x-api-key",
					Internal: fmt.Errorf("api key not found in bearer token or x-api-key"),
				}
			}
		}
		c.Set("apikey", apiKey)
		return next(c)
	}
}

func (p *PartnerApi) ValidateAndGetFederatorInfo(c echo.Context, origKey, destKey, origOperatorId, origCountryCode string) (*ormapi.Federator, *ormapi.Federation, error) {
	apiKeyIntf := c.Get("apikey")
	ctx := ormutil.GetContext(c)
	if apiKeyIntf == nil {
		log.SpanLog(ctx, log.DebugLevelApi, "no apikey found")
		return nil, nil, echo.ErrUnauthorized
	}
	apiKey, ok := apiKeyIntf.(string)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelApi, "invalid apikey type")
		return nil, nil, echo.ErrUnauthorized
	}
	// sanity check
	if origKey == "" {
		return nil, nil, fmt.Errorf("Missing origin federation key")
	}
	if destKey == "" {
		return nil, nil, fmt.Errorf("Missing destination federation key")
	}
	if origOperatorId == "" {
		return nil, nil, fmt.Errorf("Missing origin Operator ID")
	}
	if origCountryCode == "" {
		return nil, nil, fmt.Errorf("Missing origin country code")
	}
	db := p.loggedDB(ctx)

	// We are using destination federation key to get self federator info.
	// A federator is identified by operatorID/countryCode, but the partner
	// federator does not send these details.
	// Hence, MC uses the destination federation key to multiplex federation
	// requests to appropriate self federator
	selfFed := ormapi.Federator{
		FederationId: destKey,
	}
	res := db.Where(&selfFed).First(&selfFed)
	if res.RecordNotFound() {
		return nil, nil, fmt.Errorf("Invalid destination federation key")
	}
	if res.Error != nil {
		return nil, nil, ormutil.DbErr(res.Error)
	}

	partnerLookup := ormapi.Federation{
		SelfFederationId: selfFed.FederationId,
	}
	partnerFed := ormapi.Federation{}
	res = db.Where(&partnerLookup).First(&partnerFed)
	if res.RecordNotFound() {
		return nil, nil, fmt.Errorf("Origin federator with ID %q does not exist", selfFed.FederationId)
	}
	if res.Error != nil {
		return nil, nil, ormutil.DbErr(res.Error)
	}
	// validate api key
	matches, err := ormutil.PasswordMatches(apiKey, selfFed.ApiKeyHash, selfFed.Salt, selfFed.Iter)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "apiKeyId matches err", "err", err)
	}
	if !matches || err != nil {
		time.Sleep(BadAuthDelay)
		return nil, nil, fmt.Errorf("Invalid ApiKey")
	}

	// validate origin (partner) FederationId/operator/country
	if partnerFed.FederationId != origKey {
		return nil, nil, fmt.Errorf("Invalid origin federation key")
	}
	return &selfFed, &partnerFed, nil
}

// Remote partner federator requests to create the federation, which
// allows its developers and subscribers to run their applications
// on our cloudlets
func (p *PartnerApi) FederationOperatorPartnerCreate(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	opRegReq := OperatorRegistrationRequest{}
	if err := c.Bind(&opRegReq); err != nil {
		return err
	}

	selfFed, partnerFed, err := p.ValidateAndGetFederatorInfo(
		c,
		opRegReq.OrigFederationId,
		opRegReq.DestFederationId,
		opRegReq.OperatorId,
		opRegReq.CountryCode,
	)
	if err != nil {
		return err
	}

	// check that there is no existing federation with partner federator
	db := p.loggedDB(ctx)
	if partnerFed.PartnerRoleAccessToSelfZones {
		return fmt.Errorf("Federation already exists with partner federator (id:%q)",
			partnerFed.FederationId)
	}

	// Get list of zones to be shared with partner federator
	opShZones := []ormapi.FederatedSelfZone{}
	lookup := ormapi.FederatedSelfZone{
		FederationName: partnerFed.Name,
	}
	err = db.Where(&lookup).Find(&opShZones).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	out := OperatorRegistrationResponse{}
	out.RequestId = opRegReq.RequestId
	out.OrigFederationId = selfFed.FederationId
	out.DestFederationId = opRegReq.OrigFederationId
	out.OrigOperatorId = selfFed.OperatorId
	out.PartnerOperatorId = opRegReq.OperatorId
	out.MCC = selfFed.MCC
	out.MNC = selfFed.MNC
	out.LocatorEndPoint = selfFed.LocatorEndPoint
	for _, opShZone := range opShZones {
		zoneLookup := ormapi.FederatorZone{
			ZoneId: opShZone.ZoneId,
		}
		opZone := ormapi.FederatorZone{}
		err = db.Where(&zoneLookup).First(&opZone).Error
		if err != nil {
			return ormutil.DbErr(err)
		}

		partnerZone := ZoneInfo{
			ZoneId:      opZone.ZoneId,
			GeoLocation: opZone.GeoLocation,
			City:        opZone.City,
			State:       opZone.State,
			Locality:    opZone.Locality,
			EdgeCount:   len(opZone.Cloudlets),
		}
		out.PartnerZone = append(out.PartnerZone, partnerZone)
	}

	// Add federation with partner federator
	partnerFed.PartnerRoleAccessToSelfZones = true
	partnerFed.Revision = opRegReq.RequestId
	if err := db.Save(&partnerFed).Error; err != nil {
		return ormutil.DbErr(err)
	}

	// Return with list of zones to be shared
	return c.JSON(http.StatusOK, out)
}

// Remote partner federator sends this request to us to notify about
// the change in its MNC, MCC or locator URL
func (p *PartnerApi) FederationOperatorPartnerUpdate(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	opConf := UpdateMECNetConf{}
	if err := c.Bind(&opConf); err != nil {
		return err
	}

	_, partnerFed, err := p.ValidateAndGetFederatorInfo(
		c,
		opConf.OrigFederationId,
		opConf.DestFederationId,
		opConf.Operator,
		opConf.Country,
	)
	if err != nil {
		return err
	}

	if !partnerFed.PartnerRoleAccessToSelfZones {
		return fmt.Errorf("Federation does not exist with partner federator (id:%q)",
			partnerFed.FederationId)
	}

	db := p.loggedDB(ctx)
	update := false
	if opConf.MCC != "" {
		partnerFed.MCC = opConf.MCC
		update = true
	}
	if len(opConf.MNC) > 0 {
		partnerFed.MNC = opConf.MNC
		update = true
	}
	if opConf.LocatorEndPoint != "" {
		partnerFed.LocatorEndPoint = opConf.LocatorEndPoint
		update = true
	}

	if !update {
		return fmt.Errorf("Nothing to update")
	}

	partnerFed.Revision = opConf.RequestId
	err = db.Save(partnerFed).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	return c.JSON(http.StatusOK, "Federation attributes of partner federator updated successfully")
}

// Remote partner federator requests to delete the federation, which
// disallows its developers and subscribers to run their applications
// on our cloudlets
func (p *PartnerApi) FederationOperatorPartnerDelete(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	opFedReq := FederationRequest{}
	if err := c.Bind(&opFedReq); err != nil {
		return err
	}

	selfFed, partnerFed, err := p.ValidateAndGetFederatorInfo(
		c,
		opFedReq.OrigFederationId,
		opFedReq.DestFederationId,
		opFedReq.Operator,
		opFedReq.Country,
	)
	if err != nil {
		return err
	}

	if !partnerFed.PartnerRoleAccessToSelfZones {
		return fmt.Errorf("Federation does not exist with partner federator (id:%q)",
			partnerFed.FederationId)
	}

	// Check if all the self zones are deregistered by partner federator
	db := p.loggedDB(ctx)
	lookup := ormapi.FederatedSelfZone{
		FederationName: partnerFed.Name,
	}
	partnerZones := []ormapi.FederatedSelfZone{}
	err = db.Where(&lookup).Find(&partnerZones).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	for _, pZone := range partnerZones {
		if pZone.Registered {
			return fmt.Errorf("Cannot delete partner federation as zone %q of self federator (%q) "+
				"is registered by partner federator. Please deregister it before deleting the "+
				"partner federation", pZone.ZoneId,
				selfFed.FederationId)
		}
	}

	// Remove federation with partner federator
	partnerFed.PartnerRoleAccessToSelfZones = false
	partnerFed.Revision = opFedReq.RequestId
	if err = db.Save(&partnerFed).Error; err != nil {
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg("Deleted partner federation successfully"))
}

func (p *PartnerApi) GetZoneResourcesUpperLimit(ctx context.Context, region, operatorOrg string, cloudlets pq.StringArray) (map[string]uint64, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "get zone resources upper limit", "org", operatorOrg, "cloudlets", cloudlets)
	rc := ormutil.RegionContext{
		Region:    region,
		SkipAuthz: true,
		Database:  p.Database,
	}
	// get supported resources upper limit values
	totalRes := map[string]uint64{
		cloudcommon.ResourceRamMb: 0,
		cloudcommon.ResourceVcpus: 0,
		cloudcommon.ResourceDisk:  0,
	}
	for _, cloudletName := range cloudlets {
		cloudletRes := map[string]uint64{
			cloudcommon.ResourceRamMb: 0,
			cloudcommon.ResourceVcpus: 0,
			cloudcommon.ResourceDisk:  0,
		}
		cloudletKey := edgeproto.CloudletKey{
			Name:         string(cloudletName),
			Organization: operatorOrg,
		}
		err := ctrlclient.ShowCloudletStream(
			ctx, &rc, &edgeproto.Cloudlet{Key: cloudletKey}, p.ConnCache, nil,
			func(cloudlet *edgeproto.Cloudlet) error {
				for _, resQuota := range cloudlet.ResourceQuotas {
					if _, ok := cloudletRes[resQuota.Name]; ok {
						cloudletRes[resQuota.Name] += resQuota.Value
					}
				}
				return nil
			},
		)
		if err != nil {
			return nil, err
		}
		// If resource quota is empty, then use infra max value as the
		// upper limit quota of the cloudlet resources
		err = ctrlclient.ShowCloudletInfoStream(
			ctx, &rc, &edgeproto.CloudletInfo{Key: cloudletKey}, p.ConnCache, nil,
			func(cloudletInfo *edgeproto.CloudletInfo) error {
				for _, res := range cloudletInfo.ResourcesSnapshot.Info {
					if val, ok := cloudletRes[res.Name]; ok && val == 0 {
						cloudletRes[res.Name] += res.InfraMaxValue
					}
				}
				return nil
			},
		)
		if err != nil {
			return nil, err
		}
		for k, v := range cloudletRes {
			if _, ok := totalRes[k]; ok {
				totalRes[k] += v
			}
		}
	}
	return totalRes, nil
}

// Remote partner federator sends this request to us to register
// our zone i.e cloudlet. Once our cloudlet is registered,
// remote partner federator can then make it accessible to its
// developers or subscribers
func (p *PartnerApi) FederationOperatorZoneRegister(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	opRegReq := OperatorZoneRegister{}
	if err := c.Bind(&opRegReq); err != nil {
		return err
	}
	if len(opRegReq.Zones) == 0 {
		return fmt.Errorf("Must specify zones")
	}
	selfFed, partnerFed, err := p.ValidateAndGetFederatorInfo(
		c,
		opRegReq.OrigFederationId,
		opRegReq.DestFederationId,
		opRegReq.Operator,
		opRegReq.Country,
	)
	if err != nil {
		return err
	}

	if !partnerFed.PartnerRoleAccessToSelfZones {
		return fmt.Errorf("Federation does not exist with partner federator (id:%q)",
			partnerFed.FederationId)
	}

	// Check if zone exists
	db := p.loggedDB(ctx)
	zoneRegDetails := []ZoneRegisterDetails{}
	for _, zoneId := range opRegReq.Zones {
		lookup := ormapi.FederatedSelfZone{
			ZoneId:         zoneId,
			FederationName: partnerFed.Name,
		}
		existingZone := ormapi.FederatedSelfZone{}
		err = db.Where(&lookup).First(&existingZone).Error
		if err != nil {
			return ormutil.DbErr(err)
		}
		if existingZone.ZoneId == "" {
			return fmt.Errorf("Zone ID %q not shared with partner federator %s", zoneId,
				partnerFed.FederationId)
		}
		if existingZone.Registered {
			return fmt.Errorf("Zone ID %q is already registered by partner federator %s", zoneId,
				partnerFed.FederationId)
		}

		zlookup := ormapi.FederatorZone{
			ZoneId: zoneId,
		}
		fedZone := ormapi.FederatorZone{}
		err = db.Where(&zlookup).First(&fedZone).Error
		if err != nil {
			return ormutil.DbErr(err)
		}
		if fedZone.ZoneId == "" {
			return fmt.Errorf("Zone ID %q does not exist", zoneId)
		}
		zoneResLimit, err := p.GetZoneResourcesUpperLimit(ctx, fedZone.Region, fedZone.OperatorId, fedZone.Cloudlets)
		if err != nil {
			// ignore if failed to find upper limit for now
			log.SpanLog(ctx, log.DebugLevelApi, "failed to get zone resources upper limit", "zone", fedZone.ZoneId, "err", err)
		}
		upperLimitQuota := ZoneResourceInfo{}
		if val, ok := zoneResLimit[cloudcommon.ResourceVcpus]; ok {
			upperLimitQuota.CPU = int64(val)
		}
		if val, ok := zoneResLimit[cloudcommon.ResourceRamMb]; ok {
			upperLimitQuota.RAM = int64(val) / 1024 // RAM is in GBs
		}
		if val, ok := zoneResLimit[cloudcommon.ResourceDisk]; ok {
			upperLimitQuota.Disk = int64(val)
		}

		existingZone.Registered = true
		existingZone.Revision = opRegReq.RequestId
		if err := db.Save(&existingZone).Error; err != nil {
			return ormutil.DbErr(err)
		}
		zoneRegDetails = append(zoneRegDetails, ZoneRegisterDetails{
			ZoneId:            zoneId,
			RegistrationToken: selfFed.FederationId,
			UpperLimitQuota:   upperLimitQuota,
			// Guaranteed resources are the resources that you can most definitely utilize
			// from an operations standpoint, going beyond the guaranteed resources limit
			// would likely mean some form of compromise in service uptime.
			// In our case, upper limit quota is the guaranteed resources
			GuaranteedResources: upperLimitQuota,
		})
	}
	// Share zone details
	resp := OperatorZoneRegisterResponse{}
	resp.RequestId = opRegReq.RequestId
	resp.LeadOperatorId = selfFed.OperatorId
	resp.PartnerOperatorId = opRegReq.Operator
	resp.FederationId = selfFed.FederationId
	resp.Zone = zoneRegDetails
	return c.JSON(http.StatusOK, resp)
}

// Remote partner federator deregisters our zone i.e. cloudlet.
// This will ensure that our cloudlet is no longer accessible
// to remote partner federator's developers or subscribers
func (p *PartnerApi) FederationOperatorZoneDeRegister(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	opRegReq := ZoneMultiRequest{}
	if err := c.Bind(&opRegReq); err != nil {
		return err
	}
	if len(opRegReq.Zones) == 0 {
		return fmt.Errorf("Must specify zones")
	}
	_, partnerFed, err := p.ValidateAndGetFederatorInfo(
		c,
		opRegReq.OrigFederationId,
		opRegReq.DestFederationId,
		opRegReq.Operator,
		opRegReq.Country,
	)
	if err != nil {
		return err
	}

	if !partnerFed.PartnerRoleAccessToSelfZones {
		return fmt.Errorf("Federation does not exist with partner federator (id:%q)",
			partnerFed.FederationId)
	}

	db := p.loggedDB(ctx)
	zones := []ormapi.FederatedSelfZone{}
	for _, zoneId := range opRegReq.Zones {
		lookup := ormapi.FederatedSelfZone{
			ZoneId:         zoneId,
			FederationName: partnerFed.Name,
		}
		existingZone := ormapi.FederatedSelfZone{}
		err = db.Where(&lookup).First(&existingZone).Error
		if err != nil {
			return ormutil.DbErr(err)
		}
		if existingZone.ZoneId == "" {
			return fmt.Errorf("Zone ID %q not shared with partner federator %s", zoneId,
				partnerFed.FederationId)
		}
		if !existingZone.Registered {
			return fmt.Errorf("Zone ID %q is not registered by partner federator %s", zoneId,
				partnerFed.FederationId)
		}
		zones = append(zones, existingZone)
	}

	// TODO: make sure no AppInsts are deployed on the cloudlet
	//       before the zone is deregistered

	for _, existingZone := range zones {
		existingZone.Registered = false
		existingZone.Revision = opRegReq.RequestId
		if err := db.Save(&existingZone).Error; err != nil {
			return ormutil.DbErr(err)
		}
	}

	return c.JSON(http.StatusOK, "Zone(s) deregistered successfully")
}

// Remote partner federator sends this request to us to share its zone.
// It is triggered by partner federator when it has a new zone available
// and it wishes to share the zone with us
func (p *PartnerApi) FederationOperatorZoneShare(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	opZoneShare := NotifyPartnerOperatorZone{}
	if err := c.Bind(&opZoneShare); err != nil {
		return err
	}

	if opZoneShare.PartnerZone.ZoneId == "" {
		return fmt.Errorf("Must specify zone ID")
	}

	selfFed, partnerFed, err := p.ValidateAndGetFederatorInfo(
		c,
		opZoneShare.OrigFederationId,
		opZoneShare.DestFederationId,
		opZoneShare.Operator,
		opZoneShare.Country,
	)
	if err != nil {
		return err
	}

	if !partnerFed.PartnerRoleShareZonesWithSelf {
		return fmt.Errorf("No federation with partner federator (%s) to access self zones exists",
			partnerFed.FederationId)
	}

	db := p.loggedDB(ctx)
	zoneId := opZoneShare.PartnerZone.ZoneId
	zoneObj := ormapi.FederatedPartnerZone{}
	zoneObj.SelfOperatorId = selfFed.OperatorId
	zoneObj.FederationName = partnerFed.Name
	zoneObj.ZoneId = zoneId
	zoneObj.OperatorId = partnerFed.OperatorId
	zoneObj.CountryCode = partnerFed.CountryCode
	zoneObj.GeoLocation = opZoneShare.PartnerZone.GeoLocation
	zoneObj.City = opZoneShare.PartnerZone.City
	zoneObj.Locality = opZoneShare.PartnerZone.Locality
	zoneObj.Revision = opZoneShare.RequestId
	if err := db.Create(&zoneObj).Error; err != nil {
		if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
			return fmt.Errorf("Zone ID %q already exists for partner federator %s", zoneId,
				partnerFed.FederationId)
		}
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg("Added zone successfully"))
}

// Remote partner federator sends this request to us to unshare its zone.
// This api is triggered when the remote partner federator decides to unshare
// one of its zone with us
func (p *PartnerApi) FederationOperatorZoneUnShare(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	opZone := ZoneSingleRequest{}
	if err := c.Bind(&opZone); err != nil {
		return err
	}

	if opZone.Zone == "" {
		return fmt.Errorf("Must specify zone ID")
	}

	_, partnerFed, err := p.ValidateAndGetFederatorInfo(
		c,
		opZone.OrigFederationId,
		opZone.DestFederationId,
		opZone.Operator,
		opZone.Country,
	)
	if err != nil {
		return err
	}

	if !partnerFed.PartnerRoleShareZonesWithSelf {
		return fmt.Errorf("No federation with partner federator (%s) to access self zones exists",
			partnerFed.FederationId)
	}

	// Check if zone exists
	db := p.loggedDB(ctx)
	zoneId := opZone.Zone
	lookup := ormapi.FederatedPartnerZone{
		FederationName: partnerFed.Name,
		FederatorZone: ormapi.FederatorZone{
			ZoneId: zoneId,
		},
	}
	existingZone := ormapi.FederatedPartnerZone{}
	res := db.Where(&lookup).First(&existingZone)
	if !res.RecordNotFound() && err != nil {
		return ormutil.DbErr(err)
	}
	if existingZone.ZoneId == "" {
		return fmt.Errorf("Zone ID %q does not exist for partner federator (id:%q)", zoneId,
			partnerFed.FederationId)
	}

	// Ensure that this zone is not registered by us
	if existingZone.Registered {
		return fmt.Errorf("Cannot remove partner federator zone %q as it is registered locally. "+
			"Please deregister it before unsharing the zone", existingZone.ZoneId)
	}

	// Delete zone from shared list in DB
	if err := db.Delete(&existingZone).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			return ormutil.DbErr(err)
		}
	}

	return ormutil.SetReply(c, ormutil.Msg("Removed zone successfully"))
}
