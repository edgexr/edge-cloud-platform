package federation

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	dme_proto "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	fedcommon "github.com/edgexr/edge-cloud-platform/pkg/mc/federation/common"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/labstack/echo/v4"
)

func (p *PartnerApi) LookupProviderZone(ctx context.Context, providerName, zoneId, operatorId string) (*ormapi.ProviderZone, error) {
	if providerName == "" {
		return nil, fmt.Errorf("missing federation provider name")
	}
	if zoneId == "" {
		return nil, fmt.Errorf("missing zone id")
	}
	if operatorId == "" {
		return nil, fmt.Errorf("missing operator id")
	}
	lookup := ormapi.ProviderZone{
		ProviderName: providerName,
		ZoneId:       zoneId,
		OperatorId:   operatorId,
	}
	db := p.loggedDB(ctx)
	res := db.Where(&lookup).First(&lookup)
	if res.RecordNotFound() {
		return nil, fmt.Errorf("Zone not found")
	}
	if res.Error != nil {
		return nil, ormutil.DbErr(res.Error)
	}
	return &lookup, nil
}

func (p *PartnerApi) LookupConsumerZone(ctx context.Context, consumerName, zoneId, operatorId string) (*ormapi.ConsumerZone, error) {
	if consumerName == "" {
		return nil, fmt.Errorf("missing federation consumer name")
	}
	if zoneId == "" {
		return nil, fmt.Errorf("missing zone id")
	}
	if operatorId == "" {
		return nil, fmt.Errorf("missing operator id")
	}
	lookup := ormapi.ConsumerZone{
		ConsumerName: consumerName,
		ZoneId:       zoneId,
		OperatorId:   operatorId,
	}
	db := p.loggedDB(ctx)
	res := db.Where(&lookup).First(&lookup)
	if res.RecordNotFound() {
		return nil, fmt.Errorf("Zone not found")
	}
	if res.Error != nil {
		return nil, ormutil.DbErr(res.Error)
	}
	return &lookup, nil
}

func (p *PartnerApi) lookupProviderZoneBase(ctx context.Context, zoneId, operatorId string) (*ormapi.ProviderZoneBase, error) {
	basis := ormapi.ProviderZoneBase{
		ZoneId:     zoneId,
		OperatorId: operatorId,
	}
	db := p.loggedDB(ctx)
	res := db.Where(&basis).First(&basis)
	if !res.RecordNotFound() && res.Error != nil {
		return nil, ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		return nil, fmt.Errorf("Zone not found")
	}
	return &basis, nil
}

// Remote partner federator sends this request to us to register
// our zone i.e cloudlet. Once our cloudlet is registered,
// remote partner federator can then make it accessible to its
// developers or subscribers
func (p *PartnerApi) ZoneSubscribe(c echo.Context, fedCtxId FederationContextId) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	in := fedewapi.ZoneRegistrationRequestData{}
	if err := c.Bind(&in); err != nil {
		return err
	}
	if len(in.AcceptedAvailabilityZones) == 0 {
		return fmt.Errorf("Must specify accepted availability zones")
	}
	if in.AvailZoneNotifLink == "" {
		return fmt.Errorf("Must specify availZoneNotifLink")
	}

	out := fedewapi.ZoneRegistrationResponseData{}

	db := p.loggedDB(ctx)
	for _, zoneId := range in.AcceptedAvailabilityZones {
		zone, err := p.LookupProviderZone(ctx, provider.Name, zoneId, provider.OperatorId)
		if err != nil {
			return err
		}
		zoneInfo, err := p.getZoneRegisteredData(ctx, provider, zone)
		if err != nil {
			return err
		}
		out.AcceptedZoneResourceInfo = append(out.AcceptedZoneResourceInfo, *zoneInfo)
		// Ok if already registered, it's just a no-op
		if zone.Status == StatusUnregistered {
			zone.Status = StatusRegistered
			zone.PartnerNotifyZoneURI = in.AvailZoneNotifLink
			if err := db.Save(&zone).Error; err != nil {
				return ormutil.DbErr(err)
			}
		}
	}
	return c.JSON(http.StatusOK, out)
}

// Remote partner federator deregisters our zone i.e. cloudlet.
// This will ensure that our cloudlet is no longer accessible
// to remote partner federator's developers or subscribers
func (p *PartnerApi) ZoneUnsubscribe(c echo.Context, fedCtxId FederationContextId, zoneId ZoneIdentifier) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	db := p.loggedDB(ctx)
	zone := ormapi.ProviderZone{
		ZoneId:       string(zoneId),
		OperatorId:   provider.OperatorId,
		ProviderName: provider.Name,
	}
	res := db.Where(&zone).First(&zone)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		// allow partner to unsubscribe since it doesn't exist
		log.SpanLog(ctx, log.DebugLevelApi, "Unsubscribe from non-shared zone, ignore error", "zone", zoneId)
		return nil
	}
	if zone.Status != StatusUnregistered {
		zone.Status = StatusUnregistered
		zone.PartnerNotifyZoneURI = ""
		if err := db.Save(&zone).Error; err != nil {
			return ormutil.DbErr(err)
		}
	}
	return nil
}

// Partner asks for information about a zone we are providing for their use.
func (p *PartnerApi) GetZoneData(c echo.Context, fedCtxId FederationContextId, zoneId ZoneIdentifier) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	zone, err := p.LookupProviderZone(ctx, provider.Name, string(zoneId), provider.OperatorId)
	if err != nil {
		return err
	}
	zoneInfo, err := p.getZoneRegisteredData(ctx, provider, zone)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, zoneInfo)
}

func (p *PartnerApi) getZoneRegisteredData(ctx context.Context, provider *ormapi.FederationProvider, zone *ormapi.ProviderZone) (*fedewapi.ZoneRegisteredData, error) {
	db := p.loggedDB(ctx)
	basis := ormapi.ProviderZoneBase{
		ZoneId:     zone.ZoneId,
		OperatorId: provider.OperatorId,
	}
	res := db.Where(&basis).First(&basis)
	if !res.RecordNotFound() && res.Error != nil {
		return nil, ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		return nil, fmt.Errorf("Zone %q shared but zone basis is missing, please contact support", zone.ZoneId)
	}

	resourceLimits, flavors, err := p.getZoneResources(ctx, &basis)
	if err != nil {
		return nil, fmt.Errorf("Failed to get details for zone %q", zone.ZoneId)
	}
	zoneInfo := fedewapi.ZoneRegisteredData{}
	zoneInfo.ZoneId = zone.ZoneId
	if len(resourceLimits) > 0 {
		zoneInfo.ComputeResourceQuotaLimits = resourceLimits
	}
	if len(flavors) > 0 {
		zoneInfo.FlavoursSupported = flavors
	}
	return &zoneInfo, nil
}

func (p *PartnerApi) getZoneResources(ctx context.Context, basis *ormapi.ProviderZoneBase) ([]fedewapi.ComputeResourceInfo, []fedewapi.Flavour, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "get zone resources upper limit", "org", basis.OperatorId, "cloudlets", basis.Cloudlets)
	rc := ormutil.RegionContext{
		Region:    basis.Region,
		SkipAuthz: true,
		Database:  p.database,
	}
	// get supported resources upper limit values
	totalRes := map[string]uint64{
		cloudcommon.ResourceRamMb:  0,
		cloudcommon.ResourceVcpus:  0,
		cloudcommon.ResourceDiskGb: 0,
	}
	// take flavors from the first cloudletinfo only
	var firstCloudletInfo *edgeproto.CloudletInfo

	for _, cloudletName := range basis.Cloudlets {
		cloudletRes := map[string]uint64{
			cloudcommon.ResourceRamMb:  0,
			cloudcommon.ResourceVcpus:  0,
			cloudcommon.ResourceDiskGb: 0,
		}
		cloudletKey := edgeproto.CloudletKey{
			Name:         string(cloudletName),
			Organization: basis.OperatorId,
		}
		err := ctrlclient.ShowCloudletStream(
			ctx, &rc, &edgeproto.Cloudlet{Key: cloudletKey}, p.connCache, nil,
			func(cloudlet *edgeproto.Cloudlet) error {
				log.SpanLog(ctx, log.DebugLevelApi, "getZoneResources", "cloudlet", cloudlet)
				for _, resQuota := range cloudlet.ResourceQuotas {
					if _, ok := cloudletRes[resQuota.Name]; ok {
						cloudletRes[resQuota.Name] += resQuota.Value
					}
				}
				return nil
			},
		)
		if err != nil {
			return nil, nil, err
		}
		// If resource quota is empty, then use infra max value as the
		// upper limit quota of the cloudlet resources
		err = ctrlclient.ShowCloudletInfoStream(
			ctx, &rc, &edgeproto.CloudletInfo{Key: cloudletKey}, p.connCache, nil,
			func(cloudletInfo *edgeproto.CloudletInfo) error {
				log.SpanLog(ctx, log.DebugLevelApi, "getZoneResources", "cloudletinfo", cloudletInfo)
				for _, res := range cloudletInfo.ResourcesSnapshot.Info {
					if val, ok := cloudletRes[res.Name]; ok && val == 0 {
						cloudletRes[res.Name] += res.InfraMaxValue
					}
				}
				if firstCloudletInfo == nil {
					firstCloudletInfo = cloudletInfo
				}
				return nil
			},
		)
		if err != nil {
			return nil, nil, err
		}
		for k, v := range cloudletRes {
			if _, ok := totalRes[k]; ok {
				totalRes[k] += v
			}
		}
	}
	resourceLimits := []fedewapi.ComputeResourceInfo{{
		CpuArchType: string(fedewapi.CPUARCHTYPE_X86_64),
		NumCPU:      int32(totalRes[cloudcommon.ResourceVcpus]),
		Memory:      int64(totalRes[cloudcommon.ResourceRamMb]),
		DiskStorage: int32(totalRes[cloudcommon.ResourceDiskGb]),
	}}

	outFlavors := []fedewapi.Flavour{}
	log.SpanLog(ctx, log.DebugLevelApi, "getZoneResources", "first cloudletinfo", firstCloudletInfo)
	if firstCloudletInfo != nil {
		for _, flavor := range firstCloudletInfo.Flavors {
			outFlavor := fedewapi.Flavour{
				CpuArchType:      fedewapi.CPUARCHTYPE_X86_64,
				FlavourId:        flavor.Name,
				Gpu:              nil, // TODO,
				MemorySize:       int32(flavor.Ram),
				NumCPU:           int32(flavor.Vcpus),
				StorageSize:      int32(flavor.Disk),
				SupportedOSTypes: []fedewapi.OSType{
					// TODO, not sure it's needed, maybe arch
				},
			}
			outFlavors = append(outFlavors, outFlavor)
		}
	}

	return resourceLimits, outFlavors, nil
}

// Serialize zone registration to avoid race conditions.
// Would be better to do this per consumer, but
// for now err on the side of safety.
var zoneRegMutex sync.Mutex

// RegisterConsumerZones creates Cloudlets in the consumer region,
// which can then be targeted by users to deploy apps on the partner
// federation's zones.
func (p *PartnerApi) RegisterConsumerZones(ctx context.Context, consumer *ormapi.FederationConsumer, region string, zoneIds []string) error {
	rc := &ormutil.RegionContext{}
	rc.Username = consumer.FederationContextId
	rc.Region = region
	rc.Database = p.database
	db := p.loggedDB(ctx)

	zoneRegMutex.Lock()
	defer zoneRegMutex.Unlock()

	// Check that specified zones exist and
	// skip ones that are already registered.
	zonesMap := make(map[string]*ormapi.ConsumerZone)
	regZoneIds := []string{}
	for _, zoneId := range zoneIds {
		zone, err := p.LookupConsumerZone(ctx, consumer.Name, zoneId, consumer.OperatorId)
		if err != nil {
			return err
		}
		if zone.Status == StatusRegistered {
			// already registered
			continue
		}
		regZoneIds = append(regZoneIds, zoneId)
		zonesMap[zone.ZoneId] = zone
	}

	// Tell partner we're registering the zones
	fedClient, err := p.ConsumerPartnerClient(ctx, consumer)
	if err != nil {
		return err
	}
	opZoneReg := fedewapi.ZoneRegistrationRequestData{
		AcceptedAvailabilityZones: regZoneIds,
		AvailZoneNotifLink:        ApiRoot + PartnerZoneNotifyPath,
	}
	opZoneRes := fedewapi.ZoneRegistrationResponseData{}
	apiPath := fmt.Sprintf("/%s/%s/zones", ApiRoot, consumer.FederationContextId)
	_, err = fedClient.SendRequest(ctx, "POST", apiPath, &opZoneReg, &opZoneRes, nil)
	if err != nil {
		return err
	}

	// Create cloudlet for each zone and mark ConsumerZone as registered
	for _, zoneInfo := range opZoneRes.AcceptedZoneResourceInfo {
		cb := func(res *edgeproto.Result) error {
			log.SpanLog(ctx, log.DebugLevelApi, "add partner zone as cloudlet progress", "zone", zoneInfo.ZoneId, "progress result", res)
			return nil
		}
		zone, found := zonesMap[zoneInfo.ZoneId]
		if !found {
			log.SpanLog(ctx, log.DebugLevelApi, "Unexpected zone id response from registering partner zones", "id", zoneInfo.ZoneId, "requested", regZoneIds)
			continue
		}
		log.SpanLog(ctx, log.DebugLevelApi, "register consumer zone info", "zoneinfo", zoneInfo)
		lat, long, err := fedcommon.ParseGeoLocation(zone.GeoLocation)
		if err != nil {
			return err
		}
		fedCloudlet := edgeproto.Cloudlet{
			Key: edgeproto.CloudletKey{
				Name:                  zone.ZoneId,
				Organization:          consumer.OperatorId,
				FederatedOrganization: consumer.Name,
			},
			Location: dme_proto.Loc{
				Latitude:  lat,
				Longitude: long,
			},
			PlatformType: edgeproto.PlatformType_PLATFORM_TYPE_FEDERATION,
			// TODO: This should be removed as a required field
			NumDynamicIps: int32(10),
			FederationConfig: edgeproto.FederationConfig{
				FederationContextId:   consumer.FederationContextId,
				PartnerFederationAddr: consumer.PartnerAddr,
				FederationDbId:        uint64(consumer.ID),
			},
		}
		var quotaLimit *fedewapi.ComputeResourceInfo
		if zoneInfo.ComputeResourceQuotaLimits != nil {
			for _, quota := range zoneInfo.ComputeResourceQuotaLimits {
				if quota.CpuArchType == string(fedewapi.CPUARCHTYPE_X86_64) {
					quotaLimit = &quota
					break
				}
			}
		}
		if quotaLimit != nil {
			if quotaLimit.NumCPU > 0 {
				fedCloudlet.ResourceQuotas = append(fedCloudlet.ResourceQuotas, edgeproto.ResourceQuota{
					Name:  cloudcommon.ResourceVcpus,
					Value: uint64(quotaLimit.NumCPU),
				})
			}
			if quotaLimit.Memory > 0 {
				fedCloudlet.ResourceQuotas = append(fedCloudlet.ResourceQuotas, edgeproto.ResourceQuota{
					Name:  cloudcommon.ResourceRamMb,
					Value: uint64(quotaLimit.Memory),
				})
			}
			if quotaLimit.DiskStorage > 0 {
				fedCloudlet.ResourceQuotas = append(fedCloudlet.ResourceQuotas, edgeproto.ResourceQuota{
					Name:  cloudcommon.ResourceDiskGb,
					Value: uint64(quotaLimit.DiskStorage),
				})
			}
		}
		log.SpanLog(ctx, log.DebugLevelApi, "add partner zone as cloudlet", "key", fedCloudlet.Key)
		err = ctrlclient.CreateCloudletStream(ctx, rc, &fedCloudlet, p.connCache, cb)
		if err != nil {
			return err
		}
		// create cloudlet info with flavors
		fedCloudletInfo := edgeproto.CloudletInfo{
			Key:   fedCloudlet.Key,
			State: dme_proto.CloudletState_CLOUDLET_STATE_READY,
		}
		for _, flavor := range zoneInfo.FlavoursSupported {
			flavorInfo := edgeproto.FlavorInfo{
				Name:  flavor.FlavourId,
				Vcpus: uint64(flavor.NumCPU),
				Ram:   uint64(flavor.MemorySize),
				Disk:  uint64(flavor.StorageSize),
			}
			fedCloudletInfo.Flavors = append(fedCloudletInfo.Flavors, &flavorInfo)
		}
		log.SpanLog(ctx, log.DebugLevelApi, "add partner zone cloudlet info", "key", fedCloudlet.Key)
		_, err = ctrlclient.InjectCloudletInfoObj(ctx, rc, &fedCloudletInfo, p.connCache)
		if err != nil {
			// undo
			undoErr := ctrlclient.DeleteCloudletStream(ctx, rc, &fedCloudlet, p.connCache, cb)
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "undo failed to delete cloudlet", "err", undoErr)
			}
			return err
		}

		// Mark zone as registered in DB
		zone.Status = StatusRegistered
		err = db.Save(zone).Error
		if err != nil {
			// undo
			undoErr := ctrlclient.DeleteCloudletStream(ctx, rc, &fedCloudlet, p.connCache, cb)
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "undo failed to delete Cloudlet", "err", undoErr)
			}
			_, undoErr = ctrlclient.EvictCloudletInfoObj(ctx, rc, &fedCloudletInfo, p.connCache)
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "undo failed to delete CloudletInfo", "err", undoErr)
			}
			return ormutil.DbErr(err)
		}
	}
	return nil
}

// DeregisterConsumerZones deletes Cloudlets in the region that
// correspond to shared zones from the partner.
func (p *PartnerApi) DeregisterConsumerZones(ctx context.Context, consumer *ormapi.FederationConsumer, zoneIds []string) error {
	db := p.loggedDB(ctx)

	zoneRegMutex.Lock()
	defer zoneRegMutex.Unlock()

	// lookup zones
	zonesRegionMap := make(map[string]map[string]*ormapi.ConsumerZone)
	for _, inZone := range zoneIds {
		zone, err := p.LookupConsumerZone(ctx, consumer.Name, inZone, consumer.OperatorId)
		if err != nil {
			return err
		}
		if zone.Status == StatusUnregistered {
			continue
		}
		zones, ok := zonesRegionMap[consumer.Region]
		if !ok {
			zones = make(map[string]*ormapi.ConsumerZone)
			zonesRegionMap[consumer.Region] = zones
		}
		zones[zone.ZoneId] = zone
	}

	fedClient, err := p.ConsumerPartnerClient(ctx, consumer)
	if err != nil {
		return err
	}
	for region, zonesMap := range zonesRegionMap {
		rc := &ormutil.RegionContext{}
		rc.Username = consumer.FederationContextId
		rc.Region = region
		rc.Database = p.database
		cb := func(res *edgeproto.Result) error {
			log.SpanLog(ctx, log.DebugLevelApi, "delete partner zone as cloudlet progress", "progress result", res)
			return nil
		}

		// Delete the zone added as cloudlet from regional controller.
		// This also ensures that no AppInsts are deployed on the cloudlet
		// before the zone is deregistered
		for _, existingZone := range zonesMap {
			// delete cloudlet
			fedCloudlet := edgeproto.Cloudlet{
				Key: edgeproto.CloudletKey{
					Name:                  existingZone.ZoneId,
					Organization:          consumer.OperatorId,
					FederatedOrganization: consumer.Name,
				},
			}
			log.SpanLog(ctx, log.DebugLevelApi, "delete partner zone as cloudlet", "key", fedCloudlet.Key)
			err := ctrlclient.DeleteCloudletStream(ctx, rc, &fedCloudlet, p.connCache, cb)
			if err != nil && !strings.Contains(err.Error(), fedCloudlet.Key.NotFoundError().Error()) {
				return err
			}
			// delete cloudletinfo is not required
			// because delete cloudlet will delete it.
			// notify partner
			apiPath := fmt.Sprintf("/%s/%s/zones/%s", ApiRoot, consumer.FederationContextId, existingZone.ZoneId)
			_, err = fedClient.SendRequest(ctx, "DELETE", apiPath, nil, nil, nil)
			if err != nil {
				return err
			}
			// update status
			existingZone.Status = StatusUnregistered
			err = db.Save(&existingZone).Error
			if err != nil {
				return ormutil.DbErr(err)
			}
		}
	}
	return nil
}

func (p *PartnerApi) PartnerZoneNotify(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	fedCtxId := c.Param(PathVarFederationContextId)
	zoneId := c.Param(PathVarZoneId)
	// lookup federation consumer based on claims
	consumer, err := p.lookupConsumer(c, FederationContextId(fedCtxId))
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "partner notify", "consumer", consumer.Name, "operatorid", consumer.OperatorId, "zoneId", zoneId)
	in := fedewapi.FederationContextIdZonesPostRequest{}
	if err = c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	// Notification about resource availability,
	// nothing for us to do.
	return nil
}
