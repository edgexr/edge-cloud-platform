package federation

import (
	"fmt"

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

func (p *PartnerApi) InstallApp(c echo.Context, fedCtxId FederationContextId) error {
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

	// lookup zone basis so we can figure out region
	basis, err := p.lookupProviderZoneBase(ctx, in.ZoneInfo.ZoneId, provider.OperatorId)
	if err != nil {
		return err
	}

	// lookup zone to make sure zone is shared
	zone, err := p.LookupProviderZone(ctx, provider.Name, in.ZoneInfo.ZoneId)
	if err != nil {
		return err
	}
	if zone.Status != StatusRegistered {
		return fmt.Errorf("Specified zone is not registered")
	}

	// Create AppInst
	rc := ormutil.RegionContext{
		Region:    basis.Region,
		SkipAuthz: true,
		Database:  p.database,
	}
	appInstId := uuid.New().String()

	appInstIn := edgeproto.AppInst{
		Key:      getAppInstKey(provider, in.AppId, basis.Cloudlets[0]),
		UniqueId: appInstId,
	}
	log.SpanLog(ctx, log.DebugLevelApi, "Federation create appinst", "appInst", appInstIn)
	err = ctrlclient.CreateAppInstStream(
		ctx, &rc, &appInstIn, p.connCache,
		func(res *edgeproto.Result) error {
			return nil
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (p *PartnerApi) RemoveApp(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier, appInstId InstanceIdentifier, zoneId ZoneIdentifier) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}
	// lookup basis to find cloudlet name and region
	basis, err := p.lookupProviderZoneBase(ctx, string(zoneId), provider.OperatorId)
	if err != nil {
		return err
	}

	appInst := edgeproto.AppInst{
		Key: getAppInstKey(provider, string(appId), basis.Cloudlets[0]),
	}
	rc := ormutil.RegionContext{
		Region:    basis.Region,
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

func getAppInstKey(provider *ormapi.FederationProvider, appId, cloudletName string) edgeproto.AppInstKey {
	return edgeproto.AppInstKey{
		AppKey: edgeproto.AppKey{
			Organization: provider.FederationContextId,
			Name:         appId,
			Version:      AllAppsVersion,
		},
		ClusterInstKey: edgeproto.VirtualClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: cloudcommon.AutoClusterPrefix + appId,
			},
			CloudletKey: edgeproto.CloudletKey{
				Name:         cloudletName,
				Organization: provider.OperatorId,
			},
			Organization: provider.FederationContextId,
		},
	}
}

func (p *PartnerApi) GetAllAppInstances(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier, appProviderId AppProviderId) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) GetAppInstanceDetails(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier, appInstId InstanceIdentifier, zoneId ZoneIdentifier) error {
	return fmt.Errorf("not implemented yet")
}
