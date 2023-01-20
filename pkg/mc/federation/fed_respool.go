package federation

import (
	"fmt"

	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/labstack/echo/v4"
)

func (p *PartnerApi) CreateResourcePools(c echo.Context, fedCtxId FederationContextId, zoneId ZoneIdentifier, appProviderId AppProviderId) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) RemoveISVResPool(c echo.Context, fedCtxId FederationContextId, zoneId ZoneIdentifier, appProviderId AppProviderId, poolId PoolId) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) UpdateISVResPool(c echo.Context, fedCtxId FederationContextId, zoneId ZoneIdentifier, appProviderId AppProviderId, poolId PoolId) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) ViewISVResPool(c echo.Context, fedCtxId FederationContextId, zoneId ZoneIdentifier, appProviderId AppProviderId) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) PartnerResourceStatusChange(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	in := fedewapi.FederationContextIdIsvResourceZoneZoneIdAppProviderAppProviderIdGetRequest{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	// lookup federation consumer based on claims
	consumer, err := p.lookupConsumer(c, in.FederationContextId)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "partner resource status change", "consumer", consumer.Name, "operatorid", consumer.OperatorId, "request", in)
	return nil
}
