package federation

import (
	"fmt"

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
