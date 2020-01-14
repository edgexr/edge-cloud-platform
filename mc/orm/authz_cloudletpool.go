package orm

import (
	"context"
	"fmt"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func authzDeleteCloudletPool(ctx context.Context, region, username string, obj *edgeproto.CloudletPool, resource, action string) error {
	if !authorized(ctx, username, "", resource, action) {
		return echo.ErrForbidden
	}

	// check if cloudletpool is in use by orgcloudletpool
	lookup := ormapi.OrgCloudletPool{}
	pools := make([]ormapi.OrgCloudletPool, 0)
	lookup.Region = region
	lookup.CloudletPool = obj.Key.Name
	db := loggedDB(ctx)
	res := db.Where(&lookup).Find(&pools)
	if res.Error != nil {
		return res.Error
	}
	if res.RecordNotFound() || len(pools) == 0 {
		return nil
	}
	return fmt.Errorf("Cannot delete CloudletPool region %s name %s because it is in use by OrgCloudletPool org %s", region, obj.Key.Name, pools[0].Org)
}
