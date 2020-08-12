package orm

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func authzDeleteCloudletPool(ctx context.Context, region, username string, obj *edgeproto.CloudletPool, resource, action string) error {
	if err := authorized(ctx, username, obj.Key.Organization, resource, action); err != nil {
		return err
	}

	// check if cloudletpool is in use by orgcloudletpool
	pools := make([]ormapi.OrgCloudletPool, 0)
	db := loggedDB(ctx)
	// explicitly list fields to avoid being ignored if 0 or emtpy string
	res := db.Where(map[string]interface{}{"region": region, "cloudlet_pool": obj.Key.Name, "cloudlet_pool_org": obj.Key.Organization}).Find(&pools)
	if res.Error != nil {
		return res.Error
	}
	if res.RecordNotFound() || len(pools) == 0 {
		return nil
	}
	return fmt.Errorf("Cannot delete CloudletPool region %s name %s because it is in use by OrgCloudletPool org %s", region, obj.Key.Name, pools[0].Org)
}
