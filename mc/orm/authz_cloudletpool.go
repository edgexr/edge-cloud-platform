package orm

import (
	"context"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
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
	usedBy := make([]string, 0)
	for _, pool := range pools {
		usedBy = append(usedBy, fmt.Sprintf("%s %s", pool.Org, pool.Type))
	}
	return fmt.Errorf("Cannot delete CloudletPool region %s name %s because it is referenced by %s", region, obj.Key.Name, strings.Join(usedBy, ", "))
}

func authzCreateCloudletPool(ctx context.Context, region, username string, obj *edgeproto.CloudletPool, resource, action string) error {
	if err := authorized(ctx, username, obj.Key.Organization, resource, action, withRequiresOrg(obj.Key.Organization)); err != nil {
		return err
	}
	// OrgCloudletPool memberships cannot exist before the CloudletPool
	// exists, so any developers on the cloudlets would not be part of
	// the pool.
	rc := RegionContext{}
	rc.username = username
	rc.region = region
	rc.skipAuthz = true
	for _, cloudletName := range obj.Cloudlets {
		key := edgeproto.CloudletKey{
			Name:         cloudletName,
			Organization: obj.Key.Organization,
		}
		err := GetOrganizationsOnCloudletStream(ctx, &rc, &key, func(org *edgeproto.Organization) error {
			if org.Name == cloudcommon.OrganizationMobiledgeX {
				return nil
			}
			return fmt.Errorf("Cannot create CloudletPool with cloudlet %s with existing developer %s ClusterInsts or AppInsts. To include them as part of the pool, first create an empty pool, invite the developer to the pool, then add the cloudlet to the pool.", key.Name, org.Name)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func authzUpdateCloudletPool(ctx context.Context, region, username string, pool *edgeproto.CloudletPool, resource, action string) error {
	return authzCloudletPoolMembers(ctx, region, username, pool, resource, action)
}

func authzAddCloudletPoolMember(ctx context.Context, region, username string, obj *edgeproto.CloudletPoolMember, resource, action string) error {
	pool := &edgeproto.CloudletPool{}
	pool.Key = obj.Key
	pool.Cloudlets = []string{obj.CloudletName}
	return authzCloudletPoolMembers(ctx, region, username, pool, resource, action)
}

func authzCloudletPoolMembers(ctx context.Context, region, username string, pool *edgeproto.CloudletPool, resource, action string) error {
	if err := authorized(ctx, username, pool.Key.Organization, resource, action); err != nil {
		return err
	}
	// find developers that are part of pool.
	filter := make(map[string]interface{})
	filter["region"] = region
	filter["cloudlet_pool"] = pool.Key.Name
	filter["cloudlet_pool_org"] = pool.Key.Organization
	orgPools, err := showCloudletPoolAccessObj(ctx, username, filter, accessTypeGranted)
	if err != nil {
		return err
	}
	orgPoolsMap := make(map[string]struct{})
	for _, orgPool := range orgPools {
		orgPoolsMap[orgPool.Org] = struct{}{}
	}
	// make sure that cloudlet being added to the pool does not
	// have AppInsts/ClusterInsts from developers not part of the pool.
	rc := RegionContext{}
	rc.username = username
	rc.region = region
	rc.skipAuthz = true
	for _, cloudletName := range pool.Cloudlets {
		key := edgeproto.CloudletKey{
			Name:         cloudletName,
			Organization: pool.Key.Organization,
		}
		err = GetOrganizationsOnCloudletStream(ctx, &rc, &key, func(org *edgeproto.Organization) error {
			if org.Name == cloudcommon.OrganizationMobiledgeX {
				return nil
			}
			if _, found := orgPoolsMap[org.Name]; found {
				return nil
			}
			return fmt.Errorf("Cannot add cloudlet %s to CloudletPool with existing developer %s ClusterInsts or AppInsts which are not authorized to deploy to the CloudletPool. Please invite the developer first, or remove the developer from the Cloudlet.", key.Name, org.Name)
		})
		if err != nil {
			return err
		}
	}
	return nil
}
