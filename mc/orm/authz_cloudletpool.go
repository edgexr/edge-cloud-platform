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

package orm

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/edgexr/edge-cloud-infra/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/util"
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
	allowedOrgs := make(map[string]struct{})
	invalidOrgsHelp := "To include them as part of the pool, first create an empty pool, invite the developer to the pool, then add the cloudlet to the pool"
	return authzCloudletPoolMembers(ctx, region, username, obj, allowedOrgs, invalidOrgsHelp)
}

func authzAddCloudletPoolMember(ctx context.Context, region, username string, obj *edgeproto.CloudletPoolMember, resource, action string) error {
	if !util.ValidName(obj.Cloudlet.Name) {
		return fmt.Errorf("Invalid Cloudlet name")
	}
	pool := &edgeproto.CloudletPool{}
	pool.Key = obj.Key
	pool.Cloudlets = []edgeproto.CloudletKey{obj.Cloudlet}
	return authzUpdateCloudletPool(ctx, region, username, pool, resource, action)
}

func authzUpdateCloudletPool(ctx context.Context, region, username string, pool *edgeproto.CloudletPool, resource, action string) error {
	if err := pool.Key.ValidateKey(); err != nil {
		return err
	}
	if err := authorized(ctx, username, pool.Key.Organization, resource, action); err != nil {
		return err
	}

	// find developers that are part of the existing pool.
	filter := make(map[string]interface{})
	filter["region"] = region
	filter["cloudlet_pool"] = pool.Key.Name
	filter["cloudlet_pool_org"] = pool.Key.Organization
	orgPools, err := showCloudletPoolAccessObj(ctx, username, filter, accessTypeGranted)
	if err != nil {
		return err
	}
	allowedOrgs := make(map[string]struct{})
	for _, orgPool := range orgPools {
		allowedOrgs[orgPool.Org] = struct{}{}
	}

	invalidOrgsHelp := "Please invite the developer first, or remove the developer from the Cloudlet"
	return authzCloudletPoolMembers(ctx, region, username, pool, allowedOrgs, invalidOrgsHelp)
}

func authzCloudletPoolMembers(ctx context.Context, region, username string, pool *edgeproto.CloudletPool, allowedOrgs map[string]struct{}, invalidOrgsHelp string) error {
	// make sure that cloudlet being added to the pool does not
	// have AppInsts/ClusterInsts from developers not part of the pool.
	rc := ormutil.RegionContext{}
	rc.Username = username
	rc.Region = region
	rc.Database = database
	rc.SkipAuthz = true
	for _, key := range pool.Cloudlets {
		if !util.ValidName(key.Name) {
			return fmt.Errorf("Invalid Cloudlet name %q", key.Name)
		}
		invalidOrgs := []string{}
		err := ctrlclient.GetOrganizationsOnCloudletStream(ctx, &rc, &key, connCache, func(org *edgeproto.Organization) error {
			if org.Name == cloudcommon.OrganizationMobiledgeX {
				return nil
			}
			if _, found := allowedOrgs[org.Name]; found {
				return nil
			}
			// build list so it can be sorted for deterministic output
			invalidOrgs = append(invalidOrgs, org.Name)
			return nil
		})
		if err != nil {
			return err
		}
		if len(invalidOrgs) > 0 {
			sort.Strings(invalidOrgs)
			return fmt.Errorf("Cannot add cloudlet %s to CloudletPool because it has AppInsts/ClusterInsts from developer %s, which are not authorized to deploy to the CloudletPool. %s.", key.Name, strings.Join(invalidOrgs, ", "), invalidOrgsHelp)
		}
	}
	return nil
}
