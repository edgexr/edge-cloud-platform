package orm

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func InitOrgCloudletPool(ctx context.Context) error {
	db := loggedDB(ctx)

	// set table row to be unique so we don't get duplicates
	// Gorm has no way of doing this so we do it here manually after
	// the table is created.
	scope := db.Unscoped().NewScope(&ormapi.OrgCloudletPool{})
	fields := []string{}
	for _, field := range scope.GetModelStruct().StructFields {
		if field.IsNormal {
			fields = append(fields, scope.Quote(field.DBName))
		}
	}
	cmd := fmt.Sprintf("ALTER TABLE %s ADD UNIQUE (%s)", scope.QuotedTableName(), strings.Join(fields, ","))
	return db.Exec(cmd).Error
}

func CreateOrgCloudletPool(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)
	op := ormapi.OrgCloudletPool{}
	if err := c.Bind(&op); err != nil {
		return bindErr(c, err)
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("org", op.Org)

	err = CreateOrgCloudletPoolObj(ctx, claims, &op)
	return setReply(c, err, Msg("Organization CloudletPool created"))
}

func CreateOrgCloudletPoolObj(ctx context.Context, claims *UserClaims, op *ormapi.OrgCloudletPool) error {
	if op.Org == "" {
		return fmt.Errorf("Organization name not specified")
	}
	if op.Region == "" {
		return fmt.Errorf("Region not specified")
	}
	if op.CloudletPool == "" {
		return fmt.Errorf("CloudletPool name not specified")
	}
	if op.CloudletPoolOrg == "" {
		return fmt.Errorf("CloudletPool organization not specified")
	}

	if err := authorized(ctx, claims.Username, op.CloudletPoolOrg, ResourceCloudletPools, ActionManage, withRequiresOrg(op.CloudletPoolOrg)); err != nil {
		return err
	}
	found, err := hasCloudletPool(ctx, op.Region, op.CloudletPool, op.CloudletPoolOrg)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("Specified CloudletPool %s org %s for region %s not found", op.CloudletPool, op.CloudletPoolOrg, op.Region)
	}
	// create org cloudletpool
	db := loggedDB(ctx)
	err = db.Create(&op).Error
	if err != nil {
		if strings.Contains(err.Error(), "violates foreign key constraint \"org_cloudlet_pools_org_fkey\"") {
			return fmt.Errorf("Specified Organization %s does not exist", op.Org)
		}
		if strings.Contains(err.Error(), "violates foreign key constraint \"org_cloudlet_pools_region_fkey\"") {
			return fmt.Errorf("Specified Region %s does not exist", op.Region)
		}
		if strings.Contains(err.Error(), "violates foreign key constraint \"org_cloudlet_pools_cloudletpoolorg_fkey\"") {
			return fmt.Errorf("Specified CloudletPoolOrg %s does not exist", op.CloudletPoolOrg)
		}
		if strings.Contains(err.Error(), "duplicate key value violates unique") {
			return fmt.Errorf("OrgCloudletPool org %s, region %s, pool %s poolorg %s already exists", op.Org, op.Region, op.CloudletPool, op.CloudletPoolOrg)
		}
		return dbErr(err)
	}
	return nil
}

func hasCloudletPool(ctx context.Context, region, pool, org string) (bool, error) {
	conn, err := connectController(ctx, region)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	obj := edgeproto.CloudletPool{
		Key: edgeproto.CloudletPoolKey{
			Name:         pool,
			Organization: org,
		},
	}

	api := edgeproto.NewCloudletPoolApiClient(conn)
	stream, err := api.ShowCloudletPool(ctx, &obj)
	if err != nil {
		return false, err
	}
	found := false
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			return false, err
		}
		if res.Key.Name == pool {
			found = true
		}
	}
	return found, nil
}

func DeleteOrgCloudletPool(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)
	op := ormapi.OrgCloudletPool{}
	if err := c.Bind(&op); err != nil {
		return bindErr(c, err)
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("org", op.Org)

	err = DeleteOrgCloudletPoolObj(ctx, claims, &op)
	return setReply(c, err, Msg("organization cloudletpool deleted"))
}

func DeleteOrgCloudletPoolObj(ctx context.Context, claims *UserClaims, op *ormapi.OrgCloudletPool) error {
	if op.Org == "" {
		return fmt.Errorf("Organization name not specified")
	}
	if op.Region == "" {
		return fmt.Errorf("Region not specified")
	}
	if op.CloudletPool == "" {
		return fmt.Errorf("CloudletPool not specified")
	}

	if err := authorized(ctx, claims.Username, op.CloudletPoolOrg, ResourceCloudletPools, ActionManage); err != nil {
		// check for empty org here to allow admins to delete old
		// orgcloudletpools that do not have CloudletPoolOrg.
		if err == echo.ErrForbidden && op.CloudletPoolOrg == "" {
			return fmt.Errorf("CloudletPool organization not specified")
		}
		return err
	}
	db := loggedDB(ctx)
	// can't use db.Delete as we're not using primary key
	// see http://jinzhu.me/gorm/crud.html#delete
	args := []interface{}{
		"org = ? and region = ? and cloudlet_pool = ? and cloudlet_pool_org = ?",
		op.Org,
		op.Region,
		op.CloudletPool,
		op.CloudletPoolOrg,
	}
	err := db.Delete(op, args...).Error
	if err != nil {
		return dbErr(err)
	}
	return nil
}

func ShowOrgCloudletPool(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

	ops, err := ShowOrgCloudletPoolObj(ctx, claims.Username)
	return setReply(c, err, ops)
}

func ShowOrgCloudletPoolObj(ctx context.Context, username string) ([]ormapi.OrgCloudletPool, error) {
	ops := []ormapi.OrgCloudletPool{}
	db := loggedDB(ctx)
	err := db.Find(&ops).Error
	if err != nil {
		return nil, dbErr(err)
	}
	authz, err := newShowAuthz(ctx, "", username, ResourceCloudletPools, ActionView)
	if err != nil {
		return nil, err
	}

	retops := []ormapi.OrgCloudletPool{}
	for _, op := range ops {
		if !authz.Ok(op.CloudletPoolOrg) {
			continue
		}
		retops = append(retops, op)
	}
	return retops, nil
}

// Used by UI to show cloudlets for the current organization
func ShowOrgCloudlet(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)
	oc := ormapi.OrgCloudlet{}
	success, err := ReadConn(c, &oc)
	if !success {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelApi, "ShowOrgCloudlet", "oc", oc)
	if oc.Org == "" {
		return setReply(c, fmt.Errorf("Organization must be specified"), nil)
	}
	if oc.Region == "" {
		return setReply(c, fmt.Errorf("Region must be specified"), nil)
	}

	db := loggedDB(ctx)
	org := ormapi.Organization{}
	res := db.Where(&ormapi.Organization{Name: oc.Org}).First(&org)
	if res.RecordNotFound() {
		return setReply(c, fmt.Errorf("Specified Organization not found"), nil)
	}
	if res.Error != nil {
		return dbErr(res.Error)
	}

	authzCloudlet := AuthzCloudlet{}
	err = authzCloudlet.populate(ctx, oc.Region, claims.Username, oc.Org, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}

	rc := RegionContext{
		region:    oc.Region,
		username:  claims.Username,
		skipAuthz: true,
	}
	show := make([]*edgeproto.Cloudlet, 0)
	err = ShowCloudletStream(ctx, &rc, &edgeproto.Cloudlet{}, func(cloudlet *edgeproto.Cloudlet) {
		if authzCloudlet.Ok(cloudlet) {
			show = append(show, cloudlet)
		}
	})
	return setReply(c, err, show)
}

// Used by UI to show cloudlets for the current organization
func ShowOrgCloudletInfo(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)
	oc := ormapi.OrgCloudlet{}
	success, err := ReadConn(c, &oc)
	if !success {
		return err
	}

	if oc.Org == "" {
		return setReply(c, fmt.Errorf("Organization must be specified"), nil)
	}
	if oc.Region == "" {
		return setReply(c, fmt.Errorf("Region must be specified"), nil)
	}

	db := loggedDB(ctx)
	org := ormapi.Organization{}
	res := db.Where(&ormapi.Organization{Name: oc.Org}).First(&org)
	if res.RecordNotFound() {
		return setReply(c, fmt.Errorf("Specified Organization not found"), nil)
	}
	if res.Error != nil {
		return dbErr(res.Error)
	}

	authzCloudlet := AuthzCloudlet{}
	err = authzCloudlet.populate(ctx, oc.Region, claims.Username, oc.Org, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}

	rc := RegionContext{
		region:    oc.Region,
		username:  claims.Username,
		skipAuthz: true,
	}
	show := make([]*edgeproto.CloudletInfo, 0)
	err = ShowCloudletInfoStream(ctx, &rc, &edgeproto.CloudletInfo{}, func(CloudletInfo *edgeproto.CloudletInfo) {
		cloudlet := edgeproto.Cloudlet{
			Key: CloudletInfo.Key,
		}
		if authzCloudlet.Ok(&cloudlet) {
			show = append(show, CloudletInfo)
		}
	})
	return setReply(c, err, show)
}
