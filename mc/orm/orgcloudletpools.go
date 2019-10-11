package orm

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
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
		return fmt.Errorf("CloudletPool not specified")
	}
	if !authorized(ctx, claims.Username, op.Org, ResourceCloudletPools, ActionManage) {
		return echo.ErrForbidden
	}
	found, err := hasCloudletPool(ctx, op.Region, op.CloudletPool)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("Specified CloudletPool for region not found")
	}
	// create org cloudletpool
	db := loggedDB(ctx)
	err = db.Create(&op).Error
	if err != nil {
		if strings.Contains(err.Error(), "violates foreign key constraint \"org_cloudlet_pools_org_fkey\"") {
			return fmt.Errorf("Specified Organization does not exist")
		}
		if strings.Contains(err.Error(), "violates foreign key constraint \"org_cloudlet_pools_region_fkey\"") {
			return fmt.Errorf("Specified Region does not exist")
		}
		if strings.Contains(err.Error(), "duplicate key value violates unique") {
			return fmt.Errorf("Already exists")
		}
		return dbErr(err)
	}
	return nil
}

func hasCloudletPool(ctx context.Context, region, pool string) (bool, error) {
	conn, err := connectController(ctx, region)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	obj := edgeproto.CloudletPool{
		Key: edgeproto.CloudletPoolKey{
			Name: pool,
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
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
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

	if !authorized(ctx, claims.Username, op.Org, ResourceCloudletPools, ActionManage) {
		return echo.ErrForbidden
	}
	db := loggedDB(ctx)
	// can't use db.Delete as we're not using primary key
	// see http://jinzhu.me/gorm/crud.html#delete
	args := []interface{}{
		"org = ? and region = ? and cloudlet_pool = ?",
		op.Org,
		op.Region,
		op.CloudletPool,
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
	authz, err := newShowAuthz(ctx, username, ResourceCloudletPools, ActionView)
	if err != nil {
		return nil, err
	}

	retops := []ormapi.OrgCloudletPool{}
	for _, op := range ops {
		if !authz.Ok(ctx, op.Org) {
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
	if err := c.Bind(&oc); err != nil {
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
	}
	if oc.Org == "" {
		return c.JSON(http.StatusBadRequest, Msg("Organization must be specified"))
	}
	if oc.Region == "" {
		return c.JSON(http.StatusBadRequest, Msg("Region must be specified"))
	}

	db := loggedDB(ctx)
	org := ormapi.Organization{}
	res := db.Where(&ormapi.Organization{Name: oc.Org}).First(&org)
	if res.RecordNotFound() {
		return c.JSON(http.StatusBadRequest, Msg("Specified Organization not found"))
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
