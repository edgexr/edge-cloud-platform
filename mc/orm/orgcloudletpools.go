package orm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var tableUniqueConstraintRE = regexp.MustCompile("CREATE UNIQUE INDEX (.+?) ON (.+?) USING btree \\((.+?)\\)")

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
	err := db.Exec(cmd).Error
	if err != nil {
		return err
	}
	err = dropOtherUniqueConstraints(ctx, scope.TableName(), fields)
	if err != nil {
		return err
	}

	err = upgradeOrgCloudletPoolType(ctx, scope.TableName())
	if err != nil {
		return err
	}
	return nil
}

func dropOtherUniqueConstraints(ctx context.Context, tableName string, fields []string) error {
	// Backwards compatibility: we need to drop the old unique constraint(s)
	// that may be there from previous versions for fewer or more fields.
	// Unfortunately in older versions we never explicitly specified the
	// name of the constraint, so postgres generated one for us. And that
	// name is the only way to delete it, so we need to look it up.
	db := loggedDB(ctx)
	cmd := fmt.Sprintf("SELECT indexdef FROM pg_indexes WHERE tablename = '%s'", tableName)
	log.SpanLog(ctx, log.DebugLevelInfo, "Run select indexdef", "cmd", cmd)
	res := db.Raw(cmd)
	if res.Error != nil {
		return res.Error
	}
	rows, err := res.Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	for ii := range fields {
		fields[ii], err = strconv.Unquote(fields[ii])
		if err != nil {
			return err
		}
	}
	keepConstraint := strings.Join(fields, ", ")
	log.SpanLog(ctx, log.DebugLevelInfo, "Keep constraint", "constraint", keepConstraint)
	for rows.Next() {
		indexdef := ""
		rows.Scan(&indexdef)
		if indexdef == "" {
			continue
		}
		log.SpanLog(ctx, log.DebugLevelInfo, "Considering unique constraint", "constraint", indexdef)
		matches := tableUniqueConstraintRE.FindStringSubmatch(indexdef)
		if len(matches) != 4 {
			continue
		}
		key := matches[1]
		constraint := matches[3]
		if constraint == keepConstraint {
			log.SpanLog(ctx, log.DebugLevelInfo, "Keeping constraint", "key", key, "constraint", constraint)
			continue
		}
		log.SpanLog(ctx, log.DebugLevelInfo, "Dropping constraint", "key", key, "constraint", constraint)
		cmd = fmt.Sprintf("ALTER TABLE \"%s\" DROP CONSTRAINT %s", tableName, key)
		err := db.Exec(cmd).Error
		if err != nil {
			return err
		}
	}
	return nil
}

func upgradeOrgCloudletPoolType(ctx context.Context, tableName string) error {
	db := loggedDB(ctx)

	// Upgrade function for the new Type column.
	// Previous OrgCloudletPools without the Type field were created
	// solely by the operator to grant access, and only one needed to exist.
	// New OrgCloudletPools have a Type field to allow for separate
	// objects created by the operator and developer, to allow for
	// mutual consent only when both exist.
	// Convert the old single object into dual objects.
	old := make([]ormapi.OrgCloudletPool, 0)
	err := db.Find(&old).Error
	if err != nil {
		return err
	}
	for _, op := range old {
		if op.Type != "" {
			continue
		}
		op.Type = ormapi.CloudletPoolAccessInvitation
		err = db.FirstOrCreate(&op, &op).Error
		if err != nil {
			return err
		}
		op.Type = ormapi.CloudletPoolAccessConfirmation
		err = db.FirstOrCreate(&op, &op).Error
		if err != nil {
			return err
		}
	}
	// Note that postgres treats NULL as different from the empty string.
	// For whatever reason, automigrate of adding a new text column (type)
	// to org_cloudlet_pools starts out with that column's value as NULL,
	// instead of the empty string. And gorm doesn't have a good way to
	// specify NULL instead of the empty string in db.Where() clauses.
	cmd := fmt.Sprintf("DELETE FROM %s WHERE type IS NULL", tableName)
	err = db.Exec(cmd).Error
	if err != nil {
		return err
	}
	return nil
}

func validateOrgCloudletPool(op *ormapi.OrgCloudletPool) error {
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
	return nil
}

func createOrgCloudletPool(ctx context.Context, op *ormapi.OrgCloudletPool) error {
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
			return fmt.Errorf("CloudletPool %s for org %s, region %s, pool %s poolorg %s already exists", op.Type, op.Org, op.Region, op.CloudletPool, op.CloudletPoolOrg)
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

func deleteOrgCloudletPool(ctx context.Context, op *ormapi.OrgCloudletPool) error {
	db := loggedDB(ctx)

	// can't use db.Delete as we're not using primary key
	// see http://jinzhu.me/gorm/crud.html#delete
	args := []interface{}{
		"org = ? and region = ? and cloudlet_pool = ? and cloudlet_pool_org = ? and type = ?",
		op.Org,
		op.Region,
		op.CloudletPool,
		op.CloudletPoolOrg,
		op.Type,
	}
	err := db.Delete(op, args...).Error
	if err != nil {
		return dbErr(err)
	}
	return nil
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
		authzOk, filterOutput := authzCloudlet.Ok(cloudlet)
		if authzOk {
			if filterOutput {
				authzCloudlet.Filter(cloudlet)
			}
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
		authzOk, filterOutput := authzCloudlet.Ok(&cloudlet)
		if authzOk {
			if filterOutput {
				output := *CloudletInfo
				*CloudletInfo = edgeproto.CloudletInfo{}
				CloudletInfo.Key = output.Key
				CloudletInfo.State = output.State
				CloudletInfo.Errors = output.Errors
				CloudletInfo.Flavors = output.Flavors
				CloudletInfo.MaintenanceState = output.MaintenanceState
				CloudletInfo.TrustPolicyState = output.TrustPolicyState
				CloudletInfo.ResourcesSnapshot = output.ResourcesSnapshot
			}
			show = append(show, CloudletInfo)
		}
	})
	return setReply(c, err, show)
}

// Operators invite Developers to their CloudletPool
func CreateCloudletPoolAccessInvitation(c echo.Context) error {
	return createDeleteCloudletPoolAccess(c, cloudcommon.Create, ormapi.CloudletPoolAccessInvitation)
}

func DeleteCloudletPoolAccessInvitation(c echo.Context) error {
	return createDeleteCloudletPoolAccess(c, cloudcommon.Delete, ormapi.CloudletPoolAccessInvitation)
}

func ShowCloudletPoolAccessInvitation(c echo.Context) error {
	return showCloudletPoolAccess(c, ormapi.CloudletPoolAccessInvitation)
}

// Developers confirm Operator invitations
func CreateCloudletPoolAccessConfirmation(c echo.Context) error {
	return createDeleteCloudletPoolAccess(c, cloudcommon.Create, ormapi.CloudletPoolAccessConfirmation)
}

func DeleteCloudletPoolAccessConfirmation(c echo.Context) error {
	return createDeleteCloudletPoolAccess(c, cloudcommon.Delete, ormapi.CloudletPoolAccessConfirmation)
}

func ShowCloudletPoolAccessConfirmation(c echo.Context) error {
	return showCloudletPoolAccess(c, ormapi.CloudletPoolAccessConfirmation)
}

// Show access granted
func ShowCloudletPoolAccessGranted(c echo.Context) error {
	return showCloudletPoolAccess(c, "")
}

func createDeleteCloudletPoolAccess(c echo.Context, action cloudcommon.Action, typ string) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

	in := ormapi.OrgCloudletPool{}
	if err := c.Bind(&in); err != nil {
		return bindErr(c, err)
	}
	if err := validateOrgCloudletPool(&in); err != nil {
		return setReply(c, err, nil)
	}
	span := log.SpanFromContext(ctx)

	if typ == ormapi.CloudletPoolAccessInvitation {
		// make sure caller is authorized for operator org
		span.SetTag("org", in.CloudletPoolOrg)
		if err := authorized(ctx, claims.Username, in.CloudletPoolOrg, ResourceCloudletPools, ActionManage); err != nil {
			return err
		}
	} else if typ == ormapi.CloudletPoolAccessConfirmation {
		// make sure caller is authorized for developer org
		span.SetTag("org", in.Org)
		if err := authorized(ctx, claims.Username, in.Org, ResourceUsers, ActionManage); err != nil {
			return err
		}
		// make sure invitation exists for create
		if action == cloudcommon.Create {
			lookup := in
			lookup.Type = ormapi.CloudletPoolAccessInvitation
			db := loggedDB(ctx)
			res := db.Where(&lookup).Find(&lookup)
			if res.RecordNotFound() {
				return c.JSON(http.StatusBadRequest, Msg("No invitation for specified cloudlet pool access"))
			}
			if res.Error != nil {
				return dbErr(res.Error)
			}
		}
	} else {
		return fmt.Errorf("Internal error: invalid type")
	}

	in.Type = typ
	msg := ""
	if action == cloudcommon.Create {
		err = createOrgCloudletPool(ctx, &in)
		msg = fmt.Sprintf("%s created", typ)
	} else if action == cloudcommon.Delete {
		err = deleteOrgCloudletPool(ctx, &in)
		msg = fmt.Sprintf("%s deleted", typ)
	} else {
		return fmt.Errorf("Internal error: invalid action")
	}
	if err == nil {
		// TODO: trigger email or slack to notify other party
	}
	return setReply(c, err, Msg(msg))
}

func showCloudletPoolAccess(c echo.Context, typ string) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

	filter := ormapi.OrgCloudletPool{}
	if err := c.Bind(&filter); err != nil {
		return bindErr(c, err)
	}
	// note that gorm only filters on non-nil fields, so if typ is ""
	// it is effectively ignored for filtering on the where query.
	filter.Type = typ

	authz, err := newAuthzOrgCloudletPool(ctx, filter.Region, claims.Username)
	if err != nil {
		return err
	}

	ops := []ormapi.OrgCloudletPool{}
	db := loggedDB(ctx)
	err = db.Where(&filter).Find(&ops).Error
	if err != nil {
		return dbErr(err)
	}

	retops := []ormapi.OrgCloudletPool{}
	for _, op := range ops {
		if !authz.Ok(&op) {
			continue
		}
		if filter.Type != "" {
			// hide type as it is an internal-only field
			op.Type = ""
		}
		retops = append(retops, op)
	}
	if filter.Type == "" {
		// reduce invitations and confirmations to single granted
		retops = getAccessGranted(retops)
	}
	return setReply(c, nil, retops)

}

func getAccessGranted(ops []ormapi.OrgCloudletPool) []ormapi.OrgCloudletPool {
	tracker := make(map[ormapi.OrgCloudletPool]int)
	granted := make([]ormapi.OrgCloudletPool, 0)
	for _, op := range ops {
		lookup := op
		lookup.Type = ""
		val := tracker[lookup]
		if op.Type == ormapi.CloudletPoolAccessInvitation {
			val |= 0x1
		} else if op.Type == ormapi.CloudletPoolAccessConfirmation {
			val |= 0x2
		} else {
			continue
		}
		// can never hit 3 more than once because you can't have
		// duplicate entries because the unique key is based on all
		// the fields.
		if val == 3 {
			granted = append(granted, lookup)
		}
		tracker[lookup] = val
	}
	return granted
}
