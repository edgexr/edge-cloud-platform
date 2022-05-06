// Adapter handles reading and writing from postgres.
// Some code here is copied/adapted from github.com/casbin/gorm-adapter, which
// is copyright 2017 The casbin Authors, under Apache License Version 2.0.
//
// Unlike gorm-adapter, this code is specific to postgres. And unlike
// gorm-adapter which attempts to abstract the storage away from the model,
// here the specifics of the model are used in the postgresql queries for
// efficiency.

package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/jinzhu/gorm"
	"github.com/edgexr/edge-cloud-infra/mc/gormlog"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/log"
)

type Adapter struct {
	db       *gorm.DB
	logAuthz bool
}

// CasbinRule copies the gorm-adapter to store data in the same way
// that gorm adapter does. This makes us backwards (and forwards) compatible
// with gorm-adapter.
type CasbinRule struct {
	TablePrefix string `gorm:"-"`
	PType       string `gorm:"size:100" json:"p_type"`
	V0          string `gorm:"size:100"`
	V1          string `gorm:"size:100"`
	V2          string `gorm:"size:100"`
	V3          string `gorm:"size:100"`
	V4          string `gorm:"size:100"`
	V5          string `gorm:"size:100"`
}

func (a *Adapter) Init(ctx context.Context) error {
	return a.createTable(ctx)
}

func getTableInstance() *CasbinRule {
	return &CasbinRule{}
}

func (c *CasbinRule) TableName() string {
	return c.TablePrefix + "casbin_rule" //as Gorm keeps table names are plural, and we love consistency
}

func (a *Adapter) createTable(ctx context.Context) error {
	if a.db.HasTable(getTableInstance()) {
		return nil
	}

	db := a.loggedDB(ctx)

	// gorm does not support a way to specify the UNIQUE table constraint
	// so we have to do it manually.
	// Specifying all fields as UNIQUE prevents duplicates in the table.
	fields := []string{}
	tags := []string{}
	scope := db.Unscoped().NewScope(getTableInstance())
	for _, field := range scope.GetModelStruct().StructFields {
		if field.IsNormal {
			sqlTag := scope.Dialect().DataTypeOf(field)
			tags = append(tags, scope.Quote(field.DBName)+" "+sqlTag)
			fields = append(fields, scope.Quote(field.DBName))
		}
	}
	// Note race condition between multiple MCs starting at the same time,
	// must allow for table already existing because table may have been
	// created after earlier check passed.
	cmd := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %v (%v, UNIQUE (%v))", scope.QuotedTableName(), strings.Join(tags, ","), strings.Join(fields, ","))
	err := db.Exec(cmd).Error
	if err != nil {
		// For some reason, we still get a race condition even with
		// IF NOT EXISTS. Perhaps the above command is not atomic.
		// Detect the conflict and ignore.
		if strings.Contains(err.Error(), `pq: duplicate key value violates unique constraint "pg_type_typname_nsp_index"`) || strings.Contains(err.Error(), `pq: relation "casbin_rule" already exists`) {
			err = nil
		}
		log.SpanLog(ctx, log.DebugLevelInfo, "init adapter failed", "err", err)
	}
	return err
}

func (a *Adapter) GetAuthorized(ctx context.Context, obj, act string) (map[string]string, error) {
	c := CasbinRule{}

	// Implement the rbac check. Grabs all the roles from the table (o1)
	// that satisfy the object and action. Then grabs all the subjects
	// from the table (o2) that have that role. Note that o1 and o2 are
	// aliases for the subset of the casbin_rule table that match the
	// select criteria.
	query := fmt.Sprintf(`
SELECT o2.sub, o1.role FROM
 (SELECT v0 AS role FROM %s WHERE p_type = 'p' AND v1 = '%s' AND v2 = '%s') o1
 INNER JOIN LATERAL
 (SELECT v0 AS sub FROM %s WHERE p_type = 'g' AND v1 = o1.role) o2
 ON true;`, c.TableName(), obj, act, c.TableName())

	db := a.db
	if a.logAuthz {
		db = a.loggedDB(ctx)
	}

	rows, err := db.Raw(query).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	authz := make(map[string]string)
	for rows.Next() {
		var subj, role string
		err := rows.Scan(&subj, &role)
		if err != nil {
			return nil, err
		}
		authz[subj] = role
	}
	if a.logAuthz {
		log.SpanLog(ctx, log.DebugLevelApi, "GetAuthorized", "authz", authz)
	}
	return authz, nil
}

func (a *Adapter) GetPermissions(ctx context.Context, username, org string) (map[ormapi.RolePerm]struct{}, error) {
	c := CasbinRule{}
	subj := GetCasbinGroup(org, username)
	// Get all permissions for the specified user and org. Grabs all the roles from the table (o1)
	// that satisfy the subject (org+user). Then grabs all the resource,actions from the table (o2)
	// for those roles.
	query := fmt.Sprintf(`
SELECT o2.resource, o2.action FROM
 (SELECT v1 AS role FROM %s WHERE p_type = 'g' AND v0 = '%s') o1
 INNER JOIN LATERAL
 (SELECT v1 AS resource, v2 AS action FROM %s WHERE p_type = 'p' AND v0 = o1.role) o2
ON true;`, c.TableName(), subj, c.TableName())
	db := a.db
	if a.logAuthz {
		db = a.loggedDB(ctx)
	}
	rows, err := db.Raw(query).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	perms := make(map[ormapi.RolePerm]struct{})
	for rows.Next() {
		perm := ormapi.RolePerm{}
		err := rows.Scan(&perm.Resource, &perm.Action)
		if err != nil {
			return nil, err
		}
		perms[perm] = struct{}{}
	}
	if a.logAuthz {
		log.SpanLog(ctx, log.DebugLevelApi, "GetPermissions", "perms", perms)
	}
	return perms, nil
}

func (a *Adapter) GetPolicies(ptype string) ([][]string, error) {
	filter := CasbinRule{
		PType: ptype,
	}
	var lines []CasbinRule
	if err := a.db.Where(&filter).Find(&lines).Error; err != nil {
		return nil, err
	}

	policies := make([][]string, 0)
	for _, line := range lines {
		_, pol := line.ToPolicy()
		policies = append(policies, pol)
	}
	return policies, nil
}

func (a *Adapter) HasPolicy(ptype string, rule []string) (bool, error) {
	line := getCasbinRule(ptype, rule)
	err := a.db.Where(&line).First(&line).Error
	if gorm.IsRecordNotFoundError(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func getCasbinRule(ptype string, rule []string) CasbinRule {
	line := CasbinRule{}

	line.PType = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

func (c *CasbinRule) ToPolicy() (ptype string, rule []string) {
	ptype = c.PType
	rule = []string{}
	if c.V0 == "" {
		return
	}
	rule = append(rule, c.V0)
	if c.V1 == "" {
		return
	}
	rule = append(rule, c.V1)
	if c.V2 == "" {
		return
	}
	rule = append(rule, c.V2)
	if c.V3 == "" {
		return
	}
	rule = append(rule, c.V3)
	if c.V4 == "" {
		return
	}
	rule = append(rule, c.V4)
	if c.V5 == "" {
		return
	}
	rule = append(rule, c.V5)
	return
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(ctx context.Context, ptype string, rule []string) error {
	db := a.loggedDB(ctx)

	line := getCasbinRule(ptype, rule)
	err := db.Set("gorm:insert_option", "ON CONFLICT DO NOTHING").Create(&line).Error
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(ctx context.Context, ptype string, rule []string) error {
	db := a.loggedDB(ctx)

	line := getCasbinRule(ptype, rule)
	err := rawDelete(db, line) //can't use db.Delete as we're not using primary key http://jinzhu.me/gorm/crud.html#delete
	return err
}

func rawDelete(db *gorm.DB, line CasbinRule) error {
	queryArgs := []interface{}{line.PType}

	queryStr := "p_type = ?"
	if line.V0 != "" {
		queryStr += " and v0 = ?"
		queryArgs = append(queryArgs, line.V0)
	}
	if line.V1 != "" {
		queryStr += " and v1 = ?"
		queryArgs = append(queryArgs, line.V1)
	}
	if line.V2 != "" {
		queryStr += " and v2 = ?"
		queryArgs = append(queryArgs, line.V2)
	}
	if line.V3 != "" {
		queryStr += " and v3 = ?"
		queryArgs = append(queryArgs, line.V3)
	}
	if line.V4 != "" {
		queryStr += " and v4 = ?"
		queryArgs = append(queryArgs, line.V4)
	}
	if line.V5 != "" {
		queryStr += " and v5 = ?"
		queryArgs = append(queryArgs, line.V5)
	}
	args := append([]interface{}{queryStr}, queryArgs...)
	err := db.Delete(CasbinRule{}, args...).Error
	return err
}

func (a *Adapter) loggedDB(ctx context.Context) *gorm.DB {
	db := a.db.New() // clone
	db.SetLogger(&gormlog.Logger{Ctx: ctx})
	db.LogMode(true)
	return db
}

func (a *Adapter) LogAuthz(on bool) {
	a.logAuthz = on
}
