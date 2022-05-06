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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/labstack/echo"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/edgexr/edge-cloud-infra/mc/gormlog"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
	"github.com/edgexr/edge-cloud/util/tasks"
)

var retryInterval = 10 * time.Second
var psqlInfo string
var sqlListenerWorkers tasks.KeyWorkers
var sqlPingInterval = 90 * time.Second
var unitTest = false

func InitSql(ctx context.Context, addr, username, password, dbname string) (*gorm.DB, error) {
	hostport := strings.Split(addr, ":")
	if len(hostport) != 2 {
		return nil, fmt.Errorf("Invalid postgres address format %s", addr)
	}

	psqlInfo = fmt.Sprintf("host=%s port=%s user=%s "+
		"dbname=%s sslmode=disable password=%s",
		hostport[0], hostport[1], username, dbname, password)
	var err error
	db, err := gorm.Open("postgres", psqlInfo)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "init sql", "host", hostport[0], "port", hostport[1],
			"dbname", dbname, "err", err)
		return nil, err
	}

	// Without a span defined on this context, any code path that
	// fails to call loggedDB() will panic (intentionally).
	db.SetLogger(&gormlog.Logger{Ctx: context.Background()})
	db.LogMode(true)

	return db, nil
}

func InitData(ctx context.Context, superuser, superpass string, pingInterval time.Duration, stop *bool, done chan struct{}, initDone chan error) {
	if database == nil {
		log.FatalLog("db not initialized")
	}
	db := loggedDB(ctx)
	isDone := false
	// do first attempt immediately, then retry after interval if needed
	retryInt := time.Duration(0)
	for !isDone {
		select {
		case <-done:
			isDone = true
		case <-time.After(retryInt):
			retryInt = retryInterval
		}
		if isDone {
			return
		}

		err := upgradeCustom(ctx, db)
		if err != nil {
			initDone <- err
			return
		}

		// create or update tables
		err = db.AutoMigrate(
			&ormapi.User{},
			&ormapi.Organization{},
			&ormapi.Controller{},
			&ormapi.Config{},
			&ormapi.OrgCloudletPool{},
			&ormapi.AccountInfo{},
			&ormapi.BillingOrganization{},
			&ormapi.UserApiKey{},
			&ormapi.Reporter{},
			&ormapi.McRateLimitFlowSettings{},
			&ormapi.McRateLimitMaxReqsSettings{},
			// Federation GORM Objects
			&ormapi.Federator{},
			&ormapi.Federation{},
			&ormapi.FederatorZone{},
			&ormapi.FederatedPartnerZone{},
			&ormapi.FederatedSelfZone{},
		).Error
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "automigrate", "err", err)
			if unitTest {
				initDone <- err
				return
			}
			continue
		}
		// create initial database data
		err = InitRolePerms(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "init roles", "err", err)
			if unitTest {
				initDone <- err
				return
			}
			continue
		}
		err = InitAdmin(ctx, superuser, superpass)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "init admin", "err", err)
			if unitTest {
				initDone <- err
				return
			}
			continue
		}
		err = InitConfig(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "init config", "err", err)
			if unitTest {
				initDone <- err
				return
			}
			continue
		}
		err = InitOrgCloudletPool(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "init orgcloudletpool", "err", err)
			if unitTest {
				initDone <- err
				return
			}
			continue
		}
		err = InitRateLimitMc(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "init ratelimitmc", "err", err)
			if unitTest {
				initDone <- err
				return
			}
			continue
		}
		err = InitFederationAPIConstraints(loggedDB(ctx))
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "init federation API constraints", "err", err)
			if unitTest {
				initDone <- err
				return
			}
			continue
		}
		log.SpanLog(ctx, log.DebugLevelApi, "init data done")

		if err := fixPostgresNullValues(ctx); err != nil {
			if unitTest {
				initDone <- err
				return
			}
			// not a fatal error, so just log it
			log.SpanLog(ctx, log.DebugLevelApi, "fix postgres null values failed", "err", err)
		}
		break
	}
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(pingInterval):
				database.DB().Ping()
			}
		}
	}()
	initDone <- nil
}

func loggedDB(ctx context.Context) *gorm.DB {
	return gormlog.LoggedDB(ctx, database)
}

const sqlEventsChannel = "events"

// Trigger function for sending a notification of what changed in a table
var postgresTriggerFunc = `
CREATE OR REPLACE FUNCTION notify_event() RETURNS TRIGGER AS $$

DECLARE
    notification json;
BEGIN
    notification = json_build_object(
        'table', TG_TABLE_NAME,
        'action', TG_OP);

    -- execute pg_notify(channel, notification)
    PERFORM pg_notify('` + sqlEventsChannel + `', notification::text);

    -- result is ignored since this is an AFTER trigger
    RETURN NULL;
END;

$$ LANGUAGE plpgsql;
`

type sqlNotice struct {
	Table  string `json:"table"`
	Action string `json:"action"`
}

func initSqlListener(ctx context.Context, done chan struct{}) (*pq.Listener, error) {
	log.SpanLog(ctx, log.DebugLevelInfo, "init sql listener")
	sqlListenerWorkers.Init("sqlListener", sqlListenerWorkFunc)

	db := loggedDB(ctx)
	// set up the trigger function
	err := db.Exec(postgresTriggerFunc).Error
	if err != nil {
		return nil, err
	}
	// register trigger for controllers table
	err = setSqlTrigger(ctx, &ormapi.Controller{})
	if err != nil {
		return nil, err
	}
	// set up listener
	minReconnectInterval := 5 * time.Second
	maxReconnectInterval := 60 * time.Second
	listener := pq.NewListener(psqlInfo, minReconnectInterval, maxReconnectInterval, sqlListenerEventCb)
	go func() {
		isDone := false
		for !isDone {
			select {
			case noticeData := <-listener.Notify:
				if noticeData == nil {
					// listener reconnected
					continue
				}
				span := log.StartSpan(log.DebugLevelApi, "sql-notice")
				ctx := log.ContextWithSpan(context.Background(), span)
				span.SetTag("channel", noticeData.Channel)
				notice := &sqlNotice{}
				err := json.Unmarshal([]byte(noticeData.Extra), notice)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelApi, "failed to unmarshal notice", "err", err, "data", string(noticeData.Extra))
					span.Finish()
					continue
				}
				sqlListenerWorkers.NeedsWork(ctx, notice.Table)
				span.Finish()
			case <-time.After(sqlPingInterval):
				go func() {
					listener.Ping()
				}()
			case <-done:
				isDone = true
			}
		}
	}()
	return listener, nil
}

func setSqlTrigger(ctx context.Context, tableData interface{}) error {
	scope := loggedDB(ctx).Unscoped().NewScope(tableData)
	tableName := scope.TableName()
	cmd := fmt.Sprintf(`
CREATE TRIGGER %s_notify_event
AFTER INSERT OR UPDATE OR DELETE ON %s
FOR EACH ROW EXECUTE PROCEDURE notify_event();`,
		tableName, tableName)
	err := loggedDB(ctx).Exec(cmd).Error
	if err != nil && strings.Contains(err.Error(), "already exists") {
		err = nil
	}
	return err
}

func sqlListenerEventCb(event pq.ListenerEventType, err error) {
	span := log.StartSpan(log.DebugLevelApi, "sql-listener-event")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	log.SpanLog(ctx, log.DebugLevelApi, "callback event", "event", event, "err", err)
	if event == pq.ListenerEventConnected || event == pq.ListenerEventReconnected {
		sqlListenerWorkers.NeedsWork(ctx, "controllers")
	}
}

func sqlListenerWorkFunc(ctx context.Context, k interface{}) {
	key, ok := k.(string)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelApi, "Unexpected failure, key not string", "key", k)
		return
	}
	if key == "controllers" {
		err := allRegionCaches.refreshRegions(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to refresh controller clients", "err", err)
		}
	}
}

// fixPostgresNullValues fixes columns that are added to existing tables,
// which end up getting NULL values instead of empty values (0, "", false).
// This causes show filtering on those values to fail, because the filter
// query is looking for 0, but the value is NULL.
func fixPostgresNullValues(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfo, "fix postgres null values")
	db := loggedDB(ctx)
	// refresh null_frac stats
	err := db.Exec("ANALYZE").Error
	if err != nil {
		return err
	}
	// here, null_frac is the fractional amount of the column's
	// rows that have null values
	cmd := "SELECT tablename, attname, null_frac FROM pg_stats WHERE schemaname='public' AND null_frac > 0"
	res := db.Raw(cmd)
	if res.Error != nil {
		return res.Error
	}
	rows, err := res.Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	var colTypes map[postgresTableCol]string

	for rows.Next() {
		var tableName, colName string
		var nullFrac float64
		err = rows.Scan(&tableName, &colName, &nullFrac)
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfo, "fixing column null values", "table", tableName, "column", colName, "nullFrac", nullFrac)
		if tableName == "" || colName == "" {
			continue
		}
		if colTypes == nil {
			colTypes, err = getPostgresColumnTypes(ctx)
			if err != nil {
				return err
			}
		}
		tableCol := postgresTableCol{
			table: tableName,
			col:   colName,
		}
		dataType, ok := colTypes[tableCol]
		if !ok {
			return fmt.Errorf("column type for %s %s not found", tableName, colName)
		}
		emptyVal, err := getPostgresEmptyVal(dataType)
		if err != nil {
			return fmt.Errorf("get empty val for %s %s failed, %s", tableName, colName, err)
		}
		cmd := fmt.Sprintf("UPDATE %s SET %s = %s WHERE %s IS NULL", tableName, colName, emptyVal, colName)
		err = db.Exec(cmd).Error
		if err != nil {
			return fmt.Errorf("run cmd %q failed, %s", cmd, err)
		}
	}
	return nil
}

type postgresTableCol struct {
	table string
	col   string
}

func getPostgresColumnTypes(ctx context.Context) (map[postgresTableCol]string, error) {
	db := loggedDB(ctx)
	cmd := "SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema='public'"
	res := db.Raw(cmd)
	if res.Error != nil {
		return nil, res.Error
	}
	rows, err := res.Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	colTypes := map[postgresTableCol]string{}

	for rows.Next() {
		var tableName, colName, dataType string
		err = rows.Scan(&tableName, &colName, &dataType)
		if err != nil {
			return nil, err
		}
		if tableName == "" || colName == "" || dataType == "" {
			continue
		}
		tableCol := postgresTableCol{
			table: tableName,
			col:   colName,
		}
		colTypes[tableCol] = dataType

	}
	return colTypes, nil
}

var postgresNumericTypes = []string{"bigint", "int8", "bigserial", "serial8",
	"double precision", "float8", "integer", "int", "int4",
	"numeric", "decimal", "real", "float4", "smallint", "int2",
	"smallserial", "serial2", "serial", "serial4", "money"}
var postgresStringTypes = []string{"bit", "bit varying", "varbit", "char",
	"varchar", "json", "text", "citext"}

func getPostgresEmptyVal(dataType string) (string, error) {
	if strings.HasPrefix(dataType, "boolean") {
		return `'false'`, nil
	}
	if strings.HasPrefix(dataType, "timestamp") {
		return "'epoch'", nil
	}
	for _, t := range postgresNumericTypes {
		if strings.HasPrefix(dataType, t) {
			return `0`, nil
		}
	}
	for _, t := range postgresStringTypes {
		if strings.HasPrefix(dataType, t) {
			return `''`, nil
		}
	}
	return "", fmt.Errorf("unrecognized type %s", dataType)
}

// custom upgrades that can't be done via AutoMigrate
func upgradeCustom(ctx context.Context, db *gorm.DB) error {
	// add unique not null DnsRegion column to controllers
	cmd := `ALTER TABLE IF EXISTS "controllers" ADD IF NOT EXISTS "dns_region" text NOT NULL DEFAULT ''`
	res := db.Exec(cmd)
	if res.Error != nil {
		return res.Error
	}

	// change value to unique, desired values
	ctrls := []ormapi.Controller{}
	err := db.Find(&ctrls).Error
	updateControllers := true
	if err != nil && strings.Contains(err.Error(), `relation "controllers" does not exist`) {
		err = nil
		updateControllers = false
	}
	if err != nil {
		return err
	}
	if updateControllers {
		dnsRegions := make(map[string]*ormapi.Controller)

		for _, ctrl := range ctrls {
			if ctrl.DnsRegion == "" {
				ctrl.DnsRegion = util.DNSSanitize(ctrl.Region)
				if conflict, found := dnsRegions[ctrl.DnsRegion]; found {
					return fmt.Errorf("dns region name conflict, regions %s and %s both dns sanitizes to %s, please fix region names", conflict.Region, ctrl.Region, ctrl.DnsRegion)
				}
				cmd := fmt.Sprintf(`UPDATE "controllers" SET "dns_region" = '%s' WHERE "region" = '%s'`, ctrl.DnsRegion, ctrl.Region)
				res := db.Exec(cmd)
				if res.Error != nil {
					return res.Error
				}
			}
			dnsRegions[ctrl.DnsRegion] = &ctrl
		}
		// add unique constraint
		cmd = `ALTER TABLE IF EXISTS "controllers" ADD UNIQUE ("dns_region")`
		res = db.Exec(cmd)
		if res.Error != nil {
			return res.Error
		}
	}
	return nil
}
