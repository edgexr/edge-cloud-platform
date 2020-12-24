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
	"github.com/mobiledgex/edge-cloud-infra/billing"
	"github.com/mobiledgex/edge-cloud-infra/mc/gormlog"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util/tasks"
)

var retryInterval = 10 * time.Second
var psqlInfo string
var sqlListenerWorkers tasks.KeyWorkers
var sqlPingInterval = 90 * time.Second

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

func InitData(ctx context.Context, superuser, superpass string, pingInterval time.Duration, stop *bool, done chan struct{}) {
	if database == nil {
		log.FatalLog("db not initialized")
	}
	db := loggedDB(ctx)
	first := true
	for {
		if *stop {
			return
		}
		if !first {
			time.Sleep(retryInterval)
		}
		first = false

		// create or update tables
		err := db.AutoMigrate(&ormapi.User{}, &ormapi.Organization{},
			&ormapi.Controller{}, &ormapi.Config{}, &ormapi.OrgCloudletPool{}, &billing.AccountInfo{}, &ormapi.BillingOrganization{}, &ormapi.UserApiKey{}).Error
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "automigrate", "err", err)
			continue
		}
		// create initial database data
		err = InitRolePerms(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "init roles", "err", err)
			continue
		}
		err = InitAdmin(ctx, superuser, superpass)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "init admin", "err", err)
			continue
		}
		err = InitConfig(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "init config", "err", err)
			continue
		}
		err = InitOrgCloudletPool(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "init orgcloudletpool", "err", err)
			continue
		}
		log.SpanLog(ctx, log.DebugLevelApi, "init data done")
		break
	}
	go func() {
		for {
			time.Sleep(pingInterval)
			database.DB().Ping()
		}
	}()
	close(done)
}

// Unfortunately the logger interface used by gorm does not
// allow any context to be passed in, so each function that
// calls into the DB must first convert it to a loggedDB.
func loggedDB(ctx context.Context) *gorm.DB {
	db := database.New() // clone
	db.SetLogger(&gormlog.Logger{Ctx: ctx})
	db.LogMode(true)
	return db
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

func initSqlListener(ctx context.Context) (*pq.Listener, error) {
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
		for {
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
