package orm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/labstack/echo"
	_ "github.com/lib/pq"
	"github.com/mobiledgex/edge-cloud-infra/billing/zuora"
	"github.com/mobiledgex/edge-cloud-infra/mc/gormlog"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
)

var retryInterval = 10 * time.Second

func InitSql(ctx context.Context, addr, username, password, dbname string) (*gorm.DB, error) {
	hostport := strings.Split(addr, ":")
	if len(hostport) != 2 {
		return nil, fmt.Errorf("Invalid postgres address format %s", addr)
	}

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s "+
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
			&ormapi.Controller{}, &ormapi.Config{}, &ormapi.OrgCloudletPool{}, &zuora.AccountInfo{}, &ormapi.BillingOrganization{}).Error
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
