package orm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/persist"
	gormadapter "github.com/casbin/gorm-adapter"
	"github.com/jinzhu/gorm"
	_ "github.com/labstack/echo"
	_ "github.com/lib/pq"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
)

var retryInterval = 10 * time.Second

func InitSql(ctx context.Context, addr, username, password, dbname string) (*gorm.DB, persist.Adapter, error) {
	hostport := strings.Split(addr, ":")
	if len(hostport) != 2 {
		return nil, nil, fmt.Errorf("Invalid postgres address format %s", addr)
	}

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s "+
		"dbname=%s sslmode=disable password=%s",
		hostport[0], hostport[1], username, dbname, password)
	var err error
	db, err := gorm.Open("postgres", psqlInfo)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "init sql", "host", hostport[0], "port", hostport[1],
			"dbname", dbname, "err", err)
		return nil, nil, err
	}

	dbSpecified := true
	adapter := gormadapter.NewAdapter("postgres", psqlInfo, dbSpecified)

	// Without a span defined on this context, any code path that
	// fails to call loggedDB() will panic (intentionally).
	db.SetLogger(&sqlLogger{context.Background()})
	db.LogMode(true)

	return db, &adapterLogger{adapter}, nil
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
			&ormapi.Controller{}, &ormapi.Config{}).Error
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
	db.SetLogger(&sqlLogger{ctx})
	db.LogMode(true)
	return db
}

type sqlLogger struct {
	ctx context.Context
}

func (s *sqlLogger) Print(v ...interface{}) {
	if len(v) < 1 {
		return
	}
	kvs := make([]interface{}, 0)
	msg := "sql log"
	switch v[0] {
	case "sql":
		kvs = append(kvs, "sql")
		kvs = append(kvs, v[3])
		kvs = append(kvs, "vars")
		kvs = append(kvs, v[4])
		kvs = append(kvs, "rows-affected")
		kvs = append(kvs, v[5])
		kvs = append(kvs, "took")
		kvs = append(kvs, v[2])
		msg = "Call sql"
	default:
		kvs = append(kvs, "vals")
		kvs = append(kvs, v[2:])
	}
	log.SpanLog(s.ctx, log.DebugLevelApi, msg, kvs...)
}

type adapterLogger struct {
	adapter persist.Adapter
}

func (s *adapterLogger) LoadPolicy(model model.Model) error {
	start := time.Now()
	err := s.adapter.LoadPolicy(model)
	log.DebugLog(log.DebugLevelApi, "Call gorm LoadPolicy", "model", model, "took", time.Since(start))
	return err
}

func (s *adapterLogger) SavePolicy(model model.Model) error {
	start := time.Now()
	err := s.adapter.SavePolicy(model)
	log.DebugLog(log.DebugLevelApi, "Call gorm SavePolicy", "model", model, "took", time.Since(start))
	return err
}

func (s *adapterLogger) AddPolicy(sec, ptype string, rule []string) error {
	start := time.Now()
	err := s.adapter.AddPolicy(sec, ptype, rule)
	log.DebugLog(log.DebugLevelApi, "Call gorm AddPolicy", "sec", sec, "ptype", ptype, "rule", rule, "took", time.Since(start))
	return err
}

func (s *adapterLogger) RemovePolicy(sec, ptype string, rule []string) error {
	start := time.Now()
	err := s.adapter.RemovePolicy(sec, ptype, rule)
	log.DebugLog(log.DebugLevelApi, "Call gorm RemovePolicy", "sec", sec, "ptype", ptype, "rule", rule, "took", time.Since(start))
	return err
}

func (s *adapterLogger) RemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	start := time.Now()
	err := s.adapter.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	log.DebugLog(log.DebugLevelApi, "Call gorm RemoveFilteredPolicy", "sec", sec, "ptype", ptype, "fieldIndex", fieldIndex, "fieldValues", fieldValues, "took", time.Since(start))
	return err
}
