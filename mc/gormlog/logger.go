package gormlog

import (
	"context"

	"github.com/mobiledgex/edge-cloud/log"
)

// GormLogger carries the span context into the database logger
// so it can log SQL calls. It implements the gorm.logger interface.
type Logger struct {
	Ctx context.Context
}

func (s *Logger) Print(v ...interface{}) {
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
	log.SpanLog(s.Ctx, log.DebugLevelApi, msg, kvs...)
}
