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

package gormlog

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/jinzhu/gorm"
	"github.com/edgexr/edge-cloud/log"
)

var DoNotLogFields = map[string]struct{}{
	"passhash":            {},
	"salt":                {},
	"iter":                {},
	"picture":             {},
	"pass_entropy":        {},
	"pass_crack_time_sec": {},
	"totp":                {},
	"totp_shared_key":     {},
	"api_key":             {},
}

var updateFieldRE = regexp.MustCompile(`"([^"]+?)" = \$(\d+)`)
var insertFieldRE = regexp.MustCompile(`"([^"]+?)"`)

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
		kvs = append(kvs, filterDoNotLog(v[3], v[4]))
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

func filterDoNotLog(query, vars interface{}) interface{} {
	queryStr, ok := query.(string)
	if !ok {
		return vars
	}
	varsArray, ok := vars.([]interface{})
	if !ok {
		return vars
	}
	var dontLog []int
	if strings.HasPrefix(queryStr, "UPDATE") {
		dontLog = findUpdateFields(queryStr, DoNotLogFields)
	} else if strings.HasPrefix(queryStr, "INSERT") {
		dontLog = findInsertFields(queryStr, DoNotLogFields)
	}
	for _, ii := range dontLog {
		// note that sql fields index starts from 1, not 0
		if ii == 0 {
			continue
		}
		ii--
		if ii >= len(varsArray) {
			continue
		}
		varsArray[ii] = ""
	}
	return varsArray
}

func findUpdateFields(sql string, fieldNames map[string]struct{}) []int {
	matches := updateFieldRE.FindAllStringSubmatch(sql, -1)
	if matches == nil {
		return nil
	}
	varIndices := []int{}
	for _, match := range matches {
		if len(match) != 3 {
			continue
		}
		if _, found := fieldNames[match[1]]; !found {
			continue
		}
		ii, err := strconv.Atoi(match[2])
		if err != nil {
			continue
		}
		varIndices = append(varIndices, ii)
	}
	return varIndices
}

func findInsertFields(sql string, fieldNames map[string]struct{}) []int {
	matches := insertFieldRE.FindAllStringSubmatch(sql, -1)
	if matches == nil {
		return nil
	}
	varIndices := []int{}
	for ii, match := range matches {
		if len(match) != 2 {
			continue
		}
		if _, found := fieldNames[match[1]]; !found {
			continue
		}
		// index is the order in which it's found.
		// Note that the regexp will also match the table name,
		// and that ends up as index 0, which is ok because
		// the returned indices should start from 1.
		varIndices = append(varIndices, ii)
	}
	return varIndices
}

// Unfortunately the logger interface used by gorm does not
// allow any context to be passed in, so each function that
// calls into the DB must first convert it to a loggedDB.
func LoggedDB(ctx context.Context, database *gorm.DB) *gorm.DB {
	db := database.New() // clone
	db.SetLogger(&Logger{Ctx: ctx})
	db.LogMode(true)
	return db
}
