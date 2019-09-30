package rbac

import (
	"context"
	"strings"

	"github.com/jinzhu/gorm"
)

const (
	notImplemented = "not implemented"
)

type Enforcer struct {
	adapter Adapter
}

func NewEnforcer(db *gorm.DB) *Enforcer {
	db = db.New()
	// disable logging to avoid all the rbac checks filling up the logs
	db.LogMode(false)

	e := Enforcer{
		adapter: Adapter{
			db: db,
		},
	}
	return &e
}

func (e *Enforcer) Init(ctx context.Context) error {
	return e.adapter.Init(ctx)
}

func (e *Enforcer) Enforce(ctx context.Context, sub, org, obj, act string) (bool, error) {
	authz, err := e.adapter.GetAuthorized(ctx, obj, act)
	if err != nil {
		return false, err
	}

	subj := GetCasbinGroup(org, sub)
	_, found := authz[subj]
	if found {
		return true, nil
	}
	// may be admin so no org appended
	_, found = authz[sub]
	return found, nil
}

func (e *Enforcer) LogEnforce(on bool) {
	e.adapter.LogAuthz(on)
}

func (e *Enforcer) GetAuthorizedOrgs(ctx context.Context, sub, obj, act string) (map[string]struct{}, error) {
	authz, err := e.adapter.GetAuthorized(ctx, obj, act)
	if err != nil {
		return nil, err
	}
	orgs := make(map[string]struct{})
	for k, _ := range authz {
		// no org
		if k == sub {
			orgs[""] = struct{}{}
		}
		orguser := strings.Split(k, "::")
		if len(orguser) == 2 && orguser[1] == sub {
			org := orguser[0]
			orgs[org] = struct{}{}
		}
	}
	return orgs, nil
}
