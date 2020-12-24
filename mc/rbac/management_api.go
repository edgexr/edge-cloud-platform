package rbac

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

func (e *Enforcer) AddPolicy(ctx context.Context, params ...string) error {
	return e.adapter.AddPolicy(ctx, "p", params)
}

func (e *Enforcer) RemovePolicy(ctx context.Context, params ...string) error {
	return e.adapter.RemovePolicy(ctx, "p", params)
}

func (e *Enforcer) AddGroupingPolicy(ctx context.Context, params ...string) error {
	return e.adapter.AddPolicy(ctx, "g", params)
}

func (e *Enforcer) RemoveGroupingPolicy(ctx context.Context, params ...string) error {
	return e.adapter.RemovePolicy(ctx, "g", params)
}

func (e *Enforcer) GetPolicy() ([][]string, error) {
	return e.adapter.GetPolicies("p")
}

func (e *Enforcer) GetGroupingPolicy() ([][]string, error) {
	return e.adapter.GetPolicies("g")
}

func (e *Enforcer) HasPolicy(params ...string) (bool, error) {
	return e.adapter.HasPolicy("p", params)
}

func (e *Enforcer) HasGroupingPolicy(params ...string) (bool, error) {
	return e.adapter.HasPolicy("g", params)
}

func (e *Enforcer) GetPermissions(ctx context.Context, username, org string) (map[ormapi.RolePerm]struct{}, error) {
	return e.adapter.GetPermissions(ctx, username, org)
}
