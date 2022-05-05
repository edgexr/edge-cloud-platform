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

package rbac

import (
	"context"

	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
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
