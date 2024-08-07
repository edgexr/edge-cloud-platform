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

package controller

import (
	"context"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
)

type OrganizationApi struct {
	all  *AllApis
	sync *regiondata.Sync
}

func NewOrganizationApi(sync *regiondata.Sync, all *AllApis) *OrganizationApi {
	organizationApi := OrganizationApi{}
	organizationApi.all = all
	organizationApi.sync = sync
	return &organizationApi
}

func (s *OrganizationApi) OrganizationInUse(ctx context.Context, in *edgeproto.Organization) (*edgeproto.Result, error) {
	usedBy := s.sync.UsesOrg(in.Name)
	res := &edgeproto.Result{}
	if len(usedBy) > 0 {
		res.Message = "in use by some " + strings.Join(usedBy, ", ")
		res.Code = 1
	}
	return res, nil
}
