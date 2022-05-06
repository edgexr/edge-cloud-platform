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

package doc

import (
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
)

// Swagger wrapper for MC responses

type swaggerHttpResponse struct {
	Message string `json:"message"`
}

// Authentication Token
// swagger:response authToken
type swaggerLoginSuccessResponse struct {
	// in: body
	Body ormapi.Token
}

// Bad Request
// swagger:response loginBadRequest
type swaggerLoginBadRequestResponse struct {
	// in: body
	Body swaggerHttpResponse
}

// Success
// swagger:response success
type successResponse struct {
	// in: body
	Body swaggerHttpResponse
}

// Status Bad Request
// swagger:response badRequest
type badReqResponse struct {
	// in:body
	Body ormapi.Result
}

// Forbidden
// swagger:response forbidden
type forbiddenResponse struct {
	// in: body
	Body ormapi.Result
}

// Not Found
// swagger:response notFound
type notFoundResponse struct {
	// in: body
	Body ormapi.Result
}

// List of Users
// swagger:response listUsers
type swaggerListUsers struct {
	// in: body
	Body []ormapi.User
}

// List of Roles
// swagger:response listRoles
type swaggerListRoles struct {
	// in: body
	Body []ormapi.Role
}

// List of Permissions
// swagger:response listPerms
type swaggerListPerms struct {
	// in: body
	Body []ormapi.RolePerm
}

// List of Orgs
// swagger:response listOrgs
type swaggerListOrgs struct {
	// in: body
	Body []ormapi.Organization
}

// List of BillingOrgs
// swagger:response listBillingOrgs
type swaggerListBillingOrgs struct {
	// in: body
	Body []ormapi.BillingOrganization
}
