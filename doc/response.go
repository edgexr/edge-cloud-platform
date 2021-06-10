package doc

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
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
