package doc

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

// swagger:parameters Login
type swaggerLogin struct {
	// in: body
	Body ormapi.UserLogin
}

// swagger:parameters CreateUser
type swaggerCreateUser struct {
	// in: body
	Body ormapi.CreateUser
}

// swagger:parameters DeleteUser
type swaggerDeleteUser struct {
	// in: body
	Body ormapi.User
}

// swagger:parameters ShowUser
type swaggerShowUser struct {
	// in: body
	Body ormapi.Organization
}

// swagger:parameters PasswdReset
type swaggerPasswdReset struct {
	// in: body
	Body ormapi.PasswordReset
}

// swagger:parameters CreateOrg DeleteOrg UpdateOrg
type swaggerCreateOrg struct {
	// in: body
	Body ormapi.Organization
}
