package doc

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
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

// swagger:parameters AppMetrics
type swaggerAppMetrics struct {
	// in: body
	Body ormapi.RegionAppInstMetrics
}

// swagger:parameters ClusterMetrics
type swaggerClusterMetrics struct {
	// in: body
	Body ormapi.RegionClusterInstMetrics
}

// swagger:parameters CloudletMetrics
type swaggerCloudletMetrics struct {
	// in: body
	Body ormapi.RegionCloudletMetrics
}

// swagger:parameters ClientApiUsageMetrics
type swaggerClientApiUsageMetrics struct {
	// in: body
	Body ormapi.RegionClientApiUsageMetrics
}

// swagger:parameters ClientAppUsageMetrics
type swaggerClientAppUsageMetrics struct {
	// in: body
	Body ormapi.RegionClientAppUsageMetrics
}

// swagger:parameters ClientCloudletUsageMetrics
type swaggerClientCloudletUsageMetrics struct {
	// in: body
	Body ormapi.RegionClientCloudletUsageMetrics
}

// swagger:parameters AppUsage
type swaggerAppUsage struct {
	// in: body
	Body ormapi.RegionAppInstUsage
}

// swagger:parameters ClusterUsage
type swaggerClusterUsage struct {
	// in: body
	Body ormapi.RegionClusterInstUsage
}

// swagger:parameters CloudletPoolUsage
type swaggerCloudletPoolUsage struct {
	// in: body
	Body ormapi.RegionCloudletPoolUsage
}

// swagger:parameters SearchEvents FindEvents
type swaggerEvents struct {
	// in: body
	Body node.EventSearch
}

// swagger:parameters TermsEvents
type swaggerTermsEvents struct {
	// in: body
	Body node.EventTerms
}

// swagger:parameters CreateAlertReceiver DeleteAlertReceiver ShowAlertReceiver
type swaggerAlertReceiver struct {
	// in: body
	Body ormapi.AlertReceiver
}
