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
	"github.com/edgexr/edge-cloud/cloudcommon/node"
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

// swagger:parameters AddUserRole RemoveUserRole ShowUserRole ShowRoleAssignment
type swaggerRole struct {
	// in: body
	Body ormapi.Role
}

// swagger:parameters ShowRolePerm
type swaggerRolePerm struct {
	// in: body
	Body ormapi.RolePerm
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
