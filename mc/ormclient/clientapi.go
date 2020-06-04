package ormclient

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
)

type Api interface {
	DoLogin(uri, user, pass string) (string, error)

	CreateUser(uri string, user *ormapi.User) (int, error)
	DeleteUser(uri, token string, user *ormapi.User) (int, error)
	ShowUser(uri, token string, org *ormapi.Organization) ([]ormapi.User, int, error)
	RestrictedUserUpdate(uri, token string, user map[string]interface{}) (int, error)

	CreateController(uri, token string, ctrl *ormapi.Controller) (int, error)
	DeleteController(uri, token string, ctrl *ormapi.Controller) (int, error)
	ShowController(uri, token string) ([]ormapi.Controller, int, error)

	CreateOrg(uri, token string, org *ormapi.Organization) (int, error)
	DeleteOrg(uri, token string, org *ormapi.Organization) (int, error)
	UpdateOrg(uri, token string, jsonData string) (int, error)
	ShowOrg(uri, token string) ([]ormapi.Organization, int, error)

	AddUserRole(uri, token string, role *ormapi.Role) (int, error)
	RemoveUserRole(uri, token string, role *ormapi.Role) (int, error)
	ShowUserRole(uri, token string) ([]ormapi.Role, int, error)
	ShowRoleAssignment(uri, token string) ([]ormapi.Role, int, error)

	CreateData(uri, token string, data *ormapi.AllData, cb func(res *ormapi.Result)) (int, error)
	DeleteData(uri, token string, data *ormapi.AllData, cb func(res *ormapi.Result)) (int, error)
	ShowData(uri, token string) (*ormapi.AllData, int, error)

	ShowAppMetrics(uri, token string, query *ormapi.RegionAppInstMetrics) (*ormapi.AllMetrics, int, error)
	ShowClusterMetrics(uri, token string, query *ormapi.RegionClusterInstMetrics) (*ormapi.AllMetrics, int, error)
	ShowCloudletMetrics(uri, token string, query *ormapi.RegionCloudletMetrics) (*ormapi.AllMetrics, int, error)

	ShowAppEvents(uri, token string, query *ormapi.RegionAppInstEvents) (*ormapi.AllMetrics, int, error)
	ShowClusterEvents(uri, token string, query *ormapi.RegionClusterInstEvents) (*ormapi.AllMetrics, int, error)
	ShowCloudletEvents(uri, token string, query *ormapi.RegionCloudletEvents) (*ormapi.AllMetrics, int, error)

	UpdateConfig(uri, token string, config map[string]interface{}) (int, error)
	ResetConfig(uri, token string) (int, error)
	ShowConfig(uri, token string) (*ormapi.Config, int, error)

	CreateOrgCloudletPool(uri, token string, op *ormapi.OrgCloudletPool) (int, error)
	DeleteOrgCloudletPool(uri, token string, op *ormapi.OrgCloudletPool) (int, error)
	ShowOrgCloudletPool(uri, token string) ([]ormapi.OrgCloudletPool, int, error)
	ShowOrgCloudlet(uri, token string, in *ormapi.OrgCloudlet) ([]edgeproto.Cloudlet, int, error)

	ShowAuditSelf(uri, token string, query *ormapi.AuditQuery) ([]ormapi.AuditResponse, int, error)
	ShowAuditOrg(uri, token string, query *ormapi.AuditQuery) ([]ormapi.AuditResponse, int, error)

	FlavorApiClient
	CloudletApiClient
	CloudletInfoApiClient
	ClusterInstApiClient
	AppApiClient
	AppInstApiClient
	CloudletPoolApiClient
	CloudletPoolMemberApiClient
	CloudletPoolShowApiClient
	AutoScalePolicyApiClient
	ResTagTableApiClient
	AutoProvPolicyApiClient
	PrivacyPolicyApiClient
	OperatorCodeApiClient
	SettingsApiClient
	AppInstClientApiClient
	NodeApiClient
	DebugApiClient
	AlertApiClient
	ExecApiClient
	CloudletRefsApiClient
	ClusterRefsApiClient
	AppInstRefsApiClient
	DeviceApiClient
}
