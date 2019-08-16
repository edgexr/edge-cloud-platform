package ormclient

import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"

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
	ShowOrg(uri, token string) ([]ormapi.Organization, int, error)

	AddUserRole(uri, token string, role *ormapi.Role) (int, error)
	RemoveUserRole(uri, token string, role *ormapi.Role) (int, error)
	ShowUserRole(uri, token string) ([]ormapi.Role, int, error)
	ShowRoleAssignment(uri, token string) ([]ormapi.Role, int, error)

	CreateData(uri, token string, data *ormapi.AllData, cb func(res *ormapi.Result)) (int, error)
	DeleteData(uri, token string, data *ormapi.AllData, cb func(res *ormapi.Result)) (int, error)
	ShowData(uri, token string) (*ormapi.AllData, int, error)

	UpdateConfig(uri, token string, config map[string]interface{}) (int, error)
	ShowConfig(uri, token string) (*ormapi.Config, int, error)

	ShowAuditSelf(uri, token string, query *ormapi.AuditQuery) ([]ormapi.AuditResponse, int, error)
	ShowAuditOrg(uri, token string, query *ormapi.AuditQuery) ([]ormapi.AuditResponse, int, error)

	FlavorApiClient
	CloudletApiClient
	ClusterInstApiClient
	AppApiClient
	AppInstApiClient
}
