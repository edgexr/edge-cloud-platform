package ormclient

import (
	"github.com/mobiledgex/edge-cloud-infra/billing"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/jaeger/plugin/storage/es/spanstore/dbmodel"
)

type Api interface {
	DoLogin(uri, user, pass, otp, apikeyid, apikey string) (string, bool, error)

	CreateUser(uri string, user *ormapi.User) (*ormapi.UserResponse, int, error)
	DeleteUser(uri, token string, user *ormapi.User) (int, error)
	UpdateUser(uri, token string, createUserJSON string) (*ormapi.UserResponse, int, error)
	ShowUser(uri, token string, org *ormapi.ShowUser) ([]ormapi.User, int, error)
	RestrictedUserUpdate(uri, token string, user map[string]interface{}) (int, error)
	NewPassword(uri, token, password string) (int, error)

	CreateController(uri, token string, ctrl *ormapi.Controller) (int, error)
	DeleteController(uri, token string, ctrl *ormapi.Controller) (int, error)
	ShowController(uri, token string) ([]ormapi.Controller, int, error)

	CreateOrg(uri, token string, org *ormapi.Organization) (int, error)
	DeleteOrg(uri, token string, org *ormapi.Organization) (int, error)
	UpdateOrg(uri, token string, jsonData string) (int, error)
	ShowOrg(uri, token string) ([]ormapi.Organization, int, error)
	RestrictedUpdateOrg(uri, token string, org map[string]interface{}) (int, error)

	CreateBillingOrg(uri, token string, org *ormapi.BillingOrganization) (int, error)
	UpdateAccountInfo(uri, token string, acc *billing.AccountInfo) (int, error)
	DeleteBillingOrg(uri, token string, org *ormapi.BillingOrganization) (int, error)
	UpdateBillingOrg(uri, token string, jsonData string) (int, error)
	ShowBillingOrg(uri, token string) ([]ormapi.BillingOrganization, int, error)
	AddChildOrg(uri, token string, org *ormapi.BillingOrganization) (int, error)
	RemoveChildOrg(uri, token string, org *ormapi.BillingOrganization) (int, error)
	GetInvoice(uri, token string, req *ormapi.InvoiceRequest) ([]billing.InvoiceData, int, error)

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
	ShowClientApiUsageMetrics(uri, token string, query *ormapi.RegionClientApiUsageMetrics) (*ormapi.AllMetrics, int, error)
	ShowClientAppUsageMetrics(uri, token string, query *ormapi.RegionClientAppUsageMetrics) (*ormapi.AllMetrics, int, error)
	ShowClientCloudletUsageMetrics(uri, token string, query *ormapi.RegionClientCloudletUsageMetrics) (*ormapi.AllMetrics, int, error)

	ShowAppEvents(uri, token string, query *ormapi.RegionAppInstEvents) (*ormapi.AllMetrics, int, error)
	ShowClusterEvents(uri, token string, query *ormapi.RegionClusterInstEvents) (*ormapi.AllMetrics, int, error)
	ShowCloudletEvents(uri, token string, query *ormapi.RegionCloudletEvents) (*ormapi.AllMetrics, int, error)

	ShowEvents(uri, token string, query *node.EventSearch) ([]node.EventData, int, error)
	FindEvents(uri, token string, query *node.EventSearch) ([]node.EventData, int, error)
	EventTerms(uri, token string, query *node.EventSearch) (*node.EventTerms, int, error)

	ShowSpans(uri, token string, query *node.SpanSearch) ([]node.SpanOutCondensed, int, error)
	ShowSpansVerbose(uri, token string, query *node.SpanSearch) ([]dbmodel.Span, int, error)
	SpanTerms(uri, token string, query *node.SpanSearch) (*node.SpanTerms, int, error)

	ShowAppUsage(uri, token string, query *ormapi.RegionAppInstUsage) (*ormapi.AllMetrics, int, error)
	ShowClusterUsage(uri, token string, query *ormapi.RegionClusterInstUsage) (*ormapi.AllMetrics, int, error)
	ShowCloudletPoolUsage(uri, token string, query *ormapi.RegionCloudletPoolUsage) (*ormapi.AllMetrics, int, error)

	UpdateConfig(uri, token string, config map[string]interface{}) (int, error)
	ResetConfig(uri, token string) (int, error)
	ShowConfig(uri, token string) (*ormapi.Config, int, error)
	PublicConfig(uri string) (*ormapi.Config, int, error)

	CreateCloudletPoolAccessInvitation(uri, token string, op *ormapi.OrgCloudletPool) (int, error)
	DeleteCloudletPoolAccessInvitation(uri, token string, op *ormapi.OrgCloudletPool) (int, error)
	ShowCloudletPoolAccessInvitation(uri, token string, filter *ormapi.OrgCloudletPool) ([]ormapi.OrgCloudletPool, int, error)
	CreateCloudletPoolAccessResponse(uri, token string, op *ormapi.OrgCloudletPool) (int, error)
	DeleteCloudletPoolAccessResponse(uri, token string, op *ormapi.OrgCloudletPool) (int, error)
	ShowCloudletPoolAccessResponse(uri, token string, filter *ormapi.OrgCloudletPool) ([]ormapi.OrgCloudletPool, int, error)
	ShowCloudletPoolAccessGranted(uri, token string, filter *ormapi.OrgCloudletPool) ([]ormapi.OrgCloudletPool, int, error)
	ShowCloudletPoolAccessPending(uri, token string, filter *ormapi.OrgCloudletPool) ([]ormapi.OrgCloudletPool, int, error)

	ShowOrgCloudlet(uri, token string, in *ormapi.OrgCloudlet) ([]edgeproto.Cloudlet, int, error)
	ShowOrgCloudletInfo(uri, token string, in *ormapi.OrgCloudlet) ([]edgeproto.CloudletInfo, int, error)

	ShowAuditSelf(uri, token string, query *ormapi.AuditQuery) ([]ormapi.AuditResponse, int, error)
	ShowAuditOrg(uri, token string, query *ormapi.AuditQuery) ([]ormapi.AuditResponse, int, error)

	CreateAlertReceiver(uri, token string, receiver *ormapi.AlertReceiver) (int, error)
	DeleteAlertReceiver(uri, token string, receiver *ormapi.AlertReceiver) (int, error)
	ShowAlertReceiver(uri, token string, in *ormapi.AlertReceiver) ([]ormapi.AlertReceiver, int, error)

	FlavorApiClient
	CloudletApiClient
	CloudletInfoApiClient
	VMPoolApiClient
	ClusterInstApiClient
	AppApiClient
	AppInstApiClient
	CloudletPoolApiClient
	AutoScalePolicyApiClient
	ResTagTableApiClient
	AutoProvPolicyApiClient
	TrustPolicyApiClient
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
	StreamObjApiClient
	DeviceApiClient
	AppInstLatencyApiClient
}
