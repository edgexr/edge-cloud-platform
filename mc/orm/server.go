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

package orm

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	"github.com/lib/pq"
	"github.com/edgexr/edge-cloud-infra/billing"
	"github.com/edgexr/edge-cloud-infra/billing/chargify"
	"github.com/edgexr/edge-cloud-infra/billing/fakebilling"
	intprocess "github.com/edgexr/edge-cloud-infra/e2e-tests/int-process"
	"github.com/edgexr/edge-cloud-infra/mc/federation"
	"github.com/edgexr/edge-cloud-infra/mc/orm/alertmgr"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud-infra/mc/rbac"
	"github.com/edgexr/edge-cloud-infra/version"
	"github.com/edgexr/edge-cloud/cli"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/accessapi"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	"github.com/edgexr/edge-cloud/cloudcommon/ratelimit"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/integration/process"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/notify"
	edgetls "github.com/edgexr/edge-cloud/tls"
	"github.com/edgexr/edge-cloud/vault"
	"github.com/nmcclain/ldap"
	gitlab "github.com/xanzy/go-gitlab"
)

// Server struct is just to track sql/db so we can stop them later.
type Server struct {
	config          *ServerConfig
	sql             *intprocess.Sql
	database        *gorm.DB
	echo            *echo.Echo
	vault           *process.Vault
	stopInitData    bool
	initDataDone    chan error
	initJWKDone     chan struct{}
	notifyServer    *notify.ServerMgr
	notifyClient    *notify.Client
	sqlListener     *pq.Listener
	ldapServer      *ldap.Server
	done            chan struct{}
	alertMgrStarted bool
	federationEcho  *echo.Echo
}

type ServerConfig struct {
	ServAddr                 string
	SqlAddr                  string
	VaultAddr                string
	FederationAddr           string
	PublicAddr               string
	RunLocal                 bool
	InitLocal                bool
	SqlDataDir               string
	IgnoreEnv                bool
	ApiTlsCertFile           string
	ApiTlsKeyFile            string
	LocalVault               bool
	LDAPAddr                 string
	LDAPUsername             string
	LDAPPassword             string
	GitlabAddr               string
	ArtifactoryAddr          string
	PingInterval             time.Duration
	SkipVerifyEmail          bool
	JaegerAddr               string
	vaultConfig              *vault.Config
	SkipOriginCheck          bool
	Hostname                 string
	NotifyAddrs              string
	NotifySrvAddr            string
	NodeMgr                  *node.NodeMgr
	BillingPlatform          string
	BillingService           billing.BillingService
	AlertCache               *edgeproto.AlertCache
	AlertMgrAddr             string
	AlertmgrResolveTimout    time.Duration
	UsageCheckpointInterval  string
	DomainName               string
	StaticDir                string
	DeploymentTag            string
	ControllerNotifyPort     string
	ConsoleAddr              string
	PasswordResetConsolePath string
	VerifyEmailConsolePath   string
}

var DefaultDBUser = "mcuser"
var DefaultDBName = "mcdb"
var DefaultDBPass = ""
var DefaultSuperuser = "mexadmin"
var DefaultSuperpass = "mexadminfastedgecloudinfra"
var Superuser string

var database *gorm.DB

var enforcer *rbac.Enforcer
var serverConfig *ServerConfig
var gitlabClient *gitlab.Client
var gitlabSync *AppStoreSync
var artifactorySync *AppStoreSync
var nodeMgr *node.NodeMgr
var AlertManagerServer *alertmgr.AlertMgrServer
var allRegionCaches AllRegionCaches
var connCache *ConnCache
var fedClient *federation.FederationClient

var unitTestNodeMgrOps []node.NodeOp
var rateLimitMgr *ratelimit.RateLimitManager

func RunServer(config *ServerConfig) (retserver *Server, reterr error) {
	server := Server{config: config}
	// keep global pointer to config stored in server for easy access
	serverConfig = server.config
	if config.NodeMgr == nil {
		config.NodeMgr = &node.NodeMgr{}
	}
	nodeMgr = config.NodeMgr
	server.done = make(chan struct{})

	dbuser := os.Getenv("db_username")
	dbpass := os.Getenv("db_password")
	dbname := os.Getenv("db_name")
	Superuser = os.Getenv("superuser")
	superpass := os.Getenv("superpass")
	gitlabToken := os.Getenv("gitlab_token")
	if dbuser == "" || config.IgnoreEnv {
		dbuser = DefaultDBUser
	}
	if dbname == "" || config.IgnoreEnv {
		dbname = DefaultDBName
	}
	if dbpass == "" || config.IgnoreEnv {
		dbpass = DefaultDBPass
	}
	if Superuser == "" || config.IgnoreEnv {
		Superuser = DefaultSuperuser
	}
	if superpass == "" || config.IgnoreEnv {
		superpass = DefaultSuperpass
	}
	if serverConfig.LDAPUsername == "" && !config.IgnoreEnv {
		serverConfig.LDAPUsername = os.Getenv("LDAP_USERNAME")
	}
	if serverConfig.LDAPPassword == "" && !config.IgnoreEnv {
		serverConfig.LDAPPassword = os.Getenv("LDAP_PASSWORD")
	}
	allRegionCaches.init()

	if config.DeploymentTag == "" {
		return nil, fmt.Errorf("Missing deployment tag")
	}

	if config.ConsoleAddr != "" {
		if !strings.HasPrefix(config.ConsoleAddr, "http") {
			// assume this to be HTTPS
			config.ConsoleAddr = "https://" + config.ConsoleAddr
		}
		// For uniformity, sanitize the console addr path to end with /
		if !strings.HasSuffix(config.ConsoleAddr, "/") {
			config.ConsoleAddr = config.ConsoleAddr + "/"
		}
	}
	if config.PublicAddr != "" {
		if !strings.HasPrefix(config.PublicAddr, "http") {
			// assume this to be HTTPS
			config.ConsoleAddr = "https://" + config.ConsoleAddr
		}
	}

	// For uniformity, sanitize the console URL paths to not start with /
	if config.PasswordResetConsolePath != "" {
		config.PasswordResetConsolePath = strings.TrimPrefix(config.PasswordResetConsolePath, "/")
	}
	if config.VerifyEmailConsolePath != "" {
		config.VerifyEmailConsolePath = strings.TrimPrefix(config.VerifyEmailConsolePath, "/")
	}

	ops := []node.NodeOp{
		node.WithName(config.Hostname),
		node.WithCloudletPoolLookup(&allRegionCaches),
		node.WithCloudletLookup(&allRegionCaches),
	}
	ops = append(ops, unitTestNodeMgrOps...)
	ctx, span, err := nodeMgr.Init(node.NodeTypeMC, node.CertIssuerGlobal, ops...)
	if err != nil {
		return nil, err
	}
	defer span.Finish()
	defer func() {
		if reterr != nil {
			server.Stop()
		}
	}()
	nodeMgr.UpdateNodeProps(ctx, version.InfraBuildProps("Infra"))

	if config.LocalVault {
		vaultProc := process.Vault{
			Common: process.Common{
				Name: "vault",
			},
			DmeSecret: "123456",
		}
		_, err := vaultProc.StartLocalRoles()
		if err != nil {
			return nil, err
		}
		roles, err := intprocess.SetupVault(&vaultProc)
		if err != nil {
			return nil, err
		}
		roleID := roles.MCRoleID
		secretID := roles.MCSecretID
		config.VaultAddr = vaultProc.ListenAddr
		server.vault = &vaultProc
		auth := vault.NewAppRoleAuth(roleID, secretID)
		config.vaultConfig = vault.NewConfig(vaultProc.ListenAddr, auth)
	}
	// vaultConfig should only be set by unit tests
	if config.vaultConfig == nil {
		vaultConfig, err := vault.BestConfig(config.VaultAddr)
		if err != nil {
			return nil, err
		}
		config.vaultConfig = vaultConfig
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "vault auth", "type", config.vaultConfig.Auth.Type())
	server.initJWKDone = make(chan struct{}, 1)
	InitVault(config.vaultConfig, server.done, server.initJWKDone)

	switch serverConfig.BillingPlatform {
	case "fake":
		serverConfig.BillingService = &fakebilling.BillingService{}
	case "chargify":
		serverConfig.BillingService = &chargify.BillingService{}
	default:
		return nil, fmt.Errorf("Unable to determine billing platform: %s\n", serverConfig.BillingPlatform)
	}

	err = serverConfig.BillingService.Init(ctx, config.vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("Unable to initialize billing services: %v", err)
	}

	if err = checkUsageCheckpointInterval(); err != nil {
		return nil, err
	}

	if gitlabToken == "" {
		log.InfoLog("Note: No gitlab_token env var found")
	}
	if config.GitlabAddr != "" {
		gitlabClient = gitlab.NewClient(nil, gitlabToken)
		if err = gitlabClient.SetBaseURL(config.GitlabAddr); err != nil {
			return nil, fmt.Errorf("Gitlab client set base URL to %s, %s",
				config.GitlabAddr, err.Error())
		}
	}

	if config.RunLocal {
		if config.SqlDataDir == "" {
			config.SqlDataDir = "./.postgres"
		}
		sql := intprocess.Sql{
			Common: process.Common{
				Name: "sql1",
			},
			DataDir:  config.SqlDataDir,
			HttpAddr: config.SqlAddr,
			Username: dbuser,
			Dbname:   dbname,
		}
		_, err := os.Stat(sql.DataDir)
		if config.InitLocal || os.IsNotExist(err) {
			sql.InitDataDir()
		}
		err = sql.StartLocal("")
		if err != nil {
			return nil, fmt.Errorf("local sql start failed, %s",
				err.Error())
		}
		server.sql = &sql
	}

	initdb, err := InitSql(ctx, config.SqlAddr, dbuser, dbpass, dbname)
	if err != nil {
		return nil, fmt.Errorf("sql init failed, %s", err.Error())
	}
	database = initdb
	server.database = database

	enforcer = rbac.NewEnforcer(initdb)
	err = enforcer.Init(ctx)
	if err != nil {
		return nil, fmt.Errorf("enforcer init failed, %v", err)
	}

	fedClient, err = federation.NewClient(accessapi.NewVaultGlobalClient(config.vaultConfig))
	if err != nil {
		log.FatalLog("Failed to setup federation client", "err", err)
	}

	server.initDataDone = make(chan error, 1)
	go InitData(ctx, Superuser, superpass, config.PingInterval, &server.stopInitData, server.done, server.initDataDone)

	if config.AlertCache != nil {
		edgeproto.InitAlertCache(config.AlertCache)
	}
	if config.AlertMgrAddr != "" {
		tlsConfig, err := nodeMgr.GetPublicClientTlsConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("Unable to get a client tls config, %s", err.Error())
		}
		AlertManagerServer, err = alertmgr.NewAlertMgrServer(config.AlertMgrAddr, tlsConfig,
			config.AlertCache, config.AlertmgrResolveTimout)
		if err != nil {
			// TODO - this needs to be a fatal failure when we add alertmanager deployment to the ansible scripts
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to start alertmanager server", "error", err)
			err = nil
		}
	}

	connCache = NewConnCache()
	connCache.Start()

	e := echo.New()
	e.HideBanner = true
	e.Binder = &CustomBinder{}
	server.echo = e

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	// AuthCookie needs to be done here at the root so it can run before RateLimit and extract the user information needed by the RateLimit middleware.
	// AuthCookie will only run for the /auth path.
	e.Use(logger, AuthCookie, RateLimit)

	// login route
	root := "api/v1"
	// accessible routes

	// swagger:route POST /login Security Login
	// Login.
	// Login to MC.
	// responses:
	//   200: authToken
	//   400: loginBadRequest
	e.POST(root+"/login", Login)
	// swagger:route POST /usercreate User CreateUser
	// Create User.
	// Creates a new user and allows them to access and manage resources.
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	e.POST(root+"/usercreate", CreateUser)
	e.POST(root+"/passwordresetrequest", PasswordResetRequest)
	// swagger:route POST /publicconfig Config PublicConfig
	// Show Public Configuration.
	// Show Public Configuration for UI
	// responses:
	//   200: success
	//   400: badRequest
	//   404: notFound
	e.POST(root+"/publicconfig", PublicConfig)
	// swagger:route POST /passwordreset Security PasswdReset
	// Reset Login Password.
	// This resets your login password.
	// responses:
	//   200: success
	//   400: badRequest
	e.POST(root+"/passwordreset", PasswordReset)
	e.POST(root+"/verifyemail", VerifyEmail)
	e.POST(root+"/resendverify", ResendVerify)
	// authenticated routes - jwt middleware
	auth := e.Group(root + "/auth")
	// refresh auth cookie
	auth.POST("/refresh", RefreshAuthCookie)

	// swagger:route POST /auth/user/show User ShowUser
	// Show Users.
	// Displays existing users to which you are authorized to access.
	// Security:
	//   Bearer:
	// responses:
	//   200: listUsers
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/user/show", ShowUser)
	auth.POST("/user/current", CurrentUser)
	// swagger:route POST /auth/user/delete User DeleteUser
	// Delete User.
	// Deletes existing user.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/user/delete", DeleteUser)
	// swagger:route POST /auth/user/update User UpdateUser
	// Update User.
	// Updates current user.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/user/update", UpdateUser)
	auth.POST("/user/newpass", NewPassword)
	auth.POST("/user/create/apikey", CreateUserApiKey)
	auth.POST("/user/delete/apikey", DeleteUserApiKey)
	auth.POST("/user/show/apikey", ShowUserApiKey)
	// swagger:route POST /auth/role/assignment/show Role ShowRoleAssignment
	// Show Role Assignment.
	// Show roles for the current user.
	// Security:
	//   Bearer:
	// responses:
	//   200: listRoles
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/role/assignment/show", ShowRoleAssignment)
	// swagger:route POST /auth/role/perms/show Role ShowRolePerm
	// Show Role Permissions.
	// Show permissions associated with each role.
	// Security:
	//   Bearer:
	// responses:
	//   200: listPerms
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/role/perms/show", ShowRolePerms)
	// swagger:route POST /auth/role/show Role ShowRoleNames
	// Show Role Names.
	// Show role names.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/role/show", ShowRole)
	// swagger:route POST /auth/role/adduser Role AddUserRole
	// Add User Role.
	// Add a role for the organization to the user.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/role/adduser", AddUserRole)
	// swagger:route POST /auth/role/removeuser Role RemoveUserRole
	// Remove User Role.
	// Remove the role for the organization from the user.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/role/removeuser", RemoveUserRole)
	// swagger:route POST /auth/role/showuser Role ShowUserRole
	// Show User Role.
	// Show roles for the organizations the current user can add or remove roles to
	// Security:
	//   Bearer:
	// responses:
	//   200: listRoles
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/role/showuser", ShowUserRole)
	// swagger:route POST /auth/org/create Organization CreateOrg
	// Create Organization.
	// Create an Organization to access operator/cloudlet APIs.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/org/create", CreateOrg)
	// swagger:route POST /auth/org/update Organization UpdateOrg
	// Update Organization.
	// API to update an existing Organization.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/org/update", UpdateOrg)
	// swagger:route POST /auth/org/show Organization ShowOrg
	// Show Organizations.
	// Displays existing Organizations in which you are authorized to access.
	// Security:
	//   Bearer:
	// responses:
	//   200: listOrgs
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/org/show", ShowOrg)
	// swagger:route POST /auth/org/delete Organization DeleteOrg
	// Delete Organization.
	// Deletes an existing Organization.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/org/delete", DeleteOrg)

	auth.POST("/billingorg/create", CreateBillingOrg)
	// swagger:route POST /auth/billingorg/update BillingOrganization UpdateBillingOrg
	// Update BillingOrganization.
	// API to update an existing BillingOrganization.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/billingorg/update", UpdateBillingOrg)
	// swagger:route POST /auth/billingorg/addchild BillingOrganization AddChildOrg
	// Add Child to BillingOrganization.
	// Adds an Organization to an existing parent BillingOrganization.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/billingorg/addchild", AddChildOrg)
	// swagger:route POST /auth/billingorg/removechild BillingOrganization RemoveChildOrg
	// Remove Child from BillingOrganization.
	// Removes an Organization from an existing parent BillingOrganization.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/billingorg/removechild", RemoveChildOrg)
	// swagger:route POST /auth/billingorg/show BillingOrganization ShowBillingOrg
	// Show BillingOrganizations.
	// Displays existing BillingOrganizations in which you are authorized to access.
	// Security:
	//   Bearer:
	// responses:
	//   200: listBillingOrgs
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/billingorg/show", ShowBillingOrg)
	// swagger:route POST /auth/billingorg/delete BillingOrganization DeleteBillingOrg
	// Delete BillingOrganization.
	// Deletes an existing BillingOrganization.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/billingorg/delete", DeleteBillingOrg)
	auth.POST("/billingorg/invoice", GetInvoice)
	auth.POST("/billingorg/showaccount", ShowAccountInfo)
	auth.POST("/billingorg/showpaymentprofiles", ShowPaymentInfo)
	auth.POST("/billingorg/deletepaymentprofile", DeletePaymentInfo)

	auth.POST("/controller/create", CreateController)
	auth.POST("/controller/update", UpdateController)
	auth.POST("/controller/delete", DeleteController)
	auth.POST("/controller/show", ShowController)
	auth.POST("/gitlab/resync", GitlabResync)
	auth.POST("/artifactory/resync", ArtifactoryResync)
	auth.POST("/artifactory/summary", ArtifactorySummary)
	auth.POST("/config/update", UpdateConfig)
	auth.POST("/config/reset", ResetConfig)
	auth.POST("/config/show", ShowConfig)
	auth.POST("/config/version", ShowVersion)
	auth.POST("/restricted/user/update", RestrictedUserUpdate)
	auth.POST("/restricted/org/update", RestrictedUpdateOrg)
	auth.POST("/cloudletpoolaccessinvitation/create", CreateCloudletPoolAccessInvitation)
	auth.POST("/cloudletpoolaccessinvitation/delete", DeleteCloudletPoolAccessInvitation)
	auth.POST("/cloudletpoolaccessinvitation/show", ShowCloudletPoolAccessInvitation)
	auth.POST("/cloudletpoolaccessresponse/create", CreateCloudletPoolAccessResponse)
	auth.POST("/cloudletpoolaccessresponse/delete", DeleteCloudletPoolAccessResponse)
	auth.POST("/cloudletpoolaccessresponse/show", ShowCloudletPoolAccessResponse)
	auth.POST("/cloudletpoolaccessgranted/show", ShowCloudletPoolAccessGranted)
	auth.POST("/cloudletpoolaccesspending/show", ShowCloudletPoolAccessPending)
	auth.POST("/orgcloudlet/show", ShowOrgCloudlet)
	auth.POST("/orgcloudletinfo/show", ShowOrgCloudletInfo)
	auth.POST("/ratelimitsettingsmc/show", ShowRateLimitSettingsMc)
	auth.POST("/ratelimitsettingsmc/createflow", CreateFlowRateLimitSettingsMc)
	auth.POST("/ratelimitsettingsmc/deleteflow", DeleteFlowRateLimitSettingsMc)
	auth.POST("/ratelimitsettingsmc/updateflow", UpdateFlowRateLimitSettingsMc)
	auth.POST("/ratelimitsettingsmc/showflow", ShowFlowRateLimitSettingsMc)
	auth.POST("/ratelimitsettingsmc/createmaxreqs", CreateMaxReqsRateLimitSettingsMc)
	auth.POST("/ratelimitsettingsmc/deletemaxreqs", DeleteMaxReqsRateLimitSettingsMc)
	auth.POST("/ratelimitsettingsmc/updatemaxreqs", UpdateMaxReqsRateLimitSettingsMc)
	auth.POST("/ratelimitsettingsmc/showmaxreqs", ShowMaxReqsRateLimitSettingsMc)

	// Support multiple connection types: HTTP(s), Websockets
	addControllerApis("POST", auth)

	// Metrics api route use auth to serve a query to influxDB

	// swagger:route POST /auth/metrics/app DeveloperMetrics AppMetrics
	// App related metrics.
	// Display app related metrics.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/metrics/app", GetMetricsCommon)

	auth.POST("/metrics/app/v2", GetAppMetricsV2)

	// swagger:route POST /auth/metrics/cluster DeveloperMetrics ClusterMetrics
	// Cluster related metrics.
	// Display cluster related metrics.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/metrics/cluster", GetMetricsCommon)

	// swagger:route POST /auth/metrics/cloudlet OperatorMetrics CloudletMetrics
	// Cloudlet related metrics.
	// Display cloudlet related metrics.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/metrics/cloudlet", GetMetricsCommon)

	// swagger:route POST /auth/metrics/cloudlet/usage OperatorMetrics CloudletUsageMetrics
	// Cloudlet usage related metrics.
	// Display cloudlet usage related metrics.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/metrics/cloudlet/usage", GetMetricsCommon)

	// swagger:route POST /auth/metrics/clientapiusage DeveloperMetrics ClientApiUsageMetrics
	// Client api usage related metrics.
	// Display client api usage related metrics.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/metrics/clientapiusage", GetMetricsCommon)

	// swagger:route POST /auth/metrics/clientappusage DeveloperMetrics ClientAppUsageMetrics
	// Client app usage related metrics.
	// Display client app usage related metrics.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/metrics/clientappusage", GetMetricsCommon)

	// swagger:route POST /auth/metrics/clientcloudletusage DeveloperMetrics ClientCloudletUsageMetrics
	// Client cloudlet usage related metrics.
	// Display client cloudlet usage related metrics.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/metrics/clientcloudletusage", GetMetricsCommon)

	auth.POST("/events/app", GetEventsCommon)
	auth.POST("/events/cluster", GetEventsCommon)
	auth.POST("/events/cloudlet", GetEventsCommon)

	// new events/audit apis
	// swagger:route POST /auth/events/show Events SearchEvents
	// Search events
	// Display events based on search filter.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/events/show", ShowEvents)
	// swagger:route POST /auth/events/find Events FindEvents
	// Find events
	// Display events based on find filter.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/events/find", FindEvents)
	// swagger:route POST /auth/events/terms Events TermsEvents
	// Terms Events
	// Display events terms.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/events/terms", EventTerms)

	auth.POST("/spans/terms", SpanTerms)
	auth.POST("/spans/show", ShowSpans)
	auth.POST("/spans/showverbose", ShowSpansVerbose)

	// swagger:route POST /auth/usage/app DeveloperUsage AppUsage
	// App Usage
	// Display app usage.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/usage/app", GetUsageCommon)
	// swagger:route POST /auth/usage/cluster DeveloperUsage ClusterUsage
	// Cluster Usage
	// Display cluster usage.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/usage/cluster", GetUsageCommon)
	// swagger:route POST /auth/usage/cloudletpool OperatorUsage CloudletPoolUsage
	// CloudletPool Usage
	// Display cloudletpool usage.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/usage/cloudletpool", GetCloudletPoolUsageCommon)

	// Alertmanager apis
	// swagger:route POST /auth/alertreceiver/create AlertReceiver CreateAlertReceiver
	// Create Alert Receiver
	// Create alert receiver.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/alertreceiver/create", CreateAlertReceiver)
	// swagger:route POST /auth/alertreceiver/delete AlertReceiver DeleteAlertReceiver
	// Delete Alert Receiver
	// Delete alert receiver.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/alertreceiver/delete", DeleteAlertReceiver)
	// swagger:route POST /auth/alertreceiver/show AlertReceiver ShowAlertReceiver
	// Show Alert Receiver
	// Show alert receiver.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
	auth.POST("/alertreceiver/show", ShowAlertReceiver)

	auth.POST("/reporter/create", CreateReporter)
	auth.POST("/reporter/update", UpdateReporter)
	auth.POST("/reporter/delete", DeleteReporter)
	auth.POST("/reporter/show", ShowReporter)
	auth.POST("/report/generatedata", GenerateReportData)
	auth.POST("/report/generate", GenerateReport)
	auth.POST("/report/show", ShowReport)
	auth.POST("/report/download", DownloadReport)

	// Plan and manage federation
	auth.POST("/federator/self/create", CreateSelfFederator)
	auth.POST("/federator/self/update", UpdateSelfFederator)
	auth.POST("/federator/self/delete", DeleteSelfFederator)
	auth.POST("/federator/self/show", ShowSelfFederator)
	auth.POST("/federator/self/generateapikey", GenerateSelfFederatorAPIKey)
	auth.POST("/federator/self/zone/create", CreateSelfFederatorZone)
	auth.POST("/federator/self/zone/delete", DeleteSelfFederatorZone)
	auth.POST("/federator/self/zone/show", ShowSelfFederatorZone)
	auth.POST("/federator/self/zone/share", ShareSelfFederatorZone)
	auth.POST("/federator/self/zone/unshare", UnshareSelfFederatorZone)
	auth.POST("/federator/partner/zone/register", RegisterPartnerFederatorZone)
	auth.POST("/federator/partner/zone/deregister", DeregisterPartnerFederatorZone)
	auth.POST("/federation/create", CreateFederation)
	auth.POST("/federation/delete", DeleteFederation)
	auth.POST("/federation/register", RegisterFederation)
	auth.POST("/federation/deregister", DeregisterFederation)
	auth.POST("/federation/partner/setapikey", SetPartnerFederationAPIKey)
	auth.POST("/federation/show", ShowFederation)
	auth.POST("/federation/self/zone/show", ShowFederatedSelfZone)
	auth.POST("/federation/partner/zone/show", ShowFederatedPartnerZone)

	// Generate new short-lived token to authenticate websocket connections
	// Note: Web-client should not store auth token as part of local storage,
	//       instead browser should store it as secure cookies.
	//       For HTTP endpoints, server responds with "set-cookie" to store
	//       cookie in browser. But the same cannot be used for websockets
	//       due to browser limitations.
	//       Hence, authenticated clients can use this API endpoint to
	//       fetch a short-lived token to authenticate websocket endpoints
	auth.POST("/wstoken", GenerateWSAuthToken)

	// Use GET method for websockets as thats the method used
	// in setting up TCP connection by most of the clients
	// Also, authorization is handled as part of websocketUpgrade
	ws := e.Group("ws/"+root+"/auth", server.websocketUpgrade)
	addControllerApis("GET", ws)
	// Metrics api route use ws to serve a query to influxDB
	ws.GET("/metrics/app", GetMetricsCommon)
	ws.GET("/metrics/cluster", GetMetricsCommon)
	ws.GET("/metrics/cloudlet", GetMetricsCommon)
	ws.GET("/metrics/cloudlet/usage", GetMetricsCommon)
	ws.GET("/metrics/clientapiusage", GetMetricsCommon)
	ws.GET("/metrics/clientappusage", GetMetricsCommon)
	ws.GET("/metrics/clientcloudletusage", GetMetricsCommon)

	if config.NotifySrvAddr != "" {
		server.notifyServer = &notify.ServerMgr{}
		nodeMgr.RegisterServer(server.notifyServer)

		tlsConfig, err := nodeMgr.InternalPki.GetServerTlsConfig(ctx,
			nodeMgr.CommonName(),
			node.CertIssuerGlobal,
			[]node.MatchCA{node.AnyRegionalMatchCA()})
		if err != nil {
			return nil, err
		}
		// sets the callback to be the alertMgr thread callback
		server.notifyServer.RegisterRecvAlertCache(config.AlertCache)
		if AlertManagerServer != nil {
			config.AlertCache.SetUpdatedCb(AlertManagerServer.UpdateAlert)
		}
		server.notifyServer.Start(nodeMgr.Name(), config.NotifySrvAddr, tlsConfig)
	}
	if config.NotifyAddrs != "" {
		tlsConfig, err := nodeMgr.InternalPki.GetClientTlsConfig(ctx,
			nodeMgr.CommonName(),
			node.CertIssuerGlobal,
			[]node.MatchCA{node.GlobalMatchCA()})
		if err != nil {
			return nil, err
		}
		addrs := strings.Split(config.NotifyAddrs, ",")
		server.notifyClient = notify.NewClient(nodeMgr.Name(), addrs, edgetls.GetGrpcDialOption(tlsConfig))
		nodeMgr.RegisterClient(server.notifyClient)

		server.notifyClient.Start()
	}

	go func() {
		var err error
		if config.ApiTlsCertFile != "" {
			err = e.StartTLS(config.ServAddr, config.ApiTlsCertFile, config.ApiTlsKeyFile)
		} else {
			err = e.Start(config.ServAddr)
		}
		if err != nil && err != http.ErrServerClosed {
			server.Stop()
			log.FatalLog("Failed to serve", "err", err)
		}
	}()

	ldapServer := ldap.NewServer()
	handler := &ldapHandler{}
	ldapServer.BindFunc("", handler)
	ldapServer.SearchFunc("", handler)
	server.ldapServer = ldapServer
	go func() {
		var err error
		if config.ApiTlsCertFile != "" {
			err = ldapServer.ListenAndServeTLS(config.LDAPAddr, config.ApiTlsCertFile, config.ApiTlsKeyFile)
		} else {
			err = ldapServer.ListenAndServe(config.LDAPAddr)
		}
		if err != nil {
			log.FatalLog("LDAP Server Failed", "err", err)
		}
	}()

	if config.FederationAddr != "" {
		// Global Operator Platform Federation
		federationEcho := echo.New()
		federationEcho.HideBanner = true
		federationEcho.Binder = &CustomBinder{}

		// RateLimit based on partner's federation ID if present or else use partner's IP
		federationEcho.Use(logger, federation.AuthAPIKey, FederationRateLimit)
		server.federationEcho = federationEcho

		partnerApi := federation.PartnerApi{
			Database:  database,
			ConnCache: connCache,
		}
		partnerApi.InitAPIs(federationEcho)

		go func() {
			if config.ApiTlsCertFile != "" {
				err = federationEcho.StartTLS(config.FederationAddr, config.ApiTlsCertFile, config.ApiTlsKeyFile)
			} else {
				err = federationEcho.Start(config.FederationAddr)
			}
			if err != nil && err != http.ErrServerClosed {
				server.Stop()
				log.FatalLog("Failed to serve federation", "err", err)
			}
		}()
	}

	// gitlab/artifactory sync and alertmanager requires data to be initialized
	err = <-server.initDataDone
	if err != nil {
		return nil, err
	}

	if config.GitlabAddr != "" {
		gitlabSync = GitlabNewSync()
		gitlabSync.Start(server.done)
	}
	if config.ArtifactoryAddr != "" {
		artifactorySync = ArtifactoryNewSync()
		artifactorySync.Start(server.done)
	}
	if AlertManagerServer != nil {
		AlertManagerServer.Start()
		server.alertMgrStarted = true
	}
	sqlListener, err := initSqlListener(ctx, server.done)
	if err != nil {
		return nil, err
	}
	server.sqlListener = sqlListener
	go func() {
		err := server.sqlListener.Listen(sqlEventsChannel)
		if err != nil && !strings.Contains(err.Error(), "Listener has been closed") {
			log.FatalLog("Failed to listen for sql events", "err", err)
		}
	}()
	if err := allRegionCaches.refreshRegions(ctx); err != nil {
		return nil, err
	}

	return &server, err
}

func (s *Server) WaitUntilReady() error {
	// login won't work until jwt keys are pulled
	<-s.initJWKDone

	// wait until server is online
	for ii := 0; ii < 10; ii++ {
		// if TLS specified, status response will be BadRequest.
		// In any case, as long as the server is responding,
		// then it is ready.
		resp, err := http.Get("http://" + s.config.ServAddr)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for server ready")
}

func (s *Server) Stop() {
	s.stopInitData = true
	close(s.done)
	if s.ldapServer != nil {
		close(s.ldapServer.Quit)
	}
	if s.echo != nil {
		s.echo.Close()
	}
	if s.federationEcho != nil {
		s.federationEcho.Close()
	}
	if connCache != nil {
		connCache.Finish()
	}
	if s.database != nil {
		s.database.Close()
	}
	if s.sqlListener != nil {
		s.sqlListener.Close()
	}
	if s.sql != nil {
		s.sql.StopLocal()
	}
	if s.vault != nil {
		s.vault.StopLocal()
	}
	if s.notifyServer != nil {
		s.notifyServer.Stop()
	}
	if s.notifyClient != nil {
		s.notifyClient.Stop()
	}
	if AlertManagerServer != nil {
		if s.alertMgrStarted {
			AlertManagerServer.Stop()
		}
		AlertManagerServer = nil
	}
	nodeMgr.Finish()
	serverConfig = &ServerConfig{}
	gitlabClient = nil
}

func ShowVersion(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)

	if err := authorized(ctx, claims.Username, "", ResourceConfig, ActionView); err != nil {
		return err
	}
	ver := ormapi.Version{
		BuildMaster: version.BuildMaster,
		BuildHead:   version.BuildHead,
		BuildAuthor: version.BuildAuthor,
		Hostname:    cloudcommon.Hostname(),
	}
	return c.JSON(http.StatusOK, ver)
}

func (s *Server) websocketUpgrade(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		upgrader := websocket.Upgrader{}
		if s.config.SkipOriginCheck {
			// Skip origin check restriction.
			// This is to be used for testing purpose only, as it is
			// not safe to allow all origins
			upgrader.CheckOrigin = func(r *http.Request) bool { return true }
		}
		ws, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
		if err != nil {
			return nil
		}
		defer ws.Close()

		// Verify Auth
		// ===========
		// JWT token is received after websocket connection is established, although
		// Websocket server can receive full request header from client before
		// upgrade to websocket

		// Infact most of the golang websocket clients do support that. But the problem
		// is on the UI side. Javascript doesn't support it directly

		// Following are some links describing this issue:
		//  - https://stackoverflow.com/questions/22383089/is-it-possible-to-use-bearer-authentication-for-websocket-upgrade-requests/26123316#26123316
		// The above URL does give another way to send access token, but then it is not
		// safe enough to use

		// Here's another way to solve this, but again complicated and insecure:
		//  - https://devcenter.heroku.com/articles/websocket-security#authentication-authorization

		// In summary, it is not straightforward to implement this from our console UI
		// as we plan to call this directly from React (browser)
		isAuth, err := AuthWSCookie(c, ws)
		if !isAuth {
			if err != nil {
				code, res := getErrorResult(err)
				wsPayload := ormapi.WSStreamPayload{
					Code: code,
					Data: res,
				}
				writeErr := writeWS(c, ws, &wsPayload)
				if writeErr != nil {
					ctx := ormutil.GetContext(c)
					log.SpanLog(ctx, log.DebugLevelApi, "Failed to write error to websocket stream", "err", err, "writeErr", writeErr)
				}
			}
			ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			return err
		}

		// Set ws on echo context
		ormutil.SetWs(c, ws)

		// call next handler
		err = next(c)

		// Any handler errors are sent via the websocket here before
		// it is closed. The error is also passed to the caller, but
		// only for being recorded in the audit log.
		if err != nil {
			code, res := getErrorResult(err)
			wsPayload := ormapi.WSStreamPayload{
				Code: code,
				Data: res,
			}
			writeErr := writeWS(c, ws, &wsPayload)
			if writeErr != nil {
				ctx := ormutil.GetContext(c)
				log.SpanLog(ctx, log.DebugLevelApi, "Failed to write error to websocket stream", "err", err, "writeErr", writeErr)
			}
		}

		ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))

		return err
	}
}

const StreamAPITag = "StreamAPITag"

func ReadConn(c echo.Context, in interface{}) ([]byte, error) {
	var dat []byte
	var err error

	// Mark stream API
	c.Set(StreamAPITag, true)

	if ws := ormutil.GetWs(c); ws != nil {
		_, dat, err = ws.ReadMessage()
		if err == nil {
			ormutil.LogWsRequest(c, dat)
		}
	} else {
		// This plus json.Umarshal is the equivalent of c.Bind()
		dat, err = ioutil.ReadAll(c.Request().Body)
	}
	if err == nil {
		err = BindJson(dat, in)
	}

	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("Invalid data")
		}
		return nil, err
	}

	return dat, nil
}

// Override the echo.DefaultBinder so we can have better error messages.
// It's also slightly more secure in that it only accepts JSON.
type CustomBinder struct{}

func (s *CustomBinder) Bind(i interface{}, c echo.Context) error {
	// reference echo.DefaultBinder
	req := c.Request()
	if req.ContentLength == 0 {
		return fmt.Errorf("Request body can't be empty")
	}
	// we only accept JSON
	ctype := req.Header.Get(echo.HeaderContentType)
	switch {
	case strings.HasPrefix(ctype, echo.MIMEApplicationJSON):
		dat, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return err
		}
		return BindJson(dat, i)
	default:
		return echo.ErrUnsupportedMediaType
	}
}

func BindJson(js []byte, i interface{}) error {
	err := json.Unmarshal(js, i)
	if err == nil {
		return nil
	}
	// Unfortunately, if the json library hits an error using
	// a custom unmarshaler, it simply passes that error up instead
	// of wrapping it in a custom error type that would include the
	// field and offset. Therefore we have subpar error messages
	// for custom unmarshalers (time, duration) that do not include
	// the field and offset. The only way to fix this would be to
	// fork the json package, and add a new CustomUnmarshalTypeError
	// that would include the original time.ParseError plus the
	// field and offset.

	switch e := err.(type) {
	case *json.UnmarshalTypeError:
		errType, help, _ := cli.GetParseHelp(e.Type)
		// offset may be unspecified for custom unmarshaling errors
		offsetStr := ""
		if e.Offset != 0 {
			offsetStr = fmt.Sprintf(" at offset %d", e.Offset)
		}
		err = fmt.Errorf("Unmarshal error: expected %v, but got %v for field %q%s%s", errType, e.Value, e.Field, offsetStr, help)
	case *json.SyntaxError:
		err = fmt.Errorf("Syntax error at offset %v, %v", e.Offset, e.Error())
	case *time.ParseError:
		val := e.Value
		if valuq, err := strconv.Unquote(val); err == nil {
			val = valuq
		}
		errType, help, _ := cli.GetParseHelp(reflect.TypeOf(time.Time{}))
		err = fmt.Errorf("Unmarshal %s %q failed%s", errType, val, help)
	}
	return fmt.Errorf("Invalid JSON data: %v", err)
}

func WaitForConnClose(c echo.Context, serverClosed chan bool) {
	if ws := ormutil.GetWs(c); ws != nil {
		clientClosed := make(chan error)
		go func() {
			// Handling close events from client is different here
			// A close message is sent from client, hence just wait
			// on getting a close message
			_, _, err := ws.ReadMessage()
			clientClosed <- err
		}()
		select {
		case <-serverClosed:
			return
		case err := <-clientClosed:
			if _, ok := err.(*websocket.CloseError); !ok {
				ws.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseAbnormalClosure, ""))
				ws.Close()
			}
		}
	} else {
		if <-serverClosed {
			return
		}
	}
}

func writeWS(c echo.Context, ws *websocket.Conn, wsPayload *ormapi.WSStreamPayload) error {
	out, err := json.Marshal(wsPayload)
	if err == nil {
		ormutil.LogWsResponse(c, string(out))
	}
	return ws.WriteJSON(wsPayload)
}

func WriteStream(c echo.Context, payload *ormapi.StreamPayload) error {
	if ws := ormutil.GetWs(c); ws != nil {
		wsPayload := ormapi.WSStreamPayload{
			Code: http.StatusOK,
			Data: (*payload).Data,
		}
		return writeWS(c, ws, &wsPayload)
	} else {
		// stream func may return "forbidden", so don't write
		// header until we know it's ok
		if !c.Response().Committed {
			// Write header now that we're streaming back data
			c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			c.Response().WriteHeader(http.StatusOK)
		}
		err := json.NewEncoder(c.Response()).Encode(*payload)
		if err != nil {
			return err
		}
		c.Response().Flush()
	}
	return nil
}
