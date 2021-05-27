package orm

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	"github.com/lib/pq"
	"github.com/mobiledgex/edge-cloud-infra/billing"
	"github.com/mobiledgex/edge-cloud-infra/billing/chargify"
	"github.com/mobiledgex/edge-cloud-infra/billing/fakebilling"
	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud-infra/mc/orm/alertmgr"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/rbac"
	"github.com/mobiledgex/edge-cloud-infra/version"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/integration/process"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/notify"
	edgetls "github.com/mobiledgex/edge-cloud/tls"
	"github.com/mobiledgex/edge-cloud/vault"
	"github.com/nmcclain/ldap"
	gitlab "github.com/xanzy/go-gitlab"
)

// Server struct is just to track sql/db so we can stop them later.
type Server struct {
	config       *ServerConfig
	sql          *intprocess.Sql
	database     *gorm.DB
	echo         *echo.Echo
	vault        *process.Vault
	stopInitData bool
	initDataDone chan error
	initJWKDone  chan struct{}
	notifyServer *notify.ServerMgr
	notifyClient *notify.Client
	sqlListener  *pq.Listener
	ldapServer   *ldap.Server
	done         chan struct{}
}

type ServerConfig struct {
	ServAddr                string
	SqlAddr                 string
	VaultAddr               string
	RunLocal                bool
	InitLocal               bool
	IgnoreEnv               bool
	ApiTlsCertFile          string
	ApiTlsKeyFile           string
	LocalVault              bool
	LDAPAddr                string
	LDAPUsername            string
	LDAPPassword            string
	GitlabAddr              string
	ArtifactoryAddr         string
	PingInterval            time.Duration
	SkipVerifyEmail         bool
	JaegerAddr              string
	vaultConfig             *vault.Config
	SkipOriginCheck         bool
	Hostname                string
	NotifyAddrs             string
	NotifySrvAddr           string
	NodeMgr                 *node.NodeMgr
	BillingPlatform         string
	BillingService          billing.BillingService
	AlertCache              *edgeproto.AlertCache
	AlertMgrAddr            string
	AlertmgrResolveTimout   time.Duration
	UsageCheckpointInterval string
	DomainName              string
	StaticDir               string
	DeploymentTag           string
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

	ctx, span, err := nodeMgr.Init(node.NodeTypeMC, node.CertIssuerGlobal, node.WithName(config.Hostname), node.WithCloudletPoolLookup(&allRegionCaches))
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
		config.VaultAddr = process.VaultAddress
		server.vault = &vaultProc
		auth := vault.NewAppRoleAuth(roleID, secretID)
		config.vaultConfig = vault.NewConfig(process.VaultAddress, auth)
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
	gitlabClient = gitlab.NewClient(nil, gitlabToken)
	if err = gitlabClient.SetBaseURL(config.GitlabAddr); err != nil {
		return nil, fmt.Errorf("Gitlab client set base URL to %s, %s",
			config.GitlabAddr, err.Error())
	}

	if config.RunLocal {
		sql := intprocess.Sql{
			Common: process.Common{
				Name: "sql1",
			},
			DataDir:  "./.postgres",
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

	server.initDataDone = make(chan error, 1)
	go InitData(ctx, Superuser, superpass, config.PingInterval, &server.stopInitData, server.done, server.initDataDone)

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

	e := echo.New()
	e.HideBanner = true
	server.echo = e

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})
	e.Use(logger)

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
	auth.Use(AuthCookie)
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
	auth.POST("/role/assignment/show", ShowRoleAssignment)
	auth.POST("/role/perms/show", ShowRolePerms)
	auth.POST("/role/show", ShowRole)
	auth.POST("/role/adduser", AddUserRole)
	auth.POST("/role/removeuser", RemoveUserRole)
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
	auth.POST("/audit/showself", ShowAuditSelf)
	auth.POST("/audit/showorg", ShowAuditOrg)
	auth.POST("/audit/operations", GetAuditOperations)
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
		edgeproto.InitAlertCache(config.AlertCache)
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

	gitlabSync = GitlabNewSync()
	artifactorySync = ArtifactoryNewSync()

	// gitlab/artifactory sync and alertmanager requires data to be initialized
	err = <-server.initDataDone
	if err != nil {
		return nil, err
	}
	gitlabSync.Start(server.done)
	artifactorySync.Start(server.done)
	if AlertManagerServer != nil {
		AlertManagerServer.Start()
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
		AlertManagerServer.Stop()
		AlertManagerServer = nil
	}
	nodeMgr.Finish()
}

func ShowVersion(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

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
			return err
		}

		// Set ws on echo context
		SetWs(c, ws)

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
				ctx := GetContext(c)
				log.SpanLog(ctx, log.DebugLevelApi, "Failed to write error to websocket stream", "err", err, "writeErr", writeErr)
			}
		}

		ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))

		return err
	}
}

const StreamAPITag = "StreamAPITag"

func ReadConn(c echo.Context, in interface{}) (bool, error) {
	var err error

	// Mark stream API
	c.Set(StreamAPITag, true)

	if ws := GetWs(c); ws != nil {
		err = ws.ReadJSON(in)
		if err == nil {
			out, err := json.Marshal(in)
			if err == nil {
				LogWsRequest(c, out)
			}
		}
	} else {
		err = c.Bind(in)
	}
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, fmt.Errorf("Invalid data")
		}
		errStr := checkForTimeError(fmt.Sprintf("Invalid data: %v", err))
		return false, fmt.Errorf(errStr)
	}

	return true, nil
}

func WaitForConnClose(c echo.Context, serverClosed chan bool) {
	if ws := GetWs(c); ws != nil {
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
		LogWsResponse(c, string(out))
	}
	return ws.WriteJSON(wsPayload)
}

func WriteStream(c echo.Context, payload *ormapi.StreamPayload) error {
	if ws := GetWs(c); ws != nil {
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
