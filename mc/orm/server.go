package orm

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/billing/zuora"
	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud-infra/mc/orm/alertmgr"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/rbac"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	edgecli "github.com/mobiledgex/edge-cloud/edgectl/cli"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/integration/process"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/notify"
	edgetls "github.com/mobiledgex/edge-cloud/tls"
	"github.com/mobiledgex/edge-cloud/vault"
	"github.com/mobiledgex/edge-cloud/version"
	"github.com/nmcclain/ldap"
	gitlab "github.com/xanzy/go-gitlab"
	"google.golang.org/grpc/status"
)

// Server struct is just to track sql/db so we can stop them later.
type Server struct {
	config       *ServerConfig
	sql          *intprocess.Sql
	database     *gorm.DB
	echo         *echo.Echo
	vault        *process.Vault
	stopInitData bool
	initDataDone chan struct{}
	initJWKDone  chan struct{}
	notifyServer *notify.ServerMgr
	notifyClient *notify.Client
}

type ServerConfig struct {
	ServAddr              string
	SqlAddr               string
	VaultAddr             string
	ConsoleProxyAddr      string
	RunLocal              bool
	InitLocal             bool
	IgnoreEnv             bool
	TlsCertFile           string
	TlsKeyFile            string
	LocalVault            bool
	LDAPAddr              string
	GitlabAddr            string
	ArtifactoryAddr       string
	ClientCert            string
	PingInterval          time.Duration
	SkipVerifyEmail       bool
	JaegerAddr            string
	vaultConfig           *vault.Config
	SkipOriginCheck       bool
	Hostname              string
	NotifyAddrs           string
	NotifySrvAddr         string
	NodeMgr               *node.NodeMgr
	Billing               bool
	BillingPath           string
	AlertCache            *edgeproto.AlertCache
	AlertMgrAddr          string
	AlertmgrResolveTimout time.Duration
}

var DefaultDBUser = "mcuser"
var DefaultDBName = "mcdb"
var DefaultDBPass = ""
var DefaultSuperuser = "mexadmin"
var DefaultSuperpass = "mexadmin123"
var Superuser string

var database *gorm.DB

//var enforcer *casbin.SyncedEnforcer
var enforcer *rbac.Enforcer
var serverConfig *ServerConfig
var gitlabClient *gitlab.Client
var gitlabSync *AppStoreSync
var artifactorySync *AppStoreSync
var nodeMgr *node.NodeMgr
var AlertManagerServer *alertmgr.AlertMgrServer

func RunServer(config *ServerConfig) (*Server, error) {
	server := Server{config: config}
	// keep global pointer to config stored in server for easy access
	serverConfig = server.config
	if config.NodeMgr == nil {
		config.NodeMgr = &node.NodeMgr{}
	}
	nodeMgr = config.NodeMgr

	span := log.StartSpan(log.DebugLevelInfo, "main")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

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

	err := nodeMgr.Init(ctx, "mc", node.WithName(config.Hostname))

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
	InitVault(config.vaultConfig, server.initJWKDone)

	if config.Billing {
		err = zuora.InitZuora(config.vaultConfig, config.BillingPath)
		if err != nil {
			return nil, fmt.Errorf("Unable to initialize zuora: %v", err)
		}
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

	server.initDataDone = make(chan struct{}, 1)
	go InitData(ctx, Superuser, superpass, config.PingInterval, &server.stopInitData, server.initDataDone)

	if config.AlertMgrAddr != "" {
		AlertManagerServer, err = alertmgr.NewAlertMgrServer(config.AlertMgrAddr,
			config.AlertCache, config.AlertmgrResolveTimout)
		if err != nil {
			// TODO - this needs to be a fatal failure when we add alertmanager deployment to the ansible scripts
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to start alertmanager server", "error", err)
			err = nil
		}
	}
	go server.setupConsoleProxy(ctx)

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
	// authenticated routes - gorm router

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
	auth.POST("/user/newpass", NewPassword)
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

	// swagger:route POST /auth/billingorg/create BillingOrganization CreateBillingOrg
	// Create BillingOrganization.
	// Create a BillingOrganization to set up billing info.
	// Security:
	//   Bearer:
	// responses:
	//   200: success
	//   400: badRequest
	//   403: forbidden
	//   404: notFound
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
	auth.POST("/audit/showself", ShowAuditSelf)
	auth.POST("/audit/showorg", ShowAuditOrg)
	auth.POST("/audit/operations", GetAuditOperations)
	auth.POST("/orgcloudletpool/create", CreateOrgCloudletPool)
	auth.POST("/orgcloudletpool/delete", DeleteOrgCloudletPool)
	auth.POST("/orgcloudletpool/show", ShowOrgCloudletPool)
	auth.POST("/orgcloudlet/show", ShowOrgCloudlet)
	auth.POST("/orgcloudletinfo/show", ShowOrgCloudletInfo)

	// Support multiple connection types: HTTP(s), Websockets
	addControllerApis("POST", auth)
	// Metrics api route use auth to serve a query to influxDB
	auth.POST("/metrics/app", GetMetricsCommon)
	auth.POST("/metrics/cluster", GetMetricsCommon)
	auth.POST("/metrics/cloudlet", GetMetricsCommon)
	auth.POST("/metrics/client", GetMetricsCommon)
	auth.POST("/events/app", GetEventsCommon)
	auth.POST("/events/cluster", GetEventsCommon)
	auth.POST("/events/cloudlet", GetEventsCommon)

	// Alertmanager apis
	auth.POST("/alertreceiver/create", CreateAlertReceiver)
	auth.POST("/alertreceiver/delete", DeleteAlertReceiver)
	auth.POST("/alertreceiver/show", ShowAlertReceiver)

	// Use GET method for websockets as thats the method used
	// in setting up TCP connection by most of the clients
	// Also, authorization is handled as part of websocketUpgrade
	ws := e.Group("ws/"+root+"/auth", server.websocketUpgrade)
	addControllerApis("GET", ws)
	// Metrics api route use ws to serve a query to influxDB
	ws.GET("/metrics/app", GetMetricsCommon)
	ws.GET("/metrics/cluster", GetMetricsCommon)
	ws.GET("/metrics/cloudlet", GetMetricsCommon)
	ws.GET("/metrics/client", GetMetricsCommon)
	// WebRTC based APIs
	ws.GET("/ctrl/RunCommand", RunWebrtcStream)
	ws.GET("/ctrl/ShowLogs", RunWebrtcStream)
	ws.GET("/ctrl/RunConsole", RunWebrtcStream)

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
		if config.TlsCertFile != "" {
			err = e.StartTLS(config.ServAddr, config.TlsCertFile, config.TlsKeyFile)
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
	go func() {
		var err error
		if config.TlsCertFile != "" {
			err = ldapServer.ListenAndServeTLS(config.LDAPAddr, config.TlsCertFile, config.TlsKeyFile)
		} else {
			err = ldapServer.ListenAndServe(config.LDAPAddr)
		}
		if err != nil {
			server.Stop()
			log.FatalLog("LDAP Server Failed", "err", err)
		}
	}()

	gitlabSync = GitlabNewSync()
	artifactorySync = ArtifactoryNewSync()

	// gitlab/artifactory sync and alertmanager requires data to be initialized
	<-server.initDataDone
	gitlabSync.Start()
	artifactorySync.Start()
	if AlertManagerServer != nil {
		AlertManagerServer.Start()
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
	s.echo.Close()
	s.database.Close()
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
	}
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
			ws.Close()
			return err
		}

		// Set ws on echo context
		SetWs(c, ws)

		// call next handler
		return next(c)
	}
}

func ReadConn(c echo.Context, in interface{}) (bool, error) {
	var err error

	// Init header state while reading connection.
	// This will be used to track if headers is written
	// for response.
	c.Set("WroteHeader", false)

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
			return false, setReply(c, fmt.Errorf("Invalid data"), nil)
		}
		errStr := checkForTimeError(fmt.Sprintf("Invalid data: %v", err))
		return false, setReply(c, fmt.Errorf(errStr), nil)
	}

	return true, nil
}

func CloseConn(c echo.Context) {
	if ws := GetWs(c); ws != nil {
		ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		ws.Close()
	}
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

func WriteStream(c echo.Context, payload *ormapi.StreamPayload) error {
	if ws := GetWs(c); ws != nil {
		wsPayload := ormapi.WSStreamPayload{
			Code: http.StatusOK,
			Data: (*payload).Data,
		}
		out, err := json.Marshal(wsPayload)
		if err == nil {
			LogWsResponse(c, string(out))
		}
		return ws.WriteJSON(wsPayload)
	} else {
		headerFlag := c.Get("WroteHeader")
		wroteHeader := false
		if headerFlag != nil {
			if h, ok := headerFlag.(bool); ok {
				wroteHeader = h
			}
		}
		// stream func may return "forbidden", so don't write
		// header until we know it's ok
		if !wroteHeader {
			c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			c.Response().WriteHeader(http.StatusOK)
			c.Set("WroteHeader", true)
		}
		json.NewEncoder(c.Response()).Encode(*payload)
		c.Response().Flush()
	}

	return nil
}

func WriteError(c echo.Context, err error) error {
	if st, ok := status.FromError(err); ok {
		err = fmt.Errorf("%s", st.Message())
	}
	headerFlag := c.Get("WroteHeader")
	wroteHeader := false
	if headerFlag != nil {
		if h, ok := headerFlag.(bool); ok {
			wroteHeader = h
		}
	}
	if !wroteHeader {
		return setReply(c, err, nil)
	}
	if ws := GetWs(c); ws != nil {
		wsPayload := ormapi.WSStreamPayload{
			Code: http.StatusBadRequest,
			Data: MsgErr(err),
		}
		out, err := json.Marshal(wsPayload)
		if err == nil {
			LogWsResponse(c, string(out))
		}
		return ws.WriteJSON(wsPayload)
	} else {
		res := ormapi.Result{}
		res.Message = err.Error()
		res.Code = http.StatusBadRequest
		payload := ormapi.StreamPayload{Result: &res}
		json.NewEncoder(c.Response()).Encode(payload)
	}

	return nil
}

func (s *Server) setupConsoleProxy(ctx context.Context) {
	var err error

	if s.config.ConsoleProxyAddr == "" {
		return
	}

	log.SpanLog(ctx, log.DebugLevelInfo, "setup console proxy", "addr", s.config.ConsoleProxyAddr)

	director := func(req *http.Request) {
		token := ""
		queryArgs := req.URL.Query()
		tokenVals, ok := queryArgs["token"]
		if !ok || len(tokenVals) != 1 {
			// try token from cookies
			for _, cookie := range req.Cookies() {
				if cookie.Name == "mextoken" {
					token = cookie.Value
					break
				}
			}
		} else {
			token = tokenVals[0]
		}
		if s.config.TlsCertFile != "" {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = "http"
		}
		req.URL.Host = s.config.ConsoleProxyAddr
		port := edgecli.ConsoleProxy.Get(token)
		if port != "" {
			addrObj := strings.Split(s.config.ConsoleProxyAddr, ":")
			if len(addrObj) == 2 {
				req.URL.Host = strings.Replace(req.URL.Host, addrObj[1], port, -1)
			}
		} else {
			req.Close = true
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	proxy := &httputil.ReverseProxy{Director: director}

	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		queryArgs := r.URL.Query()
		tokenVals, ok := queryArgs["token"]
		if ok && len(tokenVals) == 1 {
			token := tokenVals[0]
			expire := time.Now().Add(10 * time.Minute)
			cookie := http.Cookie{
				Name:    "mextoken",
				Value:   tokenVals[0],
				Expires: expire,
			}
			http.SetCookie(w, &cookie)
			log.SpanLog(ctx, log.DebugLevelInfo, "setup console proxy cookies", "url", r.URL, "token", token)
		}
		proxy.ServeHTTP(w, r)
	})

	if s.config.TlsCertFile != "" {
		err = http.ListenAndServeTLS(s.config.ConsoleProxyAddr, s.config.TlsCertFile, s.config.TlsKeyFile, nil)
	} else {
		err = http.ListenAndServe(s.config.ConsoleProxyAddr, nil)
	}
	if err != nil && err != http.ErrServerClosed {
		s.Stop()
		log.FatalLog("Failed to start console proxy server", "err", err)
	}
}
