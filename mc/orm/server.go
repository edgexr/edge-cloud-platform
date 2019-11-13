package orm

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/rbac"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/integration/process"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	"github.com/mobiledgex/edge-cloud/version"
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
	initDataDone chan struct{}
	initJWKDone  chan struct{}
}

type ServerConfig struct {
	ServAddr        string
	SqlAddr         string
	VaultAddr       string
	RunLocal        bool
	InitLocal       bool
	IgnoreEnv       bool
	TlsCertFile     string
	TlsKeyFile      string
	LocalVault      bool
	LDAPAddr        string
	GitlabAddr      string
	ArtifactoryAddr string
	ClientCert      string
	PingInterval    time.Duration
	SkipVerifyEmail bool
	JaegerAddr      string
	vaultConfig     *vault.Config
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

func RunServer(config *ServerConfig) (*Server, error) {
	server := Server{config: config}
	// keep global pointer to config stored in server for easy access
	serverConfig = server.config

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

	if gitlabToken == "" {
		log.InfoLog("Note: No gitlab_token env var found")
	}
	gitlabClient = gitlab.NewClient(nil, gitlabToken)
	if err := gitlabClient.SetBaseURL(config.GitlabAddr); err != nil {
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

	e := echo.New()
	e.HideBanner = true
	server.echo = e

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})
	e.Use(logger)

	// login route
	root := "api/v1"
	e.POST(root+"/login", Login)
	// accessible routes
	e.POST(root+"/usercreate", CreateUser)
	e.POST(root+"/passwordresetrequest", PasswordResetRequest)
	e.POST(root+"/passwordreset", PasswordReset)
	e.POST(root+"/verifyemail", VerifyEmail)
	e.POST(root+"/resendverify", ResendVerify)
	// authenticated routes - jwt middleware
	auth := e.Group(root + "/auth")
	auth.Use(AuthCookie)
	// authenticated routes - gorm router
	auth.POST("/user/show", ShowUser)
	auth.POST("/user/current", CurrentUser)
	auth.POST("/user/delete", DeleteUser)
	auth.POST("/user/newpass", NewPassword)
	auth.POST("/role/assignment/show", ShowRoleAssignment)
	auth.POST("/role/perms/show", ShowRolePerms)
	auth.POST("/role/show", ShowRole)
	auth.POST("/role/adduser", AddUserRole)
	auth.POST("/role/removeuser", RemoveUserRole)
	auth.POST("/role/showuser", ShowUserRole)
	auth.POST("/org/create", CreateOrg)
	auth.POST("/org/update", UpdateOrg)
	auth.POST("/org/show", ShowOrg)
	auth.POST("/org/delete", DeleteOrg)
	auth.POST("/controller/create", CreateController)
	auth.POST("/controller/delete", DeleteController)
	auth.POST("/controller/show", ShowController)
	auth.POST("/data/create", CreateData)
	auth.POST("/data/delete", DeleteData)
	auth.POST("/data/show", ShowData)
	auth.POST("/gitlab/resync", GitlabResync)
	auth.POST("/artifactory/resync", ArtifactoryResync)
	auth.POST("/artifactory/summary", ArtifactorySummary)
	auth.POST("/config/update", UpdateConfig)
	auth.POST("/config/show", ShowConfig)
	auth.POST("/config/version", ShowVersion)
	auth.POST("/restricted/user/update", RestrictedUserUpdate)
	auth.POST("/audit/showself", ShowAuditSelf)
	auth.POST("/audit/showorg", ShowAuditOrg)
	auth.POST("/orgcloudletpool/create", CreateOrgCloudletPool)
	auth.POST("/orgcloudletpool/delete", DeleteOrgCloudletPool)
	auth.POST("/orgcloudletpool/show", ShowOrgCloudletPool)
	auth.POST("/orgcloudlet/show", ShowOrgCloudlet)
	addControllerApis(auth)
	// Metrics api route use auth to serve a query to influxDB
	auth.POST("/metrics/app", GetMetricsCommon)
	auth.POST("/metrics/cluster", GetMetricsCommon)
	auth.POST("/metrics/cloudlet", GetMetricsCommon)

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
		if err := ldapServer.ListenAndServe(config.LDAPAddr); err != nil {
			server.Stop()
			log.FatalLog("LDAP Server Failed", "err", err)
		}
	}()

	gitlabSync = GitlabNewSync()
	artifactorySync = ArtifactoryNewSync()

	// gitlab/artifactory sync requires data to be initialized
	<-server.initDataDone
	gitlabSync.Start()
	artifactorySync.Start()

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
}

func ShowVersion(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

	if !authorized(ctx, claims.Username, "", ResourceConfig, ActionView) {
		return echo.ErrForbidden
	}
	ver := ormapi.Version{
		BuildMaster: version.BuildMaster,
		BuildHead:   version.BuildHead,
		BuildAuthor: version.BuildAuthor,
		Hostname:    cloudcommon.Hostname(),
	}
	return c.JSON(http.StatusOK, ver)
}
