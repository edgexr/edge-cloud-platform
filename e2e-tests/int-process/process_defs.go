package intprocess

import (
	"os/exec"

	"github.com/mobiledgex/edge-cloud/integration/process"
)

type MC struct {
	process.Common          `yaml:",inline"`
	process.NodeCommon      `yaml:",inline"`
	Addr                    string
	FederationAddr          string
	SqlAddr                 string
	NotifyAddrs             string
	RolesFile               string
	LdapAddr                string
	NotifySrvAddr           string
	ConsoleProxyAddr        string
	AlertResolveTimeout     string
	BillingPlatform         string
	UsageCollectionInterval string
	UsageCheckpointInterval string
	AlertMgrApiAddr         string
	ApiTlsCert              string
	ApiTlsKey               string
	StaticDir               string
	TestMode                bool
	cmd                     *exec.Cmd
}
type Sql struct {
	process.Common `yaml:",inline"`
	DataDir        string
	HttpAddr       string
	Username       string
	Dbname         string
	TLS            process.TLSCerts
	cmd            *exec.Cmd
}
type Shepherd struct {
	process.Common     `yaml:",inline"`
	process.NodeCommon `yaml:",inline"`
	NotifyAddrs        string
	Platform           string
	MetricsAddr        string
	PhysicalName       string
	CloudletKey        string
	cmd                *exec.Cmd
	Span               string
	Region             string
	AppDNSRoot         string
	ChefServerPath     string
}
type AutoProv struct {
	process.Common     `yaml:",inline"`
	process.NodeCommon `yaml:",inline"`
	NotifyAddrs        string
	CtrlAddrs          string
	InfluxAddr         string
	Region             string
	cmd                *exec.Cmd
}

type PromE2e struct {
	process.DockerGeneric `yaml:",inline"`
	Port                  int
}

type HttpServer struct {
	process.Common `yaml:",inline"`
	PromDataFile   string
	Port           int
	cmd            *exec.Cmd
}

type ChefServer struct {
	process.Common `yaml:",inline"`
	Port           int
	cmd            *exec.Cmd
}

type Alertmanager struct {
	process.DockerGeneric `yaml:",inline"`
	ConfigFile            string
	TemplateFile          string
	Port                  int
}

type Maildev struct {
	process.DockerGeneric `yaml:",inline"`
	UiPort                int
	MailPort              int
}

type AlertmanagerSidecar struct {
	process.Common `yaml:",inline"`
	AlertmgrAddr   string
	ConfigFile     string
	HttpAddr       string
	LocalTest      bool
	TLS            process.TLSCerts
	cmd            *exec.Cmd
}
