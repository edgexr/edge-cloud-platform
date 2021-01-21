package intprocess

import (
	"os/exec"

	"github.com/mobiledgex/edge-cloud/integration/process"
)

type MC struct {
	process.Common          `yaml:",inline"`
	Addr                    string
	SqlAddr                 string
	VaultAddr               string
	RolesFile               string
	LdapAddr                string
	NotifySrvAddr           string
	ConsoleProxyAddr        string
	UseVaultCAs             bool
	UseVaultCerts           bool
	AlertResolveTimeout     string
	BillingPlatform         string
	UsageCollectionInterval string
	UsageCheckpointInterval string
	AlertMgrApiAddr         string
	ApiTlsCert              string
	ApiTlsKey               string
	TLS                     process.TLSCerts
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
	process.Common `yaml:",inline"`
	NotifyAddrs    string
	Platform       string
	VaultAddr      string
	MetricsAddr    string
	PhysicalName   string
	CloudletKey    string
	UseVaultCAs    bool
	UseVaultCerts  bool
	TLS            process.TLSCerts
	cmd            *exec.Cmd
	Span           string
	Region         string
	AppDNSRoot     string
	DeploymentTag  string
	ChefServerPath string
	AccessKeyFile  string
	AccessApiAddr  string
}
type AutoProv struct {
	process.Common `yaml:",inline"`
	NotifyAddrs    string
	CtrlAddrs      string
	VaultAddr      string
	InfluxAddr     string
	Region         string
	UseVaultCAs    bool
	UseVaultCerts  bool
	TLS            process.TLSCerts
	cmd            *exec.Cmd
}

type PromE2e struct {
	process.Common `yaml:",inline"`
	Port           int
	cmd            *exec.Cmd
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
	process.Common `yaml:",inline"`
	ConfigFile     string
	TemplateFile   string
	Port           int
	cmd            *exec.Cmd
}

type Maildev struct {
	process.Common `yaml:",inline"`
	UiPort         int
	MailPort       int
	cmd            *exec.Cmd
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
