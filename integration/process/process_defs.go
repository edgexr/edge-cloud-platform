package process

import "os/exec"

type Vault struct {
	Common      `yaml:",inline"`
	DmeSecret   string
	McormSecret string
	cmd         *exec.Cmd
}
type Etcd struct {
	Common         `yaml:",inline"`
	DataDir        string
	PeerAddrs      string
	ClientAddrs    string
	InitialCluster string
	cmd            *exec.Cmd
}
type Controller struct {
	Common        `yaml:",inline"`
	EtcdAddrs     string
	ApiAddr       string
	HttpAddr      string
	NotifyAddr    string
	TLS           TLSCerts
	ShortTimeouts bool
	cmd           *exec.Cmd
}
type Dme struct {
	Common      `yaml:",inline"`
	ApiAddr     string
	HttpAddr    string
	NotifyAddrs string
	LocVerUrl   string
	TokSrvUrl   string
	Carrier     string
	CloudletKey string
	VaultAddr   string
	CookieExpr  string
	TLS         TLSCerts
	cmd         *exec.Cmd
}
type Crm struct {
	Common      `yaml:",inline"`
	ApiAddr     string
	NotifyAddrs string
	CloudletKey string
	Platform    string
	Plugin      string
	TLS         TLSCerts
	cmd         *exec.Cmd
}
type LocApiSim struct {
	Common  `yaml:",inline"`
	Port    int
	Locfile string
	Geofile string
	Country string
	cmd     *exec.Cmd
}
type TokSrvSim struct {
	Common `yaml:",inline"`
	Port   int
	Token  string
	cmd    *exec.Cmd
}
type SampleApp struct {
	Common       `yaml:",inline"`
	Exename      string
	Args         []string
	Command      string
	VolumeMounts []string
	cmd          *exec.Cmd
}
type Influx struct {
	Common   `yaml:",inline"`
	DataDir  string
	HttpAddr string
	Config   string // set during Start
	cmd      *exec.Cmd
}
type ClusterSvc struct {
	Common      `yaml:",inline"`
	NotifyAddrs string
	CtrlAddrs   string
	PromPorts   string
	InfluxDB    string
	Interval    string
	TLS         TLSCerts
	cmd         *exec.Cmd
}