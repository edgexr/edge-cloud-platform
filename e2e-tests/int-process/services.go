package intprocess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/integration/process"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	"github.com/prometheus/common/model"
)

const (
	PrometheusContainer    = "cloudletPrometheus"
	PrometheusImagePath    = "prom/prometheus"
	PrometheusImageVersion = "v2.19.2"
	PrometheusRulesPrefix  = "rulefile_"
	CloudletPrometheusPort = "9092"
)

var prometheusConfig = `global:
  evaluation_interval: {{.EvalInterval}}
rule_files:
- "/tmp/` + PrometheusRulesPrefix + `*"
scrape_configs:
- job_name: envoy_targets
  scrape_interval: {{.ScrapeInterval}}
  file_sd_configs:
  - files:
    - '/tmp/prom_targets.json'
`

type prometheusConfigArgs struct {
	EvalInterval   string
	ScrapeInterval string
}

var prometheusConfigTemplate *template.Template
var prometheusConfigMux sync.Mutex

func init() {
	prometheusConfigTemplate = template.Must(template.New("prometheusconfig").Parse(prometheusConfig))
}

func getShepherdProc(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) (*Shepherd, []process.StartOp, error) {
	opts := []process.StartOp{}

	cloudletKeyStr, err := json.Marshal(cloudlet.Key)
	if err != nil {
		return nil, opts, fmt.Errorf("unable to marshal cloudlet key")
	}

	envVars := make(map[string]string)
	notifyAddr := ""
	tlsCertFile := ""
	vaultAddr := ""
	span := ""
	region := ""
	useVaultCAs := false
	useVaultCerts := false
	appDNSRoot := ""
	deploymentTag := ""
	chefServerPath := ""
	if pfConfig != nil {
		// Same vault role-id/secret-id as CRM
		for k, v := range pfConfig.EnvVar {
			envVars[k] = v
		}
		notifyAddr = cloudlet.NotifySrvAddr
		tlsCertFile = pfConfig.TlsCertFile
		vaultAddr = pfConfig.VaultAddr
		span = pfConfig.Span
		region = pfConfig.Region
		useVaultCAs = pfConfig.UseVaultCas
		useVaultCerts = pfConfig.UseVaultCerts
		appDNSRoot = pfConfig.AppDnsRoot
		deploymentTag = pfConfig.DeploymentTag
		chefServerPath = pfConfig.ChefServerPath
	}

	for envKey, envVal := range cloudlet.EnvVar {
		envVars[envKey] = envVal
	}

	opts = append(opts, process.WithDebug("api,infra,notify,metrics"))

	return &Shepherd{
		NotifyAddrs: notifyAddr,
		CloudletKey: string(cloudletKeyStr),
		Platform:    cloudlet.PlatformType.String(),
		Common: process.Common{
			Hostname: cloudlet.Key.Name,
			EnvVars:  envVars,
		},
		TLS: process.TLSCerts{
			ServerCert: tlsCertFile,
		},
		VaultAddr:      vaultAddr,
		PhysicalName:   cloudlet.PhysicalName,
		Span:           span,
		Region:         region,
		UseVaultCAs:    useVaultCAs,
		UseVaultCerts:  useVaultCerts,
		AppDNSRoot:     appDNSRoot,
		DeploymentTag:  deploymentTag,
		ChefServerPath: chefServerPath,
	}, opts, nil
}

func GetShepherdCmd(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) (string, *map[string]string, error) {
	ShepherdProc, opts, err := getShepherdProc(cloudlet, pfConfig)
	if err != nil {
		return "", nil, err
	}

	return ShepherdProc.String(opts...), &ShepherdProc.Common.EnvVars, nil
}

func GetShepherdCmdArgs(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) ([]string, *map[string]string, error) {
	ShepherdProc, opts, err := getShepherdProc(cloudlet, pfConfig)
	if err != nil {
		return nil, nil, err
	}

	return ShepherdProc.GetArgs(opts...), &ShepherdProc.Common.EnvVars, nil
}

func StartShepherdService(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) (*Shepherd, error) {
	shepherdProc, opts, err := getShepherdProc(cloudlet, pfConfig)
	if err != nil {
		return nil, err
	}

	err = shepherdProc.StartLocal("/tmp/"+cloudlet.Key.Name+".shepherd.log", opts...)
	if err != nil {
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "started "+shepherdProc.GetExeName())

	return shepherdProc, nil
}

func StopShepherdService(ctx context.Context, cloudlet *edgeproto.Cloudlet) error {
	args := ""
	if cloudlet != nil {
		ShepherdProc, _, err := getShepherdProc(cloudlet, nil)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "cannot stop Shepherdserver", "err", err)
			return err
		}
		args = util.EscapeJson(ShepherdProc.LookupArgs())
	}

	// max wait time for process to go down gracefully, after which it is killed forcefully
	maxwait := 1 * time.Second

	c := make(chan string)
	go process.KillProcessesByName("shepherd", maxwait, args, c)

	log.SpanLog(ctx, log.DebugLevelInfra, "stopped Shepherdserver", "msg", <-c)
	return nil
}

func StopFakeEnvoyExporters(ctx context.Context) error {
	c := make(chan string)
	go process.KillProcessesByName("fake_envoy_exporter", time.Second, "", c)
	log.SpanLog(ctx, log.DebugLevelInfra, "stopped fake_envoy_exporter", "msg", <-c)
	return nil
}

func GetCloudletPrometheusConfigHostFilePath() string {
	return "/tmp/prometheus.yml"
}

// command line options for prometheus container
func GetCloudletPrometheusCmdArgs() []string {
	return []string{
		"--config.file",
		"/etc/prometheus/prometheus.yml",
		"--web.listen-address",
		":" + CloudletPrometheusPort,
		"--web.enable-lifecycle",
		"--log.level=debug", // Debug
	}
}

// base docker run args
func GetCloudletPrometheusDockerArgs(cloudlet *edgeproto.Cloudlet, cfgFile string) []string {

	// label with a cloudlet name and org
	cloudletName := util.DockerSanitize(cloudlet.Key.Name)
	cloudletOrg := util.DockerSanitize(cloudlet.Key.Organization)

	return []string{
		"--label", "cloudlet=" + cloudletName,
		"--label", "cloudletorg=" + cloudletOrg,
		"--publish", CloudletPrometheusPort + ":" + CloudletPrometheusPort, // container interface
		"--volume", "/tmp:/tmp",
		"--volume", cfgFile + ":/etc/prometheus/prometheus.yml",
	}
}

// Starts prometheus container and connects it to the default ports
func StartCloudletPrometheus(ctx context.Context, cloudlet *edgeproto.Cloudlet, settings *edgeproto.Settings) error {
	if err := WriteCloudletPromConfig(ctx, settings); err != nil {
		return err
	}
	cfgFile := GetCloudletPrometheusConfigHostFilePath()
	args := GetCloudletPrometheusDockerArgs(cloudlet, cfgFile)
	cmdOpts := GetCloudletPrometheusCmdArgs()

	// local container specific options
	args = append([]string{"run", "--rm"}, args...)
	// set name and image path
	promImage := PrometheusImagePath + ":" + PrometheusImageVersion
	args = append(args, []string{"--name", PrometheusContainer, promImage}...)
	args = append(args, cmdOpts...)

	_, err := process.StartLocal(PrometheusContainer, "docker", args, nil, "/tmp/cloudlet_prometheus.log")
	if err != nil {
		return err
	}
	return nil
}

func WriteCloudletPromConfig(ctx context.Context, settings *edgeproto.Settings) error {
	scrape := model.Duration(settings.ShepherdMetricsCollectionInterval)
	eval := model.Duration(settings.ShepherdAlertEvaluationInterval)

	args := prometheusConfigArgs{
		ScrapeInterval: scrape.String(),
		EvalInterval:   eval.String(),
	}
	buf := bytes.Buffer{}
	if err := prometheusConfigTemplate.Execute(&buf, &args); err != nil {
		return err
	}

	// Protect against concurrent changes to the config.
	// Shepherd may update the config due to changes in settings,
	// while crm/chef may start/restart it.
	prometheusConfigMux.Lock()
	defer prometheusConfigMux.Unlock()

	cfgFile := GetCloudletPrometheusConfigHostFilePath()
	f, err := os.Create(cfgFile)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(buf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func StopCloudletPrometheus(ctx context.Context) error {
	cmd := exec.Command("docker", "kill", PrometheusContainer)
	cmd.Run()
	return nil
}

func CloudletPrometheusExists(ctx context.Context) bool {
	cmd := exec.Command("docker", "logs", PrometheusContainer)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil && strings.Contains(out.String(), "No such container") {
		return false
	}
	return true
}
