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

package intprocess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/integration/process"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
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
- "/var/tmp/` + PrometheusRulesPrefix + `*"
scrape_configs:
- job_name: MobiledgeX Monitoring
  scrape_interval: {{.ScrapeInterval}}
  file_sd_configs:
  - files:
    - '/var/tmp/prom_targets.json'
  metric_relabel_configs:
    - source_labels: [envoy_cluster_name]
      target_label: port
      regex: 'backend(.*)'
      replacement: '${1}'
    - regex: 'instance|envoy_cluster_name'
      action: labeldrop
{{- if .RemoteWriteAddr}}
remote_write:
- url: {{.RemoteWriteAddr}}/api/v1/receive
{{- end}}
`

type prometheusConfigArgs struct {
	EvalInterval    string
	ScrapeInterval  string
	RemoteWriteAddr string
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
	tlsKeyFile := ""
	tlsCAFile := ""
	vaultAddr := ""
	span := ""
	region := ""
	useVaultPki := false
	appDNSRoot := ""
	deploymentTag := ""
	chefServerPath := ""
	accessApiAddr := ""
	thanosRecvAddr := ""
	if pfConfig != nil {
		// Same vault role-id/secret-id as CRM
		for k, v := range pfConfig.EnvVar {
			envVars[k] = v
		}
		notifyAddr = cloudlet.NotifySrvAddr
		tlsCertFile = pfConfig.TlsCertFile
		tlsKeyFile = pfConfig.TlsKeyFile
		tlsCAFile = pfConfig.TlsCaFile
		span = pfConfig.Span
		region = pfConfig.Region
		useVaultPki = pfConfig.UseVaultPki
		appDNSRoot = pfConfig.AppDnsRoot
		deploymentTag = pfConfig.DeploymentTag
		chefServerPath = pfConfig.ChefServerPath
		accessApiAddr = pfConfig.AccessApiAddr
		thanosRecvAddr = pfConfig.ThanosRecvAddr
	}

	for envKey, envVal := range cloudlet.EnvVar {
		envVars[envKey] = envVal
	}

	opts = append(opts, process.WithDebug("api,infra,metrics"))

	return &Shepherd{
		NotifyAddrs: notifyAddr,
		CloudletKey: string(cloudletKeyStr),
		Platform:    cloudlet.PlatformType.String(),
		Common: process.Common{
			Hostname: cloudlet.Key.Name,
			EnvVars:  envVars,
		},
		NodeCommon: process.NodeCommon{
			TLS: process.TLSCerts{
				ServerCert: tlsCertFile,
				ServerKey:  tlsKeyFile,
				CACert:     tlsCAFile,
			},
			VaultAddr:     vaultAddr,
			UseVaultPki:   useVaultPki,
			DeploymentTag: deploymentTag,
			AccessApiAddr: accessApiAddr,
		},
		PhysicalName:   cloudlet.PhysicalName,
		Span:           span,
		Region:         region,
		AppDNSRoot:     appDNSRoot,
		ChefServerPath: chefServerPath,
		ThanosRecvAddr: thanosRecvAddr,
	}, opts, nil
}

func GetShepherdCmdArgs(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) ([]string, *map[string]string, error) {
	ShepherdProc, opts, err := getShepherdProc(cloudlet, pfConfig)
	if err != nil {
		return nil, nil, err
	}
	ShepherdProc.AccessKeyFile = cloudcommon.GetCrmAccessKeyFile()

	return ShepherdProc.GetArgs(opts...), &ShepherdProc.Common.EnvVars, nil
}

func StartShepherdService(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) (*Shepherd, error) {
	shepherdProc, opts, err := getShepherdProc(cloudlet, pfConfig)
	if err != nil {
		return nil, err
	}
	// for local testing, include debug notify
	opts = append(opts, process.WithDebug("api,notify,infra,metrics"))

	shepherdProc.AccessKeyFile = cloudcommon.GetLocalAccessKeyFile(cloudlet.Key.Name, process.HARolePrimary) // TODO Shepherd HA

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
	go process.KillProcessesByName("fake_envoy_exporter", time.Second, "--port", c)
	log.SpanLog(ctx, log.DebugLevelInfra, "stopped fake_envoy_exporter", "msg", <-c)
	return nil
}

func GetCloudletPrometheusConfigHostFilePath() string {
	return "/var/tmp/prometheus.yml"
}

// command line options for prometheus container
func GetCloudletPrometheusCmdArgs() []string {
	return []string{
		"--config.file",
		"/etc/prometheus/prometheus.yml",
		"--web.listen-address",
		":" + CloudletPrometheusPort,
		"--web.enable-lifecycle",
		"--web.enable-admin-api",
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
		"--volume", "/var/tmp:/var/tmp",
		"--volume", cfgFile + ":/etc/prometheus/prometheus.yml",
	}
}

// Starts prometheus container and connects it to the default ports
func StartCloudletPrometheus(ctx context.Context, remoteWriteAddr string, cloudlet *edgeproto.Cloudlet, settings *edgeproto.Settings) error {
	if err := WriteCloudletPromConfig(ctx, remoteWriteAddr, (*time.Duration)(&settings.ShepherdMetricsCollectionInterval),
		(*time.Duration)(&settings.ShepherdAlertEvaluationInterval)); err != nil {
		return err
	}
	cfgFile := GetCloudletPrometheusConfigHostFilePath()
	args := GetCloudletPrometheusDockerArgs(cloudlet, cfgFile)
	cmdOpts := GetCloudletPrometheusCmdArgs()

	// local container specific options
	args = append([]string{"run", "--rm"}, args...)
	if runtime.GOOS != "darwin" {
		// For Linux, "host.docker.internal" host name doesn't work from inside docker container
		// Use "--add-host" to add this mapping, only works if Docker version >= 20.04
		args = append(args, "--add-host", "host.docker.internal:host-gateway")
	}
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

func WriteCloudletPromConfig(ctx context.Context, remoteWriteAddr string, promScrapeInterval *time.Duration, alertEvalInterval *time.Duration) error {
	args := prometheusConfigArgs{
		ScrapeInterval:  promScrapeInterval.String(),
		EvalInterval:    alertEvalInterval.String(),
		RemoteWriteAddr: remoteWriteAddr,
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
