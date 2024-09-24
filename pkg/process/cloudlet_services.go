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

package process

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
)

func GetCloudletLogFile(filePrefix string) string {
	return "/tmp/" + filePrefix + ".log"
}

func GetLocalAccessKeyDir() string {
	return "/tmp/accesskeys"
}

func GetLocalAccessKeyFile(filePrefix string, haRole HARole) string {
	return GetLocalAccessKeyDir() + "/" + filePrefix + string(haRole) + ".key"
}

func GetCrmAccessKeyFile() string {
	return "/root/accesskey/accesskey.pem"
}

type CrmServiceOptions struct {
	getCrmProc GetCrmProcFunc
	exeName    string
}

type CrmServiceOp func(options *CrmServiceOptions)

func WithGetCrmProc(getCrmProc GetCrmProcFunc) CrmServiceOp {
	return func(op *CrmServiceOptions) { op.getCrmProc = getCrmProc }
}

func WithExeName(name string) CrmServiceOp {
	return func(op *CrmServiceOptions) { op.exeName = name }
}

func GetCrmServiceOptions(ops ...CrmServiceOp) *CrmServiceOptions {
	opts := CrmServiceOptions{
		getCrmProc: GetCrmProc,
		exeName:    "crm",
	}
	for _, fn := range ops {
		fn(&opts)
	}
	return &opts
}

type GetCrmProcFunc func(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, HARole HARole) (CrmProcess, []StartOp, error)

func GetCrmProc(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, HARole HARole) (CrmProcess, []StartOp, error) {
	opts := []StartOp{}

	cloudletKeyStr, err := json.Marshal(cloudlet.Key)
	if err != nil {
		return nil, opts, fmt.Errorf("unable to marshal cloudlet key")
	}

	opts = append(opts, WithDebug("api,infra,notify,info"))

	notifyAddr := cloudlet.NotifySrvAddr
	if HARole == HARoleSecondary {
		notifyAddr = cloudlet.SecondaryNotifySrvAddr
	}
	crm := &Crm{
		NotifySrvAddr: notifyAddr,
		CloudletKey:   string(cloudletKeyStr),
		Platform:      cloudlet.PlatformType,
		Common: Common{
			Hostname: cloudlet.Key.Name,
			EnvVars:  make(map[string]string),
		},
		PhysicalName:     cloudlet.PhysicalName,
		ContainerVersion: cloudlet.ContainerVersion,
		VMImageVersion:   cloudlet.VmImageVersion,
		HARole:           HARole,
	}
	if pfConfig != nil {
		for k, v := range pfConfig.EnvVar {
			crm.Common.EnvVars[k] = v
		}
		crm.NotifyAddrs = pfConfig.NotifyCtrlAddrs
		crm.NodeCommon.TLS.ServerCert = pfConfig.TlsCertFile
		crm.NodeCommon.TLS.ServerKey = pfConfig.TlsKeyFile
		crm.NodeCommon.TLS.CACert = pfConfig.TlsCaFile
		crm.TestMode = pfConfig.TestMode
		crm.Span = pfConfig.Span
		crm.CloudletVMImagePath = pfConfig.CloudletVmImagePath
		crm.EnvoyWithCurlImage = pfConfig.EnvoyWithCurlImage
		crm.NginxWithCurlImage = pfConfig.NginxWithCurlImage
		crm.Region = pfConfig.Region
		crm.CommercialCerts = pfConfig.CommercialCerts
		crm.UseVaultPki = pfConfig.UseVaultPki
		crm.AppDNSRoot = pfConfig.AppDnsRoot
		crm.AnsiblePublicAddr = pfConfig.AnsiblePublicAddr
		crm.DeploymentTag = pfConfig.DeploymentTag
		crm.AccessApiAddr = pfConfig.AccessApiAddr
		crm.CacheDir = pfConfig.CacheDir
	}
	for envKey, envVal := range cloudlet.EnvVar {
		crm.Common.EnvVars[envKey] = envVal
	}
	return crm, opts, nil
}

type trackedProcessKey struct {
	cloudletKey edgeproto.CloudletKey
	haRole      HARole
}

var trackedProcess = map[trackedProcessKey]CrmProcess{}
var trackedProcessMux sync.Mutex

func GetCRMCmdArgs(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, haRole HARole, crmOps ...CrmServiceOp) ([]string, *map[string]string, error) {
	crmOpts := GetCrmServiceOptions(crmOps...)
	crmProc, opts, err := crmOpts.getCrmProc(cloudlet, pfConfig, haRole)
	if err != nil {
		return nil, nil, err
	}
	crmProc.CrmProc().AccessKeyFile = GetCrmAccessKeyFile()
	return crmProc.CrmProc().GetArgs(opts...), &crmProc.CrmProc().Common.EnvVars, nil
}

func StartCRMService(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, haRole HARole, redisCfg *rediscache.RedisConfig, crmOps ...CrmServiceOp) error {
	log.SpanLog(ctx, log.DebugLevelApi, "start crmserver", "cloudlet", cloudlet.Key, "haRole", haRole, "rediscfg", redisCfg)

	crmOpts := GetCrmServiceOptions(crmOps...)

	// Get non-conflicting port for NotifySrvAddr if actual port is 0
	var newAddr string
	var err error
	if haRole == HARoleSecondary {
		newAddr, err = cloudcommon.GetAvailablePort(cloudlet.SecondaryNotifySrvAddr)
		cloudlet.SecondaryNotifySrvAddr = newAddr
	} else {
		newAddr, err = cloudcommon.GetAvailablePort(cloudlet.NotifySrvAddr)
		cloudlet.NotifySrvAddr = newAddr
	}
	if err != nil {
		return err
	}
	ak := pfConfig.CrmAccessPrivateKey
	if haRole == HARoleSecondary {
		ak = pfConfig.SecondaryCrmAccessPrivateKey
	}
	accessKeyFile := GetLocalAccessKeyFile(cloudlet.Key.Name, haRole)
	if ak != "" {
		// Write access key to local disk
		err = os.MkdirAll(GetLocalAccessKeyDir(), 0744)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(accessKeyFile, []byte(ak), 0644)
		if err != nil {
			return err
		}
	}

	// skip CRM service after writing accesskey file for Shepherd
	if !cloudlet.CrmOnEdge {
		// no CRM service
		log.SpanLog(ctx, log.DebugLevelApi, "skip start crm service because no crm on edge", "cloudlet", cloudlet.Key)
		return nil
	}

	// track all local crm processes
	procKey := trackedProcessKey{
		cloudletKey: cloudlet.Key,
		haRole:      haRole,
	}
	trackedProcessMux.Lock()
	trackedProcess[procKey] = nil
	trackedProcessMux.Unlock()
	crmP, opts, err := crmOpts.getCrmProc(cloudlet, pfConfig, haRole)
	if err != nil {
		return err
	}
	crmProc := crmP.CrmProc()
	crmProc.AccessKeyFile = accessKeyFile
	crmProc.HARole = haRole
	if redisCfg != nil {
		crmProc.RedisMasterName = redisCfg.MasterName
		crmProc.RedisSentinelAddrs = redisCfg.SentinelAddrs
		crmProc.RedisStandaloneAddr = redisCfg.StandaloneAddr
	}
	filePrefix := cloudlet.Key.Name + string(haRole)

	err = crmP.StartLocal(GetCloudletLogFile(filePrefix), opts...)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "started "+crmP.GetExeName(), "pfConfig", pfConfig)
	trackedProcessMux.Lock()
	trackedProcess[procKey] = crmP
	trackedProcessMux.Unlock()

	return nil
}

// StopCRMService stops the crmserver on the specified cloudlet, or kills any
// crm process if the cloudlet specified is nil
func StopCRMService(ctx context.Context, cloudlet *edgeproto.Cloudlet, haRole HARole, crmOps ...CrmServiceOp) error {
	crmOpts := GetCrmServiceOptions(crmOps...)
	args := ""
	if cloudlet != nil {
		if !cloudlet.CrmOnEdge {
			// no CRM service
			log.SpanLog(ctx, log.DebugLevelApi, "stop crm service skip because no crm on edge", "cloudlet", cloudlet.Key)
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelApi, "stop crmserver", "cloudlet", cloudlet.Key, "haRole", haRole)
		crmProc, _, err := crmOpts.getCrmProc(cloudlet, nil, haRole)
		if err != nil {
			return err
		}
		lookupArgs := crmProc.LookupArgs()
		if haRole != HARoleAll {
			lookupArgs = crmProc.CrmProc().LookupArgsWithHARole(haRole)
		}
		args = util.EscapeJson(lookupArgs)
	}
	// max wait time for process to go down gracefully, after which it is killed forcefully
	maxwait := 10 * time.Millisecond

	c := make(chan string)
	go KillProcessesByName(crmOpts.exeName, maxwait, args, c)

	log.SpanLog(ctx, log.DebugLevelInfra, "stopped crmserver", "msg", <-c)

	// After above, processes will be in Zombie state. Hence use wait to cleanup the processes
	trackedProcessMux.Lock()
	if cloudlet != nil {
		procKey := trackedProcessKey{
			cloudletKey: cloudlet.Key,
			haRole:      haRole,
		}
		if cmdProc, ok := trackedProcess[procKey]; ok {
			// Wait is in a goroutine as it is blocking call if
			// process is not killed for some reasons
			go cmdProc.CrmProc().Wait()
			delete(trackedProcess, procKey)
		}
	} else {
		for _, v := range trackedProcess {
			go v.CrmProc().Wait()
		}
		trackedProcess = make(map[trackedProcessKey]CrmProcess)
	}
	trackedProcessMux.Unlock()
	return nil
}

var maxPrimaryCrmStartupWait = 10 * time.Second

func StartCRMServicesHA(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, redisCfg *rediscache.RedisConfig, crmOps ...CrmServiceOp) error {
	if !cloudlet.CrmOnEdge {
		return fmt.Errorf("active-standby HA is not allowed for CRM off-site")
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "creating 2 instances for H/A", "key", cloudlet.Key)

	err := StartCRMService(ctx, cloudlet, pfConfig, HARolePrimary, redisCfg, crmOps...)
	if err != nil {
		return fmt.Errorf("primary CRM startup failed, %s", err)
	}
	procKey := trackedProcessKey{
		cloudletKey: cloudlet.Key,
		haRole:      HARolePrimary,
	}
	trackedProcessMux.Lock()
	crmPrimary := trackedProcess[procKey]
	trackedProcessMux.Unlock()

	crmP := crmPrimary.CrmProc()
	// Pause before starting the secondary to let the primary become active first for the sake of
	// e2e tests that need consistent ordering. Secondary will be started up in a separate thread after
	// cloudletInfo shows up from the primary
	start := time.Now()
	for {
		time.Sleep(time.Millisecond * 200)
		elapsed := time.Since(start)
		if elapsed >= (maxPrimaryCrmStartupWait) {
			log.SpanLog(ctx, log.DebugLevelInfra, "timed out waiting for primary CRM process")
			return fmt.Errorf("timed out waiting for primary CRM process")
		}
		if !EnsureProcessesByName(crmP.GetExeName(), crmP.LookupArgs()) {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to detect primary CRM up, will retry", "cloudletKey", cloudlet.Key)
		} else {
			err = StartCRMService(ctx, cloudlet, pfConfig, HARoleSecondary, redisCfg, crmOps...)
			if err != nil {
				return fmt.Errorf("secondary CRM startup failed, %s", err)
			}
			break
		}
	}
	return nil
}

// Parses cloudlet logfile and fetches FatalLog output
func GetCloudletLog(ctx context.Context, key *edgeproto.CloudletKey) (string, error) {
	logFile := GetCloudletLogFile(key.Name)
	log.SpanLog(ctx, log.DebugLevelApi, fmt.Sprintf("parse cloudlet logfile %s to fetch crash details", logFile))

	file, err := os.Open(logFile)
	if err != nil {
		return "", err
	}
	defer file.Close()

	out := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "FATAL") {
			fields := strings.Fields(line)
			if len(fields) > 3 {
				out = strings.Join(fields[3:], " ")
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return out, nil
}

func CrmServiceWait(key edgeproto.CloudletKey) error {

	roles := []HARole{
		HARolePrimary,
		HARoleSecondary,
	}
	// loop through all possible HA roles to find running CRMs
	var crmProcs []CrmProcess
	trackedProcessMux.Lock()
	for _, r := range roles {
		procKey := trackedProcessKey{
			cloudletKey: key,
			haRole:      r,
		}
		tp, ok := trackedProcess[procKey]
		delete(trackedProcess, procKey)
		if ok {
			crmProcs = append(crmProcs, tp)
		}
	}
	trackedProcessMux.Unlock()
	for _, p := range crmProcs {
		err := p.CrmProc().Wait()
		if err != nil && strings.Contains(err.Error(), "Wait was already called") {
			return nil
		}
		if err != nil {
			return fmt.Errorf("Crm Service Stopped: %v", err)
		}
	}
	return nil
}

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
- job_name: EdgeCloud Monitoring
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

func getShepherdProc(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) (*Shepherd, []StartOp, error) {
	opts := []StartOp{}

	cloudletKeyStr, err := json.Marshal(cloudlet.Key)
	if err != nil {
		return nil, opts, fmt.Errorf("unable to marshal cloudlet key")
	}

	opts = append(opts, WithDebug("api,infra,metrics"))

	s := &Shepherd{
		NotifyAddrs: cloudlet.NotifySrvAddr,
		CloudletKey: string(cloudletKeyStr),
		Platform:    cloudlet.PlatformType,
		Common: Common{
			Hostname: cloudlet.Key.Name,
			EnvVars:  cloudlet.EnvVar,
		},
		PhysicalName: cloudlet.PhysicalName,
	}
	if pfConfig != nil {
		if !cloudlet.CrmOnEdge {
			// shepherd on LB connects directly to Controller, not to CRM
			s.NotifyAddrs = pfConfig.NotifyCtrlAddrs
		}
		s.NodeCommon.TLS.ServerCert = pfConfig.TlsCertFile
		s.NodeCommon.TLS.ServerKey = pfConfig.TlsKeyFile
		s.NodeCommon.TLS.CACert = pfConfig.TlsCaFile
		s.Span = pfConfig.Span
		s.Region = pfConfig.Region
		s.NodeCommon.UseVaultPki = pfConfig.UseVaultPki
		s.AppDNSRoot = pfConfig.AppDnsRoot
		s.NodeCommon.DeploymentTag = pfConfig.DeploymentTag
		s.NodeCommon.AccessApiAddr = pfConfig.AccessApiAddr
		s.ThanosRecvAddr = pfConfig.ThanosRecvAddr
		for k, v := range pfConfig.EnvVar {
			if s.Common.EnvVars == nil {
				s.Common.EnvVars = make(map[string]string)
			}
			s.Common.EnvVars[k] = v
		}
	}
	return s, opts, nil
}

func GetShepherdCmdArgs(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) ([]string, *map[string]string, error) {
	ShepherdProc, opts, err := getShepherdProc(cloudlet, pfConfig)
	if err != nil {
		return nil, nil, err
	}
	ShepherdProc.AccessKeyFile = GetCrmAccessKeyFile()

	return ShepherdProc.GetArgs(opts...), &ShepherdProc.Common.EnvVars, nil
}

func StartShepherdService(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) (*Shepherd, error) {
	shepherdProc, opts, err := getShepherdProc(cloudlet, pfConfig)
	if err != nil {
		return nil, err
	}
	// for local testing, include debug notify
	opts = append(opts, WithDebug("api,notify,infra,metrics"))
	// for local testing, shepherd runs as a process but
	// the "cloudlet" prometheus runs in a container, so we need
	// to specify the prometheus target address to be able to
	// reach Shepherd.
	shepherdProc.PromTargetAddr = "host.docker.internal:9091"

	shepherdProc.AccessKeyFile = GetLocalAccessKeyFile(cloudlet.Key.Name, HARolePrimary) // TODO Shepherd HA

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
	go KillProcessesByName("shepherd", maxwait, args, c)

	log.SpanLog(ctx, log.DebugLevelInfra, "stopped Shepherdserver", "msg", <-c)
	return nil
}

func StopFakeEnvoyExporters(ctx context.Context) error {
	c := make(chan string)
	go KillProcessesByName("fake_envoy_exporter", time.Second, "--port", c)
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
	var err error
	args, err = AddHostDockerInternal(args)
	if err != nil {
		return err
	}
	// set name and image path
	promImage := PrometheusImagePath + ":" + PrometheusImageVersion
	args = append(args, []string{"--name", PrometheusContainer, promImage}...)
	args = append(args, cmdOpts...)

	_, err = StartLocal(PrometheusContainer, "docker", args, nil, "/tmp/cloudlet_prometheus.log")
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
