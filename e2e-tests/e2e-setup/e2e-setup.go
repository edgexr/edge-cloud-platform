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

package e2esetup

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	intprocess "github.com/edgexr/edge-cloud-infra/e2e-tests/int-process"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/integration/process"
	"github.com/edgexr/edge-cloud/setup-env/apis"
	"github.com/edgexr/edge-cloud/setup-env/e2e-tests/e2eapi"
	setupmex "github.com/edgexr/edge-cloud/setup-env/setup-mex"
	"github.com/edgexr/edge-cloud/setup-env/util"
	"github.com/mobiledgex/jaeger/plugin/storage/es/spanstore/dbmodel"
)

var Deployment DeploymentData

type GoogleCloudInfo struct {
	Cluster     string
	Zone        string
	MachineType string
}
type ClusterInfo struct {
	MexManifest string
}
type DnsRecord struct {
	Name    string
	Type    string
	Content string
}

//cloudflare dns records
type CloudflareDNS struct {
	Zone    string
	Records []DnsRecord
}

// Note: Any services that are declared in the Deployment
// but are actually instantiated by the K8S scripts must
// have a non-local hostname defined, otherwise they will be
// treated as a local service.
type K8sDeploymentStep struct {
	File        string
	Description string
	WaitForPods []K8sPod
	CopyFiles   []K8CopyFile
}
type K8sPod struct {
	PodName  string
	PodCount int
	MaxWait  int
}
type K8CopyFile struct {
	PodName string
	Src     string
	Dest    string
}

type DeploymentData struct {
	util.DeploymentData `yaml:",inline"`
	Cluster             ClusterInfo                       `yaml:"cluster"`
	K8sDeployment       []*K8sDeploymentStep              `yaml:"k8s-deployment"`
	Mcs                 []*intprocess.MC                  `yaml:"mcs"`
	Sqls                []*intprocess.Sql                 `yaml:"sqls"`
	Frms                []*intprocess.FRM                 `yaml:"frms"`
	Shepherds           []*intprocess.Shepherd            `yaml:"shepherds"`
	AutoProvs           []*intprocess.AutoProv            `yaml:"autoprovs"`
	Cloudflare          CloudflareDNS                     `yaml:"cloudflare"`
	Prometheus          []*intprocess.PromE2e             `yaml:"prometheus"`
	HttpServers         []*intprocess.HttpServer          `yaml:"httpservers"`
	ChefServers         []*intprocess.ChefServer          `yaml:"chefserver"`
	Alertmanagers       []*intprocess.Alertmanager        `yaml:"alertmanagers"`
	Maildevs            []*intprocess.Maildev             `yaml:"maildevs"`
	AlertmgrSidecars    []*intprocess.AlertmanagerSidecar `yaml:"alertmanagersidecars"`
	ThanosQueries       []*intprocess.ThanosQuery         `yaml:"thanosqueries"`
	ThanosReceives      []*intprocess.ThanosReceive       `yaml:"thanosreceives"`
	Qossessims          []*intprocess.QosSesSrvSim        `yaml:"qossessims"`
}

// a comparison and yaml friendly version of AllMetrics for e2e-tests
type MetricsCompare struct {
	Name   string
	Tags   map[string]string
	Values map[string]float64
}

type OptimizedMetricsCompare struct {
	Name    string
	Tags    map[string]string
	Values  [][]string
	Columns []string
}

type MetricTargets struct {
	AppInstKey             edgeproto.AppInstKey
	ClusterInstKey         edgeproto.ClusterInstKey
	CloudletKey            edgeproto.CloudletKey
	LocationTileLatency    string // used for clientappusage and clientcloudletusage metrics to guarantee correct metric
	LocationTileDeviceInfo string // used for clientappusage and clientcloudletusage metrics to guarantee correct metric
}

type EventSearch struct {
	Search  node.EventSearch
	Results []node.EventData
}

type EventTerms struct {
	Search node.EventSearch
	Terms  *node.EventTerms
}

type SpanSearch struct {
	Search  node.SpanSearch
	Results []node.SpanOutCondensed
}

type SpanSearchVerbose struct {
	Search  node.SpanSearch
	Results []dbmodel.Span
}

type SpanTerms struct {
	Search node.SpanSearch
	Terms  *node.SpanTerms
}

// metrics that e2e currently tests for
var E2eAppSelectors = []string{
	"cpu",
	"mem",
	"disk",
	"network",
}

var E2eClusterSelectors = []string{
	"cpu",
	"mem",
	"disk",
	"network",
	"tcp",
	"udp",
}

var TagValues = map[string]struct{}{
	"app":         struct{}{},
	"cloudlet":    struct{}{},
	"cluster":     struct{}{},
	"apporg":      struct{}{},
	"clusterorg":  struct{}{},
	"cloudletorg": struct{}{},
	"method":      struct{}{},
	// special event tags
	"event":  struct{}{},
	"status": struct{}{},
	"flavor": struct{}{},
	// edgeevents metrics tags
	"deviceos":        struct{}{},
	"devicemodel":     struct{}{},
	"locationtile":    struct{}{},
	"devicecarrier":   struct{}{},
	"datanetworktype": struct{}{},
}

// methods for dme-api metric
var ApiMethods = []string{
	"FindCloudlet",
	"PlatformFindCloudlet",
	"RegisterClient",
	"VerifyLocation",
}

var apiAddrsUpdated = false

func GetAllProcesses() []process.Process {
	// get all procs from edge-cloud
	all := util.GetAllProcesses()
	for _, p := range Deployment.Sqls {
		all = append(all, p)
	}
	for _, p := range Deployment.Alertmanagers {
		all = append(all, p)
	}
	for _, p := range Deployment.AlertmgrSidecars {
		all = append(all, p)
	}
	for _, p := range Deployment.Mcs {
		all = append(all, p)
	}
	for _, p := range Deployment.Frms {
		all = append(all, p)
	}
	for _, p := range Deployment.Shepherds {
		all = append(all, p)
	}
	for _, p := range Deployment.AutoProvs {
		all = append(all, p)
	}
	for _, p := range Deployment.Prometheus {
		all = append(all, p)
	}
	for _, p := range Deployment.HttpServers {
		all = append(all, p)
	}
	for _, p := range Deployment.ChefServers {
		all = append(all, p)
	}
	for _, p := range Deployment.Maildevs {
		all = append(all, p)
	}
	for _, p := range Deployment.ThanosQueries {
		all = append(all, p)
	}
	for _, p := range Deployment.ThanosReceives {
		all = append(all, p)
	}
	for _, p := range Deployment.Qossessims {
		all = append(all, p)
	}
	return all
}

func GetProcessByName(processName string) process.Process {
	for _, p := range GetAllProcesses() {
		if processName == p.GetName() {
			return p
		}
	}
	return nil
}

func IsK8sDeployment() bool {
	return Deployment.Cluster.MexManifest != "" //TODO Azure
}

func setupVault(rolesfile string) bool {
	pr := util.GetProcessByName("vault")
	if pr == nil {
		return true
	}
	p, ok := pr.(*process.Vault)
	if !ok {
		log.Printf("found process named vault but not Vault type")
		return false
	}

	_, err := intprocess.SetupVault(p, process.WithRolesFile(rolesfile))
	if err != nil {
		log.Printf("Failed to setup vault, %v\n", err)
		return false
	}
	return true
}

type ChefClient struct {
	NodeName   string   `yaml:"nodename"`
	JsonAttrs  string   `yaml:"jsonattrs"`
	ConfigFile string   `yaml:"configfile"`
	Runlist    []string `yaml:"runlist"`
}

// RunChefClient executes a single chef client run
func RunChefClient(apiFile string, vars map[string]string) error {
	chefClient := ChefClient{}
	err := util.ReadYamlFile(apiFile, &chefClient, util.WithVars(vars), util.ValidateReplacedVars())
	if err != nil {
		if !util.IsYamlOk(err, "runchefclient") {
			log.Printf("error in unmarshal for file, %s\n", apiFile)
		}
		return err
	}
	var cmdargs = []string{
		"--node-name", chefClient.NodeName,
	}
	if chefClient.JsonAttrs != "" {
		err = ioutil.WriteFile("/tmp/chefattrs.json", []byte(chefClient.JsonAttrs), 0644)
		if err != nil {
			log.Printf("write to file failed, %s, %v\n", chefClient.JsonAttrs, err)
			return err
		}
		cmdargs = append(cmdargs, "-j", "/tmp/chefattrs.json")
	}
	if chefClient.Runlist != nil {
		runlistStr := strings.Join(chefClient.Runlist, ",")
		cmdargs = append(cmdargs, "--runlist", runlistStr)
	}
	cmdargs = append(cmdargs, "-c", chefClient.ConfigFile)
	cmd := exec.Command("chef-client", cmdargs[0:]...)
	output, err := cmd.CombinedOutput()
	log.Printf("chef-client run with args: %v output:\n%v\n", cmdargs, string(output))
	if err != nil {
		log.Printf("Failed to run chef client, %v\n", err)
		return err
	}
	return nil
}

func StartProcesses(processName string, args []string, outputDir string) bool {
	if !setupmex.StartProcesses(processName, args, outputDir) {
		return false
	}

	if outputDir == "" {
		outputDir = "."
	}
	rolesfile := outputDir + "/roles-infra.yaml"
	if !setupVault(rolesfile) {
		return false
	}

	opts := []process.StartOp{}
	if processName == "" {
		// full start of all processes, do clean start
		opts = append(opts, process.WithCleanStartup())
	}

	for _, p := range Deployment.Sqls {
		opts := append(opts, process.WithCleanStartup())
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.Alertmanagers {
		opts := append(opts, process.WithCleanStartup())
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.AlertmgrSidecars {
		opts = append(opts, process.WithDebug("api,notify,metrics,events"))
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.Mcs {
		opts = append(opts, process.WithRolesFile(rolesfile))
		opts = append(opts, process.WithDebug("api,metrics,events,notify"))
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.Frms {
		opts = append(opts, process.WithRolesFile(rolesfile))
		opts = append(opts, process.WithDebug("api,infra,notify"))
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.Shepherds {
		opts = append(opts, process.WithRolesFile(rolesfile))
		opts = append(opts, process.WithDebug("metrics,events"))
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.AutoProvs {
		opts = append(opts, process.WithRolesFile(rolesfile))
		opts = append(opts, process.WithDebug("api,notify,metrics,events"))
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.Prometheus {
		opts := append(opts, process.WithCleanStartup())
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.HttpServers {
		opts := append(opts, process.WithCleanStartup())
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.ChefServers {
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.Maildevs {
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.ThanosQueries {
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.ThanosReceives {
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.Qossessims {
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	return true
}

// Clean up leftover files
func CleanupTmpFiles(ctx context.Context) error {
	filesToRemove, err := filepath.Glob("/var/tmp/rulefile_*")
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	configFiles := []string{"/var/tmp/prom_targets.json", "/var/tmp/prometheus.yml", "/tmp/alertmanager.yml"}
	filesToRemove = append(filesToRemove, configFiles...)
	for ii := range filesToRemove {
		err = os.Remove(filesToRemove[ii])
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func RunAction(ctx context.Context, actionSpec, outputDir string, config *e2eapi.TestConfig, spec *TestSpec, specStr string, mods []string, vars map[string]string, sharedData map[string]string, retry *bool) []string {
	var actionArgs []string
	act, actionParam := setupmex.GetActionParam(actionSpec)
	action, actionSubtype := setupmex.GetActionSubtype(act)

	errors := []string{}

	if action == "status" ||
		action == "ctrlapi" ||
		action == "dmeapi" ||
		action == "mcapi" {
		if !UpdateAPIAddrs() {
			errors = append(errors, "update API addrs failed")
		}
	}

	switch action {
	case "deploy":
		err := CreateCloudflareRecords()
		if err != nil {
			errors = append(errors, err.Error())
		}
		if Deployment.Cluster.MexManifest != "" {
			dir := path.Dir(config.SetupFile)
			err := DeployK8sServices(dir)
			if err != nil {
				errors = append(errors, err.Error())
			}
		} else {
			if !DeployProcesses() {
				errors = append(errors, "deploy failed")
			}
		}
	case "start":
		startFailed := false
		allprocs := GetAllProcesses()
		if actionSubtype == "argument" {
			// extract the action param and action args
			actionArgs = setupmex.GetActionArgs(actionParam)
			actionParam = actionArgs[0]
			actionArgs = actionArgs[1:]
		}
		if actionSubtype == "crm" {
			// extract the action param and action args
			actionArgs = setupmex.GetActionArgs(actionParam)
			actionParam = actionArgs[0]
			actionArgs = actionArgs[1:]
			ctrlName := ""

			// We can specify controller to connect to
			if len(actionArgs) > 0 {
				ctrlName = setupmex.GetCtrlNameFromCrmStartArgs(actionArgs)
			}

			// read the apifile and start crm with the details
			err := apis.StartCrmsLocal(ctx, actionParam, ctrlName, spec.ApiFile, spec.ApiFileVars, outputDir)
			if err != nil {
				errors = append(errors, err.Error())
			}
			break
		}
		if !StartProcesses(actionParam, actionArgs, outputDir) {
			startFailed = true
			errors = append(errors, "start failed")
		} else {
			if !StartRemoteProcesses(actionParam) {
				startFailed = true
				errors = append(errors, "start remote failed")
			}
		}
		if startFailed {
			break
		}
		if !UpdateAPIAddrs() {
			errors = append(errors, "update API addrs failed")
		} else {
			if !setupmex.WaitForProcesses(actionParam, allprocs) {
				errors = append(errors, "wait for process failed")
			}
		}
	case "status":
		if !setupmex.WaitForProcesses(actionParam, GetAllProcesses()) {
			errors = append(errors, "wait for process failed")
		}
	case "stop":
		if actionSubtype == "crm" {
			if err := apis.StopCrmsLocal(ctx, actionParam, spec.ApiFile, spec.ApiFileVars, process.HARoleAll); err != nil {
				errors = append(errors, err.Error())
			}
		} else {
			allprocs := GetAllProcesses()
			if !setupmex.StopProcesses(actionParam, allprocs) {
				errors = append(errors, "stop local failed")
			}
			if !StopRemoteProcesses(actionParam) {
				errors = append(errors, "stop remote failed")
			}
		}
	case "mcapi":
		if !RunMcAPI(actionSubtype, actionParam, spec.ApiFile, spec.ApiFileVars, spec.CurUserFile, outputDir, mods, vars, sharedData, retry) {
			log.Printf("Unable to run api for %s\n", action)
			errors = append(errors, "MC api failed")
		}
	case "cleanup":
		err := DeleteCloudfareRecords()
		if err != nil {
			errors = append(errors, err.Error())
		}
		if Deployment.Cluster.MexManifest != "" {
			dir := path.Dir(config.SetupFile)
			err := DeleteK8sServices(dir)
			if err != nil {
				errors = append(errors, err.Error())
			}
		} else {
			if !CleanupRemoteProcesses() {
				errors = append(errors, "cleanup failed")
			}
		}
		err = intprocess.StopShepherdService(ctx, nil)
		if err != nil {
			errors = append(errors, err.Error())
		}
		err = intprocess.StopCloudletPrometheus(ctx)
		if err != nil {
			errors = append(errors, err.Error())
		}
		err = CleanupTmpFiles(ctx)
		if err != nil {
			errors = append(errors, err.Error())
		}
		err = intprocess.StopFakeEnvoyExporters(ctx)
		if err != nil {
			errors = append(errors, err.Error())
		}
		err = setupmex.Cleanup(ctx)
		if err != nil {
			errors = append(errors, err.Error())
		}
	case "fetchlogs":
		if !FetchRemoteLogs(outputDir) {
			errors = append(errors, "fetch failed")
		}
	case "runchefclient":
		err := RunChefClient(spec.ApiFile, vars)
		if err != nil {
			errors = append(errors, err.Error())
		}
	case "email":
		*retry = true
		err := RunEmailAPI(actionSubtype, spec.ApiFile, outputDir)
		if err != nil {
			errors = append(errors, err.Error())
		}
	case "slack":
		*retry = true
		err := RunSlackAPI(actionSubtype, spec.ApiFile, outputDir)
		if err != nil {
			errors = append(errors, err.Error())
		}
	case "pagerduty":
		*retry = true
		err := RunPagerDutyAPI(actionSubtype, spec.ApiFile, outputDir)
		if err != nil {
			errors = append(errors, err.Error())
		}
	default:
		ecSpec := util.TestSpec{}
		err := json.Unmarshal([]byte(specStr), &ecSpec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: unmarshaling setupmex TestSpec: %v", err)
			errors = append(errors, "Error in unmarshaling TestSpec")
		} else {
			errs := setupmex.RunAction(ctx, actionSpec, outputDir, &ecSpec, mods, vars, retry)
			errors = append(errors, errs...)
		}
	}
	return errors
}
