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
	"strings"

	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/integration/process"
	"github.com/mobiledgex/edge-cloud/setup-env/e2e-tests/e2eapi"
	setupmex "github.com/mobiledgex/edge-cloud/setup-env/setup-mex"
	"github.com/mobiledgex/edge-cloud/setup-env/util"
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
	Shepherds           []*intprocess.Shepherd            `yaml:"shepherds"`
	AutoProvs           []*intprocess.AutoProv            `yaml:"autoprovs"`
	Cloudflare          CloudflareDNS                     `yaml:"cloudflare"`
	Prometheus          []*intprocess.PromE2e             `yaml:"prometheus"`
	HttpServers         []*intprocess.HttpServer          `yaml:"httpservers"`
	ChefServers         []*intprocess.ChefServer          `yaml:"chefserver"`
	Alertmanagers       []*intprocess.Alertmanager        `yaml:"alertmanagers"`
	Maildevs            []*intprocess.Maildev             `yaml:"maildevs"`
	AlertmgrSidecars    []*intprocess.AlertmanagerSidecar `yaml:"alertmanagersidecars"`
}

// a comparison and yaml friendly version of AllMetrics for e2e-tests
type MetricsCompare struct {
	Name   string
	Tags   map[string]string
	Values map[string]float64
}

type MetricTargets struct {
	AppInstKey     edgeproto.AppInstKey
	ClusterInstKey edgeproto.ClusterInstKey
	CloudletKey    edgeproto.CloudletKey
}

type EventSearch struct {
	Search  node.EventSearch
	Results []node.EventData
}

type EventTerms struct {
	Search node.EventSearch
	Terms  *node.EventTerms
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
	// special event tags
	"event":  struct{}{},
	"status": struct{}{},
	"flavor": struct{}{},
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
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.Mcs {
		opts = append(opts, process.WithRolesFile(rolesfile))
		opts = append(opts, process.WithDebug("api,metrics,events"))
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
	return true
}

func RunAction(ctx context.Context, actionSpec, outputDir string, config *e2eapi.TestConfig, spec *TestSpec, specStr string, mods []string, vars map[string]string, retry *bool) []string {
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
			if !setupmex.StopProcesses(actionParam, allprocs) || !StopRemoteProcesses(actionParam) {
				errors = append(errors, "stop failed")
			}
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
		allprocs := GetAllProcesses()
		if !setupmex.StopProcesses(actionParam, allprocs) {
			errors = append(errors, "stop local failed")
		}
		if !StopRemoteProcesses(actionParam) {
			errors = append(errors, "stop remote failed")
		}
	case "mcapi":
		if !RunMcAPI(actionSubtype, actionParam, spec.ApiFile, spec.CurUserFile, outputDir, mods, vars, retry) {
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
	default:
		ecSpec := setupmex.TestSpec{}
		err := json.Unmarshal([]byte(specStr), &ecSpec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: unmarshaling setupmex TestSpec: %v", err)
			errors = append(errors, "Error in unmarshaling TestSpec")
		} else {
			retry := false
			errs := setupmex.RunAction(ctx, actionSpec, outputDir, &ecSpec, mods, vars, &retry)
			errors = append(errors, errs...)
		}
	}
	return errors
}
