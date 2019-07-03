package e2esetup

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"strconv"
	"time"

	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
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
	Cluster             ClusterInfo            `yaml:"cluster"`
	K8sDeployment       []*K8sDeploymentStep   `yaml:"k8s-deployment"`
	Mcs                 []*intprocess.MC       `yaml:"mcs"`
	Sqls                []*intprocess.Sql      `yaml:"sqls"`
	Shepherds           []*intprocess.Shepherd `yaml:"shepherds"`
	Cloudflare          CloudflareDNS          `yaml:"cloudflare"`
}

var apiAddrsUpdated = false

func GetAllProcesses() []process.Process {
	// get all procs from edge-cloud
	all := util.GetAllProcesses()
	for _, p := range Deployment.Sqls {
		all = append(all, p)
	}
	for _, p := range Deployment.Mcs {
		all = append(all, p)
	}
	for _, p := range Deployment.Shepherds {
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

func StartProcesses(processName string, outputDir string) bool {
	if !setupmex.StartProcesses(processName, outputDir) {
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
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.Mcs {
		opts = append(opts, process.WithRolesFile(rolesfile))
		opts = append(opts, process.WithDebug("api"))
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	for _, p := range Deployment.Shepherds {
		opts = append(opts, process.WithRolesFile(rolesfile))
		opts = append(opts, process.WithDebug("metrics"))
		if !setupmex.StartLocal(processName, outputDir, p, opts...) {
			return false
		}
	}
	return true
}

func RunAction(actionSpec, outputDir string, config *e2eapi.TestConfig, spec *TestSpec, specStr string, mods []string) []string {
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
		if !StartProcesses(actionParam, outputDir) {
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
	case "stop":
		allprocs := GetAllProcesses()
		if !setupmex.StopProcesses(actionParam, allprocs) {
			errors = append(errors, "stop local failed")
		}
		if !StopRemoteProcesses(actionParam) {
			errors = append(errors, "stop remote failed")
		}
	case "mcapi":
		if !RunMcAPI(actionSubtype, actionParam, spec.ApiFile, spec.CurUserFile, outputDir, mods) {
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
		err = setupmex.Cleanup()
		if err != nil {
			errors = append(errors, err.Error())
		}
	case "fetchlogs":
		if !FetchRemoteLogs(outputDir) {
			errors = append(errors, "fetch failed")
		}
	case "sleep":
		t, err := strconv.ParseUint(actionParam, 10, 32)
		if err == nil {
			time.Sleep(time.Second * time.Duration(t))
		} else {
			errors = append(errors, "Error in parsing sleeptime")
		}
	default:
		ecSpec := setupmex.TestSpec{}
		err := json.Unmarshal([]byte(specStr), &ecSpec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: unmarshaling setupmex TestSpec: %v", err)
			errors = append(errors, "Error in unmarshaling TestSpec")
		} else {
			errs := setupmex.RunAction(actionSpec, outputDir, &ecSpec, mods)
			errors = append(errors, errs...)
		}
	}
	return errors
}
