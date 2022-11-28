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

package e2e

// consists of utilities used to deploy, start, stop processes locally.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/xind"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/kind"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/process"

	"github.com/edgexr/edge-cloud-platform/pkg/util"
	yaml "gopkg.in/yaml.v2"
)

//root TLS Dir
var tlsDir = ""

//outout TLS cert dir
var tlsOutDir = ""

// some actions have sub arguments associated after equal sign,
// e.g.--actions stop=ctrl1
func GetActionParam(a string) (string, string) {
	argslice := strings.SplitN(a, "=", 2)
	action := argslice[0]
	actionParam := ""
	if len(argslice) > 1 {
		actionParam = argslice[1]
	}
	return action, actionParam
}

func GetCtrlNameFromCrmStartArgs(args []string) string {
	for ii := range args {
		act, param := GetActionParam(args[ii])
		if act == "ctrl" {
			return param
		}
	}
	return ""
}

func GetHARoleFromActionArgs(args []string) string {
	for ii := range args {
		act, param := GetActionParam(args[ii])
		if act == "harole" {
			return param
		}
	}
	return ""
}

// Change "cluster-svc1 scrapeInterval=30s updateAll" int []{"cluster-svc1", "scrapeInterval=30s", "updateApp"}
func GetActionArgs(a string) []string {
	argSlice := strings.Fields(a)
	return argSlice
}

// actions can be split with a dash like ctrlapi-show
func GetActionSubtype(a string) (string, string) {
	argslice := strings.SplitN(a, "-", 2)
	action := argslice[0]
	actionSubtype := ""
	if len(argslice) > 1 {
		actionSubtype = argslice[1]
	}
	return action, actionSubtype
}

func IsLocalIP(hostname string) bool {
	return hostname == "localhost" || hostname == "127.0.0.1"
}

func WaitForProcesses(processName string, procs []process.Process) bool {
	if !ensureProcesses(processName, procs) {
		return false
	}
	log.Println("Wait for processes to respond to APIs")
	c := make(chan ReturnCodeWithText)
	count := 0
	for _, ctrl := range Deployment.Controllers {
		if processName != "" && processName != ctrl.Name {
			continue
		}
		count++
		go ConnectController(ctrl, c)
	}
	for _, dme := range Deployment.Dmes {
		if processName != "" && processName != dme.Name {
			continue
		}
		count++
		go ConnectDme(dme, c)
	}
	allpass := true
	for i := 0; i < count; i++ {
		rc := <-c
		log.Println(rc.Text)
		if !rc.Success {
			log.Printf("Error: connect failed: %s", rc.Text)
			allpass = false
		}
	}
	return allpass
}

// This uses the same methods as kill processes to look for local processes,
// to ensure that the lookup method for finding local processes is valid.
func ensureProcesses(processName string, procs []process.Process) bool {
	log.Println("Check processes are running")
	ensured := true
	for _, p := range procs {
		if processName != "" && processName != p.GetName() {
			continue
		}
		if !IsLocalIP(p.GetHostname()) {
			continue
		}

		exeName := p.GetExeName()
		args := p.LookupArgs()
		log.Printf("Looking for host %v processexe %v processargs %v\n", p.GetHostname(), exeName, args)
		if !process.EnsureProcessesByName(exeName, args) {
			log.Printf("Error: ensure process failed: %s", exeName)
			ensured = false
		}
	}
	return ensured
}

func getLogFile(procname string, outputDir string) string {
	if outputDir == "" {
		return "./" + procname + ".log"
	} else {
		return outputDir + "/" + procname + ".log"
	}
}

func ReadSetupFile(setupfile string, deployment interface{}, vars map[string]string) bool {
	//the setup file has a vars section with replacement variables.  ingest the file once
	//to get these variables, and then ingest again to parse the setup data with the variables
	var setupVars SetupVariables

	_, exist := vars["tlsoutdir"]
	if !exist {
		//{{tlsoutdir}} is relative to the GO dir.
		goPath := os.Getenv("GOPATH")
		if goPath == "" {
			fmt.Fprintf(os.Stderr, "GOPATH not set, cannot calculate tlsoutdir")
			return false
		}
		tlsDir = goPath + "/src/github.com/edgexr/edge-cloud-platform/pkg/tls"
		tlsOutDir = tlsDir + "/out"
		vars["tlsoutdir"] = tlsOutDir
	}

	setupdir := filepath.Dir(setupfile)
	vars["setupdir"] = setupdir

	ReadYamlFile(setupfile, &setupVars)

	for _, repl := range setupVars.Vars {
		for varname, value := range repl {
			vars[varname] = value
		}
	}
	files := []string{setupfile}
	files = append(files, setupVars.Includes...)

	for _, filename := range files {
		err := ReadYamlFile(filename, deployment,
			WithVars(vars),
			ValidateReplacedVars())
		if err != nil {
			//if !IsYamlOk(err, "setup") {
			fmt.Fprintf(os.Stderr, "One or more fatal unmarshal errors in %s: %s", setupfile, err)
			return false
			//}
		}
	}
	//equals sign is not well handled in yaml so it is url encoded and changed after loading
	//for some reason, this only happens when the yaml is read as ProcessData and not
	//as a generic interface.  TODO: further study on this.
	for i, _ := range Deployment.Dmes {
		Deployment.Dmes[i].TokSrvUrl = strings.Replace(Deployment.Dmes[i].TokSrvUrl, "%3D", "=", -1)
	}
	return true
}

// CleanupDIND kills all containers on the kubeadm-dind-net-xxx network and then cleans up DIND
func CleanupDIND() error {
	// find docker networks
	log.Printf("Running CleanupDIND, getting docker networks\n")
	r, _ := regexp.Compile("kubeadm-dind-net(-(\\S+)-(\\d+))?")

	lscmd := exec.Command("docker", "network", "ls", "--format='{{.Name}}'")
	output, err := lscmd.Output()
	if err != nil {
		log.Printf("Error running docker network ls: %v", err)
		return err
	}
	netnames := strings.Split(string(output), "\n")
	for _, n := range netnames {
		n := strings.Trim(n, "'") //remove quotes
		if r.MatchString(n) {
			matches := r.FindStringSubmatch(n)
			clusterName := matches[2]
			clusterID := matches[3]

			log.Printf("found DIND net: %s clusterName: %s clusterID: %s\n", n, clusterName, clusterID)
			inscmd := exec.Command("docker", "network", "inspect", n, "--format={{range .Containers}}{{.Name}},{{end}}")
			output, err = inscmd.CombinedOutput()
			if err != nil {
				log.Printf("Error running docker network inspect: %s - %v - %v\n", n, string(output), err)
				return fmt.Errorf("error in docker inspect %v", err)
			}
			ostr := strings.TrimRight(string(output), ",") //trailing comma
			ostr = strings.TrimSpace(ostr)
			containers := strings.Split(ostr, ",")
			// first we need to kill all containers using the network as the dind script will
			// not clean these up, and cannot delete the network if they are present
			for _, c := range containers {
				if c == "" {
					continue
				}
				if strings.HasPrefix(c, "kube-node") || strings.HasPrefix(c, "kube-master") {
					// dind clean should handle this
					log.Printf("skipping kill of kube container: %s\n", c)
					continue
				}
				log.Printf("killing container: [%s]\n", c)
				killcmd := exec.Command("docker", "kill", c)
				output, err = killcmd.CombinedOutput()
				if err != nil {
					log.Printf("Error killing docker container: %s - %v - %v\n", c, string(output), err)
					return fmt.Errorf("error in docker kill %v", err)
				}
			}
			// now cleanup DIND cluster
			if clusterName != "" {
				os.Setenv("DIND_LABEL", clusterName)
				os.Setenv("CLUSTER_ID", clusterID)
			} else {
				log.Printf("no clustername, doing clean for default cluster")
				os.Unsetenv("DIND_LABEL")
				os.Unsetenv("CLUSTER_ID")
			}
			log.Printf("running %s clean clusterName: %s clusterID: %s\n", cloudcommon.DindScriptName, clusterName, clusterID)
			out, err := sh.Command(cloudcommon.DindScriptName, "clean").CombinedOutput()
			if err != nil {
				log.Printf("Error in dind clean: %v - %v\n", out, err)
				return fmt.Errorf("ERROR in cleanup Dind Cluster: %s", clusterName)
			}
			log.Printf("done dind clean for: %s out: %s\n", clusterName, out)
		}
	}
	log.Println("done CleanupDIND")
	return nil
}

func CleanupLocalProxies() error {
	// cleanup nginx and other docker containers common to both DIND and KIND
	pscmd := exec.Command("docker", "ps", "-a", "-q", "--filter", "label=edge-cloud")
	output, err := pscmd.Output()
	if err != nil {
		log.Printf("Error running docker ps: %v", err)
		return err
	}
	mexContainers := strings.Split(string(output), "\n")
	cmds := []string{"kill", "rm"}
	for _, c := range mexContainers {
		if c == "" {
			continue
		}
		for _, cmd := range cmds {
			killcmd := exec.Command("docker", cmd, c)
			output, err = killcmd.CombinedOutput()
			if err != nil {
				// not fatal as it may not have been running
				log.Printf("Error running command: %s on container: %s - %v - %v\n", cmd, c, string(output), err)
			}
		}
	}
	log.Println("done Cleanup local proxies")
	return nil
}

func CleanupKIND(ctx context.Context) error {
	log.Printf("Running CleanupKIND\n")
	vercmd := exec.Command("kind", "version")
	_, err := vercmd.CombinedOutput()
	if err != nil {
		// no kind installed
		log.Printf("No kind installed\n")
		return nil
	}
	client := &pc.LocalClient{
		WorkingDir: "/tmp",
	}

	clusters, err := kind.GetClusters(ctx, client)
	if err != nil {
		return err
	}
	for _, name := range clusters {
		log.Printf("pausing KIND cluster %s\n", name)
		nodes, err := kind.GetClusterContainerNames(ctx, client, name)
		if err != nil {
			log.Printf("Failed to get KIND cluster %s container names, %s", name, err)
			return err
		}
		err = xind.PauseContainers(ctx, client, nodes)
		if err != nil {
			log.Printf("Failed to pause KIND cluster %s, %s\n", name, err)
			return err
		}
	}
	log.Printf("done Cleanup KIND\n")
	return nil
}

func StopProcesses(processName string, allprocs []process.Process) bool {
	PrintStepBanner("stopping processes " + processName)
	maxWait := time.Second * 15
	c := make(chan string)
	count := 0

	for ii, p := range allprocs {
		if !IsLocalIP(p.GetHostname()) {
			continue
		}
		if processName != "" && processName != p.GetName() {
			// If a process name is specified, we stop just that one.
			// The name here identifies the specific instance of the
			// application, e.g. 'ctrl1'.
			continue
		}
		log.Println("stopping/killing processes " + p.GetName())
		go process.StopProcess(allprocs[ii], maxWait, c)
		count++
	}
	if processName != "" && count == 0 {
		log.Printf("Error: unable to find process name %v in setup\n", processName)
		return false
	}

	for i := 0; i < count; i++ {
		log.Printf("stop/kill result: %v\n", <-c)
	}

	if processName == "" {
		// doing full clean up
		for _, p := range Deployment.Etcds {
			log.Printf("cleaning etcd %+v", p)
			p.ResetData()
		}
		for _, dn := range Deployment.DockerNetworks {
			log.Printf("Removing docker network %+v\n", dn)
			if err := dn.Delete(); err != nil {
				log.Printf("%s\n", err)
			}
		}
	}
	return true
}

func StageYamlFile(filename string, directory string, contents interface{}) bool {

	dstFile := directory + "/" + filename

	//rather than just copy the file, we unmarshal it because we have done variable replace
	data, err := yaml.Marshal(contents)
	if err != nil {
		log.Printf("Error in marshal of setupfile for ansible %v\n", err)
		return false
	}

	log.Printf("writing setup data to %s\n", dstFile)

	// Write data to dst
	err = ioutil.WriteFile(dstFile, data, 0644)
	if err != nil {
		log.Printf("Error writing file: %v\n", err)
		return false
	}
	return true
}

func StageLocDbFile(srcFile string, destDir string) {
	var locdb interface{}
	yerr := ReadYamlFile(srcFile, &locdb)
	if yerr != nil {
		fmt.Fprintf(os.Stderr, "Error reading location file %s -- %v\n", srcFile, yerr)
	}
	if !StageYamlFile("locsim.yml", destDir, locdb) {
		fmt.Fprintf(os.Stderr, "Error staging location db file %s to %s\n", srcFile, destDir)
	}
}

// CleanupTLSCerts . Deletes certs for a CN
func CleanupTLSCerts() error {
	for _, t := range Deployment.TLSCerts {
		patt := tlsOutDir + "/" + t.CommonName + ".*"
		log.Printf("Removing [%s]\n", patt)

		files, err := filepath.Glob(patt)
		if err != nil {
			return err
		}
		for _, f := range files {
			if err := os.Remove(f); err != nil {
				return err
			}
		}
	}
	return nil
}

// GenerateTLSCerts . create tls certs using certstrap.  This requires certstrap binary to be installed.  We can eventually
// do this programmatically but certstrap has some dependency problems that require manual package workarounds
// and so will use the command for now so as not to break builds.
func GenerateTLSCerts() error {
	for _, t := range Deployment.TLSCerts {

		var cmdargs = []string{"--depot-path", tlsOutDir, "request-cert", "--passphrase", "", "--common-name", t.CommonName}
		if len(t.DNSNames) > 0 {
			cmdargs = append(cmdargs, "--domain", strings.Join(t.DNSNames, ","))
		}
		if len(t.IPs) > 0 {
			cmdargs = append(cmdargs, "--ip", strings.Join(t.IPs, ","))
		}

		cmd := exec.Command("certstrap", cmdargs[0:]...)
		output, err := cmd.CombinedOutput()
		log.Printf("Certstrap Request Cert cmdargs: %v output:\n%v\n", cmdargs, string(output))
		if err != nil {
			if strings.HasPrefix(string(output), "Certificate request has existed") {
				// this is ok
			} else {
				return err
			}
		}

		cmd = exec.Command("certstrap", "--depot-path", tlsOutDir, "sign", "--CA", "mex-ca", t.CommonName)
		output, err = cmd.CombinedOutput()
		log.Printf("Certstrap Sign Cert cmdargs: %v output:\n%v\n", cmdargs, string(output))
		if strings.HasPrefix(string(output), "Certificate has existed") {
			// this is ok
		} else {
			return err
		}
	}
	return nil
}

func StartLocal(processName, outputDir string, p process.Process, portsInUse map[string]string, opts ...process.StartOp) bool {
	if processName != "" && processName != p.GetName() {
		return true
	}
	if !IsLocalIP(p.GetHostname()) {
		return true
	}
	if err := process.CheckBindOk(portsInUse, p.GetBindAddrs()); err != nil {
		log.Printf("%s: %s\n", p.GetName(), err)
		return false
	}
	typ := process.GetTypeString(p)
	log.Printf("Starting %s %s+v\n", typ, p)
	logfile := getLogFile(p.GetName(), outputDir)

	err := p.StartLocal(logfile, opts...)
	if err != nil {
		log.Printf("Error on %s startup: %v\n", typ, err)
		return false
	}
	return true
}

func StartLocalPar(processName, outputDir string, p process.Process, portsInUse map[string]string, wg *sync.WaitGroup, failed *bool, opts ...process.StartOp) {
	wg.Add(1)
	go func() {
		if !StartLocal(processName, outputDir, p, portsInUse, opts...) {
			*failed = true
		}
		wg.Done()
	}()
}

func StartProcesses(processName string, args []string, outputDir string) bool {
	if outputDir == "" {
		outputDir = "."
	}
	rolesfile := outputDir + "/roles.yaml"
	PrintStepBanner("starting local processes")

	opts := []process.StartOp{}
	if processName == "" {
		// full start of all processes, do clean start
		opts = append(opts, process.WithCleanStartup())
	}
	if len(args) > 0 {
		opts = append(opts, process.WithExtraArgs(args))
	}
	portsInUse, err := process.GetPortsInUse()
	if err != nil {
		log.Printf("Failed to get ports in use: %s\n", err)
		return false
	}

	for _, dn := range Deployment.DockerNetworks {
		if processName != "" && dn.Name != processName {
			continue
		}
		if !IsLocalIP(dn.Hostname) {
			continue
		}
		if err := dn.Create(); err != nil {
			log.Printf("%s\n", err)
			return false
		}
	}
	wg := sync.WaitGroup{}
	failed := false
	for _, p := range Deployment.Influxs {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	vaultOpts := append(opts, process.WithRolesFile(rolesfile))
	for _, p := range Deployment.Vaults {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, vaultOpts...)
	}
	for _, p := range Deployment.Etcds {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.ElasticSearchs {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.RedisCaches {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.Sqls {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	// wait for databases
	wg.Wait()
	if failed {
		return false
	}
	// wait for jaeger which depends on elastic search
	for _, p := range Deployment.Jaegers {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	wg.Wait()
	if failed {
		return false
	}
	opts = append(opts, process.WithRolesFile(rolesfile))

	for _, p := range Deployment.Traefiks {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.NginxProxys {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.NotifyRoots {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, append(opts, process.WithDebug("api,notify,events"))...)
	}
	for _, p := range Deployment.EdgeTurns {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, append(opts, process.WithDebug("api,notify"))...)
	}
	for _, p := range Deployment.Controllers {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, append(opts, process.WithDebug("etcd,api,notify,metrics,infra,events"))...)
	}
	for _, p := range Deployment.Dmes {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, append(opts, process.WithRolesFile(rolesfile), process.WithDebug("locapi,dmedb,dmereq,notify,metrics,events"))...)
	}
	for _, p := range Deployment.ClusterSvcs {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, append(opts, process.WithDebug("notify,infra,api,events"))...)
	}
	for _, p := range Deployment.Crms {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, append(opts, process.WithDebug("notify,infra,api,events"))...)
	}
	for _, p := range Deployment.Locsims {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.Toksims {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.SampleApps {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.Alertmanagers {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.AlertmgrSidecars {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, append(opts, process.WithDebug("api,notify,metrics,events"))...)
	}
	for _, p := range Deployment.Mcs {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, append(opts, process.WithDebug("api,metrics,events,notify"))...)
	}
	for _, p := range Deployment.Frms {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, append(opts, process.WithDebug("api,infra,notify"))...)
	}
	for _, p := range Deployment.Shepherds {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, append(opts, process.WithDebug("metrics,events"))...)
	}
	for _, p := range Deployment.AutoProvs {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, append(opts, process.WithDebug("api,notify,metrics,events"))...)
	}
	for _, p := range Deployment.Prometheus {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.HttpServers {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.ChefServers {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.Maildevs {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.ThanosQueries {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.ThanosReceives {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	for _, p := range Deployment.Qossessims {
		StartLocalPar(processName, outputDir, p, portsInUse, &wg, &failed, opts...)
	}
	wg.Wait()
	if failed {
		return false
	}
	return true
}

func Cleanup(ctx context.Context) error {
	err := process.StopCRMService(ctx, nil, process.HARolePrimary)
	if err != nil {
		return err
	}
	err = CleanupKIND(ctx)
	if err != nil {
		return err
	}
	err = CleanupDIND()
	if err != nil {
		return err
	}
	err = process.CleanupEtcdRamDisk()
	if err != nil {
		return err
	}
	return CleanupLocalProxies()
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

func RunAction(ctx context.Context, actionSpec, outputDir string, config *TestConfig, spec *TestSpec, mods []string, vars map[string]string, sharedData map[string]string, retry *bool) []string {
	var actionArgs []string

	act, actionParam := GetActionParam(actionSpec)
	action, actionSubtype := GetActionSubtype(act)
	vars = util.AddMaps(vars, spec.ApiFileVars)

	errs := []string{}

	switch action {
	case "deploy":
		err := CreateCloudflareRecords()
		if err != nil {
			errs = append(errs, err.Error())
		}
		if Deployment.Cluster.MexManifest != "" {
			dir := path.Dir(config.SetupFile)
			err := DeployK8sServices(dir)
			if err != nil {
				errs = append(errs, err.Error())
			}
		}
	case "gencerts":
		err := GenerateTLSCerts()
		if err != nil {
			errs = append(errs, err.Error())
		}
	case "cleancerts":
		err := CleanupTLSCerts()
		if err != nil {
			errs = append(errs, err.Error())
		}
	case "start":
		startFailed := false
		allprocs := GetAllProcesses()
		if actionSubtype == "argument" {
			// extract the action param and action args
			actionArgs = GetActionArgs(actionParam)
			actionParam = actionArgs[0]
			actionArgs = actionArgs[1:]
		}
		if actionSubtype == "crm" {
			// extract the action param and action args
			actionArgs = GetActionArgs(actionParam)
			ctrlName := ""
			if len(actionArgs) > 0 {
				actionParam = actionArgs[0]
				actionArgs = actionArgs[1:]
				ctrlName = GetCtrlNameFromCrmStartArgs(actionArgs)
			}
			log.Printf("Starting CRM %s connected to ctrl %s\n", actionParam, ctrlName)
			// read the apifile and start crm with the details
			err := StartCrmsLocal(ctx, actionParam, ctrlName, spec.ApiFile, spec.ApiFileVars, outputDir)
			if err != nil {
				errs = append(errs, err.Error())
			}
			break
		}
		if !StartProcesses(actionParam, actionArgs, outputDir) {
			startFailed = true
			errs = append(errs, "start failed")
		}
		if startFailed {
			if !StopProcesses(actionParam, allprocs) {
				errs = append(errs, "stop failed")
			}
			break

		}
		if !WaitForProcesses(actionParam, allprocs) {
			errs = append(errs, "wait for process failed")
		}
	case "status":
		if !WaitForProcesses(actionParam, GetAllProcesses()) {
			errs = append(errs, "wait for process failed")
		}
	case "stop":
		if actionSubtype == "argument" {
			// extract the action param and action args
			actionArgs = GetActionArgs(actionParam)
			actionParam = actionArgs[0]
			actionArgs = actionArgs[1:]
		}
		if actionSubtype == "crm" || actionParam == "crm" {
			haRole := process.HARoleAll
			rolearg := GetHARoleFromActionArgs(actionArgs)
			if rolearg != "" {
				haRole = process.HARole(rolearg)
			}
			if err := StopCrmsLocal(ctx, actionParam, spec.ApiFile, spec.ApiFileVars, haRole); err != nil {
				errs = append(errs, err.Error())
			}
		} else {
			allprocs := GetAllProcesses()
			if !StopProcesses(actionParam, allprocs) {
				errs = append(errs, "stop failed")
			}
		}
	case "ctrlapi":
		if !RunControllerAPI(actionSubtype, actionParam, spec.ApiFile, spec.ApiFileVars, outputDir, mods, retry) {
			log.Printf("Unable to run api for %s-%s, %v\n", action, actionSubtype, mods)
			errs = append(errs, "controller api failed")
		}
	case "clientshow":
		if !RunAppInstClientAPI(actionSubtype, actionParam, spec.ApiFile, outputDir) {
			log.Printf("Unable to run ShowAppInstClient api for %s, %v\n", action, mods)
			errs = append(errs, "ShowAppInstClient api failed")
		}
	case "exec":
		if !RunCommandAPI(actionSubtype, actionParam, spec.ApiFile, spec.ApiFileVars, outputDir) {
			log.Printf("Unable to run RunCommand api for %s, %v\n", action, mods)
			errs = append(errs, "controller RunCommand api failed")
		}
	case "dmeapi":
		if !RunDmeAPI(actionSubtype, actionParam, spec.ApiFile, spec.ApiFileVars, spec.ApiType, outputDir, mods) {
			log.Printf("Unable to run api for %s\n", action)
			errs = append(errs, "dme api failed")
		}
	case "influxapi":
		if !RunInfluxAPI(actionSubtype, actionParam, spec.ApiFile, spec.ApiFileVars, outputDir) {
			log.Printf("Unable to run influx api for %s\n", action)
			errs = append(errs, "influx api failed")
		}
	case "cmds":
		if !RunCommands(spec.ApiFile, spec.ApiFileVars, outputDir, retry) {
			log.Printf("Unable to run commands for %s\n", action)
			errs = append(errs, "commands failed")
		}
	case "script":
		if !RunScript(spec.ApiFile, outputDir, retry) {
			log.Printf("Unable to run script for %s\n", action)
			errs = append(errs, "script failed")
		}
	case "mcapi":
		if !RunMcAPI(actionSubtype, actionParam, spec.ApiFile, spec.ActionVars, spec.ApiFileVars, spec.CurUserFile, outputDir, mods, vars, sharedData, retry) {
			log.Printf("Unable to run api for %s\n", action)
			errs = append(errs, "MC api failed")
		}
	case "cleanup":
		err := DeleteCloudfareRecords()
		if err != nil {
			errs = append(errs, err.Error())
		}
		if Deployment.Cluster.MexManifest != "" {
			dir := path.Dir(config.SetupFile)
			err := DeleteK8sServices(dir)
			if err != nil {
				errs = append(errs, err.Error())
			}
		}
		err = process.StopShepherdService(ctx, nil)
		if err != nil {
			errs = append(errs, err.Error())
		}
		err = process.StopCloudletPrometheus(ctx)
		if err != nil {
			errs = append(errs, err.Error())
		}
		err = CleanupTmpFiles(ctx)
		if err != nil {
			errs = append(errs, err.Error())
		}
		err = process.StopFakeEnvoyExporters(ctx)
		if err != nil {
			errs = append(errs, err.Error())
		}
		err = Cleanup(ctx)
		if err != nil {
			errs = append(errs, err.Error())
		}
	case "runchefclient":
		err := RunChefClient(spec.ApiFile, vars)
		if err != nil {
			errs = append(errs, err.Error())
		}
	case "email":
		*retry = true
		err := RunEmailAPI(actionSubtype, spec.ApiFile, outputDir)
		if err != nil {
			errs = append(errs, err.Error())
		}
	case "slack":
		*retry = true
		err := RunSlackAPI(actionSubtype, spec.ApiFile, outputDir)
		if err != nil {
			errs = append(errs, err.Error())
		}
	case "pagerduty":
		*retry = true
		err := RunPagerDutyAPI(actionSubtype, spec.ApiFile, outputDir)
		if err != nil {
			errs = append(errs, err.Error())
		}
	case "sleep":
		t, err := strconv.ParseFloat(actionParam, 64)
		if err == nil {
			time.Sleep(time.Second * time.Duration(t))
		} else {
			errs = append(errs, fmt.Sprintf("Error in parsing sleeptime: %v", err))
		}
	default:
		errs = append(errs, fmt.Sprintf("invalid action %s", action))
	}
	return errs
}

type Retry struct {
	Enable    bool
	Count     int // number of retries (does not include first try)
	Interval  time.Duration
	Try       int
	runAction []bool
}

func NewRetry(count int, intervalSec float64, numActions int) *Retry {
	r := Retry{}
	r.Try = 1
	r.Count = count
	r.Interval = time.Duration(float64(time.Second) * intervalSec)
	r.runAction = make([]bool, numActions, numActions)
	if r.Count > 0 {
		r.Enable = true
	}
	if r.Enable && r.Interval == 0 {
		log.Fatal("Retry interval cannot be zero")
	}
	return &r
}

func (r *Retry) Tries() string {
	return fmt.Sprintf(" (try %d of %d)", r.Try, r.Try+r.Count)
}

func (r *Retry) SetActionRetry(ii int, retry bool) {
	// set whether or not to run the specific action on retries
	r.runAction[ii] = retry
	if !retry {
		return
	}
	// enable retries
	if r.Enable {
		return
	}
	r.Enable = true
	// set defaults
	r.Count = 5
	r.Interval = 500 * time.Millisecond
}

func (r *Retry) ShouldRunAction(ii int) bool {
	if r.Try == 1 {
		// always run actions the first iteration
		return true
	}
	return r.runAction[ii]
}

func (r *Retry) WillRetry() bool {
	return r.Count > 0
}

func (r *Retry) Done() bool {
	if r.Count == 0 {
		return true
	}
	r.Count--
	r.Try++
	time.Sleep(r.Interval)
	return false
}

func RunTestSpec(ctx context.Context, config *TestConfig, spec *TestSpec, mods []string, stopOnFail bool) error {
	errs := []string{}
	outputDir := config.Vars["outputdir"]
	sharedDataPath := outputDir + "/shared_data.json"

	if config.SetupFile != "" {
		if !ReadSetupFile(config.SetupFile, &Deployment, config.Vars) {
			return fmt.Errorf("Failed to read setup file")
		}
		DeploymentReplacementVars = config.Vars
	}

	retry := NewRetry(spec.RetryCount, spec.RetryIntervalSec, len(spec.Actions))
	ranTest := false

	// Load from file
	sharedData := make(map[string]string)
	plan, err := ioutil.ReadFile(sharedDataPath)
	if err != nil {
		// ignore
		log.Printf("error reading shared data file %s, err: %v\n", sharedDataPath, err)
	} else {
		err = json.Unmarshal(plan, &sharedData)
		if err != nil {
			// ignore
			log.Printf("failed to marshal shared data, err: %v\n", err)
		}
	}

	for {
		tryErrs := []string{}
		for ii, a := range spec.Actions {
			if !retry.ShouldRunAction(ii) {
				continue
			}
			PrintStepBanner("name: " + spec.Name)
			PrintStepBanner("running action: " + a + retry.Tries())
			actionretry := false
			runerrs := RunAction(ctx, a, outputDir, config, spec, mods, config.Vars, sharedData, &actionretry)
			ranTest = true
			if len(runerrs) > 0 {
				if actionretry {
					// potential errs that may be ignored after retry
					tryErrs = append(tryErrs, runerrs...)
				} else {
					// no retry for action, so register errs as final errs
					errs = append(errs, runerrs...)
					if stopOnFail {
						break
					}
				}
			}
			retry.SetActionRetry(ii, actionretry)
		}
		if stopOnFail && len(errs) > 0 {
			// stopOnFail case
			break
		}
		if spec.CompareYaml.Yaml1 != "" && spec.CompareYaml.Yaml2 != "" {
			pass := CompareYamlFiles(spec.Name, spec.Actions, &spec.CompareYaml)
			if !pass {
				tryErrs = append(tryErrs, "compare yaml failed")
			}
			ranTest = true
		}
		if len(tryErrs) == 0 || retry.Done() {
			errs = append(errs, tryErrs...)
			break
		}
		log.Printf("encountered failures, will retry:\n")
		for _, e := range tryErrs {
			log.Printf("- %s\n", e)
		}
		log.Printf("")
	}
	if !ranTest {
		errs = append(errs, "no test content")
	}

	if len(sharedData) > 0 {
		dataStr, err := json.Marshal(sharedData)
		if err != nil {
			// ignore
			log.Printf("error in json marshal of shared data, err: %v\n", err)
		} else {
			err = ioutil.WriteFile(sharedDataPath, []byte(dataStr), 0644)
			if err != nil {
				// ignore
				log.Printf("error writing shared data file, err: %v\n", err)
			}
		}
	}

	log.Printf("\nNum Errs found: %d, Results in: %s\n", len(errs), outputDir)
	if len(errs) > 0 {
		errstring := strings.Join(errs, ",")
		return errors.New(errstring)
	}
	return nil
}
