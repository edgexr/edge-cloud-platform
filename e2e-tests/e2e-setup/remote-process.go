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
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/edgexr/edge-cloud/integration/process"
	setupmex "github.com/edgexr/edge-cloud/setup-env/setup-mex"
)

//when first creating a cluster, it may take a while for the load balancer to get an IP. Usually
// this happens much faster, but occasionally it takes longer
var maxWaitForServiceSeconds = 900 //15 min

func getAnsibleHome() string {
	ebAbsible := os.Getenv("EBANSIBLE")
	if ebAbsible != "" {
		return ebAbsible
	}

	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		log.Fatalf("GOPATH not set")
	}
	return goPath + "/src/github.com/edgexr/edge-cloud-infra/ansible"
}

func getExternalApiAddress(internalApiAddr string, externalHost string) string {
	//in cloud deployments, the internal address the controller listens to may be different than the
	//external address which clients need to use.   So use the external hostname and api port
	if externalHost == "0.0.0.0" || externalHost == "127.0.0.1" {
		// local host: prevent swapping around these two addresses
		// because they are used interchangably between the host and
		// api addr fields, and they are also used by pgrep to search
		// for the process, which can cause pgrep to fail to find the
		// process.
		return internalApiAddr
	}
	return externalHost + ":" + strings.Split(internalApiAddr, ":")[1]
}

// if there is a DNS address configured we will use that.  Required because TLS certs
// are generated against the DNS name if one is available.
func getDNSNameForAddr(addr string) string {
	//split the port off

	ss := strings.Split(addr, ":")
	if len(ss) < 2 {
		return addr
	}
	a := ss[0]
	p := ss[1]

	for _, r := range Deployment.Cloudflare.Records {
		if r.Content == a {
			return r.Name + ":" + p
		}
	}
	// no record found, just use the add
	return addr
}

//in cloud deployments, the internal address the controller listens to may be different than the
//external address which clients need to use as floating IPs are used.  So use the external
//hostname and api port when connecting to the API.  This needs to be done after startup
//but before trying to connect to the APIs remotely
func UpdateAPIAddrs() bool {
	if apiAddrsUpdated {
		//no need to do this more than once
		return true
	}
	//for k8s deployments, get the ip from the service
	if IsK8sDeployment() {
		if len(Deployment.Controllers) > 0 {
			if Deployment.Controllers[0].ApiAddr != "" {
				for i, ctrl := range Deployment.Controllers {
					Deployment.Controllers[i].ApiAddr = getExternalApiAddress(ctrl.ApiAddr, ctrl.Hostname)
					log.Printf("set controller API addr to %s\n", Deployment.Controllers[i].ApiAddr)
				}
			} else {
				addr, err := GetK8sServiceAddr("controller", maxWaitForServiceSeconds)
				if err != nil {
					fmt.Fprintf(os.Stderr, "unable to get controller service ")
					return false
				}
				Deployment.Controllers[0].ApiAddr = addr
				log.Printf("set controller API addr from k8s service to %s\n", addr)

			}
		}
		if len(Deployment.Dmes) > 0 {
			if Deployment.Dmes[0].ApiAddr != "" {
				for i, dme := range Deployment.Dmes {
					Deployment.Dmes[i].ApiAddr = getExternalApiAddress(dme.ApiAddr, dme.Hostname)
				}
			} else {
				addr, err := GetK8sServiceAddr("dme", maxWaitForServiceSeconds)
				if err != nil {
					fmt.Fprintf(os.Stderr, "unable to get dme service ")
					return false
				}
				Deployment.Dmes[0].ApiAddr = addr
			}
		}
	} else {
		for i, ctrl := range Deployment.Controllers {
			Deployment.Controllers[i].ApiAddr = getExternalApiAddress(ctrl.ApiAddr, ctrl.Hostname)
		}
		for i, dme := range Deployment.Dmes {
			Deployment.Dmes[i].ApiAddr = getExternalApiAddress(dme.ApiAddr, dme.Hostname)
		}
	}
	apiAddrsUpdated = true
	return true
}

func runPlaybook(playbook string, evars []string, procNamefilter string) bool {
	invFile, found := createAnsibleInventoryFile(procNamefilter)
	ansHome := getAnsibleHome()

	if !setupmex.StageYamlFile("setup.yml", ansHome+"/playbooks", &Deployment) {
		return false
	}

	if !found {
		log.Println("No remote servers found, local environment only")
		return true
	}

	argstr := ""
	for _, ev := range evars {
		argstr += ev
		argstr += " "
	}
	// TODO: migrate playbooks to support python3
	argstr += "ansible_python_interpreter=/usr/bin/python"

	log.Printf("Running Playbook: %s with extra-vars: %s\n", playbook, argstr)
	cmd := exec.Command("ansible-playbook", "-i", invFile, "-e", argstr, playbook)

	output, err := cmd.CombinedOutput()
	log.Printf("Ansible Output:\n%v\n", string(output))

	if err != nil {
		fmt.Fprintf(os.Stderr, "Ansible playbook failed: %v ", err)
		return false
	}
	return true
}

// for ansible we need to ssh to the ip address if available as the DNS record may not yet exist
func hostNameToAnsible(hostname string) string {
	for _, r := range Deployment.Cloudflare.Records {
		if r.Name == hostname {
			return hostname + " ansible_ssh_host=" + r.Content
		}
	}
	return hostname
}

func createAnsibleInventoryFile(procNameFilter string) (string, bool) {
	ansHome := getAnsibleHome()
	log.Printf("Creating inventory file in dir: %s using procname filter: %s\n", ansHome, procNameFilter)

	invfile, err := os.Create(ansHome + "/mex_inventory")
	log.Printf("Creating inventory file: %v", invfile.Name())
	if err != nil {
		fmt.Fprint(os.Stderr, "Cannot create file", err)
	}
	defer invfile.Close()

	//use the mobiledgex ssh key
	fmt.Fprintln(invfile, "[all:vars]")
	fmt.Fprintln(invfile, "ansible_ssh_private_key_file=~/.mobiledgex/id_rsa_mex")
	fmt.Fprintln(invfile, "jaeger_hostname=jaeger.mobiledgex.net")
	fmt.Fprintln(invfile, "jaeger_port=14268")
	allservers := make(map[string]map[string]string)

	allprocs := GetAllProcesses()
	for _, p := range allprocs {
		if procNameFilter != "" && procNameFilter != p.GetName() {
			continue
		}
		if p.GetHostname() == "" || setupmex.IsLocalIP(p.GetHostname()) {
			continue
		}

		i := hostNameToAnsible(p.GetHostname())
		typ := process.GetTypeString(p)
		alltyps, found := allservers[typ]
		if !found {
			alltyps = make(map[string]string)
			allservers[typ] = alltyps
		}
		alltyps[i] = p.GetName()

		// type-specific stuff
		if locsim, ok := p.(*process.LocApiSim); ok {
			if locsim.Locfile != "" {
				setupmex.StageLocDbFile(locsim.Locfile, ansHome+"/playbooks")
			}
		}
	}

	//create ansible inventory
	fmt.Fprintln(invfile, "[mexservers]")
	for _, alltyps := range allservers {
		for s := range alltyps {
			fmt.Fprintln(invfile, s)
		}
	}
	for typ, alltyps := range allservers {
		fmt.Fprintln(invfile, "")
		fmt.Fprintln(invfile, "["+strings.ToLower(typ)+"]")
		for s := range alltyps {
			fmt.Fprintln(invfile, s)
		}
	}
	fmt.Fprintln(invfile, "")
	return invfile.Name(), len(allservers) > 0
}

func DeployProcesses() bool {
	if IsK8sDeployment() {
		return true //nothing to do for k8s
	}

	ansHome := getAnsibleHome()
	playbook := ansHome + "/playbooks/mex_deploy.yml"
	return runPlaybook(playbook, []string{}, "")
}

func StartRemoteProcesses(processName string) bool {
	if IsK8sDeployment() {
		return true //nothing to do for k8s
	}
	ansHome := getAnsibleHome()
	playbook := ansHome + "/playbooks/mex_start.yml"

	return runPlaybook(playbook, []string{}, processName)
}

func StopRemoteProcesses(processName string) bool {
	if IsK8sDeployment() {
		return true //nothing to do for k8s
	}

	ansHome := getAnsibleHome()

	if processName != "" {
		p := GetProcessByName(processName)
		if setupmex.IsLocalIP(p.GetHostname()) {
			log.Printf("process %v is not remote\n", processName)
			return true
		}
		vars := []string{"processbin=" + p.GetExeName(), "processargs=\"" + p.LookupArgs() + "\""}
		playbook := ansHome + "/playbooks/mex_stop_matching_process.yml"
		return runPlaybook(playbook, vars, processName)

	}
	playbook := ansHome + "/playbooks/mex_stop.yml"
	return runPlaybook(playbook, []string{}, "")
}

func CleanupRemoteProcesses() bool {
	ansHome := getAnsibleHome()
	playbook := ansHome + "/playbooks/mex_cleanup.yml"
	return runPlaybook(playbook, []string{}, "")
}

func FetchRemoteLogs(outputDir string) bool {
	if IsK8sDeployment() {
		//TODO: need to get the logs from K8s
		return true
	}
	ansHome := getAnsibleHome()
	playbook := ansHome + "/playbooks/mex_fetch_logs.yml"
	return runPlaybook(playbook, []string{"local_log_path=" + outputDir}, "")
}
