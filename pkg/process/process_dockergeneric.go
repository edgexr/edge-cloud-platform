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
	"fmt"
	"log"
	"os/exec"
	"strings"
)

type DockerGeneric struct {
	Common        `yaml:",inline"`
	Links         []string
	DockerNetwork string
	DockerEnvVars map[string]string
	TLS           TLSCerts
	cmd           *exec.Cmd
}

type DockerNetwork struct {
	Common `yaml:",inline"`
}

func (d *DockerNetwork) Create() error {
	return d.run("create")
}

func (d *DockerNetwork) Delete() error {
	err := d.run("rm")
	if err != nil && strings.Contains(err.Error(), "No such network") {
		err = nil
	}
	return err
}

func (d *DockerNetwork) run(action string) error {
	args := []string{"docker", "network", action, d.Name}
	log.Printf("Running: %s\n", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s, %s", string(out), err)
	}
	log.Printf("%s", string(out))
	return nil
}

func (p *DockerGeneric) GetRunArgs() []string {
	args := []string{
		"run", "--rm", "--name", p.Name,
	}
	var err error
	args, err = AddHostDockerInternal(args)
	if err != nil {
		panic(err)
	}
	for k, v := range p.DockerEnvVars {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
	}
	for _, link := range p.Links {
		args = append(args, "--link", link)
	}
	if p.DockerNetwork != "" {
		args = append(args, "--network", p.DockerNetwork)
	}
	return args
}

func (p *DockerGeneric) StopLocal() {
	StopLocal(p.cmd)
	// if container is from previous aborted run
	cmd := exec.Command("docker", "kill", p.Name)
	cmd.Run()
	cmd = exec.Command("docker", "rm", p.Name)
	cmd.Run()
}

func (p *DockerGeneric) GetExeName() string { return "docker" }

func (p *DockerGeneric) LookupArgs() string { return p.Name }

func (p *DockerGeneric) SetCmd(cmd *exec.Cmd) { p.cmd = cmd }

func (p *DockerGeneric) GetCmd() *exec.Cmd { return p.cmd }

// OS-specific function to add host.docker.internal mapping if needed,
// so that process from inside container can reach service running outside container.
func AddHostDockerInternal(args []string) ([]string, error) {
	out, err := exec.Command("uname", "-r").CombinedOutput()
	if err != nil {
		return args, fmt.Errorf("Unable to determine OS release, %s, %v", string(out), err)
	}
	kernelRelease := strings.TrimSpace(string(out))
	if strings.Contains(kernelRelease, "microsoft") && strings.Contains(kernelRelease, "WSL") {
		// WSL2 may be configured for NAT networking mode or mirrored
		// networking mode.
		out, err := exec.Command("wslinfo", "--networking-mode").CombinedOutput()
		if err == nil && strings.TrimSpace(string(out)) == "mirrored" {
			args = append(args, "--add-host", "host.docker.internal:host-gateway")
			return args, nil
		}
		// get wsl ip
		ip := ""
		for ii := range 10 {
			out, err = exec.Command("sh", "-c", `ip addr show eth`+fmt.Sprintf("%d", ii)+` | grep -oP '(?<=inet\s)\d+(\.\d+){3}'`).CombinedOutput()
			if err != nil && string(out) == "" {
				continue
			}
			if err != nil {
				return args, fmt.Errorf("Unable to determine WSL ip address, %s, %v", string(out), err)
			}
			ip = strings.TrimSpace(string(out))
			break
		}
		if ip == "" {
			return args, fmt.Errorf("Unable to determine WSL ip address")
		}
		// remap host.docker.internal to wsl ip instead of windows ip
		args = append(args, "--add-host", "host.docker.internal:"+ip)
	} else if strings.Contains(kernelRelease, "generic") {
		// standard linux
		args = append(args, "--add-host", "host.docker.internal:host-gateway")
	}
	return args, nil
}
