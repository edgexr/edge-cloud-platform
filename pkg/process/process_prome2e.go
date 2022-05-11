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
	"os"
	"os/exec"
	"strings"
)

type PromE2e struct {
	DockerGeneric `yaml:",inline"`
	Port          int
}

func (p *PromE2e) StartLocal(logfile string, opts ...StartOp) error {
	// if the image doesn't exist, build it
	if !imageFound(p.Name) {
		directory := os.Getenv("GOPATH") + "/src/github.com/edgexr/edge-cloud-platform/shepherd/e2eHttpServer"
		builder := exec.Command("docker", "build", "-t", p.Name, directory)
		err := builder.Run()
		if err != nil {
			return fmt.Errorf("Failed to build docker image for e2e prometheus: %v", err)
		}
	}
	args := p.GetRunArgs()
	args = append(args,
		"-p", fmt.Sprintf("%d:%d", p.Port, p.Port),
		p.Name)
	cmd, err := StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	return err
}

func (p *PromE2e) GetBindAddrs() []string {
	return []string{fmt.Sprintf(":%d", p.Port)}
}

func imageFound(name string) bool {
	listCmd := exec.Command("docker", "images")
	output, err := listCmd.Output()
	if err != nil {
		return false
	}
	imageList := strings.Split(string(output), "\n")
	for _, row := range imageList {
		if name == strings.SplitN(row, " ", 2)[0] {
			return true
		}
	}
	return false
}
