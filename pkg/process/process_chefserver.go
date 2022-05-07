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
	"os/exec"
)

type ChefServer struct {
	Common `yaml:",inline"`
	Port   int
	cmd    *exec.Cmd
}

func (p *ChefServer) StartLocal(logfile string, opts ...StartOp) error {
	args := []string{}
	if p.Port > 0 {
		args = append(args, "--port")
		args = append(args, fmt.Sprintf("%d", p.Port))
	} else {
		args = append(args, "--port")
		args = append(args, "8889")
	}
	args = append(args, "--multi-org")

	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	if err != nil {
		return err
	}

	cmd := exec.Command("./e2e-tests/chef/setup.sh")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to execute ./e2e-tests/chef/setup.sh: %v, %s", err, out)
	}

	return err
}

func (p *ChefServer) StopLocal() {
	StopLocal(p.cmd)
}

func (p *ChefServer) GetExeName() string { return "chef-zero" }

func (p *ChefServer) LookupArgs() string { return fmt.Sprintf("--port %d --multi-org", p.Port) }
