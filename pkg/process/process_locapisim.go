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

type LocApiSim struct {
	Common  `yaml:",inline"`
	Port    int
	Locfile string
	Geofile string
	Country string
	cmd     *exec.Cmd
}

func (p *LocApiSim) StartLocal(logfile string, opts ...StartOp) error {
	args := []string{"-port", fmt.Sprintf("%d", p.Port), "-file", p.Locfile}
	if p.Geofile != "" {
		args = append(args, "-geo", p.Geofile)
	}
	if p.Country != "" {
		args = append(args, "-country", p.Country)
	}
	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	return err
}

func (p *LocApiSim) StopLocal() {
	StopLocal(p.cmd)
}

func (p *LocApiSim) GetExeName() string { return "loc-api-sim" }

func (p *LocApiSim) LookupArgs() string {
	return fmt.Sprintf("-port %d", p.Port)
}

func (p *LocApiSim) GetBindAddrs() []string {
	return []string{fmt.Sprintf(":%d", p.Port)}
}
