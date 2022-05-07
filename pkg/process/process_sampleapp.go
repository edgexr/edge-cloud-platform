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
	"os/exec"
	"strings"
)

// Generic sample app for use in test

type SampleApp struct {
	Common       `yaml:",inline"`
	Exename      string
	Args         []string
	Command      string
	VolumeMounts []string
	cmd          *exec.Cmd
}

func (p *SampleApp) StartLocal(logfile string, opts ...StartOp) error {
	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), p.Args, p.GetEnv(), logfile)
	return err
}

func (p *SampleApp) StopLocal() {
	StopLocal(p.cmd)
}

func (p *SampleApp) GetExeName() string { return p.Exename }

func (p *SampleApp) LookupArgs() string {
	return strings.Join(p.Args, " ")
}
