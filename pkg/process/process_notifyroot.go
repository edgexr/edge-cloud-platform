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
	"io/ioutil"
	"os/exec"

	yaml "gopkg.in/yaml.v2"
)

type NotifyRoot struct {
	Common     `yaml:",inline"`
	NodeCommon `yaml:",inline"`
	NotifyAddr string
	cmd        *exec.Cmd
}

func (p *NotifyRoot) StartLocal(logfile string, opts ...StartOp) error {
	args := p.GetNodeMgrArgs()

	options := StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.Debug != "" {
		args = append(args, "-d")
		args = append(args, options.Debug)
	}
	if p.NotifyAddr != "" {
		args = append(args, "--notifyAddr", p.NotifyAddr)
	}
	envs := p.GetEnv()
	if options.RolesFile != "" {
		dat, err := ioutil.ReadFile(options.RolesFile)
		if err != nil {
			return err
		}
		roles := VaultRoles{}
		err = yaml.Unmarshal(dat, &roles)
		if err != nil {
			return err
		}
		envs = append(envs,
			fmt.Sprintf("VAULT_ROLE_ID=%s", roles.NotifyRootRoleID),
			fmt.Sprintf("VAULT_SECRET_ID=%s", roles.NotifyRootSecretID),
		)
	}

	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, envs, logfile)
	return err
}

func (p *NotifyRoot) StopLocal() {
	StopLocal(p.cmd)
}

func (p *NotifyRoot) GetExeName() string { return "notifyroot" }

func (p *NotifyRoot) LookupArgs() string { return "" }

func (p *NotifyRoot) GetBindAddrs() []string {
	return []string{p.NotifyAddr}
}
