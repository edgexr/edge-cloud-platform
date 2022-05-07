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

type EdgeTurn struct {
	Common     `yaml:",inline"`
	NodeCommon `yaml:",inline"`
	cmd        *exec.Cmd
	ListenAddr string
	ProxyAddr  string
	Region     string
	TestMode   bool
}

func (p *EdgeTurn) StartLocal(logfile string, opts ...StartOp) error {
	args := p.GetNodeMgrArgs()
	if p.ListenAddr != "" {
		args = append(args, "--listenAddr")
		args = append(args, p.ListenAddr)
	}
	if p.ProxyAddr != "" {
		args = append(args, "--proxyAddr")
		args = append(args, p.ProxyAddr)
	}
	if p.Region != "" {
		args = append(args, "--region", p.Region)
	}
	if p.TestMode {
		args = append(args, "--testMode")
	}
	options := StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.Debug != "" {
		args = append(args, "-d")
		args = append(args, options.Debug)
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
		rr := roles.GetRegionRoles(p.Region)
		envs = append(envs,
			fmt.Sprintf("VAULT_ROLE_ID=%s", rr.EdgeTurnRoleID),
			fmt.Sprintf("VAULT_SECRET_ID=%s", rr.EdgeTurnSecretID),
		)
	}
	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, envs, logfile)
	return err
}

func (p *EdgeTurn) StopLocal() {
	StopLocal(p.cmd)
}

func (p *EdgeTurn) GetExeName() string { return "edgeturn" }

func (p *EdgeTurn) LookupArgs() string { return "" }
