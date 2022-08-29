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

type AlertmanagerSidecar struct {
	Common       `yaml:",inline"`
	AlertmgrAddr string
	ConfigFile   string
	HttpAddr     string
	LocalTest    bool
	TLS          TLSCerts
	cmd          *exec.Cmd
}

func (p *AlertmanagerSidecar) StartLocal(logfile string, opts ...StartOp) error {
	args := []string{"--httpAddr", p.HttpAddr}
	if p.AlertmgrAddr != "" {
		args = append(args, "--alertmgrAddr")
		args = append(args, p.AlertmgrAddr)
	}
	if p.ConfigFile != "" {
		args = append(args, "--configFile")
		args = append(args, p.ConfigFile)
	}
	if p.TLS.ServerCert != "" {
		args = append(args, "--tlsCert")
		args = append(args, p.TLS.ServerCert)
	}
	if p.TLS.ServerKey != "" {
		args = append(args, "--tlsCertKey")
		args = append(args, p.TLS.ServerKey)
	}
	if p.TLS.CACert != "" {
		args = append(args, "--tlsClientCert")
		args = append(args, p.TLS.CACert)
	}
	if p.LocalTest {
		args = append(args, "-localTest")
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
		envs = append(envs,
			fmt.Sprintf("VAULT_ROLE_ID=%s", roles.AlertMgrSidecarRoleID),
			fmt.Sprintf("VAULT_SECRET_ID=%s", roles.AlertMgrSidecarSecretID),
		)
	}

	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, envs, logfile)
	return err
}

func (p *AlertmanagerSidecar) StopLocal() {
	StopLocal(p.cmd)
}

func (p *AlertmanagerSidecar) GetExeName() string { return "alertmgr-sidecar" }

func (p *AlertmanagerSidecar) LookupArgs() string {
	return fmt.Sprintf("--httpAddr %s --alertmgrAddr %s", p.HttpAddr, p.AlertmgrAddr)
}

func (p *AlertmanagerSidecar) GetBindAddrs() []string {
	return []string{p.AlertmgrAddr}
}
