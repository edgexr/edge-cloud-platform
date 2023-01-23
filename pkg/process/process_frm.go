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

type FRM struct {
	Common                 `yaml:",inline"`
	NodeCommon             `yaml:",inline"`
	NotifyAddrs            string
	Region                 string
	FederationExternalAddr string
	cmd                    *exec.Cmd
}

func (p *FRM) StartLocal(logfile string, opts ...StartOp) error {
	args := p.GetNodeMgrArgs()
	if p.NotifyAddrs != "" {
		args = append(args, "--notifyAddrs")
		args = append(args, p.NotifyAddrs)
	}
	if p.TLS.ClientCert != "" {
		args = append(args, "--clientCert")
		args = append(args, p.TLS.ClientCert)
	}
	if p.Region != "" {
		args = append(args, "--region")
		args = append(args, p.Region)
	}
	if p.FederationExternalAddr != "" {
		args = append(args, "--federationExternalAddr", p.FederationExternalAddr)
	}
	args = append(args, "--hostname", p.Name)
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
			fmt.Sprintf("VAULT_ROLE_ID=%s", rr.FrmRoleID),
			fmt.Sprintf("VAULT_SECRET_ID=%s", rr.FrmSecretID),
		)
	}

	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, envs, logfile)
	return err
}

func (p *FRM) StopLocal() {
	StopLocal(p.cmd)
}

func (p *FRM) GetExeName() string { return "frm" }

func (p *FRM) LookupArgs() string { return p.Name }

func (p *FRM) GetBindAddrs() []string { return []string{} }
