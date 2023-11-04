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
	"net/http"
	"os/exec"
	"time"

	yaml "gopkg.in/yaml.v2"
)

type MC struct {
	Common                  `yaml:",inline"`
	NodeCommon              `yaml:",inline"`
	Addr                    string
	ConsoleAddr             string
	FederationAddr          string
	SqlAddr                 string
	NotifyAddrs             string
	RolesFile               string
	LdapAddr                string
	GitlabAddr              string
	HarborAddr              string
	NotifySrvAddr           string
	ConsoleProxyAddr        string
	AlertResolveTimeout     string
	BillingPlatform         string
	UsageCollectionInterval string
	UsageCheckpointInterval string
	AlertMgrApiAddr         string
	ApiTlsCert              string
	ApiTlsKey               string
	StaticDir               string
	Domain                  string
	TestMode                bool
	cmd                     *exec.Cmd
}

func (p *MC) StartLocal(logfile string, opts ...StartOp) error {
	args := p.GetNodeMgrArgs()
	if p.Addr != "" {
		args = append(args, "--addr")
		args = append(args, p.Addr)
	}
	if p.ConsoleAddr != "" {
		args = append(args, "--consoleAddr")
		args = append(args, p.ConsoleAddr)
	}
	if p.FederationAddr != "" {
		args = append(args, "--federationAddr")
		args = append(args, p.FederationAddr)
	}
	if p.SqlAddr != "" {
		args = append(args, "--sqlAddr")
		args = append(args, p.SqlAddr)
	}
	if p.NotifyAddrs != "" {
		args = append(args, "--notifyAddrs")
		args = append(args, p.NotifyAddrs)
	}
	if p.TLS.ClientCert != "" {
		args = append(args, "--clientCert")
		args = append(args, p.TLS.ClientCert)
	}
	if p.ApiTlsCert != "" {
		args = append(args, "--apiTlsCert", p.ApiTlsCert)
	}
	if p.ApiTlsKey != "" {
		args = append(args, "--apiTlsKey", p.ApiTlsKey)
	}
	if p.LdapAddr != "" {
		args = append(args, "--ldapAddr")
		args = append(args, p.LdapAddr)
	}
	if p.GitlabAddr != "" {
		args = append(args, "--gitlabAddr")
		args = append(args, p.GitlabAddr)
	}
	if p.HarborAddr != "" {
		args = append(args, "--harborAddr")
		args = append(args, p.HarborAddr)
	}
	if p.NotifySrvAddr != "" {
		args = append(args, "--notifySrvAddr")
		args = append(args, p.NotifySrvAddr)
	}
	if p.ConsoleProxyAddr != "" {
		args = append(args, "--consoleproxyaddr")
		args = append(args, p.ConsoleProxyAddr)
	}
	if p.AlertResolveTimeout != "" {
		args = append(args, "--alertResolveTimeout")
		args = append(args, p.AlertResolveTimeout)
	}
	if p.BillingPlatform != "" {
		args = append(args, "--billingPlatform")
		args = append(args, p.BillingPlatform)
	}
	if p.UsageCollectionInterval != "" {
		args = append(args, "--usageCollectionInterval")
		args = append(args, p.UsageCollectionInterval)
	}
	if p.UsageCheckpointInterval != "" {
		args = append(args, "--usageCheckpointInterval")
		args = append(args, p.UsageCheckpointInterval)
	}
	if p.AlertMgrApiAddr != "" {
		args = append(args, "--alertMgrApiAddr")
		args = append(args, p.AlertMgrApiAddr)
	}
	if p.StaticDir != "" {
		args = append(args, "--staticDir", p.StaticDir)
	}
	if p.Domain != "" {
		args = append(args, "--domain", p.Domain)
	}
	if p.TestMode {
		args = append(args, "--testMode")
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
		envs = append(envs,
			fmt.Sprintf("VAULT_ROLE_ID=%s", roles.MCRoleID),
			fmt.Sprintf("VAULT_SECRET_ID=%s", roles.MCSecretID),
		)
	}

	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, envs, logfile)
	if err == nil {
		// wait until server is online
		online := false
		for ii := 0; ii < 90; ii++ {
			resp, serr := http.Get("http://" + p.Addr)
			if serr == nil {
				resp.Body.Close()
				online = true
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if !online {
			p.StopLocal()
			return fmt.Errorf("failed to detect MC online")
		}
	}
	return err
}

func (p *MC) StopLocal() {
	StopLocal(p.cmd)
}

func (p *MC) GetExeName() string { return "mc" }

func (p *MC) LookupArgs() string { return "--addr " + p.Addr }

func (p *MC) GetBindAddrs() []string {
	return []string{
		fmt.Sprintf(":%s", p.Addr),
		fmt.Sprintf(":%s", p.FederationAddr),
		fmt.Sprintf(":%s", p.NotifySrvAddr),
		fmt.Sprintf(":%s", p.LdapAddr),
	}
}
