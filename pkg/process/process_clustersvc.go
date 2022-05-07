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
	"strings"

	yaml "gopkg.in/yaml.v2"
)

type ClusterSvc struct {
	Common         `yaml:",inline"`
	NodeCommon     `yaml:",inline"`
	NotifyAddrs    string
	CtrlAddrs      string
	PromPorts      string
	InfluxDB       string
	Interval       string
	Region         string
	PluginRequired bool
	cmd            *exec.Cmd
}

func (p *ClusterSvc) StartLocal(logfile string, opts ...StartOp) error {
	args := []string{"--notifyAddrs", p.NotifyAddrs}
	args = append(args, p.GetNodeMgrArgs()...)
	if p.CtrlAddrs != "" {
		args = append(args, "--ctrlAddrs")
		args = append(args, p.CtrlAddrs)
	}
	if p.PromPorts != "" {
		args = append(args, "--prometheus-ports")
		args = append(args, p.PromPorts)
	}
	if p.InfluxDB != "" {
		args = append(args, "--influxdb")
		args = append(args, p.InfluxDB)
	}
	if p.Interval != "" {
		args = append(args, "--scrapeInterval")
		args = append(args, p.Interval)
	}
	if p.PluginRequired {
		args = append(args, "--pluginRequired")
	}
	if p.Region != "" {
		args = append(args, "--region", p.Region)
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
			fmt.Sprintf("VAULT_ROLE_ID=%s", rr.ClusterSvcRoleID),
			fmt.Sprintf("VAULT_SECRET_ID=%s", rr.ClusterSvcSecretID),
		)
	}

	// Append extra args convert from [arg1=val1, arg2] into ["-arg1", "val1", "-arg2"]
	if len(options.ExtraArgs) > 0 {
		for _, v := range options.ExtraArgs {
			tmp := strings.Split(v, "=")
			args = append(args, "-"+tmp[0])
			if len(tmp) > 1 {
				args = append(args, tmp[1])
			}
		}
	}

	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, envs, logfile)
	return err
}

func (p *ClusterSvc) StopLocal() {
	StopLocal(p.cmd)
}

func (p *ClusterSvc) GetExeName() string { return "cluster-svc" }

func (p *ClusterSvc) LookupArgs() string { return p.Name }
