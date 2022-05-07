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
)

type Shepherd struct {
	Common         `yaml:",inline"`
	NodeCommon     `yaml:",inline"`
	NotifyAddrs    string
	Platform       string
	MetricsAddr    string
	PhysicalName   string
	CloudletKey    string
	cmd            *exec.Cmd
	Span           string
	Region         string
	AppDNSRoot     string
	ChefServerPath string
	ThanosRecvAddr string
}

func (p *Shepherd) GetArgs(opts ...StartOp) []string {
	args := p.GetNodeMgrArgs()
	if p.Name != "" {
		args = append(args, "--name")
		args = append(args, p.Name)
	}
	if p.NotifyAddrs != "" {
		args = append(args, "--notifyAddrs")
		args = append(args, p.NotifyAddrs)
	}
	if p.Platform != "" {
		args = append(args, "--platform")
		args = append(args, p.Platform)
	}
	if p.PhysicalName != "" {
		args = append(args, "--physicalName")
		args = append(args, p.PhysicalName)
	}
	if p.CloudletKey != "" {
		args = append(args, "--cloudletKey")
		args = append(args, p.CloudletKey)
	}
	if p.Span != "" {
		args = append(args, "--span")
		args = append(args, p.Span)
	}
	if p.Region != "" {
		args = append(args, "--region")
		args = append(args, p.Region)
	}
	if p.MetricsAddr != "" {
		args = append(args, "--metricsAddr")
		args = append(args, p.MetricsAddr)
	}
	if p.AppDNSRoot != "" {
		args = append(args, "--appDNSRoot")
		args = append(args, p.AppDNSRoot)
	}
	if p.ChefServerPath != "" {
		args = append(args, "--chefServerPath")
		args = append(args, p.ChefServerPath)
	}
	if p.ThanosRecvAddr != "" {
		args = append(args, "--thanosRecvAddr")
		args = append(args, p.ThanosRecvAddr)
	}
	options := StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.Debug != "" {
		args = append(args, "-d")
		args = append(args, options.Debug)
	}
	return args
}
func (p *Shepherd) StartLocal(logfile string, opts ...StartOp) error {
	var err error
	args := p.GetArgs(opts...)
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	return err
}

func (p *Shepherd) String(opts ...StartOp) string {
	cmd_str := p.GetExeName()
	args := p.GetArgs(opts...)
	key := true
	for _, v := range args {
		if key {
			cmd_str += " " + v
			key = false
		} else {
			cmd_str += " '" + v + "'"
			key = true
		}
	}
	return cmd_str
}

func (p *Shepherd) StopLocal() {
	StopLocal(p.cmd)
}

func (p *Shepherd) GetExeName() string { return "shepherd" }

func (p *Shepherd) LookupArgs() string { return "--cloudletKey " + p.CloudletKey }

func (p *Shepherd) Wait() {
	p.cmd.Wait()
}
