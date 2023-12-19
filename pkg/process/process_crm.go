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

type Crm struct {
	Common              `yaml:",inline"`
	NodeCommon          `yaml:",inline"`
	RedisClientCommon   `yaml:",inline"`
	NotifyAddrs         string
	NotifySrvAddr       string
	CloudletKey         string
	Platform            string
	Plugin              string
	cmd                 *exec.Cmd
	PhysicalName        string
	TestMode            bool
	Span                string
	ContainerVersion    string
	VMImageVersion      string
	CloudletVMImagePath string
	Region              string
	CommercialCerts     bool
	AppDNSRoot          string
	AnsiblePublicAddr   string
	CacheDir            string
	HARole              HARole
}

type CrmProcess interface {
	Process
	CrmProc() *Crm
}

func (p *Crm) GetArgs(opts ...StartOp) []string {
	args := []string{"--notifyAddrs", p.NotifyAddrs}
	args = append(args, p.GetNodeMgrArgs()...)
	if p.NotifySrvAddr != "" {
		args = append(args, "--notifySrvAddr")
		args = append(args, p.NotifySrvAddr)
	}
	if p.CloudletKey != "" {
		args = append(args, "--cloudletKey")
		args = append(args, p.CloudletKey)
	}
	if p.Name != "" {
		args = append(args, "--hostname")
		args = append(args, p.Name)
	}
	if p.Platform != "" {
		args = append(args, "--platform")
		args = append(args, p.Platform)
	}
	if p.Plugin != "" {
		args = append(args, "--plugin")
		args = append(args, p.Plugin)
	}
	if p.PhysicalName != "" {
		args = append(args, "--physicalName")
		args = append(args, p.PhysicalName)
	}
	if p.Span != "" {
		args = append(args, "--span")
		args = append(args, p.Span)
	}
	if p.TestMode {
		args = append(args, "-testMode")
	}
	if p.ContainerVersion != "" {
		args = append(args, "--containerVersion")
		args = append(args, p.ContainerVersion)
	}
	if p.CloudletVMImagePath != "" {
		args = append(args, "--cloudletVMImagePath")
		args = append(args, p.CloudletVMImagePath)
	}
	if p.VMImageVersion != "" {
		args = append(args, "--vmImageVersion")
		args = append(args, p.VMImageVersion)
	}
	if p.Region != "" {
		args = append(args, "--region")
		args = append(args, p.Region)
	}
	if p.AppDNSRoot != "" {
		args = append(args, "--appDNSRoot")
		args = append(args, p.AppDNSRoot)
	}
	if p.AnsiblePublicAddr != "" {
		args = append(args, "--ansiblePublicAddr")
		args = append(args, p.AnsiblePublicAddr)
	}
	if p.CacheDir != "" {
		args = append(args, "--cacheDir")
		args = append(args, p.CacheDir)
	}
	args = append(args, "--HARole")
	args = append(args, string(p.HARole))

	options := StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.Debug != "" {
		args = append(args, "-d")
		args = append(args, options.Debug)
	}
	if p.CommercialCerts {
		args = append(args, "-commercialCerts")
	}
	return args
}

func (p *Crm) StartLocal(logfile string, opts ...StartOp) error {
	var err error

	args := p.GetArgs(opts...)
	args = append(args, p.GetRedisClientArgs()...)
	options := StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.ExeName == "" {
		options.ExeName = "crm"
	}
	p.cmd, err = StartLocal(p.Name, options.ExeName, args, p.GetEnv(), logfile)
	return err
}

func (p *Crm) StopLocal() {
	StopLocal(p.cmd)
}

func (p *Crm) Wait() error {
	if p.cmd != nil {
		return p.cmd.Wait()
	}
	return nil
}

func (p *Crm) GetExeName() string { return "crm" }

func (p *Crm) LookupArgs() string {
	retval := "--cloudletKey " + p.CloudletKey
	return retval
}

func (p *Crm) LookupArgsWithHARole(HARole HARole) string {
	retval := p.LookupArgs() + ".*--HARole " + string(HARole)
	return retval
}

func (p *Crm) String(opts ...StartOp) string {
	cmd_str := p.GetExeName()
	args := p.GetArgs(opts...)
	for _, v := range args {
		if strings.HasPrefix(v, "-") {
			cmd_str += " " + v
		} else {
			cmd_str += " '" + v + "'"
		}
	}
	return cmd_str
}

func (p *Crm) GetBindAddrs() []string {
	return []string{p.NotifySrvAddr}
}

func (p *Crm) CrmProc() *Crm {
	return p
}
