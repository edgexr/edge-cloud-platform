package process

import (
	"fmt"
	"io/ioutil"
	"os/exec"

	yaml "gopkg.in/yaml.v2"
)

type CCRM struct {
	Common                        `yaml:",inline"`
	NodeCommon                    `yaml:",inline"`
	RedisClientCommon             `yaml:",inline"`
	Region                        string
	AppDNSRoot                    string
	CloudletRegistryPath          string
	CloudletVMImagePath           string
	VersionTag                    string
	ControllerApiAddr             string
	ControllerNotifyAddr          string
	ControllerPublicAccessApiAddr string
	ControllerPublicNotifyAddr    string
	ChefServerPath                string
	ThanosRecvAddr                string
	AnsibleListenAddr             string
	AnsiblePublicAddr             string
	DNSProvider                   string
	TestMode                      bool
	cmd                           *exec.Cmd
}

func (p *CCRM) StartLocal(logfile string, opts ...StartOp) error {
	args := []string{}
	args = append(args, p.GetNodeMgrArgs()...)
	args = append(args, p.GetRedisClientArgs()...)

	if p.Region != "" {
		args = append(args, "--region", p.Region)
	}
	if p.AppDNSRoot != "" {
		args = append(args, "--appDNSRoot", p.AppDNSRoot)
	}
	if p.CloudletRegistryPath != "" {
		args = append(args, "--cloudletRegistryPath", p.CloudletRegistryPath)
	}
	if p.CloudletVMImagePath != "" {
		args = append(args, "--cloudletVMImagePath", p.CloudletVMImagePath)
	}
	if p.VersionTag != "" {
		args = append(args, "--versionTag", p.VersionTag)
	}
	if p.ControllerApiAddr != "" {
		args = append(args, "--controllerApiAddr", p.ControllerApiAddr)
	}
	if p.ControllerPublicAccessApiAddr != "" {
		args = append(args, "--controllerPublicAccessApiAddr", p.ControllerPublicAccessApiAddr)
	}
	if p.ControllerNotifyAddr != "" {
		args = append(args, "--controllerPublicNotifyAddr", p.ControllerNotifyAddr)
	}
	if p.ControllerPublicNotifyAddr != "" {
		args = append(args, "--controllerNotifyAddr", p.ControllerNotifyAddr)
	}
	if p.AnsibleListenAddr != "" {
		args = append(args, "--ansibleListenAddr")
		args = append(args, p.AnsibleListenAddr)
	}
	if p.AnsiblePublicAddr != "" {
		args = append(args, "--ansiblePublicAddr")
		args = append(args, p.AnsiblePublicAddr)
	}
	if p.ThanosRecvAddr != "" {
		args = append(args, "--thanosRecvAddr")
		args = append(args, p.ThanosRecvAddr)
	}
	if p.TestMode {
		args = append(args, "-testMode")
	}
	if p.DNSProvider != "" {
		args = append(args, "--dnsProvider", p.DNSProvider)
	}
	options := StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.Debug != "" {
		args = append(args, "-d")
		args = append(args, options.Debug)
	}
	if options.ExeName == "" {
		options.ExeName = p.GetExeName()
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
			fmt.Sprintf("VAULT_ROLE_ID=%s", rr.CtrlRoleID),
			fmt.Sprintf("VAULT_SECRET_ID=%s", rr.CtrlSecretID),
		)
	}

	var err error
	p.cmd, err = StartLocal(p.Name, options.ExeName, args, envs, logfile)
	return err
}

func (p *CCRM) StopLocal() {
	StopLocal(p.cmd)
}

func (p *CCRM) GetExeName() string { return "ccrm" }

func (p *CCRM) LookupArgs() string { return "" }

func (p *CCRM) GetBindAddrs() []string {
	return []string{}
}
