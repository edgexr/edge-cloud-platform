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
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"time"

	mextls "github.com/edgexr/edge-cloud-platform/pkg/tls"
	"google.golang.org/grpc"
	yaml "gopkg.in/yaml.v2"
)

type Controller struct {
	Common               `yaml:",inline"`
	NodeCommon           `yaml:",inline"`
	RedisClientCommon    `yaml:",inline"`
	EtcdAddrs            string
	ApiAddr              string
	HttpAddr             string
	NotifyAddr           string
	NotifyRootAddrs      string
	NotifyParentAddrs    string
	EdgeTurnAddr         string
	InfluxAddr           string
	Region               string
	cmd                  *exec.Cmd
	TestMode             bool
	RegistryFQDN         string
	ArtifactoryFQDN      string
	CloudletRegistryPath string
	VersionTag           string
	CloudletVMImagePath  string
	CheckpointInterval   string
	AppDNSRoot           string
	ChefServerPath       string
	ThanosRecvAddr       string
}

func (p *Controller) StartLocal(logfile string, opts ...StartOp) error {
	args := []string{"--etcdUrls", p.EtcdAddrs, "--notifyAddr", p.NotifyAddr}
	args = append(args, p.GetNodeMgrArgs()...)
	args = append(args, p.GetRedisClientArgs()...)
	if p.ApiAddr != "" {
		args = append(args, "--apiAddr")
		args = append(args, p.ApiAddr)
	}
	if p.HttpAddr != "" {
		args = append(args, "--httpAddr")
		args = append(args, p.HttpAddr)
	}
	if p.InfluxAddr != "" {
		args = append(args, "--influxAddr")
		args = append(args, p.InfluxAddr)
	}
	if p.RegistryFQDN != "" {
		args = append(args, "--registryFQDN")
		args = append(args, p.RegistryFQDN)
	}
	if p.ArtifactoryFQDN != "" {
		args = append(args, "--artifactoryFQDN")
		args = append(args, p.ArtifactoryFQDN)
	}
	if p.CloudletRegistryPath != "" {
		args = append(args, "--cloudletRegistryPath")
		args = append(args, p.CloudletRegistryPath)
	}
	if p.CloudletVMImagePath != "" {
		args = append(args, "--cloudletVMImagePath")
		args = append(args, p.CloudletVMImagePath)
	}
	if p.NotifyRootAddrs != "" {
		args = append(args, "--notifyRootAddrs")
		args = append(args, p.NotifyRootAddrs)
	}
	if p.NotifyParentAddrs != "" {
		args = append(args, "--notifyParentAddrs")
		args = append(args, p.NotifyParentAddrs)
	}
	if p.Region != "" {
		args = append(args, "--region", p.Region)
	}
	if p.EdgeTurnAddr != "" {
		args = append(args, "--edgeTurnAddr")
		args = append(args, p.EdgeTurnAddr)
	}
	if p.AppDNSRoot != "" {
		args = append(args, "--appDNSRoot")
		args = append(args, p.AppDNSRoot)
	}
	options := StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.Debug != "" {
		args = append(args, "-d")
		args = append(args, options.Debug)
	}
	if p.TestMode {
		args = append(args, "-testMode")
	}
	if p.VersionTag != "" {
		args = append(args, "--versionTag")
		args = append(args, p.VersionTag)
	}
	if p.CheckpointInterval != "" {
		args = append(args, "--checkpointInterval")
		args = append(args, p.CheckpointInterval)
	}
	if p.ChefServerPath != "" {
		args = append(args, "--chefServerPath")
		args = append(args, p.ChefServerPath)
	}
	if p.ThanosRecvAddr != "" {
		args = append(args, "--thanosRecvAddr")
		args = append(args, p.ThanosRecvAddr)
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
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, envs, logfile)
	return err
}

func (p *Controller) StopLocal() {
	StopLocal(p.cmd)
}

func (p *Controller) GetExeName() string { return "controller" }

func (p *Controller) LookupArgs() string { return "--apiAddr " + p.ApiAddr }

func connectAPIImpl(timeout time.Duration, apiaddr string, tlsConfig *tls.Config) (*grpc.ClientConn, error) {
	// Wait for service to be ready to connect.
	// Note: using grpc WithBlock() takes about a second longer
	// than doing the retry connect below so requires a larger timeout.
	startTimeMs := time.Now().UnixNano() / int64(time.Millisecond)
	maxTimeMs := int64(timeout/time.Millisecond) + startTimeMs
	wait := 20 * time.Millisecond
	for {
		_, err := net.Dial("tcp", apiaddr)
		currTimeMs := time.Now().UnixNano() / int64(time.Millisecond)

		if currTimeMs > maxTimeMs {
			err := errors.New("Timeout in connection to " + apiaddr)
			log.Printf("Error: %v\n", err)
			return nil, err
		}
		if err == nil {
			break
		}
		timeout -= wait
		time.Sleep(wait)
	}
	conn, err := grpc.Dial(apiaddr, mextls.GetGrpcDialOption(tlsConfig))
	return conn, err
}

func (p *Controller) GetTlsFile() string {
	if p.UseVaultPki && p.VaultAddr != "" {
		region := p.Region
		if region == "" {
			region = "local"
		}
		return "/tmp/edgectl." + region + "/mex.crt"
	}
	return p.TLS.ClientCert
}

func (p *Controller) ConnectAPI(timeout time.Duration) (*grpc.ClientConn, error) {
	tlsMode := mextls.MutualAuthTLS
	skipVerify := false
	if p.TestMode {
		skipVerify = true
	}
	tlsConfig, err := mextls.GetTLSClientConfig(tlsMode, p.ApiAddr, nil, p.GetTlsFile(), "", skipVerify)
	if err != nil {
		return nil, err
	}
	return connectAPIImpl(timeout, p.ApiAddr, tlsConfig)
}
