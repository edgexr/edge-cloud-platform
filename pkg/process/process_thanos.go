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

import "fmt"

type ThanosQuery struct {
	DockerGeneric `yaml:",inline"`
	Region        string
	HttpPort      int
	Stores        []string
}

type ThanosReceive struct {
	DockerGeneric   `yaml:",inline"`
	Region          string
	GrpcPort        int
	HttpPort        int
	RemoteWritePort int
}

func (p *ThanosQuery) StartLocal(logfile string, opts ...StartOp) error {
	args := p.GetRunArgs()
	args = append(args,
		"-p", fmt.Sprintf("%d:%d", p.HttpPort, p.HttpPort),
		"quay.io/thanos/thanos:v0.21.0",
		"query",
		"--http-address",
		fmt.Sprintf(":%d", p.HttpPort),
	)
	for ii := range p.Stores {
		args = append(args, "--store", p.Stores[ii])
	}

	cmd, err := StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	return err
}

func (p *ThanosQuery) GetBindAddrs() []string {
	return []string{fmt.Sprintf(":%d", p.HttpPort)}
}

func (p *ThanosReceive) StartLocal(logfile string, opts ...StartOp) error {
	args := p.GetRunArgs()
	args = append(args,
		"-p", fmt.Sprintf("%d:%d", p.GrpcPort, p.GrpcPort),
		"-p", fmt.Sprintf("%d:%d", p.RemoteWritePort, p.RemoteWritePort),
		"quay.io/thanos/thanos:v0.21.0",
		"receive",
		"--label",
		fmt.Sprintf("region=\"%s\"", p.Region),
		"--grpc-address",
		fmt.Sprintf(":%d", p.GrpcPort),
		"--remote-write.address",
		fmt.Sprintf(":%d", p.RemoteWritePort),
	)

	cmd, err := StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	return err
}

func (p *ThanosReceive) GetBindAddrs() []string {
	return []string{
		fmt.Sprintf(":%d", p.GrpcPort),
		fmt.Sprintf(":%d", p.RemoteWritePort),
	}
}
