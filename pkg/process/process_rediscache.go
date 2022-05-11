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
	"bufio"
	"fmt"
	"html/template"
	"net"
	"os"
	"os/exec"
	"path"
	"time"
)

type RedisCache struct {
	Common     `yaml:",inline"`
	cmd        *exec.Cmd
	Type       string
	Port       string
	MasterPort string
}

var redisServerConfig = `
port {{.Port}}
{{- if .MasterPort}}
slaveof {{.Hostname}} {{.MasterPort}}
{{- end}}
`

var redisSentinelConfig = `
port {{.Port}}
sentinel monitor redismaster {{.Hostname}} {{.MasterPort}} 2
sentinel down-after-milliseconds redismaster 8000
sentinel failover-timeout redismaster 8000
sentinel parallel-syncs redismaster 1
`

func (p *RedisCache) StartLocal(logfile string, opts ...StartOp) error {
	options := StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.CleanStartup {
		if err := p.ResetData(logfile); err != nil {
			return err
		}
	}

	cfgFile := fmt.Sprintf("%s/%s.conf", path.Dir(logfile), p.Name)

	args := []string{}

	p.setBindPort()

	switch p.Type {
	case "master":
		fallthrough
	case "slave":
		configFileReqd := true
		if p.Port == LocalRedisPort && options.NoConfig {
			configFileReqd = false
		}
		if configFileReqd {
			tmpl := template.Must(template.New(p.Name).Parse(redisServerConfig))
			f, err := os.Create(cfgFile)
			if err != nil {
				return err
			}
			defer f.Close()

			wr := bufio.NewWriter(f)
			err = tmpl.Execute(wr, p)
			if err != nil {
				return err
			}
			wr.Flush()
			args = append(args, cfgFile)
		}
	case "sentinel":
		if p.MasterPort == "" {
			p.MasterPort = LocalRedisPort
		}
		tmpl := template.Must(template.New(p.Name).Parse(redisSentinelConfig))
		f, err := os.Create(cfgFile)
		if err != nil {
			return err
		}
		defer f.Close()

		wr := bufio.NewWriter(f)
		err = tmpl.Execute(wr, p)
		if err != nil {
			return err
		}
		wr.Flush()
		args = append(args, cfgFile)
		args = append(args, "--sentinel")
	default:
		return fmt.Errorf("Invalid type %s specified, "+
			"valid types are master, slave, sentinel", p.Type)
	}

	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	if err != nil {
		return err
	}
	// wait for redis to become ready
	maxRedisWait := 20 * time.Second
	start := time.Now()
	for {
		conn, err := net.Dial("tcp", p.Hostname+":"+p.Port)
		if err == nil {
			conn.Close()
			break
		}
		elapsed := time.Since(start)
		if elapsed > maxRedisWait {
			return fmt.Errorf("Timed out try to connect to redis")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func (p *RedisCache) setBindPort() {
	switch p.Type {
	case "master":
		fallthrough
	case "slave":
		if p.Port == "" {
			p.Port = LocalRedisPort
		}
	case "sentinel":
		if p.Port == "" {
			p.Port = LocalRedisSentinelPort
		}
	}
}

func (p *RedisCache) StopLocal() {
	StopLocal(p.cmd)
}

func (p *RedisCache) GetExeName() string { return "redis-server" }

func (p *RedisCache) LookupArgs() string {
	return ":" + p.Port
}

func (p *RedisCache) ResetData(logfile string) error {
	cfgFile := fmt.Sprintf("%s/%s.conf", path.Dir(logfile), p.Name)
	os.Remove(cfgFile)
	return nil
}

func (p *RedisCache) GetBindAddrs() []string {
	p.setBindPort()
	return []string{fmt.Sprintf(":%s", p.Port)}
}
