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
	"log"
	"net/http"
	"time"

	opensearch "github.com/opensearch-project/opensearch-go/v2"
)

type ElasticSearch struct {
	DockerGeneric `yaml:",inline"`
	Type          string
	Port          string
}

func (p *ElasticSearch) StartLocal(logfile string, opts ...StartOp) error {
	switch p.Type {
	case "kibana":
		return p.StartKibana(logfile, opts...)
	default:
		return p.StartElasticSearch(logfile, opts...)
	}
}

func (p *ElasticSearch) StartElasticSearch(logfile string, opts ...StartOp) error {
	// simple single node cluster
	if p.Port == "" {
		p.Port = "9200"
	}
	args := p.GetRunArgs()
	args = append(args,
		"-p", p.Port+":9200",
		"-p", "9300:9300",
		"-e", "discovery.type=single-node",
		"-e", "plugins.security.disabled=true",
		"opensearchproject/opensearch:2.9.0",
	)
	cmd, err := StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	if err == nil {
		// wait until up
		addr := "http://127.0.0.1:" + p.Port
		cfg := opensearch.Config{
			Addresses: []string{addr},
		}
		client, perr := opensearch.NewClient(cfg)
		if perr != nil {
			return perr
		}
		for ii := 0; ii < 30; ii++ {
			res, perr := client.Info()
			log.Printf("opensearch info %s try %d: res %v, perr %v\n", addr, ii, res, perr)
			if perr == nil {
				res.Body.Close()
			}
			if perr == nil && res.StatusCode == http.StatusOK {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if perr != nil {
			return perr
		}
	}
	return err
}

func (p *ElasticSearch) GetBindAddrs() []string {
	switch p.Type {
	case "kibana":
		return []string{":5601"}
	default:
		return []string{":" + p.Port, ":9300"}
	}
}

func (p *ElasticSearch) StartKibana(logfile string, opts ...StartOp) error {
	args := p.GetRunArgs()
	args = append(args,
		"-p", "5601:5601",
		"docker.elastic.co/kibana/kibana:7.6.2",
	)
	cmd, err := StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	return err
}
