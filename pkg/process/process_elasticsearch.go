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

	"github.com/elastic/go-elasticsearch/v7"
)

type ElasticSearch struct {
	DockerGeneric `yaml:",inline"`
	Type          string
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
	args := p.GetRunArgs()
	args = append(args,
		"-p", "9200:9200",
		"-p", "9300:9300",
		"-e", "discovery.type=single-node",
		"-e", "xpack.security.enabled=false",
		"docker.elastic.co/elasticsearch/elasticsearch:7.6.2",
	)
	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	if err == nil {
		// wait until up
		addr := "http://127.0.0.1:9200"
		cfg := elasticsearch.Config{
			Addresses: []string{addr},
		}
		client, perr := elasticsearch.NewClient(cfg)
		if perr != nil {
			return perr
		}
		for ii := 0; ii < 30; ii++ {
			res, perr := client.Info()
			log.Printf("elasticsearch info %s try %d: res %v, perr %v\n", addr, ii, res, perr)
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
		return []string{":9200", ":9300"}
	}
}

func (p *ElasticSearch) StartKibana(logfile string, opts ...StartOp) error {
	args := p.GetRunArgs()
	args = append(args,
		"-p", "5601:5601",
		"docker.elastic.co/kibana/kibana:7.6.2",
	)
	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	return err
}
