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
)

type Jaeger struct {
	DockerGeneric `yaml:",inline"`
}

func (p *Jaeger) StartLocal(logfile string, opts ...StartOp) error {
	// Jaeger does not support TLS, so we use traefik
	// as a sidecar reverse proxy to implement mTLS.
	// No Jaeger ports are exposed because traefik proxies requests
	// to Jaeger on the internal docker network.
	// However, in order for traefik to understand how to do so,
	// it checks the labels set on the Jaeger docker process.
	labels := []string{
		"traefik.http.routers.jaeger-ui.entrypoints=jaeger-ui",
		"traefik.http.routers.jaeger-ui.rule=PathPrefix(`/`)",
		"traefik.http.routers.jaeger-ui.service=jaeger-ui",
		"traefik.http.routers.jaeger-ui.tls=true",
		"traefik.http.routers.jaeger-c.entrypoints=jaeger-collector",
		"traefik.http.routers.jaeger-c.rule=PathPrefix(`/`)",
		"traefik.http.routers.jaeger-c.service=jaeger-c",
		"traefik.http.routers.jaeger-c.tls=true",
		"traefik.http.routers.jaeger-ui-notls.entrypoints=jaeger-ui-insecure",
		"traefik.http.routers.jaeger-ui-notls.rule=PathPrefix(`/`)",
		"traefik.http.routers.jaeger-ui-notls.service=jaeger-ui-notls",
		"traefik.http.services.jaeger-ui.loadbalancer.server.port=16686",
		"traefik.http.services.jaeger-c.loadbalancer.server.port=14268",
		"traefik.http.services.jaeger-ui-notls.loadbalancer.server.port=16686",
	}
	args := p.GetRunArgs()
	for _, l := range labels {
		args = append(args, "-l", l)
	}
	// jaeger version should match "jaeger_version" in
	// ansible/roles/jaeger/defaults/main.yaml
	args = append(args, "jaegertracing/all-in-one:1.45.0",
		"--collector.num-workers=500",
		"--collector.queue-size=10000",
	)
	cmd, err := StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	return err
}

func (p *Jaeger) StartLocalNoTraefik(logfile string, opts ...StartOp) error {
	args := p.GetRunArgs()
	// jaeger version should match "jaeger_version" in
	// ansible/roles/jaeger/defaults/main.yaml
	args = append(args,
		"-p", "16686:16686",
		"-p", "14268:14268",
		"jaegertracing/all-in-one:1.45.0")
	cmd, err := StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	if err == nil {
		// wait until up
		url := "http://127.0.0.1:16686/"
		var resp *http.Response
		for ii := 0; ii < 30; ii++ {
			client := http.Client{
				Timeout: time.Second,
			}
			resp, err = client.Get(url)
			if err != nil {
				time.Sleep(time.Second)
				log.Printf("jeager %s try %d: err %v\n", url, ii, err)
				continue
			}
			log.Printf("jeager %s try %d: response %d\n", url, ii, resp.StatusCode)
			if resp.StatusCode != http.StatusOK {
				time.Sleep(time.Second)
				continue
			}
			break
		}
	}
	return err
}

func (p *Jaeger) GetBindAddrs() []string {
	return []string{":16686", ":14268"}
}
