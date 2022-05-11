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
	"os"
	"os/exec"
	"path"
)

type Traefik struct {
	Common        `yaml:",inline"`
	DockerNetwork string
	TLS           TLSCerts
	cmd           *exec.Cmd
}

func (p *Traefik) StartLocal(logfile string, opts ...StartOp) error {
	configDir := path.Dir(logfile) + "/traefik"
	if err := os.MkdirAll(configDir, 0777); err != nil {
		return err
	}
	certsDir := ""
	if p.TLS.ServerCert != "" && p.TLS.ServerKey != "" && p.TLS.CACert != "" {
		certsDir = path.Dir(p.TLS.ServerCert)
	}

	args := []string{
		"run", "--rm", "--name", p.Name,
		"-p", "8080:8080", // web UI
		"-p", "14268:14268", // jaeger collector
		"-p", "16686:16686", // jeager UI
		"-p", "16687:16687", // jeager UI insecure (for local debugging)
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"-v", fmt.Sprintf("%s:/etc/traefik", configDir),
	}
	if certsDir != "" {
		args = append(args, "-v", fmt.Sprintf("%s:/certs", certsDir))
	}
	if p.DockerNetwork != "" {
		args = append(args, "--network", p.DockerNetwork)
	}
	args = append(args, "traefik:v2.0")

	staticArgs := TraefikStaticArgs{}

	// Traefik consists of a Static Config file, and zero or more
	// dynamic config files. Dynamic config files can be hot-reloaded.
	// The allowed contents of each type are different.
	// Entry points are configured statically, while routers, services,
	// etc are configured dynmically, either through a file provider
	// or docker provider (snooping on docker events).

	err := writeAllCAs(p.TLS.CACert, configDir+"/traefikCAs.pem")
	if err != nil {
		return err
	}
	if p.TLS.ServerCert != "" && p.TLS.ServerKey != "" && p.TLS.CACert != "" {
		certsDir = path.Dir(p.TLS.ServerCert)
		args = append(args, "-v", fmt.Sprintf("%s:/certs", certsDir))
		dynArgs := TraefikDynArgs{
			ServerCert: path.Base(p.TLS.ServerCert),
			ServerKey:  path.Base(p.TLS.ServerKey),
			CACert:     path.Base(p.TLS.CACert),
		}
		dynFile := "dyn.yml"
		tmpl := template.Must(template.New("dyn").Parse(TraefikDynFile))
		f, err := os.Create(configDir + "/" + dynFile)
		if err != nil {
			return err
		}
		defer f.Close()

		out := bufio.NewWriter(f)
		err = tmpl.Execute(out, dynArgs)
		if err != nil {
			return err
		}
		out.Flush()
		staticArgs.DynFile = dynFile
	}

	tmpl := template.Must(template.New("st").Parse(TraefikStaticFile))
	f, err := os.Create(configDir + "/traefik.yml")
	if err != nil {
		return err
	}
	defer f.Close()

	out := bufio.NewWriter(f)
	err = tmpl.Execute(out, staticArgs)
	if err != nil {
		return err
	}
	out.Flush()

	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	return err
}

func (p *Traefik) StopLocal() {
	StopLocal(p.cmd)
	// if container is from previous aborted run
	cmd := exec.Command("docker", "kill", p.Name)
	cmd.Run()
}

func (p *Traefik) GetExeName() string { return "docker" }

func (p *Traefik) LookupArgs() string { return p.Name }

func (p *Traefik) GetBindAddrs() []string {
	return []string{":8080", ":14268", ":16686", ":16687"}
}

type TraefikStaticArgs struct {
	DynFile string
}

var TraefikStaticFile = `
providers:
  docker: {}
{{- if ne .DynFile ""}}
  file:
    watch: true
    filename: /etc/traefik/{{.DynFile}}
{{- end}}
log:
  level: debug
api:
  dashboard: true
  debug: true
entryPoints:
  jaeger-collector:
    address: :14268
  jaeger-ui:
    address: :16686
  jaeger-ui-insecure:
    address: :16687
`

type TraefikDynArgs struct {
	ServerCert string
	ServerKey  string
	CACert     string
}

var TraefikDynFile = `
tls:
  certificates:
  - certFile: /certs/{{.ServerCert}}
    keyFile: /certs/{{.ServerKey}}
  options:
    default:
      clientAuth:
        caFiles:
        - traefikCAs.pem
        clientAuthType: RequireAndVerifyClientCert
  stores:
    default:
      defaultCertificate:
        certFile: /certs/{{.ServerCert}}
        keyFile: /certs/{{.ServerKey}}
`
