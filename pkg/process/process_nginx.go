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
	"log"
	"os"
	"os/exec"
	"path"
)

type NginxProxy struct {
	DockerGeneric `yaml:",inline"`
	Servers       []NginxServerConfig
}
type NginxServerConfig struct {
	ServerName string
	Port       string
	TlsPort    string
	Target     string
}

func writeAllCAs(inputCAFile, outputCAFile string) error {
	// Combine all CAs into one for nginx or other TLS-terminating proxies.
	// Note that nginx requires the full CA chain, so must include
	// the root's public CA cert as well (not just intermediates).
	certs := "/tmp/vault_pki/*.pem"
	if inputCAFile != "" {
		certs += " " + inputCAFile
	}
	cmd := exec.Command("bash", "-c", "cat "+certs+" > "+outputCAFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s, %s", string(out), err)
	}
	return nil
}

func (p *NginxProxy) StartLocal(logfile string, opts ...StartOp) error {
	configDir := path.Dir(logfile) + "/" + p.Name
	if err := os.MkdirAll(configDir, 0777); err != nil {
		return err
	}

	// make a copy of process to remap certs files
	pArgs := *p

	// Terminate TLS using mex-ca.crt and vault CAs.
	if p.TLS.ServerCert != "" {
		if p.TLS.ServerKey == "" {
			err := fmt.Errorf("NginxProxy with ServerCert requires ServerKey")
			log.Printf("%v\n", err)
			return err
		}
		err := writeAllCAs("", configDir+"/allcas.pem")
		if err != nil {
			return err
		}
		pArgs.TLS.ServerCert = path.Base(p.TLS.ServerCert)
		pArgs.TLS.ServerKey = path.Base(p.TLS.ServerKey)
	}

	tmpl := template.Must(template.New("nginxProxy").Parse(nginxProxyConfig))
	f, err := os.Create(configDir + "/nginx.conf")
	if err != nil {
		return err
	}
	defer f.Close()

	wr := bufio.NewWriter(f)
	err = tmpl.Execute(wr, &pArgs)
	if err != nil {
		return err
	}
	wr.Flush()

	args := p.GetRunArgs()
	for _, server := range p.Servers {
		if server.Port != "" {
			args = append(args, "-p", server.Port+":"+server.Port)
		}
		if server.TlsPort != "" {
			args = append(args, "-p", server.TlsPort+":"+server.TlsPort)
		}
	}
	if p.TLS.ServerCert != "" {
		certsDir := path.Dir(p.TLS.ServerCert)
		args = append(args, "-v", fmt.Sprintf("%s:/certs", certsDir))
	}
	args = append(args,
		"-v", fmt.Sprintf("%s:/etc/nginx", configDir),
		"nginx:latest",
	)
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	return err
}

func (p *NginxProxy) GetBindAddrs() []string {
	addrs := []string{}
	for _, server := range p.Servers {
		if server.Port != "" {
			addrs = append(addrs, fmt.Sprintf(":%d", server.Port))
		}
		if server.TlsPort != "" {
			addrs = append(addrs, fmt.Sprintf(":%d", server.TlsPort))
		}
	}
	return addrs
}

var nginxProxyConfig = `
events {
  worker_connections 128;
}
http {
  tcp_nopush on;
  tcp_nodelay on;
  default_type application/octet-stream;

  access_log /etc/nginx/access.log;
  error_log /etc/nginx/error.log;

{{- range .Servers}}
  server {
{{- if .TlsPort}}
    listen {{.TlsPort}} ssl;
{{- end}}
{{- if .Port}}
    listen {{.Port}};
{{- end}}
{{- if $.TLS.ServerCert}}

    ssl_certificate /certs/{{$.TLS.ServerCert}};
    ssl_certificate_key /certs/{{$.TLS.ServerKey}};
    ssl_client_certificate /etc/nginx/allcas.pem;
    ssl_verify_client on;
    ssl_verify_depth 2;
    ssl_session_cache shared:le_nginx_SSL:1m;
    ssl_session_cache shared:le_nginx_SSL:1m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS";
{{- end}}

    server_name {{$.Name}} localhost;

    proxy_buffering off;

    location / {
      proxy_pass         {{.Target}};
      proxy_set_header   Host $host;
      proxy_set_header   X-Real-IP $remote_addr;
      proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    }
  }
{{- end}}
}
`
