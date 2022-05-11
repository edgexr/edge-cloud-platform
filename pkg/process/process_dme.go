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
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"time"

	mextls "github.com/edgexr/edge-cloud-platform/pkg/tls"
	"google.golang.org/grpc"
	yaml "gopkg.in/yaml.v2"
)

type Dme struct {
	Common      `yaml:",inline"`
	NodeCommon  `yaml:",inline"`
	ApiAddr     string
	HttpAddr    string
	NotifyAddrs string
	LocVerUrl   string
	TokSrvUrl   string
	QosPosUrl   string
	QosSesAddr  string
	Carrier     string
	CloudletKey string
	CookieExpr  string
	Region      string
	cmd         *exec.Cmd
}

func (p *Dme) StartLocal(logfile string, opts ...StartOp) error {
	args := []string{"--notifyAddrs", p.NotifyAddrs}
	args = append(args, p.GetNodeMgrArgs()...)
	if p.ApiAddr != "" {
		args = append(args, "--apiAddr")
		args = append(args, p.ApiAddr)
	}
	if p.HttpAddr != "" {
		args = append(args, "--httpAddr")
		args = append(args, p.HttpAddr)
	}
	if p.LocVerUrl != "" {
		args = append(args, "--locverurl")
		args = append(args, p.LocVerUrl)
	}
	if p.TokSrvUrl != "" {
		args = append(args, "--toksrvurl")
		args = append(args, p.TokSrvUrl)
	}
	if p.QosPosUrl != "" {
		args = append(args, "--qosposurl")
		args = append(args, p.QosPosUrl)
	}
	if p.QosSesAddr != "" {
		args = append(args, "--qossesaddr")
		args = append(args, p.QosSesAddr)
	}
	if p.Carrier != "" {
		args = append(args, "--carrier")
		args = append(args, p.Carrier)
	}
	if p.CloudletKey != "" {
		args = append(args, "--cloudletKey")
		args = append(args, p.CloudletKey)
	}
	if p.CookieExpr != "" {
		args = append(args, "--cookieExpiration")
		args = append(args, p.CookieExpr)
	}
	if p.Region != "" {
		args = append(args, "--region", p.Region)
	}

	options := StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.Debug != "" {
		args = append(args, "-d")
		args = append(args, options.Debug)
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
			fmt.Sprintf("VAULT_ROLE_ID=%s", rr.DmeRoleID),
			fmt.Sprintf("VAULT_SECRET_ID=%s", rr.DmeSecretID),
		)
	}

	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, envs, logfile)
	return err
}

func (p *Dme) StopLocal() {
	StopLocal(p.cmd)
}

func (p *Dme) GetExeName() string { return "dme" }

func (p *Dme) LookupArgs() string { return "--apiAddr " + p.ApiAddr }

func (p *Dme) ConnectAPI(timeout time.Duration) (*grpc.ClientConn, error) {
	return connectAPIImpl(timeout, p.ApiAddr, p.getTlsConfig(p.ApiAddr))
}

func (p *Dme) GetRestClient(timeout time.Duration) (*http.Client, error) {
	return getRestClientImpl(timeout, p.HttpAddr, p.getTlsConfig(p.HttpAddr))
}

func (p *Dme) getTlsConfig(addr string) *tls.Config {
	if p.UseVaultPki && p.VaultAddr != "" {
		return &tls.Config{
			InsecureSkipVerify: true,
		}
	} else if p.TLS.ServerCert != "" && p.TLS.ServerKey != "" {
		// ServerAuth TLS. For real clients, they'll use
		// their built-in trusted CAs to verify the cert.
		// Since we're using self-signed certs here, add
		// our CA to the cert pool.
		certPool, err := mextls.GetClientCertPool(p.TLS.ServerCert, "")
		if err != nil {
			log.Printf("GetClientCertPool failed, %v\n", err)
			return nil
		}
		config := &tls.Config{
			RootCAs: certPool,
		}
		return config
	} else {
		return nil
	}
}

func (p *Dme) GetBindAddrs() []string {
	return []string{p.ApiAddr, p.HttpAddr}
}

func getRestClientImpl(timeout time.Duration, addr string, tlsConfig *tls.Config) (*http.Client, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: timeout,
	}
	return client, nil
}
