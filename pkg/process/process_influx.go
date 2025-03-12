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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/influxsup"
	influxclient "github.com/influxdata/influxdb/client/v2"
)

type Influx struct {
	Common   `yaml:",inline"`
	DataDir  string
	HttpAddr string
	BindAddr string
	Config   string // set during Start
	TLS      TLSCerts
	Auth     LocalAuth
	cmd      *exec.Cmd
}

type LocalAuth struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

var InfluxCredsFile = "/tmp/influx.json"
var InfluxClientTimeout = 5 * time.Second

func (p *Influx) StartLocal(logfile string, opts ...StartOp) (reterr error) {
	var prefix string
	options := StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.CleanStartup {
		if err := p.ResetData(); err != nil {
			return err
		}
	}

	// check if another influx already running
	if p.HttpAddr == "" {
		p.HttpAddr = DefaultHttpAddr
	}
	if p.BindAddr == "" {
		p.BindAddr = DefaultBindAddr
	}
	conn, err := net.DialTimeout("tcp", p.HttpAddr, 100*time.Millisecond)
	if err == nil && conn != nil {
		conn.Close()
		return fmt.Errorf("InfluxDB http addr %s already in use", p.HttpAddr)
	}
	conn, err = net.DialTimeout("tcp", p.BindAddr, 100*time.Millisecond)
	if err == nil && conn != nil {
		conn.Close()
		return fmt.Errorf("InfluxDB bind addr %s already in use", p.BindAddr)
	}

	influxops := []InfluxOp{
		WithAuth(p.Auth.User != ""),
	}
	if p.TLS.ServerCert != "" {
		influxops = append(influxops, WithServerCert(p.TLS.ServerCert))
	}
	if p.TLS.ServerKey != "" {
		influxops = append(influxops, WithServerCertKey(p.TLS.ServerKey))
	}
	if p.BindAddr != "" {
		influxops = append(influxops, WithBindAddr(p.BindAddr))
	}
	if p.HttpAddr != "" {
		influxops = append(influxops, WithHttpAddr(p.HttpAddr))
	}

	configFile, err := SetupInflux(p.DataDir, influxops...)
	if err != nil {
		return err
	}
	p.Config = configFile
	args := []string{"-config", configFile}
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	if err != nil {
		return err
	}
	defer func() {
		if reterr != nil {
			p.StopLocal()
		}
	}()

	// if auth is enabled we need to create default user
	if p.Auth.User != "" {
		time.Sleep(5 * time.Second)
		if p.TLS.ServerCert != "" {
			prefix = "https://" + p.HttpAddr
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		} else {
			prefix = "http://" + p.HttpAddr
		}

		resource := "/query"
		data := url.Values{}
		data.Set("q", "CREATE USER "+p.Auth.User+" WITH PASSWORD '"+p.Auth.Pass+"' WITH ALL PRIVILEGES")
		u, _ := url.ParseRequestURI(prefix)
		u.Path = resource
		u.RawQuery = data.Encode()
		urlStr := fmt.Sprintf("%v", u)
		client := &http.Client{}
		r, _ := http.NewRequest("POST", urlStr, nil)

		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
		fmt.Printf("Query: %s\n", urlStr)
		_, err := client.Do(r)
		if err != nil {
			return err
		}
	}
	// create auth file for Vault
	creds_json, err := json.Marshal(p.Auth)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(InfluxCredsFile, creds_json, 0644)
	if err != nil {
		return err
	}
	// make sure influx is online
	if prefix == "" {
		prefix = "http://" + p.HttpAddr
	}
	client, err := influxsup.GetClient(prefix, p.Auth.User, p.Auth.Pass, InfluxClientTimeout)
	if err != nil {
		return err
	}
	online := false
	for ii := 0; ii < 50; ii++ {
		if _, _, err := client.Ping(0); err == nil {
			online = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !online {
		return fmt.Errorf("InfluxDB service not online")
	}
	return nil
}

func (p *Influx) StopLocal() {
	StopLocal(p.cmd)
	// make sure influx isn't running anymore
	log.Printf("Check that InfluxDB at %s is not running\n", p.HttpAddr)
	done := false
	for ii := 0; ii < 50; ii++ {
		conn, err := net.DialTimeout("tcp", p.HttpAddr, 100*time.Millisecond)
		if err == nil && conn != nil {
			conn.Close()
			time.Sleep(100 * time.Millisecond)
			continue
		}
		done = true
		break
	}
	log.Printf("InfluxDB at %s is done: %t\n", p.HttpAddr, done)
}

func (p *Influx) GetExeName() string { return "influxd" }

func (p *Influx) LookupArgs() string { return "-config " + p.Config }

func (p *Influx) ResetData() error {
	return os.RemoveAll(p.DataDir)
}

func (p *Influx) GetClient() (influxclient.Client, error) {
	httpaddr := ""
	if p.TLS.ServerCert != "" {
		httpaddr = "https://" + p.HttpAddr
	} else {
		httpaddr = "http://" + p.HttpAddr
	}
	return influxsup.GetClient(httpaddr, p.Auth.User, p.Auth.Pass, InfluxClientTimeout)
}

func (p *Influx) GetBindAddrs() []string {
	if p.HttpAddr == "" {
		p.HttpAddr = DefaultHttpAddr
	}
	if p.BindAddr == "" {
		p.BindAddr = DefaultBindAddr
	}
	return []string{p.HttpAddr, p.BindAddr}
}
