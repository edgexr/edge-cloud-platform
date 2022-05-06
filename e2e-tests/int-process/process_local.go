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

package intprocess

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud/integration/process"
	yaml "gopkg.in/yaml.v2"
)

// Master Controller

func (p *MC) StartLocal(logfile string, opts ...process.StartOp) error {
	args := p.GetNodeMgrArgs()
	if p.Addr != "" {
		args = append(args, "--addr")
		args = append(args, p.Addr)
	}
	if p.FederationAddr != "" {
		args = append(args, "--federationAddr")
		args = append(args, p.FederationAddr)
	}
	if p.SqlAddr != "" {
		args = append(args, "--sqlAddr")
		args = append(args, p.SqlAddr)
	}
	if p.NotifyAddrs != "" {
		args = append(args, "--notifyAddrs")
		args = append(args, p.NotifyAddrs)
	}
	if p.TLS.ClientCert != "" {
		args = append(args, "--clientCert")
		args = append(args, p.TLS.ClientCert)
	}
	if p.ApiTlsCert != "" {
		args = append(args, "--apiTlsCert", p.ApiTlsCert)
	}
	if p.ApiTlsKey != "" {
		args = append(args, "--apiTlsKey", p.ApiTlsKey)
	}
	if p.LdapAddr != "" {
		args = append(args, "--ldapAddr")
		args = append(args, p.LdapAddr)
	}
	if p.GitlabAddr != "" {
		args = append(args, "--gitlabAddr")
		args = append(args, p.GitlabAddr)
	}
	if p.NotifySrvAddr != "" {
		args = append(args, "--notifySrvAddr")
		args = append(args, p.NotifySrvAddr)
	}
	if p.ConsoleProxyAddr != "" {
		args = append(args, "--consoleproxyaddr")
		args = append(args, p.ConsoleProxyAddr)
	}
	if p.AlertResolveTimeout != "" {
		args = append(args, "--alertResolveTimeout")
		args = append(args, p.AlertResolveTimeout)
	}
	if p.BillingPlatform != "" {
		args = append(args, "--billingPlatform")
		args = append(args, p.BillingPlatform)
	}
	if p.UsageCollectionInterval != "" {
		args = append(args, "--usageCollectionInterval")
		args = append(args, p.UsageCollectionInterval)
	}
	if p.UsageCheckpointInterval != "" {
		args = append(args, "--usageCheckpointInterval")
		args = append(args, p.UsageCheckpointInterval)
	}
	if p.AlertMgrApiAddr != "" {
		args = append(args, "--alertMgrApiAddr")
		args = append(args, p.AlertMgrApiAddr)
	}
	if p.StaticDir != "" {
		args = append(args, "--staticDir", p.StaticDir)
	}
	if p.TestMode {
		args = append(args, "--testMode")
	}
	args = append(args, "--hostname", p.Name)
	options := process.StartOptions{}
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
		envs = append(envs,
			fmt.Sprintf("VAULT_ROLE_ID=%s", roles.MCRoleID),
			fmt.Sprintf("VAULT_SECRET_ID=%s", roles.MCSecretID),
		)
	}

	var err error
	p.cmd, err = process.StartLocal(p.Name, p.GetExeName(), args, envs, logfile)
	if err == nil {
		// wait until server is online
		online := false
		for ii := 0; ii < 90; ii++ {
			resp, serr := http.Get("http://" + p.Addr)
			if serr == nil {
				resp.Body.Close()
				online = true
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if !online {
			p.StopLocal()
			return fmt.Errorf("failed to detect MC online")
		}
	}
	return err
}

func (p *MC) StopLocal() {
	process.StopLocal(p.cmd)
}

func (p *MC) GetExeName() string { return "mc" }

func (p *MC) LookupArgs() string { return "--addr " + p.Addr }

// Postgres Sql

func (p *Sql) StartLocal(logfile string, opts ...process.StartOp) error {
	sopts := process.StartOptions{}
	sopts.ApplyStartOptions(opts...)
	if sopts.CleanStartup {
		if err := p.InitDataDir(); err != nil {
			return err
		}
	}

	args := []string{"-D", p.DataDir, "start"}
	options := []string{"-F -k /tmp"}
	addr := []string{}
	if p.HttpAddr != "" {
		addr = strings.Split(p.HttpAddr, ":")
		if len(addr) == 2 {
			options = append(options, "-p")
			options = append(options, addr[1])
		}
	}
	if p.TLS.ServerCert != "" {
		// files server.crt and server.key must exist
		// in server's data directory.
		os.Symlink(p.TLS.ServerCert, p.DataDir+"/server.crt")
		os.Symlink(p.TLS.ServerKey, p.DataDir+"/server.key")
		// sql db has strict requirements on cert perms
		os.Chmod(p.TLS.ServerCert, 0600)
		os.Chmod(p.TLS.ServerKey, 0600)
		options = append(options, "-l")
	}
	if len(options) > 0 {
		args = append(args, "-o")
		args = append(args, strings.Join(options, " "))
	}
	var err error
	p.cmd, err = process.StartLocal(p.Name, "pg_ctl", args, p.GetEnv(), logfile)
	if err != nil {
		return err
	}
	// wait until pg_ctl script exits (means postgres service is ready)
	state, err := p.cmd.Process.Wait()
	if err != nil {
		return fmt.Errorf("failed wait for pg_ctl, %s", err.Error())
	}
	if !state.Exited() {
		return fmt.Errorf("pg_ctl not exited")
	}
	if !state.Success() {
		return fmt.Errorf("pg_ctl failed, see script output")
	}

	// create primary user
	out, err := p.runPsql([]string{"-c", "select rolname from pg_roles",
		"postgres"})
	if err != nil {
		p.StopLocal()
		return fmt.Errorf("sql: failed to list postgres roles, %s", err.Error())
	}
	if !strings.Contains(string(out), p.Username) {
		out, err = p.runPsql([]string{"-c",
			fmt.Sprintf("create user %s", p.Username), "postgres"})
		fmt.Println(string(out))
		if err != nil {
			p.StopLocal()
			return fmt.Errorf("sql: failed to create user %s, %s",
				p.Username, err.Error())
		}
	}

	// create user database
	out, err = p.runPsql([]string{"-c", "select datname from pg_database",
		"postgres"})
	if err != nil {
		p.StopLocal()
		return fmt.Errorf("sql: failed to list databases, %s, %s", string(out), err.Error())
	}
	if !strings.Contains(string(out), p.Dbname) {
		out, err = p.runPsql([]string{"-c",
			fmt.Sprintf("create database %s", p.Dbname), "postgres"})
		fmt.Println(string(out))
		if err != nil {
			p.StopLocal()
			return fmt.Errorf("sql: failed to create database %s, %s",
				p.Dbname, err.Error())
		}
		// citext allows columns to be case-insensitive text
		out, err = p.runPsql([]string{
			"-c", fmt.Sprintf("\\c %s", p.Dbname),
			"-c", "create extension if not exists citext",
			"postgres"})
		fmt.Println(string(out))
		if err != nil {
			p.StopLocal()
			return fmt.Errorf("sql: failed to enable citext %s, %s, %s",
				p.Dbname, string(out), err.Error())
		}
	}
	return nil
}
func (p *Sql) StopLocal() {
	exec.Command("pg_ctl", "-D", p.DataDir, "stop").CombinedOutput()
}

func (p *Sql) GetExeName() string { return "postgres" }

func (p *Sql) LookupArgs() string { return "" }

func (p *Sql) InitDataDir() error {
	err := os.RemoveAll(p.DataDir)
	if err != nil {
		return err
	}
	out, err := exec.Command("initdb", "--locale", "en_US.UTF-8", p.DataDir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sql initdb failed: %s, %v", string(out), err)
	}
	return nil
}
func (p *Sql) runPsql(args []string) ([]byte, error) {
	if p.HttpAddr != "" {
		addr := strings.Split(p.HttpAddr, ":")
		if len(addr) == 2 {
			args = append([]string{"-h", addr[0], "-p", addr[1]}, args...)
		}
	}
	return exec.Command("psql", args...).CombinedOutput()
}

func (p *Shepherd) GetArgs(opts ...process.StartOp) []string {
	args := p.GetNodeMgrArgs()
	if p.Name != "" {
		args = append(args, "--name")
		args = append(args, p.Name)
	}
	if p.NotifyAddrs != "" {
		args = append(args, "--notifyAddrs")
		args = append(args, p.NotifyAddrs)
	}
	if p.Platform != "" {
		args = append(args, "--platform")
		args = append(args, p.Platform)
	}
	if p.PhysicalName != "" {
		args = append(args, "--physicalName")
		args = append(args, p.PhysicalName)
	}
	if p.CloudletKey != "" {
		args = append(args, "--cloudletKey")
		args = append(args, p.CloudletKey)
	}
	if p.Span != "" {
		args = append(args, "--span")
		args = append(args, p.Span)
	}
	if p.Region != "" {
		args = append(args, "--region")
		args = append(args, p.Region)
	}
	if p.MetricsAddr != "" {
		args = append(args, "--metricsAddr")
		args = append(args, p.MetricsAddr)
	}
	if p.AppDNSRoot != "" {
		args = append(args, "--appDNSRoot")
		args = append(args, p.AppDNSRoot)
	}
	if p.ChefServerPath != "" {
		args = append(args, "--chefServerPath")
		args = append(args, p.ChefServerPath)
	}
	if p.ThanosRecvAddr != "" {
		args = append(args, "--thanosRecvAddr")
		args = append(args, p.ThanosRecvAddr)
	}
	options := process.StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.Debug != "" {
		args = append(args, "-d")
		args = append(args, options.Debug)
	}
	return args
}
func (p *Shepherd) StartLocal(logfile string, opts ...process.StartOp) error {
	var err error
	args := p.GetArgs(opts...)
	p.cmd, err = process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	return err
}

func (p *Shepherd) String(opts ...process.StartOp) string {
	cmd_str := p.GetExeName()
	args := p.GetArgs(opts...)
	key := true
	for _, v := range args {
		if key {
			cmd_str += " " + v
			key = false
		} else {
			cmd_str += " '" + v + "'"
			key = true
		}
	}
	return cmd_str
}

func (p *Shepherd) StopLocal() {
	process.StopLocal(p.cmd)
}

func (p *Shepherd) GetExeName() string { return "shepherd" }

func (p *Shepherd) LookupArgs() string { return "--cloudletKey " + p.CloudletKey }

func (p *Shepherd) Wait() {
	p.cmd.Wait()
}

func (p *AutoProv) StartLocal(logfile string, opts ...process.StartOp) error {
	args := []string{"--notifyAddrs", p.NotifyAddrs}
	args = append(args, p.GetNodeMgrArgs()...)
	if p.CtrlAddrs != "" {
		args = append(args, "--ctrlAddrs")
		args = append(args, p.CtrlAddrs)
	}
	if p.InfluxAddr != "" {
		args = append(args, "--influxAddr")
		args = append(args, p.InfluxAddr)
	}
	if p.Region != "" {
		args = append(args, "--region")
		args = append(args, p.Region)
	}
	options := process.StartOptions{}
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
			fmt.Sprintf("VAULT_ROLE_ID=%s", rr.AutoProvRoleID),
			fmt.Sprintf("VAULT_SECRET_ID=%s", rr.AutoProvSecretID),
		)
	}

	var err error
	p.cmd, err = process.StartLocal(p.Name, p.GetExeName(), args, envs, logfile)
	return err
}

func (p *AutoProv) StopLocal() {
	process.StopLocal(p.cmd)
}

func (p *AutoProv) GetExeName() string { return "autoprov" }

func (p *AutoProv) LookupArgs() string { return "" }

type VaultRoles struct {
	MCRoleID        string `json:"mcroleid"`
	MCSecretID      string `json:"mcsecretid"`
	RotatorRoleID   string `json:"rotatorroleid"`
	RotatorSecretID string `json:"rotatorsecretid"`
	RegionRoles     map[string]*VaultRegionRoles
}

type VaultRegionRoles struct {
	AutoProvRoleID   string `json:"autoprovroleid"`
	AutoProvSecretID string `json:"autoprovsecretid"`
	FrmRoleID        string `json:"frmroleid"`
	FrmSecretID      string `json:"frmsecretid"`
}

func (s *VaultRoles) GetRegionRoles(region string) *VaultRegionRoles {
	if region == "" {
		region = "local"
	}
	return s.RegionRoles[region]
}

func GetDummyPrivateKey(fileName string) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}

	chefApiKey := struct {
		ApiKey string `json:"apikey"`
	}{}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	out := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	chefApiKey.ApiKey = string(out)
	jsonKey, err := json.Marshal(chefApiKey)
	if err != nil {
		return err
	}
	outFile.Write(jsonKey)

	return nil
}

// Vault is already started by edge-cloud setup file.
func SetupVault(p *process.Vault, opts ...process.StartOp) (*VaultRoles, error) {
	var err error
	mcormSecret := "mc-secret"

	// run global setup script
	gopath := os.Getenv("GOPATH")
	setup := gopath + "/src/github.com/edgexr/edge-cloud-infra/vault/setup.sh"
	out := p.Run("/bin/sh", setup, &err)
	if err != nil {
		fmt.Println(out)
		return nil, err
	}
	// get roleIDs and secretIDs
	roles := VaultRoles{}
	roles.RegionRoles = make(map[string]*VaultRegionRoles)
	p.GetAppRole("", "mcorm", &roles.MCRoleID, &roles.MCSecretID, &err)
	p.GetAppRole("", "rotator", &roles.RotatorRoleID, &roles.RotatorSecretID, &err)
	p.PutSecret("", "mcorm", mcormSecret+"-old", &err)
	p.PutSecret("", "mcorm", mcormSecret, &err)

	// Set up dummy key to be used with local chef server to provision cloudlets
	chefApiKeyPath := "/tmp/dummyChefApiKey.json"
	err = GetDummyPrivateKey(chefApiKeyPath)
	if err != nil {
		return &roles, err
	}
	p.Run("vault", fmt.Sprintf("kv put %s @%s", "/secret/accounts/chef", chefApiKeyPath), &err)
	if err != nil {
		return &roles, err
	}

	p.Run("vault", fmt.Sprintf("kv put /secret/accounts/noreplyemail Email=dummy@email.com"), &err)
	if err != nil {
		return &roles, err
	}

	// Set up dummy API key to be used to call the GDDT QOS Priority Sessions API.
	fileName := gopath + "/src/github.com/edgexr/edge-cloud-infra/e2e-tests/data/gddt_qos_session_api_key.txt"
	// The vault path for "kv put" omits the /data portion.
	// To read this key with vault.GetData(), use path=/secret/data/accounts/gddt/sessionsapi
	path := "/secret/accounts/gddt/sessionsapi"
	p.Run("vault", fmt.Sprintf("kv put %s @%s", path, fileName), &err)
	log.Printf("PutQosApiKeyToVault at path %s, err=%s", path, err)
	if err != nil {
		return &roles, err
	}

	if p.Regions == "" {
		p.Regions = "local"
	}
	for _, region := range strings.Split(p.Regions, ",") {
		setup := gopath + "/src/github.com/edgexr/edge-cloud-infra/vault/setup-region.sh " + region
		out := p.Run("/bin/sh", setup, &err)
		if err != nil {
			fmt.Println(out)
			return nil, err
		}
		rr := VaultRegionRoles{}
		p.GetAppRole(region, "autoprov", &rr.AutoProvRoleID, &rr.AutoProvSecretID, &err)
		p.GetAppRole(region, "frm", &rr.FrmRoleID, &rr.FrmSecretID, &err)
		roles.RegionRoles[region] = &rr
	}
	options := process.StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.RolesFile != "" {
		roleYaml, err := yaml.Marshal(&roles)
		if err != nil {
			return &roles, err
		}
		err = ioutil.WriteFile(options.RolesFile, roleYaml, 0644)
		if err != nil {
			return &roles, err
		}
	}
	return &roles, err
}

func (p *PromE2e) StartLocal(logfile string, opts ...process.StartOp) error {
	// if the image doesn't exist, build it
	if !imageFound(p.Name) {
		directory := os.Getenv("GOPATH") + "/src/github.com/edgexr/edge-cloud-infra/shepherd/e2eHttpServer"
		builder := exec.Command("docker", "build", "-t", p.Name, directory)
		err := builder.Run()
		if err != nil {
			return fmt.Errorf("Failed to build docker image for e2e prometheus: %v", err)
		}
	}
	args := p.GetRunArgs()
	args = append(args,
		"-p", fmt.Sprintf("%d:%d", p.Port, p.Port),
		p.Name)
	cmd, err := process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	return err
}

func imageFound(name string) bool {
	listCmd := exec.Command("docker", "images")
	output, err := listCmd.Output()
	if err != nil {
		return false
	}
	imageList := strings.Split(string(output), "\n")
	for _, row := range imageList {
		if name == strings.SplitN(row, " ", 2)[0] {
			return true
		}
	}
	return false
}

func (p *HttpServer) StartLocal(logfile string, opts ...process.StartOp) error {
	args := []string{
		"-port", fmt.Sprintf("%d", p.Port), "-promStatsPath", p.PromDataFile,
	}

	var err error
	p.cmd, err = process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	return err
}

func (p *HttpServer) StopLocal() {
	process.StopLocal(p.cmd)
}

func (p *HttpServer) GetExeName() string { return "e2eHttpServer" }

func (p *HttpServer) LookupArgs() string { return "" }

func (p *ChefServer) StartLocal(logfile string, opts ...process.StartOp) error {
	args := []string{}
	if p.Port > 0 {
		args = append(args, "--port")
		args = append(args, fmt.Sprintf("%d", p.Port))
	} else {
		args = append(args, "--port")
		args = append(args, "8889")
	}
	args = append(args, "--multi-org")

	var err error
	p.cmd, err = process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	if err != nil {
		return err
	}

	cmd := exec.Command("./e2e-tests/chef/setup.sh")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to execute ./e2e-tests/chef/setup.sh: %v, %s", err, out)
	}

	return err
}

func (p *ChefServer) StopLocal() {
	process.StopLocal(p.cmd)
}

func (p *ChefServer) GetExeName() string { return "chef-zero" }

func (p *ChefServer) LookupArgs() string { return fmt.Sprintf("--port %d --multi-org", p.Port) }

func (p *Alertmanager) StartLocal(logfile string, opts ...process.StartOp) error {
	configFile := "/tmp/alertmanager.yml"
	templateFile := "/tmp/alertmanager.tmpl"
	if p.ConfigFile != "" {
		// Copy file from data dir to /tmp since it's going to be written to
		in, err := ioutil.ReadFile(p.ConfigFile)
		if err != nil {
			log.Printf("Failed to open alertmanager configuration file - %s\n", err.Error())
			return err
		}
		err = ioutil.WriteFile(configFile, in, 0644)
		if err != nil {
			log.Printf("Failed to copy alertmanager configuration file - %s\n", err.Error())
			return err
		}
	}
	if p.TemplateFile != "" {
		templateFile = p.TemplateFile
	}
	args := p.GetRunArgs()
	args = append(args,
		"-p", fmt.Sprintf("%d:%d", p.Port, p.Port),
		"-v", configFile+":/etc/prometheus/alertmanager.yml",
		"-v", templateFile+":/etc/alertmanager/templates/alertmanager.tmpl",
		"prom/alertmanager:v0.21.0",
		"--web.listen-address", fmt.Sprintf(":%d", p.Port),
		"--log.level", "debug",
		"--config.file", "/etc/prometheus/alertmanager.yml",
	)

	log.Printf("Start Alertmanager: %v\n", args)
	cmd, err := process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	return err
}

func (p *Maildev) StartLocal(logfile string, opts ...process.StartOp) error {
	args := p.GetRunArgs()
	args = append(args,
		"-p", fmt.Sprintf("%d:%d", p.UiPort, 80),
		"-p", fmt.Sprintf("%d:%d", p.MailPort, 25),
		"maildev/maildev:1.1.0",
	)
	cmd, err := process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	return err
}

func (p *AlertmanagerSidecar) StartLocal(logfile string, opts ...process.StartOp) error {
	args := []string{"--httpAddr", p.HttpAddr}
	if p.AlertmgrAddr != "" {
		args = append(args, "--alertmgrAddr")
		args = append(args, p.AlertmgrAddr)
	}
	if p.ConfigFile != "" {
		args = append(args, "--configFile")
		args = append(args, p.ConfigFile)
	}
	if p.TLS.ServerCert != "" {
		args = append(args, "--tlsCert")
		args = append(args, p.TLS.ServerCert)
	}
	if p.TLS.ServerKey != "" {
		args = append(args, "--tlsCertKey")
		args = append(args, p.TLS.ServerKey)
	}
	if p.TLS.CACert != "" {
		args = append(args, "--tlsClientCert")
		args = append(args, p.TLS.CACert)
	}
	if p.LocalTest {
		args = append(args, "-localTest")
	}

	options := process.StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.Debug != "" {
		args = append(args, "-d")
		args = append(args, options.Debug)
	}

	var err error
	p.cmd, err = process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	return err
}

func (p *AlertmanagerSidecar) StopLocal() {
	process.StopLocal(p.cmd)
}

func (p *AlertmanagerSidecar) GetExeName() string { return "alertmgr-sidecar" }

func (p *AlertmanagerSidecar) LookupArgs() string {
	return fmt.Sprintf("--httpAddr %s --alertmgrAddr %s", p.HttpAddr, p.AlertmgrAddr)
}

func (p *FRM) StartLocal(logfile string, opts ...process.StartOp) error {
	args := p.GetNodeMgrArgs()
	if p.NotifyAddrs != "" {
		args = append(args, "--notifyAddrs")
		args = append(args, p.NotifyAddrs)
	}
	if p.TLS.ClientCert != "" {
		args = append(args, "--clientCert")
		args = append(args, p.TLS.ClientCert)
	}
	if p.Region != "" {
		args = append(args, "--region")
		args = append(args, p.Region)
	}
	args = append(args, "--hostname", p.Name)
	options := process.StartOptions{}
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
			fmt.Sprintf("VAULT_ROLE_ID=%s", rr.FrmRoleID),
			fmt.Sprintf("VAULT_SECRET_ID=%s", rr.FrmSecretID),
		)
	}

	var err error
	p.cmd, err = process.StartLocal(p.Name, p.GetExeName(), args, envs, logfile)
	return err
}

func (p *FRM) StopLocal() {
	process.StopLocal(p.cmd)
}

func (p *FRM) GetExeName() string { return "frm" }

func (p *FRM) LookupArgs() string { return p.Name }

func (p *ThanosQuery) StartLocal(logfile string, opts ...process.StartOp) error {
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

	cmd, err := process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	return err
}

func (p *ThanosReceive) StartLocal(logfile string, opts ...process.StartOp) error {
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

	cmd, err := process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	return err
}

//DT QOS Sessions API server simulator
func (p *QosSesSrvSim) StartLocal(logfile string, opts ...process.StartOp) error {
	args := []string{"-port", fmt.Sprintf("%d", p.Port)}
	var err error
	p.cmd, err = process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	return err
}

func (p *QosSesSrvSim) StopLocal() {
	process.StopLocal(p.cmd)
}

func (p *QosSesSrvSim) GetExeName() string { return "sessions-srv-sim" }

func (p *QosSesSrvSim) LookupArgs() string {
	return fmt.Sprintf("-port %d", p.Port)
}
