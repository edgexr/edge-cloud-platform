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

	"github.com/mobiledgex/edge-cloud/integration/process"
	yaml "gopkg.in/yaml.v2"
)

// Master Controller

func (p *MC) StartLocal(logfile string, opts ...process.StartOp) error {
	args := []string{}
	if p.Addr != "" {
		args = append(args, "--addr")
		args = append(args, p.Addr)
	}
	if p.SqlAddr != "" {
		args = append(args, "--sqlAddr")
		args = append(args, p.SqlAddr)
	}
	if p.VaultAddr != "" {
		args = append(args, "--vaultAddr")
		args = append(args, p.VaultAddr)
	}
	args = p.TLS.AddInternalPkiArgs(args)
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
	if p.UseVaultCAs {
		args = append(args, "--useVaultCAs")
	}
	if p.BillingPath != "" {
		args = append(args, "--billingPath")
		args = append(args, p.BillingPath)
	}
	if p.UsageCollectionInterval != "" {
		args = append(args, "--usageCollectionInterval")
		args = append(args, p.UsageCollectionInterval)
	}
	if p.UsageCheckpointInterval != "" {
		args = append(args, "--usageCheckpointInterval")
		args = append(args, p.UsageCheckpointInterval)
	}
	if p.UseVaultCerts {
		args = append(args, "--useVaultCerts")
	}
	if p.AlertMgrApiAddr != "" {
		args = append(args, "--alertMgrApiAddr")
		args = append(args, p.AlertMgrApiAddr)
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
	options := []string{}
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
		return fmt.Errorf("sql: failed to list databases, %s", err.Error())
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
			return fmt.Errorf("sql: failed to enable citext %s, %s",
				p.Dbname, err.Error())
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
	_, err = exec.Command("initdb", p.DataDir).CombinedOutput()
	return err
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
	args := []string{}
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
	if p.VaultAddr != "" {
		args = append(args, "--vaultAddr")
		args = append(args, p.VaultAddr)
	}
	if p.PhysicalName != "" {
		args = append(args, "--physicalName")
		args = append(args, p.PhysicalName)
	}
	if p.CloudletKey != "" {
		args = append(args, "--cloudletKey")
		args = append(args, p.CloudletKey)
	}
	args = p.TLS.AddInternalPkiArgs(args)
	if p.Span != "" {
		args = append(args, "--span")
		args = append(args, p.Span)
	}
	if p.Region != "" {
		args = append(args, "--region")
		args = append(args, p.Region)
	}
	if p.UseVaultCAs {
		args = append(args, "--useVaultCAs")
	}
	if p.UseVaultCerts {
		args = append(args, "--useVaultCerts")
	}
	if p.MetricsAddr != "" {
		args = append(args, "--metricsAddr")
		args = append(args, p.MetricsAddr)
	}
	if p.AppDNSRoot != "" {
		args = append(args, "--appDNSRoot")
		args = append(args, p.AppDNSRoot)
	}
	if p.DeploymentTag != "" {
		args = append(args, "--deploymentTag")
		args = append(args, p.DeploymentTag)
	}
	if p.ChefServerPath != "" {
		args = append(args, "--chefServerPath")
		args = append(args, p.ChefServerPath)
	}
	if p.AccessKeyFile != "" {
		args = append(args, "--accessKeyFile", p.AccessKeyFile)
	}
	if p.AccessApiAddr != "" {
		args = append(args, "--accessApiAddr", p.AccessApiAddr)
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
	if p.CtrlAddrs != "" {
		args = append(args, "--ctrlAddrs")
		args = append(args, p.CtrlAddrs)
	}
	if p.VaultAddr != "" {
		args = append(args, "--vaultAddr")
		args = append(args, p.VaultAddr)
	}
	if p.InfluxAddr != "" {
		args = append(args, "--influxAddr")
		args = append(args, p.InfluxAddr)
	}
	args = p.TLS.AddInternalPkiArgs(args)
	if p.Region != "" {
		args = append(args, "--region")
		args = append(args, p.Region)
	}
	if p.UseVaultCAs {
		args = append(args, "--useVaultCAs")
	}
	if p.UseVaultCerts {
		args = append(args, "--useVaultCerts")
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
	setup := gopath + "/src/github.com/mobiledgex/edge-cloud-infra/vault/setup.sh"
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
	// Set up local mexenv.json in the vault to allow local edgebox to run
	localMexenv := gopath + "/src/github.com/mobiledgex/edge-cloud-infra/mgmt/cloudlets/mexenv.json"
	p.Run("vault", fmt.Sprintf("write %s @%s", "/secret/data/cloudlet/openstack/mexenv.json", localMexenv), &err)
	if err != nil {
		return &roles, err
	}

	// Setup up dummy key to be used with local chef server to provision cloudlets
	chefApiKeyPath := "/tmp/dummyChefApiKey.json"
	err = GetDummyPrivateKey(chefApiKeyPath)
	if err != nil {
		return &roles, err
	}
	p.Run("vault", fmt.Sprintf("kv put %s @%s", "/secret/accounts/chef", chefApiKeyPath), &err)
	if err != nil {
		return &roles, err
	}

	if p.Regions == "" {
		p.Regions = "local"
	}
	for _, region := range strings.Split(p.Regions, ",") {
		setup := gopath + "/src/github.com/mobiledgex/edge-cloud-infra/vault/setup-region.sh " + region
		out := p.Run("/bin/sh", setup, &err)
		if err != nil {
			fmt.Println(out)
			return nil, err
		}
		rr := VaultRegionRoles{}
		p.GetAppRole(region, "autoprov", &rr.AutoProvRoleID, &rr.AutoProvSecretID, &err)
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
		directory := os.Getenv("GOPATH") + "/src/github.com/mobiledgex/edge-cloud-infra/shepherd/e2eHttpServer"
		builder := exec.Command("docker", "build", "-t", p.Name, directory)
		err := builder.Run()
		if err != nil {
			return fmt.Errorf("Failed to build docker image for e2e prometheus: %v", err)
		}
	}
	args := []string{
		"run", "--rm", "-p", fmt.Sprintf("%d:%d", p.Port, p.Port), "--name", p.Name, p.Name,
	}

	var err error
	p.cmd, err = process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
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

func (p *PromE2e) StopLocal() {
	process.StopLocal(p.cmd)
}

func (p *PromE2e) GetExeName() string { return "docker" }

func (p *PromE2e) LookupArgs() string { return p.Name }

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
	args := []string{
		"run", "--rm", "-p", fmt.Sprintf("%d:%d", p.Port, p.Port),
		"-v", configFile + ":/etc/prometheus/alertmanager.yml",
		"-v", templateFile + ":/etc/alertmanager/templates/alertmanager.tmpl",
		"--name", p.Name,
		"prom/alertmanager:v0.21.0",
		"--web.listen-address", fmt.Sprintf(":%d", p.Port),
		"--log.level", "debug",
		"--config.file", "/etc/prometheus/alertmanager.yml",
	}

	var err error
	log.Printf("Start Alertmanager: %v\n", args)
	p.cmd, err = process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	return err
}

func (p *Alertmanager) StopLocal() {
	process.StopLocal(p.cmd)
	cmd := exec.Command("docker", "kill", p.Name)
	cmd.Run()
}

func (p *Alertmanager) GetExeName() string { return "docker" }

func (p *Alertmanager) LookupArgs() string { return p.Name }

func (p *Maildev) StartLocal(logfile string, opts ...process.StartOp) error {
	args := []string{
		"run", "--rm",
		"-p", fmt.Sprintf("%d:%d", p.UiPort, 80),
		"-p", fmt.Sprintf("%d:%d", p.MailPort, 25),
		"--name", p.Name,
		"maildev/maildev:1.1.0",
	}
	var err error
	p.cmd, err = process.StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	return err
}

func (p *Maildev) StopLocal() {
	process.StopLocal(p.cmd)
	cmd := exec.Command("docker", "kill", p.Name)
	cmd.Run()
}

func (p *Maildev) GetExeName() string { return "docker" }

func (p *Maildev) LookupArgs() string { return p.Name }

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

func (p *AlertmanagerSidecar) LookupArgs() string { return "" }
