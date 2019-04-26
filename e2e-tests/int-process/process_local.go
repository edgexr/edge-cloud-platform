package intprocess

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"

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
	if p.TLS.ServerCert != "" {
		args = append(args, "--tls")
		args = append(args, p.TLS.ServerCert)
	}
	if p.TLS.ServerKey != "" {
		args = append(args, "--tlskey")
		args = append(args, p.TLS.ServerKey)
	}
	if p.TLS.ClientCert != "" {
		args = append(args, "--clientCert")
		args = append(args, p.TLS.ClientCert)
	}
	options := process.StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.Debug != "" {
		args = append(args, "-d")
		args = append(args, options.Debug)
	}
	var envs []string
	if options.RolesFile != "" {
		dat, err := ioutil.ReadFile(options.RolesFile)
		if err != nil {
			return err
		}
		roles := process.VaultRoles{}
		err = yaml.Unmarshal(dat, &roles)
		if err != nil {
			return err
		}
		envs = []string{
			fmt.Sprintf("VAULT_ROLE_ID=%s", roles.MCORMRoleID),
			fmt.Sprintf("VAULT_SECRET_ID=%s", roles.MCORMSecretID),
		}
		log.Printf("MC envs: %v\n", envs)
	}

	var err error
	p.cmd, err = process.StartLocal(p.Name, p.GetExeName(), args, envs, logfile)
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
	p.cmd, err = process.StartLocal(p.Name, "pg_ctl", args, nil, logfile)
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
			return fmt.Errorf("sql: failed to create user %s, %s",
				p.Username, err.Error())
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
