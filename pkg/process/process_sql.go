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
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Sql struct {
	Common   `yaml:",inline"`
	DataDir  string
	HttpAddr string
	Username string
	Dbname   string
	TLS      TLSCerts
	cmd      *exec.Cmd
}

func (p *Sql) StartLocal(logfile string, opts ...StartOp) error {
	sopts := StartOptions{}
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
	p.cmd, err = StartLocal(p.Name, "pg_ctl", args, p.GetEnv(), logfile)
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
