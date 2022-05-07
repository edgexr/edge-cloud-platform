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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v2"
)

type Vault struct {
	Common     `yaml:",inline"`
	DmeSecret  string
	Regions    string
	VaultDatas []VaultData
	ListenAddr string
	RootToken  string
	CADir      string
	cmd        *exec.Cmd
}

type VaultData struct {
	Path string
	Data map[string]string
}

// In dev mode, Vault is locked to below address
var defaultVaultAddress = "http://127.0.0.1:8200"

type VaultRoles struct {
	NotifyRootRoleID   string `json:"notifyrootroleid"`
	NotifyRootSecretID string `json:"notifyrootsecretid"`
	MCRoleID           string `json:"mcroleid"`
	MCSecretID         string `json:"mcsecretid"`
	RotatorRoleID      string `json:"rotatorroleid"`
	RotatorSecretID    string `json:"rotatorsecretid"`
	RegionRoles        map[string]*VaultRegionRoles
}

type VaultRegionRoles struct {
	DmeRoleID          string `json:"dmeroleid"`
	DmeSecretID        string `json:"dmesecretid"`
	RotatorRoleID      string `json:"rotatorroleid"`
	RotatorSecretID    string `json:"rotatorsecretid"`
	CtrlRoleID         string `json:"controllerroleid"`
	CtrlSecretID       string `json:"controllersecretid"`
	ClusterSvcRoleID   string `json:"clustersvcroleid"`
	ClusterSvcSecretID string `json:"clustersvcsecretid"`
	EdgeTurnRoleID     string `json:"edgeturnroleid"`
	EdgeTurnSecretID   string `json:"edgeturnsecretid"`
	AutoProvRoleID     string `json:"autoprovroleid"`
	AutoProvSecretID   string `json:"autoprovsecretid"`
	FrmRoleID          string `json:"frmroleid"`
	FrmSecretID        string `json:"frmsecretid"`
}

func (s *VaultRoles) GetRegionRoles(region string) *VaultRegionRoles {
	if region == "" {
		region = "local"
	}
	return s.RegionRoles[region]
}

func (p *Vault) StartLocal(logfile string, opts ...StartOp) error {
	// Note: for e2e tests, vault is started in dev mode.
	// In dev mode, vault is automatically unsealed, TLS is disabled,
	// data is in-memory only, and root key is printed during startup.
	// DO NOT run Vault in dev mode for production setups.
	if p.DmeSecret == "" {
		p.DmeSecret = "dme-secret"
	}

	args := []string{"server", "-dev"}
	if p.ListenAddr == "" {
		p.ListenAddr = defaultVaultAddress
	}
	if !strings.HasPrefix(p.ListenAddr, "http://") {
		return fmt.Errorf("vault listen addr must start with http://")
	}
	// unfortunately arg passed to vault cannot have http
	addr := strings.TrimPrefix(p.ListenAddr, "http://")
	args = append(args, "-dev-listen-address="+addr)

	// Specify the root token. Vault generates one automatically
	// and stores it in ~/.vault-token for the CLI to use, but
	// somehow with unit tests running multiple Vaults, they mess
	// up the ~/.vault-token for each other (even though they're
	// not supposed to be running at the same time).
	p.RootToken = "vault-token"
	args = append(args, "-dev-root-token-id="+p.RootToken)
	if p.CADir == "" {
		p.CADir = "/tmp/vault_pki"
	}
	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	if err != nil {
		return err
	}
	// wait until vault is online and ready
	for ii := 0; ii < 10; ii++ {
		var serr error
		p.Run("vault", "status", &serr)
		if serr == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if p.cmd.Process == nil {
		return fmt.Errorf("failed to start vault process, see log %s", logfile)
	}
	options := StartOptions{}
	options.ApplyStartOptions(opts...)

	// run setup script
	gopath := os.Getenv("GOPATH")
	setup := gopath + "/src/github.com/edgexr/edge-cloud-platform/pkg/vault/setup.sh"
	out := p.Run("/bin/sh", setup, &err)
	fmt.Println(out)
	// get roleIDs and secretIDs
	vroles := VaultRoles{}
	vroles.RegionRoles = make(map[string]*VaultRegionRoles)
	p.GetAppRole("", "notifyroot", &vroles.NotifyRootRoleID, &vroles.NotifyRootSecretID, &err)

	if p.Regions == "" {
		p.Regions = "local"
	}
	for _, region := range strings.Split(p.Regions, ",") {
		// run setup script
		setup := gopath + "/src/github.com/edgexr/edge-cloud-platform/pkg/vault/setup-region.sh " + region
		out := p.Run("/bin/sh", setup, &err)
		if err != nil {
			fmt.Println(out)
		}
		// get roleIDs and secretIDs
		roles := VaultRegionRoles{}
		p.GetAppRole(region, "dme", &roles.DmeRoleID, &roles.DmeSecretID, &err)
		p.GetAppRole(region, "rotator", &roles.RotatorRoleID, &roles.RotatorSecretID, &err)
		p.GetAppRole(region, "controller", &roles.CtrlRoleID, &roles.CtrlSecretID, &err)
		p.GetAppRole(region, "cluster-svc", &roles.ClusterSvcRoleID, &roles.ClusterSvcSecretID, &err)
		p.GetAppRole(region, "edgeturn", &roles.EdgeTurnRoleID, &roles.EdgeTurnSecretID, &err)
		p.PutSecret(region, "dme", p.DmeSecret+"-old", &err)
		p.PutSecret(region, "dme", p.DmeSecret, &err)
		vroles.RegionRoles[region] = &roles
		// Get the directory where the influx.json file is
		if _, serr := os.Stat(InfluxCredsFile); !os.IsNotExist(serr) {
			path := "secret/" + region + "/accounts/influxdb"
			p.PutSecretsJson(path, InfluxCredsFile, &err)
		}
		if err != nil {
			p.StopLocal()
			return err
		}
	}
	if options.RolesFile != "" {
		roleYaml, err := yaml.Marshal(&vroles)
		if err != nil {
			p.StopLocal()
			return err
		}
		err = ioutil.WriteFile(options.RolesFile, roleYaml, 0644)
		if err != nil {
			p.StopLocal()
			return err
		}
	}
	for _, vaultData := range p.VaultDatas {
		data, err := json.Marshal(vaultData.Data)
		if err != nil {
			log.Printf("Failed to marshal vault data - %v[err:%v]\n", vaultData, err)
			continue
		}
		// get a reader for the data
		reader := strings.NewReader(string(data))
		p.RunWithInput("vault", fmt.Sprintf("kv put %s -", vaultData.Path), reader, &err)
		if err != nil {
			log.Printf("Failed to store secret in [%s] - err:%v\n", vaultData.Path, err)
			continue
		}

	}
	return err
}

func (p *Vault) StopLocal() {
	StopLocal(p.cmd)
}

func (p *Vault) GetExeName() string { return "vault" }

func (p *Vault) LookupArgs() string { return "" }

func (p *Vault) GetAppRole(region, name string, roleID, secretID *string, err *error) {
	if *err != nil {
		return
	}
	if region != "" {
		name = region + "." + name
	}
	out := p.Run("vault", fmt.Sprintf("read auth/approle/role/%s/role-id", name), err)
	vals := p.mapVals(out)
	if val, ok := vals["role_id"]; ok {
		*roleID = val
	}
	out = p.Run("vault", fmt.Sprintf("write -f auth/approle/role/%s/secret-id", name), err)
	vals = p.mapVals(out)
	if val, ok := vals["secret_id"]; ok {
		*secretID = val
	}
}

func (p *Vault) PutSecretsJson(SecretsPath, jsonFile string, err *error) {
	p.Run("vault", fmt.Sprintf("kv put %s @%s", SecretsPath, jsonFile), err)
}

func (p *Vault) PutSecret(region, name, secret string, err *error) {
	if region != "" {
		region += "/"
	}
	p.Run("vault", fmt.Sprintf("kv put %sjwtkeys/%s secret=%s", region, name, secret), err)
}

func (p *Vault) Run(bin, args string, err *error) string {
	return p.RunWithInput(bin, args, nil, err)
}

func (p *Vault) RunWithInput(bin, args string, input io.Reader, err *error) string {
	if *err != nil {
		return ""
	}
	cmd := exec.Command(bin, strings.Split(args, " ")...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("VAULT_ADDR=%s", p.ListenAddr),
		fmt.Sprintf("VAULT_TOKEN=%s", p.RootToken),
		fmt.Sprintf("CADIR=%s", p.CADir))
	if input != nil {
		cmd.Stdin = input
	}
	out, cerr := cmd.CombinedOutput()
	if cerr != nil {
		*err = fmt.Errorf("cmd '%s %s' failed, %s, %v", bin, args, string(out), cerr.Error())
		return string(out)
	}
	return string(out)
}

func (p *Vault) mapVals(resp string) map[string]string {
	vals := make(map[string]string)
	for _, line := range strings.Split(resp, "\n") {
		pair := strings.Fields(strings.TrimSpace(line))
		if len(pair) != 2 {
			continue
		}
		vals[pair[0]] = pair[1]
	}
	return vals
}

func (p *Vault) StartLocalRoles() (*VaultRoles, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if p.CADir == "" {
		p.CADir = dir + "/vault_pki"
	}
	rolesfile := dir + "/roles.yaml"
	err = p.StartLocal(dir+"/vault.log", WithRolesFile(rolesfile))
	if err != nil {
		return nil, err
	}

	// rolesfile contains the roleIDs/secretIDs needed to access vault
	dat, err := ioutil.ReadFile(rolesfile)
	if err != nil {
		p.StopLocal()
		return nil, err
	}
	roles := VaultRoles{}
	err = yaml.Unmarshal(dat, &roles)
	if err != nil {
		p.StopLocal()
		return nil, err
	}
	return &roles, nil
}

// Vault is already started by edge-cloud setup file.
func SetupVault(p *Vault, opts ...StartOp) (*VaultRoles, error) {
	var err error
	mcormSecret := "mc-secret"

	// run global setup script
	gopath := os.Getenv("GOPATH")
	setup := gopath + "/src/github.com/edgexr/edge-cloud-platform/pkg/vault/setup.sh"
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
	fileName := gopath + "/src/github.com/edgexr/edge-cloud-platform/e2e-tests/data/gddt_qos_session_api_key.txt"
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
		setup := gopath + "/src/github.com/edgexr/edge-cloud-platform/pkg/vault/setup-region.sh " + region
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
	options := StartOptions{}
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