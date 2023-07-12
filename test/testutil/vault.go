package testutil

import (
	"encoding/pem"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/process"
	kv "github.com/hashicorp/vault-plugin-secrets-kv"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/builtin/audit/file"
	"github.com/hashicorp/vault/builtin/credential/approle"
	"github.com/hashicorp/vault/builtin/logical/pki"
	"github.com/hashicorp/vault/builtin/logical/ssh"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// NewVaultTestClusterBasic starts a basic in-memory test vault.
// Returns test cluster and client. Call cluster.Cleanup() when done.
func NewVaultTestClusterBasic(t *testing.T, listenAddr string) (*vault.TestCluster, *api.Client) {
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"kv":  kv.Factory,
			"pki": pki.Factory,
			"ssh": ssh.Factory,
		},
		CredentialBackends: map[string]logical.Factory{
			"approle": approle.Factory,
		},
		AuditBackends: map[string]audit.Factory{
			"file": file.Factory,
		},
		LogLevel: "debug",
	}
	listenAddr = strings.TrimPrefix(listenAddr, "https://")
	listenAddr = strings.TrimPrefix(listenAddr, "http://")
	options := &vault.TestClusterOptions{
		NumCores:          1,
		BaseListenAddress: listenAddr,
		HandlerFunc:       vaulthttp.Handler,
	}
	cluster := vault.NewTestCluster(t, coreConfig, options)
	cluster.Start()
	vault.TestWaitActive(t, cluster.Cores[0].Core)

	client := cluster.Cores[0].Client
	// set default /secret kv-store to version 2
	err := client.Sys().TuneMount("secret", api.MountConfigInput{
		Options: map[string]string{
			"version": "2",
		},
	})
	require.Nil(t, err)

	return cluster, client
}

// Start an in-memory test vault. Returns test cluster, vault roles, and cleanup func.
func NewVaultTestCluster(t *testing.T, p *process.Vault) (*vault.TestCluster, *process.VaultRoles, func()) {
	t.Helper()

	dir, err := os.Getwd()
	require.Nil(t, err)
	if p.CADir == "" {
		p.CADir = dir + "/vault_pki"
	}
	rolesfile := dir + "/roles.yaml"

	cluster, _ := NewVaultTestClusterBasic(t, p.ListenAddr)
	defer func() {
		if err != nil {
			cluster.Cleanup()
		}
	}()

	// write out server CA cert so client can use https
	vaultCAFile := "vaultca.pem"
	certOut, err := os.Create(vaultCAFile)
	require.Nil(t, err)
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cluster.CACertBytes})
	require.Nil(t, err)
	err = certOut.Close()
	require.Nil(t, err)
	p.RunCACert = vaultCAFile
	p.RootToken = cluster.RootToken
	os.Setenv("VAULT_CACERT", vaultCAFile)

	// vault setup
	err = p.Setup(process.WithRolesFile(rolesfile))
	require.Nil(t, err)

	// rolesfile contains the roleIDs/secretIDs needed to access vault
	var dat []byte
	dat, err = ioutil.ReadFile(rolesfile)
	require.Nil(t, err)
	roles := process.VaultRoles{}
	err = yaml.Unmarshal(dat, &roles)
	require.Nil(t, err)
	cleanupFunc := func() {
		cluster.Cleanup()
		os.Unsetenv("VAULT_CACERT")
		os.Remove(vaultCAFile)
		os.Remove(rolesfile)
		os.RemoveAll("vault_pki")
	}

	return cluster, &roles, cleanupFunc
}
