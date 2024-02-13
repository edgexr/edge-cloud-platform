// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutil

import (
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/testcluster"
	"github.com/hashicorp/vault/sdk/helper/testcluster/docker"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// NewVaultTestClusterBasic starts a basic in-memory docker test vault.
// Returns test cluster and client. Call cluster.Cleanup() when done.
func NewVaultTestClusterBasic(t *testing.T, listenAddr string) (*docker.DockerCluster, *api.Client) {
	opts := &docker.DockerClusterOptions{
		ClusterOptions: testcluster.ClusterOptions{
			ClusterName: listenAddr,
			NumCores:    1,
		},
		ImageRepo: "hashicorp/vault",
		ImageTag:  "1.11.11",
	}
	cluster := docker.NewTestDockerCluster(t, opts)

	client := cluster.Nodes()[0].APIClient()

	err := client.Sys().Mount("secret", &api.MountInput{
		Type: "kv-v2",
	})
	require.Nil(t, err)
	log.Printf("cluster at address %s\n", client.Address())
	return cluster, client
}

// This is separate because the setup-region.sh script does it as well.
func VaultMountTotp(t *testing.T, client *api.Client, region string) {
	// enable regional totp mount
	err := client.Sys().Mount(region+"/totp", &api.MountInput{
		Type: "totp",
	})
	require.Nil(t, err)
}

// Start an in-memory docker test vault. Returns test cluster, vault roles, and cleanup func.
// The input process's ListenAddr should be set to the unit test
// name, which will be used as the docker cluster's name.
// The ListenAddr will then be overwritten to whatever local
// address the cluster is listening on.
func NewVaultTestCluster(t *testing.T, p *process.Vault) (*docker.DockerCluster, *process.VaultRoles, func()) {
	t.Helper()

	dir, err := os.Getwd()
	require.Nil(t, err)
	if p.CADir == "" {
		p.CADir = dir + "/vault_pki"
	}
	rolesfile := dir + "/roles.yaml"

	cluster, client := NewVaultTestClusterBasic(t, p.ListenAddr)
	defer func() {
		if err != nil {
			cluster.Cleanup()
		}
	}()
	p.ListenAddr = client.Address()

	// write out server CA cert so client can use https
	vaultCAFile := "vaultca.pem"
	certOut, err := os.Create(vaultCAFile)
	require.Nil(t, err)
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cluster.CACertBytes})
	require.Nil(t, err)
	err = certOut.Close()
	require.Nil(t, err)
	p.RunCACert = vaultCAFile
	p.RootToken = cluster.GetRootToken()
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
