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

package accessvars

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestValidateAccessVars(t *testing.T) {
	props := map[string]*edgeproto.PropertyInfo{
		"URL": {
			Name:      "access URL",
			Mandatory: true,
		},
		"clientkey": {
			Name:      "authentication client key",
			Mandatory: true,
		},
		"clientsecret": {
			Name:      "authentication client secret",
			Mandatory: true,
		},
		"domain": {
			Name: "domain name",
		},
		"apiversion": {
			Name:  "api version",
			Value: "3",
		},
	}

	tests := []struct {
		desc   string
		vars   map[string]string
		expErr string
	}{{
		"valid vars",
		map[string]string{
			"URL":          "foo",
			"clientkey":    "abc",
			"clientsecret": "def",
		}, "",
	}, {
		"missing required",
		map[string]string{
			"clientkey":    "abc",
			"clientsecret": "def",
		}, "Missing required",
	}, {
		"invalid var specified",
		map[string]string{
			"URL":          "foo",
			"clientkey":    "abc",
			"clientsecret": "def",
			"domainx":      "len.com",
		}, "Invalid access vars",
	}}
	for _, test := range tests {
		err := ValidatePropVars(test.vars, props, "access")
		if test.expErr == "" {
			require.Nil(t, err, test.desc)
		} else {
			require.Contains(t, err.Error(), test.expErr, test.desc)
		}
	}
}

func TestAccessVars(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	vaultAddr := "TestAccessVars"
	vaultCluster, vaultClient := testutil.NewVaultTestClusterBasic(t, vaultAddr)
	defer vaultCluster.Cleanup()

	region := "local"
	testutil.VaultMountTotp(t, vaultClient, region)

	vaultConfig := vault.NewUnitTestConfig(vaultAddr, vaultClient)

	// Run tests against Vault
	testCloudletAccessVars(t, ctx, vaultConfig)
	testCloudletTotp(t, ctx, vaultConfig, region)
	testAppRegistryAuth(t, ctx, vaultConfig)
}

func testCloudletAccessVars(t *testing.T, ctx context.Context, vaultConfig *vault.Config) {
	vars := map[string]string{
		"URL":          "https://foo.net/api/v3",
		"clientkey":    "abc",
		"clientsecret": "def$fx.&1!^%123[]/@",
		"domain":       "abc def",
	}
	cloudlet := &testutil.CloudletData()[0]
	region := "local"
	numVars := len(vars)

	// check func
	check := func(expVars map[string]string) {
		varsOut, err := GetCloudletAccessVars(ctx, region, cloudlet, vaultConfig)
		if err != nil && vault.IsErrUpgradingNonVersionedToVersionedData(err) {
			time.Sleep(time.Second)
			varsOut, err = GetCloudletAccessVars(ctx, region, cloudlet, vaultConfig)
		}
		if expVars == nil {
			require.NotNil(t, err)
			require.True(t, vault.IsErrNoSecretsAtPath(err))
			return
		}
		require.Nil(t, err)
		require.Equal(t, len(vars), len(varsOut))
		require.Equal(t, numVars, len(varsOut))
		for k, v := range vars {
			vOut := varsOut[k]
			require.Equal(t, v, vOut, "value should match for key "+k)
		}
	}
	// errString is used for printing hashicorp wrapped error,
	// otherwise error printed by required is not useful.
	errString := func(err error) string {
		if err == nil {
			return ""
		}
		return err.Error()
	}

	// No vars to begin with
	check(nil)

	// Write vars to Vault
	err := SaveCloudletAccessVars(ctx, region, cloudlet, vaultConfig, vars, nil)
	require.Nil(t, err, errString(err))
	check(vars)

	// Update vars in Vault
	updateVars := map[string]string{
		"clientsecret": "!adf*#*&$3vEF9X93&3",
	}
	_, err = UpdateCloudletAccessVars(ctx, region, cloudlet, vaultConfig, updateVars, nil)
	require.Nil(t, err, errString(err))
	for k, v := range updateVars {
		vars[k] = v
	}
	check(vars)

	// Test ListData
	paths, err := vault.ListData(vaultConfig, "secret", "", true)
	require.Nil(t, err)
	expPaths := []string{
		strings.TrimPrefix(getCloudletAccessVarsPath(region, cloudlet), "secret/data/"),
	}
	require.Equal(t, expPaths, paths)

	// Delete vars from Vault.
	err = DeleteCloudletAccessVars(ctx, region, cloudlet, vaultConfig)
	require.Nil(t, err, errString(err))
	check(nil)

	// ListData should be empty
	paths, err = vault.ListData(vaultConfig, "secret", "", true)
	require.Nil(t, err)
	require.Equal(t, []string{}, paths)
}

func testAppRegistryAuth(t *testing.T, ctx context.Context, vaultConfig *vault.Config) {
	appKey := &edgeproto.AppKey{
		Organization: "testorg",
		Name:         "testapp",
		Version:      "1.0.0",
	}
	region := "local"

	check := func(expAuth *cloudcommon.RegistryAuth) {
		authOut, err := cloudcommon.GetAppRegistryAuth(ctx, region, *appKey, vaultConfig)
		if expAuth == nil {
			require.NotNil(t, err)
			require.True(t, vault.IsErrNoSecretsAtPath(err))
			return
		}
		require.Nil(t, err)
		require.Equal(t, expAuth, authOut)
	}

	// No vars to begin with
	check(nil)

	// Write vars to Vault
	auth := &cloudcommon.RegistryAuth{
		AuthType: cloudcommon.BasicAuth,
		Username: "user1",
		Password: "mycreds",
		Hostname: "ghcr.io",
		Port:     "",
	}
	err := cloudcommon.SaveAppRegistryAuth(ctx, region, *appKey, vaultConfig, auth)
	require.Nil(t, err)
	check(auth)

	// Update vars in Vault
	auth.Password = "newcreds"
	err = cloudcommon.SaveAppRegistryAuth(ctx, region, *appKey, vaultConfig, auth)
	require.Nil(t, err)
	check(auth)

	// Delete vars from Vault
	err = cloudcommon.DeleteAppRegistryAuth(ctx, region, *appKey, vaultConfig)
	require.Nil(t, err)
	check(nil)
}
