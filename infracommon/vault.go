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

package infracommon

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
)

type EnvData struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type VaultEnvData struct {
	Env []EnvData `json:"env"`
}

type VaultData struct {
	Data string `json:"data"`
}

var home = os.Getenv("HOME")

func interpolate(val string) string {
	if strings.HasPrefix(val, "$HOME") {
		val = strings.Replace(val, "$HOME", home, -1)
	}
	return val
}

func InternEnv(envs map[string]string) error {
	for k, v := range envs {
		val := interpolate(v)
		err := os.Setenv(k, val)
		if err != nil {
			return err
		}
	}
	return nil
}

func GetEnvVarsFromVault(ctx context.Context, config *vault.Config, path string) (map[string]string, error) {
	envData := &VaultEnvData{}
	err := vault.GetData(config, path, 0, envData)
	if err != nil {
		if strings.Contains(err.Error(), "no secrets") {
			return nil, fmt.Errorf("Failed to source access variables from '%s', does not exist in secure secrets storage (Vault)", path)
		}
		return nil, fmt.Errorf("Failed to source access variables from %s, %s: %v", config.Addr, path, err)
	}
	vars := make(map[string]string, 1)
	for _, envData := range envData.Env {
		vars[envData.Name] = envData.Value
	}
	return vars, nil
}

// Get data from Vault as a string
func GetVaultDataString(ctx context.Context, config *vault.Config, path string) ([]byte, error) {
	vaultData := &VaultData{}
	err := vault.GetData(config, path, 0, vaultData)
	if err != nil {
		return nil, err
	}
	return []byte(vaultData.Data), nil
}

func GetVaultDataToFile(config *vault.Config, path, fileName string) error {
	log.DebugLog(log.DebugLevelInfra, "get vault data to file", "addr", config.Addr, "path", path, "file", fileName)
	vaultData := &VaultData{}
	err := vault.GetData(config, path, 0, vaultData)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fileName, []byte(vaultData.Data), 0644)
	if err != nil {
		return err
	}

	log.DebugLog(log.DebugLevelInfra, "vault data imported to file successfully")
	return nil
}

func PutDataToVault(config *vault.Config, path string, data map[string]interface{}) error {
	client, err := config.Login()
	if err != nil {
		return err
	}
	out, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("Failed to marshal data to json: %v", err)
	}

	var vaultData map[string]interface{}
	err = json.Unmarshal(out, &vaultData)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal json to vault data: %v", err)
	}
	return vault.PutKV(client, path, vaultData)
}

func DeleteDataFromVault(config *vault.Config, path string) error {
	client, err := config.Login()
	if err != nil {
		return err
	}
	// Deleting metadata will delete all version of data
	metadataPath := strings.Replace(path, "secret/data", "secret/metadata", -1)
	return vault.DeleteKV(client, metadataPath)
}
