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

package vault

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
)

type EnvData struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type VaultEnvData struct {
	Env []EnvData `json:"env"`
}

type PublicCert struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	TTL  int64  `json:"ttl"` // in seconds
}

func IsErrNoSecretsAtPath(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "no secrets at path")
}

func GetData(config *Config, path string, version int, data interface{}) error {
	if config == nil {
		return fmt.Errorf("no vault Config specified")
	}
	if config.Addr == UnitTestIgnoreVaultAddr {
		return nil
	}
	client, err := config.Login()
	if err != nil {
		return err
	}
	vdat, err := GetKV(client, path, version)
	if err != nil {
		return err
	}
	return mapstructure.WeakDecode(vdat["data"], data)
}

// SplitKVPath splits a full path into it's mount, type, and path
// components. Type is either "data" or "metadata".
func SplitKVPath(fullpath string) (mount, typ, path string, err error) {
	fullpath = strings.TrimPrefix(fullpath, "/")
	parts := strings.SplitN(fullpath, "/", 3)
	if len(parts) == 2 {
		return parts[0], parts[1], "", nil
	} else if len(parts) == 3 {
		return parts[0], parts[1], parts[2], nil
	}
	return "", "", "", fmt.Errorf("Vault KV path %s cannot be split into mount path, data type, and secret path", fullpath)
}

func ensureKVDataPath(path string) (string, error) {
	return ensureKVPath(path, "data")
}

func ensureKVMetadataPath(path string) (string, error) {
	return ensureKVPath(path, "metadata")
}

func ensureKVPath(path, typ string) (string, error) {
	mount, _, secret, err := SplitKVPath(path)
	if err != nil {
		return path, err
	}
	return mount + "/" + typ + "/" + secret, nil
}

const NoCheckAndSet = -1

func PutData(config *Config, path string, data interface{}) error {
	return PutDataCAS(config, path, data, NoCheckAndSet)
}

func DeleteData(config *Config, path string) error {
	if config == nil {
		return fmt.Errorf("no vault Config specified")
	}
	if config.Addr == UnitTestIgnoreVaultAddr {
		return nil
	}
	client, err := config.Login()
	if err != nil {
		return err
	}
	// For delete, path must be metadata, not data
	// Note that approle may need explicit perms for the
	// metadata path.
	path, err = ensureKVMetadataPath(path)
	if err != nil {
		return err
	}
	return DeleteKV(client, path)
}

// Check and set:
// -1 to ignore
// 0: write only allowed if key doesn't exist
// 1+: write only allowed if cas matches the current version of the secret
func PutDataCAS(config *Config, path string, data interface{}, checkAndSet int) error {
	client, err := config.Login()
	if err != nil {
		return err
	}
	if config.Addr == UnitTestIgnoreVaultAddr {
		return nil
	}
	vdata := map[string]interface{}{
		"data": data,
	}
	if checkAndSet != NoCheckAndSet {
		vdata["options"] = map[string]interface{}{
			"cas": checkAndSet,
		}
	}
	out, err := json.Marshal(vdata)
	if err != nil {
		return fmt.Errorf("Failed to marshal data to json: %v", err)
	}

	var vaultData map[string]interface{}
	err = json.Unmarshal(out, &vaultData)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal json to vault data: %v", err)
	}
	return PutKV(client, path, vaultData)
}

func IsCheckAndSetError(err error) bool {
	if err != nil && strings.Contains(err.Error(), "check-and-set parameter did not match the current version") {
		return true
	}
	return false
}

// ListData lists which secrets are under the given path directory.
// NB: None of the services actually have "list" permissions in their
// approles so this can't be used at the moment.
func ListData(config *Config, mountPath, path string, recurse bool) ([]string, error) {
	if config == nil {
		return nil, fmt.Errorf("no vault Config specified")
	}
	if config.Addr == UnitTestIgnoreVaultAddr {
		return []string{}, nil
	}
	client, err := config.Login()
	if err != nil {
		return nil, err
	}
	if path == "/" {
		path = ""
	}
	// listing is done via the metadata, not the data
	listPath := mountPath + "/metadata/" + path
	if !strings.HasSuffix(listPath, "/") {
		// directories have a trailing slash. If the user
		// passed this path directly, assume they intended to
		// specify a directory.
		listPath += "/"
	}
	secret, err := client.Logical().List(listPath)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	if secret == nil || secret.Data == nil {
		return paths, nil
	}
	keys, ok := secret.Data["keys"]
	if !ok {
		return paths, nil
	}
	subpaths, ok := keys.([]interface{})
	if !ok {
		return paths, nil
	}
	for _, subpath := range subpaths {
		if subpathStr, ok := subpath.(string); ok {
			// if it ends with a "/", it's a directory
			// otherwise, it's a secret.
			fullPath := path + subpathStr
			if strings.HasSuffix(subpathStr, "/") {
				if recurse {
					sublist, err := ListData(config, mountPath, fullPath, recurse)
					if err != nil {
						return paths, err
					}
					paths = append(paths, sublist...)
				}
			} else {
				paths = append(paths, fullPath)
			}
		}
	}
	return paths, nil
}

func GetEnvVars(config *Config, path string) (map[string]string, error) {
	envData := &VaultEnvData{}
	err := GetData(config, path, 0, envData)
	if err != nil {
		return nil, err
	}
	vars := make(map[string]string, 1)
	for _, envData := range envData.Env {
		vars[envData.Name] = envData.Value
	}
	return vars, nil
}

func GetPublicCert(config *Config, commonName string) (*PublicCert, error) {
	if config == nil {
		return nil, fmt.Errorf("no vault Config specified")
	}
	client, err := config.Login()
	if err != nil {
		return nil, err
	}
	// vault client default timeout is 60 sec, but certgen has a 60 sec
	// wait for DNS propagation. So increase the timeout.
	client.SetClientTimeout(2 * time.Minute)

	path := "/certs/cert/" + commonName
	vdat, err := GetKV(client, path, 0)
	if err != nil {
		return nil, err
	}
	pubCert := &PublicCert{}
	err = mapstructure.WeakDecode(vdat, pubCert)
	if err != nil {
		return nil, err
	}
	return pubCert, nil
}
