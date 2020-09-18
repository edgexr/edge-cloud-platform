package infracommon

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
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

func internEnv(envs []EnvData) error {
	for _, e := range envs {
		val := interpolate(e.Value)
		err := os.Setenv(e.Name, val)
		if err != nil {
			return err
		}
		//log.SpanLog(ctx,log.DebugLevelInfra, "setenv", "name", e.Name, "value", val)
	}
	return nil
}

func InternVaultEnv(ctx context.Context, config *vault.Config, path string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "interning vault", "addr", config.Addr, "path", path)
	envData := &VaultEnvData{}
	err := vault.GetData(config, path, 0, envData)
	if err != nil {
		return err
	}
	err = internEnv(envData.Env)
	if err != nil {
		return err
	}
	return nil
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

func GetSignedKeyFromVault(config *vault.Config, data map[string]interface{}) (string, error) {
	client, err := config.Login()
	if err != nil {
		return "", err
	}
	ssh := client.SSH()
	secret, err := ssh.SignKey("machine", data)
	if err != nil {
		return "", err
	}
	signedKey, ok := secret.Data["signed_key"]
	if !ok {
		return "", fmt.Errorf("failed to get signed key from vault: %v", secret)
	}
	signedKeyStr, ok := signedKey.(string)
	if !ok {
		return "", fmt.Errorf("invalid signed key from vault: %v", signedKey)
	}

	return signedKeyStr, nil
}

type MEXKey struct {
	PrivateKey string
	PublicKey  string
}

func GetMEXKeyFromVault(vaultConfig *vault.Config) (*MEXKey, error) {
	if vaultConfig.Addr == "" {
		return &MEXKey{}, nil
	}
	vaultPath := "/secret/data/keys/id_rsa_mex"
	log.DebugLog(log.DebugLevelApi, "get mex key", "vault-path", vaultPath)
	key := &MEXKey{}
	err := vault.GetData(vaultConfig, vaultPath, 0, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get mex key for %s, %v", vaultPath, err)
	}
	return key, nil
}
