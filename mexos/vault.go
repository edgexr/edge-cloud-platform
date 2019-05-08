package mexos

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/mitchellh/mapstructure"
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

func GetVaultData(keyURL string) (map[string]interface{}, error) {
	roleID := os.Getenv("VAULT_ROLE_ID")
	secretID := os.Getenv("VAULT_SECRET_ID")

	if roleID == "" {
		return nil, fmt.Errorf("VAULT_ROLE_ID env var missing")
	}
	if secretID == "" {
		return nil, fmt.Errorf("VAULT_SECRET_ID env var missing")
	}
	uri, err := url.ParseRequestURI(keyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid keypath %s, %v", keyURL, err)
	}
	addr := uri.Scheme + "://" + uri.Host
	client, err := vault.NewClient(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to set up Vault client for %s, %v", addr, err)
	}
	err = vault.AppRoleLogin(client, roleID, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to login to Vault, %v", err)
	}
	path := strings.TrimPrefix(uri.Path, "/v1")
	data, err := vault.GetKV(client, path, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get values for %s from Vault, %v", path, err)
	}
	return data, nil
}

func GetVaultEnv(data map[string]interface{}) (*VaultEnvData, error) {
	envData := &VaultEnvData{}
	err := mapstructure.WeakDecode(data["data"], envData)
	if err != nil {
		return nil, err
	}
	return envData, nil
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
		//log.DebugLog(log.DebugLevelMexos, "setenv", "name", e.Name, "value", val)
	}
	return nil
}

func InternVaultEnv(keyURL string) error {
	log.DebugLog(log.DebugLevelMexos, "interning vault", "keyURL", keyURL)
	dat, err := GetVaultData(keyURL)
	if err != nil {
		return err
	}
	envData, err := GetVaultEnv(dat)
	if err != nil {
		return err
	}
	err = internEnv(envData.Env)
	if err != nil {
		return err
	}
	return nil
}
