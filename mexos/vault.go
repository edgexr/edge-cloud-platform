package mexos

import (
	"io/ioutil"
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

type VaultData struct {
	Data string `json:"data"`
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
	dat, err := vault.GetVaultData(keyURL)
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

func GetVaultDataToFile(keyURL, fileName string) error {
	log.DebugLog(log.DebugLevelMexos, "get vault data to file", "keyURL", keyURL, "file", fileName)
	dat, err := vault.GetVaultData(keyURL)
	if err != nil {
		return err
	}
	vaultData := &VaultData{}
	err = mapstructure.WeakDecode(dat["data"], vaultData)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fileName, []byte(vaultData.Data), 0644)
	if err != nil {
		return err
	}

	log.DebugLog(log.DebugLevelMexos, "vault data imported to file successfully")

	return nil
}
