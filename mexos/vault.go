package mexos

import (
	"context"
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
		//log.SpanLog(ctx,log.DebugLevelMexos, "setenv", "name", e.Name, "value", val)
	}
	return nil
}

func InternVaultEnv(ctx context.Context, config *vault.Config, path string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "interning vault", "addr", config.Addr, "path", path)
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
	log.DebugLog(log.DebugLevelMexos, "get vault data to file", "addr", config.Addr, "path", path, "file", fileName)
	vaultData := &VaultData{}
	err := vault.GetData(config, path, 0, vaultData)
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
