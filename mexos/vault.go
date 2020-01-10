package mexos

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/access"
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

// GetCertFromVault fills in the cert fields by calling the vault  plugin.  The vault plugin will 
// return a new cert if one is not already available, or a cached copy of an existing cert.
func GetCertFromVault(ctx context.Context, config *vault.Config, commonName string, tlsCert *access.TLSCert) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "GetCertFromVault", "commonName", commonName)
	client, err := config.Login()
	if err != nil {
		return err
	}
	// vault API uses "_" to denote wildcard
	path := "/certs/cert/" + strings.Replace(commonName, "*", "_", 1)
	result, err := vault.GetKV(client, path, 0)
	if err != nil {
		return err
	}
	var ok bool
	tlsCert.CertString, ok = result["cert"].(string)
	if !ok {
		return fmt.Errorf("No cert found in cert from vault")
	}
	tlsCert.KeyString, ok = result["key"].(string)
	if !ok {
		return fmt.Errorf("No key found in cert from vault")
	}
	ttlval, ok := result["ttl"].(json.Number)
	if !ok {
		return fmt.Errorf("ttl key found in cert from vault")
	}
	tlsCert.TTL, err = ttlval.Int64()
	if err != nil {
		return fmt.Errorf("Error in decoding TTL from vault: %v", err)
	}
	tlsCert.CommonName = commonName
	return nil
}
