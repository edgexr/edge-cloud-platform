package mexos

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type EnvData struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type VaultDataDetail struct {
	Env []EnvData `json:"env"`
}

type VaultData struct {
	Detail VaultDataDetail `json:"data"`
}

type VaultResponse struct {
	Data VaultData `json:"data"`
}

func GetVaultData(url string) ([]byte, error) {
	vault_token := os.Getenv("VAULT_TOKEN")
	if vault_token == "" {
		res, err := ioutil.ReadFile(os.Getenv("HOME") + "/.mobiledgex/vault.txt")
		if err != nil {
			return nil, fmt.Errorf("no vault token")
		}
		vault_token = strings.TrimSpace(string(res))
		if vault_token == "" {
			return nil, fmt.Errorf("missing vault token")
		}
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", vault_token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return contents, nil
}

func GetVaultEnvResponse(contents []byte) (*VaultResponse, error) {
	vr := &VaultResponse{}
	err := yaml.Unmarshal(contents, vr)
	if err != nil {
		return nil, err
	}
	return vr, nil
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

func InternVaultEnv(openrc string, mexenv string, cloudletInfra *edgeproto.CloudletInfraProperties) error {
	log.DebugLog(log.DebugLevelMexos, "interning vault", "openrc", openrc, "mexenv", mexenv)
	for _, u := range []string{openrc, mexenv} {
		if u == "" {
			continue
		}
		dat, err := GetVaultData(u)
		if err != nil {
			return err
		}
		vr, err := GetVaultEnvResponse(dat)
		if err != nil {
			return err
		}
		if u == openrc {
			for _, e := range vr.Data.Detail.Env {
				cloudletInfra.OpenstackProperties.OpenRcVars[e.Name] = e.Value
			}
		}
		//log.DebugLog(log.DebugLevelMexos, "interning vault data", "data", vr)
		err = internEnv(vr.Data.Detail.Env)
		if err != nil {
			return err
		}
	}
	//log.DebugLog(log.DebugLevelMexos, "vault env var map", "vault env map", mf.Values.VaultEnvMap)
	return nil
}

func CheckPlatformEnv(platformType string) error {
	// if !strings.Contains(platformType, "openstack") { // TODO gcp,azure,...
	// 	log.DebugLog(log.DebugLevelMexos, "warning, unsupported, skip check platform environment", "platform", platformType)
	// 	return nil
	// }
	// for _, n := range []struct {
	// 	name   string
	// 	getter func() string
	// }{
	// 	{"MEX_EXT_NETWORK", GetCloudletExternalNetwork},
	// 	{"MEX_EXT_ROUTER", GetCloudletExternalRouter},
	// 	{"MEX_NETWORK", GetCloudletNetwork},
	// 	{"MEX_SECURITY_RULE", GetCloudletSecurityRule},
	// } {
	// 	ev := os.Getenv(n.name)
	// 	if ev == "" {
	// 		ev = n.getter()
	// 	}
	// 	if ev == "" {
	// 		return fmt.Errorf("missing " + n.name)
	// 	}
	// }
	// log.DebugLog(log.DebugLevelMexos, "doing oscli sanity check")
	// _, err := ListImages()
	// if err != nil {
	// 	return fmt.Errorf("oscli sanity check failed, %v", err)
	// }
	return nil
}

func GetVaultEnv(openrc string, mexenv string, cloudletInfra *edgeproto.CloudletInfraProperties) error {
	if err := InternVaultEnv(openrc, mexenv, cloudletInfra); err != nil {
		return err
	}
	return nil
}
