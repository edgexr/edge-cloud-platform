package openstack

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

func (o *OpenstackPlatform) GetOpenRCVars(ctx context.Context, key *edgeproto.CloudletKey, region, physicalName string, vaultConfig *vault.Config) error {
	if vaultConfig == nil || vaultConfig.Addr == "" {
		return fmt.Errorf("vaultAddr is not specified")
	}
	openRCPath := vmlayer.GetVaultCloudletAccessPath(key, region, o.GetType(), physicalName, o.GetApiAccessFilename())
	log.SpanLog(ctx, log.DebugLevelInfra, "interning vault", "addr", vaultConfig.Addr, "path", openRCPath)
	envData := &infracommon.VaultEnvData{}
	err := vault.GetData(vaultConfig, openRCPath, 0, envData)
	if err != nil {
		if strings.Contains(err.Error(), "no secrets") {
			return fmt.Errorf("Failed to source access variables as '%s/%s' "+
				"does not exist in secure secrets storage (Vault)",
				key.Organization, physicalName)
		}
		return fmt.Errorf("Failed to source access variables from %s, %s: %v", vaultConfig.Addr, openRCPath, err)
	}
	o.openRCVars = make(map[string]string, 1)
	for _, envData := range envData.Env {
		o.openRCVars[envData.Name] = envData.Value
	}
	if authURL, ok := o.openRCVars["OS_AUTH_URL"]; ok {
		if strings.HasPrefix(authURL, "https") {
			if certData, ok := o.openRCVars["OS_CACERT_DATA"]; ok {
				certFile := vmlayer.GetCertFilePath(key)
				err = ioutil.WriteFile(certFile, []byte(certData), 0644)
				if err != nil {
					return err
				}
				o.openRCVars["OS_CACERT"] = certFile
			}
		}
	}
	return nil
}

func (o *OpenstackPlatform) GetProviderSpecificProps() map[string]*edgeproto.PropertyInfo {
	return map[string]*edgeproto.PropertyInfo{}
}

func (o *OpenstackPlatform) InitApiAccessProperties(ctx context.Context, key *edgeproto.CloudletKey, region, physicalName string, vaultConfig *vault.Config, vars map[string]string) error {
	err := o.GetOpenRCVars(ctx, key, region, physicalName, vaultConfig)
	if err != nil {
		return err
	}
	return nil
}

func (o *OpenstackPlatform) GetApiAccessFilename() string {
	return "openrc.json"
}

func (o *OpenstackPlatform) GetCloudletProjectName() string {
	if val, ok := o.openRCVars["OS_PROJECT_NAME"]; ok {
		return val
	}
	return ""
}
