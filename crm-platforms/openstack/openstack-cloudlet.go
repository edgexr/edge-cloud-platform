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

func (o *OpenstackPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Saving cloudlet access vars to vault", "cloudletName", cloudlet.Key.Name)
	vaultConfig, err := vault.BestConfig(pfConfig.VaultAddr, vault.WithEnvMap(pfConfig.EnvVar))
	if err != nil {
		return err
	}
	openrcData, ok := accessVarsIn["OPENRC_DATA"]
	if !ok {
		return fmt.Errorf("Invalid accessvars, missing OPENRC_DATA")
	}
	out := strings.Split(openrcData, "\n")
	if len(out) <= 1 {
		return fmt.Errorf("Invalid accessvars, as OPENRC_DATA is invalid: %v", out)
	}
	accessVars := make(map[string]string)
	for _, v := range out {
		out1 := strings.Split(v, "=")
		if len(out1) != 2 {
			return fmt.Errorf("Invalid separator for key-value pair: %v", out1)
		}
		key := strings.TrimSpace(out1[0])
		value := strings.TrimSpace(out1[1])
		if !strings.HasPrefix(key, "OS_") {
			return fmt.Errorf("Invalid accessvars: %s, must start with 'OS_' prefix", key)
		}
		accessVars[key] = value
	}
	authURL, ok := accessVars["OS_AUTH_URL"]
	if !ok {
		return fmt.Errorf("Invalid accessvars, missing OS_AUTH_URL")
	}
	if strings.HasPrefix(authURL, "https") {
		certData, ok := accessVarsIn["CACERT_DATA"]
		if !ok {
			return fmt.Errorf("Invalid accessvars, missing CACERT_DATA")
		}
		certFile := vmlayer.GetCertFilePath(&cloudlet.Key)
		err := ioutil.WriteFile(certFile, []byte(certData), 0644)
		if err != nil {
			return err
		}
		accessVars["OS_CACERT"] = certFile
		accessVars["OS_CACERT_DATA"] = certData
	}
	updateCallback(edgeproto.UpdateTask, "Saving access vars to secure secrets storage (Vault)")
	var varList infracommon.VaultEnvData
	for key, value := range accessVars {
		if key == "OS_CACERT" {
			continue
		}
		varList.Env = append(varList.Env, infracommon.EnvData{
			Name:  key,
			Value: value,
		})
	}
	data := map[string]interface{}{
		"data": varList,
	}

	path := vmlayer.GetVaultCloudletAccessPath(&cloudlet.Key, pfConfig.Region, o.GetType(), cloudlet.PhysicalName, o.GetApiAccessFilename())
	err = infracommon.PutDataToVault(vaultConfig, path, data)
	if err != nil {
		updateCallback(edgeproto.UpdateTask, "Failed to save access vars to vault")
		log.SpanLog(ctx, log.DebugLevelInfra, err.Error(), "cloudletName", cloudlet.Key.Name)
		return fmt.Errorf("Failed to save access vars to vault: %v", err)
	}
	return nil
}

func (o *OpenstackPlatform) ImportDataFromInfra(ctx context.Context) error {
	// nothing to do
	return nil
}

func (o *OpenstackPlatform) GetApiEndpointAddr(ctx context.Context) (string, error) {
	osAuthUrl := o.openRCVars["OS_AUTH_URL"]
	log.SpanLog(ctx, log.DebugLevelInfra, "GetApiEndpointAddr", "authUrl", osAuthUrl)

	if osAuthUrl == "" {
		return "", fmt.Errorf("unable to find OS_AUTH_URL")
	}
	return osAuthUrl, nil
}

func (o *OpenstackPlatform) GetCloudletManifest(ctx context.Context, name string, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletManifest", "name", name, "VMGroupOrchestrationParams", VMGroupOrchestrationParams)
	err := o.populateParams(ctx, VMGroupOrchestrationParams, heatCreate)
	if err != nil {
		return "", err
	}

	buf, err := vmlayer.ExecTemplate(name, VmGroupTemplate, VMGroupOrchestrationParams)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
