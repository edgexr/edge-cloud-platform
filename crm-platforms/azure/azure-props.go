package azure

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

const azureVaultPath string = "/secret/data/cloudlet/azure/credentials"

var azureProps = map[string]*edgeproto.PropertyInfo{
	"MEX_AZURE_LOCATION": {
		Name:        "Azure Location",
		Description: "Azure Location",
		Mandatory:   true,
	},
	"MEX_AZURE_USER": {
		Name:        "Azure User",
		Description: "Azure User",
		Mandatory:   true,
		Internal:    true,
	},
	"MEX_AZURE_PASS": {
		Name:        "Azure Password",
		Description: "Azure Password",
		Secret:      true,
		Mandatory:   true,
		Internal:    true,
	},
}

func (a *AzurePlatform) GetK8sProviderSpecificProps() map[string]*edgeproto.PropertyInfo {
	return azureProps
}

func (a *AzurePlatform) GetAzureLocation() string {
	if val, ok := a.commonPf.Properties["MEX_AZURE_LOCATION"]; ok {
		return val.Value
	}
	return ""
}

func (a *AzurePlatform) GetAzureUser() string {
	if val, ok := a.commonPf.Properties["MEX_AZURE_USER"]; ok {
		return val.Value
	}
	return ""
}

func (a *AzurePlatform) GetAzurePass() string {
	if val, ok := a.commonPf.Properties["MEX_AZURE_PASS"]; ok {
		return val.Value
	}
	return ""
}

func (a *AzurePlatform) InitApiAccessProperties(ctx context.Context, region string, vaultConfig *vault.Config, vars map[string]string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitApiAccessProperties")
	err := infracommon.InternVaultEnv(ctx, vaultConfig, azureVaultPath)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to intern vault data for API access", "err", err)
		err = fmt.Errorf("cannot intern vault data from vault %s", err.Error())
		return err
	}
	return nil
}
