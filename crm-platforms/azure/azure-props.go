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
	val, _ := a.commonPf.Properties.GetValue("MEX_AZURE_LOCATION")
	return val
}

func (a *AzurePlatform) GetAzureUser() string {
	val, _ := a.commonPf.Properties.GetValue("MEX_AZURE_USER")
	return val
}

func (a *AzurePlatform) GetAzurePass() string {
	val, _ := a.commonPf.Properties.GetValue("MEX_AZURE_PASS")
	return val
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
