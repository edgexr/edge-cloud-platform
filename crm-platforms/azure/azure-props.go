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

func (a *AzurePlatform) GetAzureLocation() string {
	val, _ := a.properties.GetValue("MEX_AZURE_LOCATION")
	return val
}

func (a *AzurePlatform) GetAzureUser() string {
	val, _ := a.properties.GetValue("MEX_AZURE_USER")
	return val
}

func (a *AzurePlatform) GetAzurePass() string {
	val, _ := a.properties.GetValue("MEX_AZURE_PASS")
	return val
}

func (a *AzurePlatform) GetProviderSpecificProps(ctx context.Context, vaultConfig *vault.Config) (map[string]*edgeproto.PropertyInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetProviderSpecificProps")
	err := infracommon.InternVaultEnv(ctx, vaultConfig, azureVaultPath)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to intern vault data", "err", err)
		err = fmt.Errorf("cannot intern vault data from vault %s", err.Error())
		return nil, err
	}
	return azureProps, nil
}
