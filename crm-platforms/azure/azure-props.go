package azure

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/accessapi"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
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

func (a *AzurePlatform) GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetProviderSpecificProps")
	return azureProps, nil
}

func (a *AzurePlatform) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AzurePlatform GetAccessData", "dataType", dataType)
	switch dataType {
	case accessapi.GetCloudletAccessVars:
		vars, err := infracommon.GetEnvVarsFromVault(ctx, vaultConfig, azureVaultPath)
		if err != nil {
			return nil, err
		}
		return vars, nil
	}
	return nil, fmt.Errorf("Azure unhandled GetAccessData type %s", dataType)
}

func (a *AzurePlatform) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {
	accessVars, err := accessApi.GetCloudletAccessVars(ctx)
	if err != nil {
		return err
	}
	a.accessVars = accessVars
	return nil
}
