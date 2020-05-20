package azure

import (
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
)

var azureProps = map[string]*infracommon.PropertyInfo{
	"MEX_AZURE_LOCATION": &infracommon.PropertyInfo{
		Mandatory: true,
	},
	"MEX_AZURE_USER": &infracommon.PropertyInfo{
		Mandatory: true,
	},
	"MEX_AZURE_PASS": &infracommon.PropertyInfo{
		Secret:    true,
		Mandatory: true,
	},
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
