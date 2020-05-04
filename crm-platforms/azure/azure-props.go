package azure

import (
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
)

var azureProps = map[string]*infracommon.PropertyInfo{
	"MEX_AZURE_LOCATION": &infracommon.PropertyInfo{},
	"MEX_AZURE_USER":     &infracommon.PropertyInfo{},
	"MEX_AZURE_PASS": &infracommon.PropertyInfo{
		Secret: true, //TODO, this prints in openstack startup because these props are not loaded
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
