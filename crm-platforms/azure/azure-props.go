package azure

import (
	"context"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

var azureProps = map[string]*edgeproto.PropertyInfo{
	"MEX_AZURE_LOCATION": &edgeproto.PropertyInfo{
		Name:        "Azure Location",
		Description: "Azure Location",
		Mandatory:   true,
	},
	"MEX_AZURE_USER": &edgeproto.PropertyInfo{
		Name:        "Azure User",
		Description: "Azure User",
		Mandatory:   true,
		Internal:    true,
	},
	"MEX_AZURE_PASS": &edgeproto.PropertyInfo{
		Name:        "Azure Password",
		Description: "Azure Password",
		Secret:      true,
		Mandatory:   true,
		Internal:    true,
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

func (a *AzurePlatform) GetCloudletProps(ctx context.Context) (*edgeproto.CloudletProps, error) {
	return &edgeproto.CloudletProps{Properties: azureProps}, nil
}
