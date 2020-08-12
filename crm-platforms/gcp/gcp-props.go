package gcp

import (
	"context"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

var gcpProps = map[string]*edgeproto.PropertyInfo{
	"MEX_GCP_PROJECT": &edgeproto.PropertyInfo{
		Name:        "GCP Project Name",
		Description: "Name of the GCP project",
		Value:       "still-entity-201400",
	},
	"MEX_GCP_ZONE": &edgeproto.PropertyInfo{
		Name:        "GCP Zone Name",
		Description: "Name of the GCP zone",
		Mandatory:   true,
	},
	"MEX_GCP_SERVICE_ACCOUNT": &edgeproto.PropertyInfo{
		Name:        "GCP Service Account Name",
		Description: "Name of the GCP service account",
	},
	"MEX_GCP_AUTH_KEY_PATH": &edgeproto.PropertyInfo{
		Name:        "GCP Auth Key Path",
		Description: "Path of the GCP auth key",
		Value:       "/secret/data/cloudlet/gcp/auth_key.json",
	},
}

func (a *GCPPlatform) GetGcpAuthKeyUrl() string {
	if val, ok := a.commonPf.Properties["MEX_GCP_AUTH_KEY_PATH"]; ok {
		return val.Value
	}
	return ""
}

func (a *GCPPlatform) GetGcpZone() string {
	if val, ok := a.commonPf.Properties["MEX_GCP_ZONE"]; ok {
		return val.Value
	}
	return ""
}

func (a *GCPPlatform) GetGcpProject() string {
	if val, ok := a.commonPf.Properties["MEX_GCP_PROJECT"]; ok {
		return val.Value
	}
	return ""
}

func (a *GCPPlatform) GetCloudletProps(ctx context.Context) (*edgeproto.CloudletProps, error) {
	return &edgeproto.CloudletProps{Properties: gcpProps}, nil
}
