package gcp

import (
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
)

var gcpProps = map[string]*infracommon.PropertyInfo{
	"MEX_GCP_PROJECT": &infracommon.PropertyInfo{
		Value: "still-entity-201400",
	},
	"MEX_GCP_ZONE": &infracommon.PropertyInfo{
		Mandatory: true,
	},
	"MEX_GCP_SERVICE_ACCOUNT": &infracommon.PropertyInfo{},
	"MEX_GCP_AUTH_KEY_PATH": &infracommon.PropertyInfo{
		Value: "/secret/data/cloudlet/gcp/auth_key.json",
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
