package aws

import (
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
)

var AWSProps = map[string]*infracommon.PropertyInfo{
	"AWS_ACCESS_KEY_ID": &infracommon.PropertyInfo{
		Secret:    true,
		Mandatory: true,
	},
	"AWS_SECRET_ACCESS_KEY": &infracommon.PropertyInfo{
		Secret:    true,
		Mandatory: true,
	},

	"AWS_DEFAULT_REGION": &infracommon.PropertyInfo{
		Value:     "us-west-2",
		Mandatory: true,
	},
}

func (a *AWSPlatform) GetAwsAccessKeyId() string {
	if val, ok := a.commonPf.Properties["AWS_ACCESS_KEY_ID"]; ok {
		return val.Value
	}
	return ""
}

func (a *AWSPlatform) GetAwsSecretAccessKey() string {
	if val, ok := a.commonPf.Properties["AWS_SECRET_ACCESS_KEY"]; ok {
		return val.Value
	}
	return ""
}

func (a *AWSPlatform) GetAwsDefaultRegion() string {
	if val, ok := a.commonPf.Properties["AWS_DEFAULT_REGION"]; ok {
		return val.Value
	}
	return ""
}
