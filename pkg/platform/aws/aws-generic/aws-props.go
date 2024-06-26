// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package awsgeneric

import (
	"context"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/vmlayer"
)

const ArnAccountIdIdx = 4

const (
	AWS_ACCESS_KEY_ID     = "AWS_ACCESS_KEY_ID"
	AWS_SECRET_ACCESS_KEY = "AWS_SECRET_ACCESS_KEY"
	AWS_TOTP_SECRET_KEY   = "aws_totp_secret_key"
)

var AccessVarProps = map[string]*edgeproto.PropertyInfo{
	AWS_ACCESS_KEY_ID: {
		Name:      "AWS access key",
		Mandatory: true,
	},
	AWS_SECRET_ACCESS_KEY: {
		Name:      "AWS secret key associated with the access key",
		Mandatory: true,
	},
	AWS_TOTP_SECRET_KEY: {
		Name:        "AWS totp secret key",
		Description: "If MFA is enabled, this is the secret key that will be used to generate RFC 6238 TOTP codes. This is the text equivalent of the TOTP QR code for authentication apps.",
		TotpSecret:  true,
	},
}

var AWSProps = map[string]*edgeproto.PropertyInfo{
	"AWS_REGION": {
		Name:        "AWS Region",
		Description: "AWS Region",
		Mandatory:   true,
	},
	// override default for flavor match pattern
	"FLAVOR_MATCH_PATTERN": &edgeproto.PropertyInfo{
		Name:        "Flavor Match Pattern",
		Description: "Flavors matching this pattern will be used by Cloudlet to bringup VMs",
		Value:       "^[acdhimrtz]\\d+", // Defaults to all standard flavors
	},
	// override default for router
	"MEX_ROUTER": {
		Name:        "External Router Type",
		Description: "AWS Router must be " + vmlayer.NoConfigExternalRouter,
		Value:       vmlayer.NoConfigExternalRouter,
	},
	"AWS_OUTPOST_VPC": {
		Name:        "AWS Outpost VPC",
		Description: "Pre-existing VPC for an outpost deployment",
	},
	"AWS_AMI_IAM_OWNER": {
		Name:        "AWS Outpost AMI Owner",
		Description: "IAM Account that owns the base image",
	},
	"AWS_OUTPOST_FLAVORS": {
		Name:        "AWS Outpost Flavors",
		Description: "AWS Outpost Flavors in format flavor1,vcpu,ram,disk;flavor2.. e.g. c5.large,2,4096,40;c5.xlarge,4,8192,40",
	},
	"AWS_USER_ARN": {
		Name:        "AWS User ARN (Amazon Resource Name)",
		Description: "AWS User ARN (Amazon Resource Name)",
	},
}

func (a *AwsGenericPlatform) GetAwsAccessKeyId() string {
	val, _ := a.AccountAccessVars[AWS_ACCESS_KEY_ID]
	return val
}

func (a *AwsGenericPlatform) GetAwsSecretAccessKey() string {
	val, _ := a.AccountAccessVars[AWS_SECRET_ACCESS_KEY]
	return val
}

func (a *AwsGenericPlatform) GetAwsRegion() string {
	val, _ := a.Properties.GetValue("AWS_REGION")
	return val
}

func (a *AwsGenericPlatform) IsAwsOutpost() bool {
	val, _ := a.Properties.GetValue("AWS_OUTPOST_VPC")
	return val != ""
}

func (a *AwsGenericPlatform) GetAwsAmiIamOwner() string {
	val, _ := a.Properties.GetValue("AWS_AMI_IAM_OWNER")
	return val
}

func (a *AwsGenericPlatform) GetAwsOutpostVPC() string {
	val, _ := a.Properties.GetValue("AWS_OUTPOST_VPC")
	return val
}

func (a *AwsGenericPlatform) GetAwsOutpostFlavors() string {
	val, _ := a.Properties.GetValue("AWS_OUTPOST_FLAVORS")
	return val
}

func (a *AwsGenericPlatform) GetAwsUserArn() string {
	val, _ := a.Properties.GetValue("AWS_USER_ARN")
	return val
}

func (a *AwsGenericPlatform) GetAwsFlavorMatchPattern() string {
	val, _ := a.Properties.GetValue("FLAVOR_MATCH_PATTERN")
	return val
}

func (a *AwsGenericPlatform) GetUserAccountIdFromArn(ctx context.Context, arn string) (string, error) {
	arns := strings.Split(arn, ":")
	if len(arns) <= ArnAccountIdIdx {
		log.SpanLog(ctx, log.DebugLevelInfra, "Wrong number of fields in ARN", "iamResult.User.Arn", arn)
		return "", fmt.Errorf("Cannot parse IAM ARN: %s", arn)
	}
	return arns[ArnAccountIdIdx], nil
}
