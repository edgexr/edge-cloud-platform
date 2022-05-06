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

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/accessapi"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
)

const AwsDefaultVaultPath string = "/secret/data/cloudlet/aws/credentials"
const ArnAccountIdIdx = 4

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
	val, _ := a.Properties.GetValue("AWS_ACCESS_KEY_ID")
	return val
}

func (a *AwsGenericPlatform) GetAwsSecretAccessKey() string {
	val, _ := a.Properties.GetValue("AWS_SECRET_ACCESS_KEY")
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

func (a *AwsGenericPlatform) GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error) {
	return AWSProps, nil
}

func (a *AwsGenericPlatform) GetSessionTokens(ctx context.Context, vaultConfig *vault.Config, account string) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "AwsGenericPlatform GetSessionTokens", "account", account)
	token, err := a.GetAwsTotpToken(ctx, vaultConfig, account)
	if err != nil {
		return nil, err
	}
	tokens := map[string]string{
		TotpTokenName: token,
	}
	return tokens, nil
}

func (a *AwsGenericPlatform) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "AwsGenericPlatform GetAccessData", "dataType", dataType)
	switch dataType {
	case accessapi.GetCloudletAccessVars:
		path := a.GetVaultCloudletAccessPath(&cloudlet.Key, region, cloudlet.PhysicalName)
		vars, err := infracommon.GetEnvVarsFromVault(ctx, vaultConfig, path)
		if err != nil {
			return nil, err
		}
		return vars, nil
	case accessapi.GetSessionTokens:
		return a.GetSessionTokens(ctx, vaultConfig, string(arg))
	}
	return nil, fmt.Errorf("AwsGeneric unhandled GetAccessData type %s", dataType)
}

func (a *AwsGenericPlatform) GetUserAccountIdFromArn(ctx context.Context, arn string) (string, error) {
	arns := strings.Split(arn, ":")
	if len(arns) <= ArnAccountIdIdx {
		log.SpanLog(ctx, log.DebugLevelInfra, "Wrong number of fields in ARN", "iamResult.User.Arn", arn)
		return "", fmt.Errorf("Cannot parse IAM ARN: %s", arn)
	}
	return arns[ArnAccountIdIdx], nil
}
