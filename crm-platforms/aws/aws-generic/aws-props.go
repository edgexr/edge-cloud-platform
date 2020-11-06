package awsgeneric

import (
	"context"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

const AwsDefaultVaultPath string = "/secret/data/cloudlet/aws/credentials"
const ArnAccountIdIdx = 4

var AWSProps = map[string]*edgeproto.PropertyInfo{
	"AWS_REGION": {
		Name:        "AWS Region",
		Description: "AWS Region",
		Mandatory:   true,
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

func (a *AwsGenericPlatform) GetProviderSpecificProps(ctx context.Context, pfconfig *pf.PlatformConfig, vaultConfig *vault.Config) (map[string]*edgeproto.PropertyInfo, error) {
	return AWSProps, nil
}

func (a *AwsGenericPlatform) GetUserAccountIdFromArn(ctx context.Context, arn string) (string, error) {
	arns := strings.Split(arn, ":")
	if len(arns) <= ArnAccountIdIdx {
		log.SpanLog(ctx, log.DebugLevelInfra, "Wrong number of fields in ARN", "iamResult.User.Arn", arn)
		return "", fmt.Errorf("Cannot parse IAM ARN: %s", arn)
	}
	return arns[ArnAccountIdIdx], nil
}
