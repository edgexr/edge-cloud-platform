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

package awsec2

import (
	"context"
	"fmt"

	awsgen "github.com/edgexr/edge-cloud-infra/crm-platforms/aws/aws-generic"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

type AwsEc2Platform struct {
	awsGenPf        *awsgen.AwsGenericPlatform
	VMProperties    *vmlayer.VMProperties
	BaseImageId     string
	AmiIamAccountId string
	caches          *platform.Caches
	VpcCidr         string
}

func (o *AwsEc2Platform) GetFeatures() *platform.Features {
	return &platform.Features{
		SupportsMultiTenantCluster: true,
	}
}

func (a *AwsEc2Platform) NameSanitize(name string) string {
	return name
}

// AwsEc2Platform IdSanitize is the same as NameSanitize
func (a *AwsEc2Platform) IdSanitize(name string) string {
	return a.NameSanitize(name)
}

func (a *AwsEc2Platform) SetVMProperties(vmProperties *vmlayer.VMProperties) {
	vmProperties.UseSecgrpForInternalSubnet = true
	vmProperties.RequiresWhitelistOwnIp = true
	a.VMProperties = vmProperties
}

func (a *AwsEc2Platform) GetInternalPortPolicy() vmlayer.InternalPortAttachPolicy {
	return vmlayer.AttachPortAfterCreate
}

func (a *AwsEc2Platform) GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error) {
	return a.awsGenPf.GetProviderSpecificProps(ctx)
}

func (a *AwsEc2Platform) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitApiAccessProperties")

	err := a.awsGenPf.GetAwsAccountAccessVars(ctx, accessApi)
	if err != nil {
		return err
	}
	return nil
}

func (a *AwsEc2Platform) InitData(ctx context.Context, caches *platform.Caches) {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitData", "AwsEc2Platform", fmt.Sprintf("%+v", a))
	a.caches = caches
	a.awsGenPf = &awsgen.AwsGenericPlatform{Properties: &a.VMProperties.CommonPf.Properties}
}

func (a *AwsEc2Platform) InitOperationContext(ctx context.Context, operationStage vmlayer.OperationInitStage) (context.Context, vmlayer.OperationInitResult, error) {
	return ctx, vmlayer.OperationNewlyInitialized, nil
}
