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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	awsgen "github.com/edgexr/edge-cloud-platform/pkg/platform/aws/aws-generic"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/vmlayer"
	"github.com/edgexr/edge-cloud-platform/pkg/syncdata"
)

type AwsEc2Platform struct {
	awsGenPf        *awsgen.AwsGenericPlatform
	VMProperties    *vmlayer.VMProperties
	BaseImageId     string
	AmiIamAccountId string
	caches          *platform.Caches
	VpcCidr         string
	reservedSubnets syncdata.SyncReservations
}

func NewPlatform() platform.Platform {
	return &vmlayer.VMPlatform{
		VMProvider: &AwsEc2Platform{},
	}
}

func (o *AwsEc2Platform) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:               platform.PlatformTypeAWSEC2,
		SupportsMultiTenantCluster: true,
		RequiresCrmOnEdge:          true, // need to make sure orchVmLock is not needed
		Properties:                 awsgen.AWSProps,
		ResourceQuotaProperties:    cloudcommon.CommonResourceQuotaProps,
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
