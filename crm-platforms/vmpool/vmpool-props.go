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

package vmpool

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
)

var VMPoolProps = map[string]*edgeproto.PropertyInfo{
	"MEX_ROUTER": {
		Name:        "External Router Type",
		Description: vmlayer.GetSupportedRouterTypes(),
		// For VMPool, we don't mess with internal networking
		Value: vmlayer.NoConfigExternalRouter,
	},
}

func (o *VMPoolPlatform) GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error) {
	return VMPoolProps, nil
}

func (o *VMPoolPlatform) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {
	return nil
}

func (o *VMPoolPlatform) GetVaultCloudletAccessPath(key *edgeproto.CloudletKey, region, physicalName string) string {
	return ""
}

func (o *VMPoolPlatform) GetExternalGateway(ctx context.Context, extNetName string) (string, error) {
	if val, ok := o.VMProperties.CommonPf.Properties.GetValue("MEX_EXTERNAL_NETWORK_GATEWAY"); ok {
		return val, nil
	}
	return "", fmt.Errorf("Unable to find MEX_EXTERNAL_NETWORK_GATEWAY")
}
