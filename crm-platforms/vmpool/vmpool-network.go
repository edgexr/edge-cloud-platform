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

	ssh "github.com/mobiledgex/golang-ssh"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/edgeproto"
)

func (o *VMPoolPlatform) GetRouterDetail(ctx context.Context, routerName string) (*vmlayer.RouterDetail, error) {
	return nil, fmt.Errorf("Router not supported for VM Pool platform")
}

func (o *VMPoolPlatform) GetInternalPortPolicy() vmlayer.InternalPortAttachPolicy {
	return vmlayer.AttachPortNotSupported
}

func (o *VMPoolPlatform) ValidateAdditionalNetworks(ctx context.Context, additionalNets map[string]vmlayer.NetworkType) error {
	return fmt.Errorf("Additional networks not supported in VMPool cloudlets")
}

func (v *VMPoolPlatform) ConfigureCloudletSecurityRules(ctx context.Context, egressRestricted bool, TrustPolicy *edgeproto.TrustPolicy, rootlbClients map[string]ssh.Client, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (v *VMPoolPlatform) ConfigureTrustPolicyExceptionSecurityRules(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, rootLbClients map[string]ssh.Client, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Platform not supported for TrustPolicyException SecurityRules")
}
