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

package openstack

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

type ReservedResources struct {
	FloatingIpIds map[string]string
	Subnets       map[string]string
}

func (o *OpenstackPlatform) InitResourceReservations(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitResourceReservations")
	syncFactory := o.VMProperties.CommonPf.PlatformConfig.SyncFactory
	o.reservedFloatingIPs = syncFactory.NewSyncReservations("floating-ips")
	o.reservedSubnets = syncFactory.NewSyncReservations("subnets")
}
