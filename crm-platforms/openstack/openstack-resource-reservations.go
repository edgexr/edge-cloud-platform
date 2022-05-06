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
	"fmt"
	"strings"
	"sync"

	"github.com/edgexr/edge-cloud/log"
)

var resourceLock sync.Mutex
var ReservedFloatingIPs map[string]string
var ReservedSubnets map[string]string

type ReservedResources struct {
	FloatingIpIds []string
	Subnets       []string
}

func (o *OpenstackPlatform) InitResourceReservations(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitResourceReservations")
	resourceLock.Lock()
	defer resourceLock.Unlock()
	ReservedFloatingIPs = make(map[string]string)
	ReservedSubnets = make(map[string]string)
}

// ReserveResourcesLocked must be called from code that locks resourceLock
func (o *OpenstackPlatform) ReserveResourcesLocked(ctx context.Context, resources *ReservedResources, reservedBy string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ReserveResourcesLocked", "resources", resources, "current fips", ReservedFloatingIPs, "current subnets", ReservedSubnets)

	var err error
	var fipsToCleanupOnErr []string
	var subnetsToCleanupOnErr []string

	for _, f := range resources.FloatingIpIds {
		err = o.reserveFloatingIPLocked(ctx, f, reservedBy)
		if err != nil {
			break
		}
		fipsToCleanupOnErr = append(fipsToCleanupOnErr, f)
	}
	if err != nil {
		// Cleanup in case we reserved something and then hit an error
		for _, f := range fipsToCleanupOnErr {
			o.releaseFloatingIPLocked(ctx, f)
		}
		return err
	}
	for _, s := range resources.Subnets {
		err := o.reserveSubnetLocked(ctx, s, reservedBy)
		if err != nil {
			break
		}
		subnetsToCleanupOnErr = append(subnetsToCleanupOnErr, s)
	}
	if err != nil {
		// Cleanup in case we reserved something and then hit an error
		for _, s := range subnetsToCleanupOnErr {
			o.releaseSubnetLocked(ctx, s)
		}
		for _, f := range fipsToCleanupOnErr {
			o.releaseFloatingIPLocked(ctx, f)
		}
		return err
	}
	return nil
}

// ReleaseResources locks around resourceLock
func (o *OpenstackPlatform) ReleaseReservations(ctx context.Context, resources *ReservedResources) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ReleaseReservations", "resources", resources, "current fips", ReservedFloatingIPs, "current subnets", ReservedSubnets)

	var errs []string
	resourceLock.Lock()
	defer resourceLock.Unlock()
	for _, f := range resources.FloatingIpIds {
		err := o.releaseFloatingIPLocked(ctx, f)
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, s := range resources.Subnets {
		err := o.releaseSubnetLocked(ctx, s)
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("Errors: %s", strings.Join(errs, ","))
}

// reserveFloatingIPLocked must be called from code that locks resourceLock
func (o *OpenstackPlatform) reserveFloatingIPLocked(ctx context.Context, fipID string, reservedBy string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ReserveFloatingIP", "fipID", fipID, "reservedBy", reservedBy)
	currUser, reserved := ReservedFloatingIPs[fipID]
	if reserved {
		return fmt.Errorf("Floating IP already reserved, fip: %s reservedBy: %s", fipID, currUser)
	}
	ReservedFloatingIPs[fipID] = reservedBy
	return nil
}

// reserveSubnet must be called from code that locks resourceLock
func (o *OpenstackPlatform) reserveSubnetLocked(ctx context.Context, cidr string, reservedBy string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "reserveSubnet", "cidr", cidr, "reservedBy", reservedBy)
	currUser, reserved := ReservedSubnets[cidr]
	if reserved {
		return fmt.Errorf("Subnet CIDR already reserved, cidr: %s reservedBy: %s", cidr, currUser)
	}
	ReservedSubnets[cidr] = reservedBy
	return nil
}

func (o *OpenstackPlatform) releaseFloatingIPLocked(ctx context.Context, fipID string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "releaseFloatingIPLocked", "fipId", fipID)
	_, reserved := ReservedFloatingIPs[fipID]
	if !reserved {
		log.SpanLog(ctx, log.DebugLevelInfra, "Warning: Floating IP not reserved, cannot be released", "fipID", fipID)
		return fmt.Errorf("Floating IP not reserved, cannot be released: %s", fipID)
	}
	delete(ReservedFloatingIPs, fipID)
	return nil
}

func (o *OpenstackPlatform) releaseSubnetLocked(ctx context.Context, cidr string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "releaseSubnetLocked", "cidr", cidr)
	_, reserved := ReservedSubnets[cidr]
	if !reserved {
		log.SpanLog(ctx, log.DebugLevelInfra, "Warning: Subnet CIDR not reserved, cannot be released", "cidr", cidr)
		return fmt.Errorf("Subnet not reserved, cannot be released: %s", cidr)
	}
	delete(ReservedSubnets, cidr)
	return nil
}
