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

package orm

import (
	"context"
	fmt "fmt"
	"strings"
	"sync"

	"github.com/edgexr/edge-cloud/cloudcommon/node"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/notify"
	edgetls "github.com/edgexr/edge-cloud/tls"
)

// Manage cached regional data

type AllRegionCaches struct {
	mux    sync.Mutex
	caches map[string]*RegionCache
}

type RegionCache struct {
	client            *notify.Client
	cloudletPoolCache node.CloudletPoolCache
	cloudletCache     node.CloudletCache
}

func (s *AllRegionCaches) init() {
	s.caches = make(map[string]*RegionCache)
}

// In order for MC to track all the cloudletpool configurations from all regions
// to be able to tag events properly, MC connects to a controller from each region
// via a notify client and receives updates whenever CloudletPools change.
func (s *AllRegionCaches) refreshRegions(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfo, "Refresh region caches")
	s.mux.Lock()
	defer s.mux.Unlock()

	ctrls, err := ShowControllerObj(ctx, NoUserClaims, NoShowFilter)
	if err != nil {
		return fmt.Errorf("failed to get controllers from database to refresh region notify clients, %v", err)
	}
	desiredRegions := make(map[string]struct{})

	for _, ctrl := range ctrls {
		desiredRegions[ctrl.Region] = struct{}{}

		if _, found := s.caches[ctrl.Region]; found {
			// client already running
			continue
		}
		notifyAddr := ctrl.NotifyAddr
		if notifyAddr == "" {
			// derive notify server address from api address
			addrObjs := strings.Split(ctrl.Address, ":")
			if len(addrObjs) != 2 {
				return fmt.Errorf("Cannot derive controller notify address from api address, bad api address format, expected name:port but is %s, please fix or specify notifyAddr", ctrl.Address)
			}
			notifyAddr = addrObjs[0] + ":" + serverConfig.ControllerNotifyPort
		}
		tlsConfig, err := nodeMgr.InternalPki.GetClientTlsConfig(ctx,
			nodeMgr.CommonName(),
			node.CertIssuerGlobal,
			[]node.MatchCA{node.AnyRegionalMatchCA()})
		if err != nil {
			return fmt.Errorf("Failed to get TLS client config for controller notify client, %s, %s, %v", ctrl.Address, notifyAddr, err)
		}
		log.SpanLog(ctx, log.DebugLevelInfo, "Starting controller notify client", "controller", ctrl.Address, "region", ctrl.Region, "notifyAddr", notifyAddr)
		dialOption := edgetls.GetGrpcDialOption(tlsConfig)
		notifyClient := notify.NewClient(ctrl.Region, []string{notifyAddr}, dialOption)
		rc := RegionCache{}
		rc.init(notifyClient)
		s.caches[ctrl.Region] = &rc

		notifyClient.RegisterRecvCloudletCache(rc.cloudletCache.GetCloudletCache(node.NoRegion))
		notifyClient.RegisterRecvCloudletPoolCache(rc.cloudletPoolCache.GetCloudletPoolCache(node.NoRegion))
		notifyClient.Start()
	}

	// clean up clients for regions no longer in the database
	for region, rc := range s.caches {
		if _, found := desiredRegions[region]; found {
			continue
		}
		log.SpanLog(ctx, log.DebugLevelInfo, "Stopping region notify client", "region", region)
		go rc.client.Stop()
		delete(s.caches, region)
	}
	return nil
}

// AllRegionCaches implements node.CloudletPoolLookup and node.CloudletLookup

func (s *AllRegionCaches) InPool(region string, key edgeproto.CloudletKey) bool {
	s.mux.Lock()
	defer s.mux.Unlock()

	cd, found := s.caches[region]
	if !found {
		return false
	}
	return cd.cloudletPoolCache.InPool(region, key)
}

func (s *AllRegionCaches) GetCloudletPoolCache(region string) *edgeproto.CloudletPoolCache {
	s.mux.Lock()
	defer s.mux.Unlock()

	cd, found := s.caches[region]
	if !found {
		return nil
	}
	return cd.cloudletPoolCache.GetCloudletPoolCache(region)
}

func (s *AllRegionCaches) Dumpable() map[string]interface{} {
	allregions := make(map[string]interface{})
	s.mux.Lock()
	defer s.mux.Unlock()
	for region, rcache := range s.caches {
		allregions[region] = rcache.Dumpable()
	}
	return allregions
}

func (s *AllRegionCaches) GetCloudlet(region string, key *edgeproto.CloudletKey, buf *edgeproto.Cloudlet) bool {
	s.mux.Lock()
	defer s.mux.Unlock()

	cd, found := s.caches[region]
	if !found {
		return false
	}
	return cd.cloudletCache.GetCloudlet(region, key, buf)
}

func (s *AllRegionCaches) GetCloudletCache(region string) *edgeproto.CloudletCache {
	s.mux.Lock()
	defer s.mux.Unlock()

	cd, found := s.caches[region]
	if !found {
		return nil
	}
	return cd.cloudletCache.GetCloudletCache(region)
}

// Per-region data

func (s *RegionCache) init(client *notify.Client) {
	s.client = client
	s.cloudletPoolCache.Init()
	s.cloudletCache.Init()
}

func (s *RegionCache) Dumpable() map[string]interface{} {
	data := make(map[string]interface{})
	data["cloudletpools"] = s.cloudletPoolCache.Dumpable()
	return data
}
