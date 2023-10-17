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

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/crmutil"
	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	pf "github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/federation"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	"github.com/edgexr/edge-cloud-platform/pkg/tls"
)

// ControllerData contains cache data for controller
type ControllerData struct {
	*crmutil.ControllerData
}

// NewControllerData creates a new instance to track data from the controller
func NewControllerData(plat pf.Platform, nodeMgr *node.NodeMgr, haMgr *redundancy.HighAvailabilityManager) *ControllerData {
	cd := &ControllerData{}
	cd.ControllerData = crmutil.NewControllerData(plat, &edgeproto.CloudletKey{}, nodeMgr, haMgr)
	return cd
}

func InitClientNotify(client *notify.Client, nodeMgr *node.NodeMgr, cd *ControllerData) {
	crmutil.InitClientNotify(client, nodeMgr, cd.ControllerData)
}

func InitFRM(ctx context.Context, nodeMgr *node.NodeMgr, haMgr *redundancy.HighAvailabilityManager, hostname, region, appDNSRoot, notifyAddrs, fedExtAddr string) (*notify.Client, *ControllerData, error) {
	// Load platform implementation.
	platform := &federation.FederationPlatform{}
	controllerData := NewControllerData(platform, nodeMgr, haMgr)
	vaultClient, err := accessapi.NewVaultClient(ctx, nodeMgr.VaultConfig, nil, region, "", dnsmgmt.NoProvider)
	if err != nil {
		return nil, nil, err
	}

	pc := pf.PlatformConfig{
		Region:          region,
		NodeMgr:         nodeMgr,
		DeploymentTag:   nodeMgr.DeploymentTag,
		AppDNSRoot:      appDNSRoot,
		AccessApi:       vaultClient,
		FedExternalAddr: fedExtAddr,
	}
	caches := controllerData.GetCaches()
	noopCb := func(updateType edgeproto.CacheUpdateType, value string) {}
	err = platform.InitCommon(ctx, &pc, caches, haMgr, noopCb)
	if err == nil {
		err = platform.InitHAConditional(ctx, &pc, noopCb)
	}
	if err != nil {
		return nil, nil, err
	}

	// ctrl notify
	addrs := strings.Split(notifyAddrs, ",")
	notifyClientTls, err := nodeMgr.InternalPki.GetClientTlsConfig(ctx,
		nodeMgr.CommonName(),
		node.CertIssuerRegional,
		[]node.MatchCA{node.SameRegionalMatchCA()})
	if err != nil {
		return nil, nil, err
	}
	dialOption := tls.GetGrpcDialOption(notifyClientTls)
	notifyClient := notify.NewClient(nodeMgr.Name(), addrs, dialOption)

	notifyClient.SetFilterByFederatedCloudlet()
	notifyClient.RegisterRecv(notify.NewFedAppInstEventRecv(platform))
	InitClientNotify(notifyClient, nodeMgr, controllerData)
	notifyClient.Start()

	haKey := fmt.Sprintf("nodeType: %s", node.NodeTypeFRM)
	haEnabled, err := controllerData.InitHAManager(ctx, haMgr, haKey)
	if err != nil {
		if err != nil {
			log.FatalLog(err.Error())
		}
	}
	if haEnabled {
		log.SpanLog(ctx, log.DebugLevelInfra, "HA enabled", "role", haMgr.HARole)
		if haMgr.PlatformInstanceActive {
			log.SpanLog(ctx, log.DebugLevelInfra, "HA instance is active", "role", haMgr.HARole)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "HA instance is not active", "role", haMgr.HARole)
		}
		controllerData.StartHAManagerActiveCheck(ctx, haMgr)
	}

	return notifyClient, controllerData, nil
}
