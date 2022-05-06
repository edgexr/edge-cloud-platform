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

package k8sbm

import (
	"context"
	"strings"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type LbInfo struct {
	Name            string
	ExternalIpAddr  string
	LbListenDevName string
}

func (k *K8sBareMetalPlatform) GetLbName(ctx context.Context, appInst *edgeproto.AppInst) string {
	lbName := k.sharedLBName
	if appInst.DedicatedIp {
		return appInst.Uri
	}
	return lbName
}

func (k *K8sBareMetalPlatform) SetupLb(ctx context.Context, client ssh.Client, lbname string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupLb", "lbname", lbname)
	_, err := infracommon.GetIPAddressFromNetplan(ctx, client, lbname)
	if err != nil {
		if strings.Contains(err.Error(), infracommon.NetplanFileNotFound) {
			log.SpanLog(ctx, log.DebugLevelInfra, "lb ip does not exist", "lbname", lbname)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "unexpected error getting lb ip", "lbname", lbname, "err", err)
			return err
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "lb ip already exists")
		return nil
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "New LB, assign free IP")
	externalIp, err := k.AssignFreeLbIp(ctx, lbname, client)
	if err != nil {
		return err
	}
	if err = k.commonPf.ActivateFQDNA(ctx, lbname, externalIp); err != nil {
		return err
	}
	return nil
}

func (k *K8sBareMetalPlatform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &edgeproto.Flavor{
		Vcpus: uint64(0),
		Ram:   uint64(0),
		Disk:  uint64(0),
	}, nil
}
