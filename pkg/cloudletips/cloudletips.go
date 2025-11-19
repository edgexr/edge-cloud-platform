// Copyright 2025 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cloudletips provides common functions for cloudlet IP management
package cloudletips

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"go.etcd.io/etcd/client/v3/concurrency"
)

// CloudletIPs allows managing IP allocation for a cloudlet.
// This is a common API for both the Controller and CCRM services.
type CloudletIPs struct {
	kvstore          objstore.KVStore
	cloudletIPsStore edgeproto.CloudletIPsStore
	cloudletStore    edgeproto.CloudletStore
	clusterInstStore edgeproto.ClusterInstStore
}

func NewCloudletIPs(kvstore objstore.KVStore, cloudletIPsStore edgeproto.CloudletIPsStore, cloudletStore edgeproto.CloudletStore, clusterInstStore edgeproto.ClusterInstStore) *CloudletIPs {
	cloudletIPsApi := CloudletIPs{}
	cloudletIPsApi.kvstore = kvstore
	cloudletIPsApi.cloudletIPsStore = cloudletIPsStore
	cloudletIPsApi.cloudletStore = cloudletStore
	cloudletIPsApi.clusterInstStore = clusterInstStore
	return &cloudletIPsApi
}

// ReserveControlPlaneIP should be called when the cluster is being
// created to reserve a control plane IP for the cluster.
// This is relevant to bare metal cloudlets where we manage IP
// address assignment to the control plane.
func (s *CloudletIPs) ReserveControlPlaneIP(stm concurrency.STM, cloudlet *edgeproto.Cloudlet, clusterInst *edgeproto.ClusterInst) error {
	vipsStr, ok := cloudlet.EnvVar[cloudcommon.FloatingVIPs]
	if !ok {
		// no need to reserve VIP
		return nil
	}
	ips := edgeproto.CloudletIPs{}
	if !s.cloudletIPsStore.STMGet(stm, &cloudlet.Key, &ips) {
		ips.Key = cloudlet.Key
	}
	vip, err := GetFreeIP(vipsStr, &ips)
	if err != nil {
		return err
	}
	cips, _ := ips.EnsureClusterIPs(&clusterInst.Key)
	cips.ControlPlaneIpv4 = vip
	s.cloudletIPsStore.STMPut(stm, &ips)
	// add the VIP as an annotation on the cluster so the platform
	// specific code can use it. This assumes caller is creating
	// a cluster and caller will commit cluster in transaction.
	clusterInst.AddAnnotation(cloudcommon.AnnotationControlVIP, vip)
	return nil
}

// FreeControlPlaneIP should be called when the cluster is being
// deleted to free the control plane IP. Note this deletes the
// entire ClusterIPs entry so also releases any load balancer IPs.
func (s *CloudletIPs) FreeControlPlaneIP(stm concurrency.STM, cloudletKey edgeproto.CloudletKey, clusterKey edgeproto.ClusterKey) {
	ips := edgeproto.CloudletIPs{}
	if !s.cloudletIPsStore.STMGet(stm, &cloudletKey, &ips) {
		return
	}
	if _, found := ips.ClusterIps[clusterKey.GetKeyString()]; !found {
		return
	}
	delete(ips.ClusterIps, clusterKey.GetKeyString())
	s.cloudletIPsStore.STMPut(stm, &ips)
}

func (s *CloudletIPs) ReserveLoadBalancerIP(ctx context.Context, cloudletKey edgeproto.CloudletKey, clusterKey edgeproto.ClusterKey, lbKey edgeproto.LoadBalancerKey) (*edgeproto.LoadBalancer, error) {
	// Ensure the load balancer has an IP
	var lbCopy edgeproto.LoadBalancer
	_, err := s.kvstore.ApplySTM(ctx, func(stm concurrency.STM) error {
		cloudlet := edgeproto.Cloudlet{}
		if !s.cloudletStore.STMGet(stm, &cloudletKey, &cloudlet) {
			return fmt.Errorf("reserve load balancer ip, %v", cloudletKey.NotFoundError())
		}
		ips := edgeproto.CloudletIPs{}
		if !s.cloudletIPsStore.STMGet(stm, &cloudletKey, &ips) {
			ips.Key = cloudletKey
		}
		vipsStr, ok := cloudlet.EnvVar[cloudcommon.FloatingVIPs]
		if !ok {
			return fmt.Errorf("no floating vips defined for cloudlet %s", cloudletKey.GetKeyString())
		}

		// look up load balancer
		changed := false
		cips, mod := ips.EnsureClusterIPs(&clusterKey)
		if mod {
			changed = true
		}
		lb, mod := cips.EnsureLoadBalancer(&lbKey)
		if mod {
			changed = true
		}
		if lb.Ipv4 == "" {
			freeIP, err := GetFreeIP(vipsStr, &ips)
			if err != nil {
				return err
			}
			lb.Ipv4 = freeIP
			changed = true
			log.SpanLog(ctx, log.DebugLevelInfra, "assigned free load balancer IP", "cloudlet", cloudletKey, "cluster", clusterKey, "lb", lbKey, "ip", freeIP)
		}

		if changed {
			s.cloudletIPsStore.STMPut(stm, &ips)
		}
		lbCopy = *lb
		return nil
	})
	log.SpanLog(ctx, log.DebugLevelInfra, "ReserveLoadBalancerIP", "cloudlet", cloudletKey, "cluster", clusterKey, "lbKey", lbKey, "lbOut", lbCopy, "err", err)
	return &lbCopy, err
}

func (s *CloudletIPs) FreeLoadBalancerIP(ctx context.Context, cloudletKey edgeproto.CloudletKey, clusterKey edgeproto.ClusterKey, lbKey edgeproto.LoadBalancerKey) error {
	_, err := s.kvstore.ApplySTM(ctx, func(stm concurrency.STM) error {
		ips := edgeproto.CloudletIPs{}
		if !s.cloudletIPsStore.STMGet(stm, &cloudletKey, &ips) {
			return nil
		}
		cips, ok := ips.ClusterIps[clusterKey.GetKeyString()]
		if !ok {
			return nil
		}
		_, ok = cips.LoadBalancers[lbKey.GetKeyString()]
		if !ok {
			return nil
		}
		delete(cips.LoadBalancers, lbKey.GetKeyString())
		s.cloudletIPsStore.STMPut(stm, &ips)
		return nil
	})
	log.SpanLog(ctx, log.DebugLevelInfra, "FreeLoadBalancerIP", "cloudlet", cloudletKey, "cluster", clusterKey, "lbKey", lbKey, "err", err)
	return err
}

// GetFreeIP returns a free IP on the Cloudlet.
// This algorithm is designed to be deterministic, not necessarily fast.
func GetFreeIP(allIPs string, cloudletIPs *edgeproto.CloudletIPs) (string, error) {
	// get IPs in use
	inUse := map[string]struct{}{}
	for _, clb := range cloudletIPs.ClusterIps {
		if clb.ControlPlaneIpv4 != "" {
			inUse[clb.ControlPlaneIpv4] = struct{}{}
		}
		for _, lb := range clb.LoadBalancers {
			if lb.Ipv4 != "" {
				inUse[lb.Ipv4] = struct{}{}
			}
		}
	}
	// find free IP
	for ip := range util.IPRangesIter(allIPs) {
		if _, found := inUse[ip]; !found {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no free IP available")
}
