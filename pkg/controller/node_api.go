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

package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessvars"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/nodemgr"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
	"github.com/oklog/ulid/v2"
	"go.etcd.io/etcd/client/v3/concurrency"
)

// NodeApi is used to manage bare metal or VM nodes.
// There are two approaches to node management.
// The first approach are user-defined nodes, where the operator
// manually creates node objects to correspond to existing
// bare metal or VM nodes. In this case, the actual
// bare metal machines or VMs are created outside of the scope
// of Edge Cloud. EdgeCloud and the platform code then create
// clusters from the pool of nodes.
// The second approach are dynamic nodes, where the platform
// provides an API to create the underlying bare metal or VM
// instances. In this case, nodes are created and deleted on demand
// via the platform, and there is no pool of nodes to manage.
type NodeApi struct {
	all   *AllApis
	sync  *regiondata.Sync
	store edgeproto.NodeStore
	cache edgeproto.NodeCache
}

func NewNodeApi(sync *regiondata.Sync, all *AllApis) *NodeApi {
	nodeApi := NodeApi{}
	nodeApi.all = all
	nodeApi.sync = sync
	nodeApi.cache.InitCacheWithSync(sync)
	nodeApi.store = nodeApi.cache.Store
	return &nodeApi
}

func (s *NodeApi) CreateNode(ctx context.Context, in *edgeproto.Node) (*edgeproto.Result, error) {
	in.DynamicallyCreated = false
	in.Owner = nil
	in.Role = ""
	in.NodePool = ""
	if !in.SkipNodeCheck {
		in.NodeResources = nil
		in.Health = edgeproto.NodeHealthUnknown
	}
	in.Assignment = edgeproto.NodeAssignmentFree
	if err := in.Key.ValidateKey(); err != nil {
		return &edgeproto.Result{}, err
	}
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if s.store.STMGet(stm, &in.Key, nil) {
			return in.Key.ExistsError()
		}
		err := s.validateNode(ctx, stm, in, cloudcommon.Create)
		if err != nil {
			return err
		}
		if err := s.addRef(ctx, stm, in); err != nil {
			return err
		}
		in.ObjId = ulid.Make().String()
		s.store.STMPut(stm, in)
		return nil
	})
	if err != nil {
		return &edgeproto.Result{}, err
	}
	s.updateFlavorInfo(ctx, in.CloudletKey)
	return &edgeproto.Result{}, nil
}

func (s *NodeApi) UpdateNode(ctx context.Context, in *edgeproto.Node) (*edgeproto.Result, error) {
	err := in.ValidateUpdateFields()
	if err != nil {
		return &edgeproto.Result{}, err
	}
	fmap := edgeproto.MakeFieldMap(in.Fields)
	if err := in.Validate(fmap); err != nil {
		return &edgeproto.Result{}, err
	}

	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		node := edgeproto.Node{}
		if !s.store.STMGet(stm, &in.Key, &node) {
			return in.Key.NotFoundError()
		}
		if fmap.HasOrHasChild(edgeproto.NodeFieldCloudletKey) {
			s.removeRef(ctx, stm, &node)
		}
		// apply changes
		count := node.CopyInFields(in)
		if count == 0 {
			// nothing changed
			return nil
		}
		err := s.validateNode(ctx, stm, &node, cloudcommon.Update)
		if err != nil {
			return err
		}
		if fmap.HasOrHasChild(edgeproto.NodeFieldCloudletKey) {
			if err := s.addRef(ctx, stm, &node); err != nil {
				return err
			}
		}
		s.store.STMPut(stm, &node)
		return nil
	})
	if err != nil {
		return &edgeproto.Result{}, err
	}
	s.updateFlavorInfo(ctx, in.CloudletKey)
	return &edgeproto.Result{}, nil
}

func (s *NodeApi) DeleteNode(ctx context.Context, in *edgeproto.Node) (*edgeproto.Result, error) {
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		node := &edgeproto.Node{}
		if !s.store.STMGet(stm, &in.Key, node) {
			return in.Key.NotFoundError()
		}
		if node.Owner != nil {
			return fmt.Errorf("cannot delete node which is in use by %s", node.Owner.GetKeyString())
		}
		s.removeRef(ctx, stm, node)
		s.store.STMDel(stm, &in.Key)
		return nil
	})
	if err != nil {
		return &edgeproto.Result{}, err
	}
	s.updateFlavorInfo(ctx, in.CloudletKey)
	return &edgeproto.Result{}, nil
}

func (s *NodeApi) ShowNode(in *edgeproto.Node, cb edgeproto.NodeApi_ShowNodeServer) error {
	return s.cache.Show(in, func(obj *edgeproto.Node) error {
		return cb.Send(obj)
	})
}

func (s *NodeApi) validateNode(ctx context.Context, stm concurrency.STM, in *edgeproto.Node, action cloudcommon.Action) error {
	// check required fields
	if err := in.CloudletKey.ValidateKey(); err != nil {
		return err
	}
	// set defaults for missing fields
	if in.MgmtAddr == "" {
		in.MgmtAddr = in.PublicAddr
	}
	if in.SshPort == 0 {
		in.SshPort = 22
	}
	if err := in.Validate(edgeproto.NodeAllFieldsMap); err != nil {
		return err
	}
	if in.CloudletKey.Organization != "" {
		// node org must be the same
		if in.CloudletKey.Organization != in.Key.Organization {
			return fmt.Errorf("node org %s does not match cloudlet org %s", in.Key.Organization, in.CloudletKey.Organization)
		}
	} else {
		in.CloudletKey.Organization = in.Key.Organization
	}

	// check that cloudlet exists and uses nodes
	// note that we don't care if cloudlet gets deleted in the meantime,
	// as user can just change the node's cloudlet key later.
	cloudlet := &edgeproto.Cloudlet{}
	if !s.all.cloudletApi.store.STMGet(stm, &in.CloudletKey, cloudlet) {
		return in.CloudletKey.NotFoundError()
	}
	features := &edgeproto.PlatformFeatures{}
	featuresKey := edgeproto.PlatformFeaturesKey(cloudlet.PlatformType)
	if !s.all.platformFeaturesApi.store.STMGet(stm, &featuresKey, features) {
		return featuresKey.NotFoundError()
	}
	if features.NodeUsage == edgeproto.NodeUsageNone {
		return errors.New("specified cloudlet does not use nodes")
	}

	// make sure public IP isn't already registered
	err := s.cache.Show(&edgeproto.Node{}, func(obj *edgeproto.Node) error {
		if obj.Key.Matches(&in.Key) {
			return nil
		}
		if obj.PublicAddr == in.PublicAddr {
			return fmt.Errorf("public address %s already registered", in.PublicAddr)
		}
		if obj.MgmtAddr == in.MgmtAddr && obj.SshPort == in.SshPort {
			return fmt.Errorf("management SSH address %s:%d already registered", in.PublicAddr, in.SshPort)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if !in.SkipNodeCheck {
		// get cloudlet node ssh key
		sshKey, err := accessvars.GetCloudletNodeSSHKey(ctx, *region, &in.CloudletKey, vaultConfig)
		if err != nil {
			return fmt.Errorf("failed to get cloudlet node ssh key, %s", err)
		}

		// verify node is valid
		nodeInfo, err := nodemgr.CheckNode(in, sshKey.PrivateRawKey)
		if err != nil && strings.Contains(err.Error(), "unable to authenticate") {
			return fmt.Errorf("failed to authenticate with node, did you install the cloudlet node ssh key? %s", err)
		}
		if err != nil {
			return fmt.Errorf("failed to check node, %s", err)
		}
		in.NodeResources = &nodeInfo.Resources
		in.Health = edgeproto.NodeHealthOnline
	}
	if action == cloudcommon.Create {
		// generate flavor key
		rs, err := resspec.NodeResourcesToResValMap(in.NodeResources)
		if err != nil {
			return err
		}
		vcpus := rs.GetInt(cloudcommon.ResourceVcpus)
		ram := rs.GetInt(cloudcommon.ResourceRamMb)
		hash := cloudcommon.GetShortHash(rs.String(), 10)
		in.FlavorName = fmt.Sprintf("%d.%d.%s", vcpus, ram, hash)
	}
	in.SkipNodeCheck = false

	return nil
}

func (s *NodeApi) removeRef(ctx context.Context, stm concurrency.STM, in *edgeproto.Node) {
	// get cloudlet node refs
	refs := edgeproto.CloudletNodeRefs{}
	if !s.all.cloudletNodeRefsApi.store.STMGet(stm, &in.CloudletKey, &refs) {
		log.SpanLog(ctx, log.DebugLevelApi, "nodeApi removeRef refs not found", "cloudlet", in.CloudletKey)
		return
	}
	removed := false
	for ii, key := range refs.Nodes {
		if key.Matches(&in.Key) {
			refs.Nodes = slices.Delete(refs.Nodes, ii, ii+1)
			log.SpanLog(ctx, log.DebugLevelApi, "nodeApi removed ref", "cloudlet", in.CloudletKey, "node", in.Key)
			removed = true
			break
		}
	}
	if !removed {
		log.SpanLog(ctx, log.DebugLevelApi, "nodeApi removeRef ref not found", "cloudlet", in.CloudletKey, "node", in.Key)
	}
	if len(refs.Nodes) == 0 {
		s.all.cloudletNodeRefsApi.store.STMDel(stm, &in.CloudletKey)
	} else {
		s.all.cloudletNodeRefsApi.store.STMPut(stm, &refs)
	}
}

func (s *NodeApi) addRef(ctx context.Context, stm concurrency.STM, in *edgeproto.Node) error {
	// get cloudlet
	cloudlet := &edgeproto.Cloudlet{}
	if !s.all.cloudletApi.store.STMGet(stm, &in.CloudletKey, cloudlet) {
		return in.CloudletKey.NotFoundError()
	}
	// get cloudlet node refs
	refs := edgeproto.CloudletNodeRefs{}
	if !s.all.cloudletNodeRefsApi.store.STMGet(stm, &in.CloudletKey, &refs) {
		refs.Key = in.CloudletKey
	}
	// check if already in list
	for _, key := range refs.Nodes {
		if key.Matches(&in.Key) {
			return nil
		}
	}
	log.SpanLog(ctx, log.DebugLevelApi, "nodeApi added ref", "cloudlet", in.CloudletKey, "node", in.Key)
	refs.Nodes = append(refs.Nodes, in.Key)
	s.all.cloudletNodeRefsApi.store.STMPut(stm, &refs)
	return nil
}

func (s *NodeApi) updateFlavorInfo(ctx context.Context, ckey edgeproto.CloudletKey) {
	log.SpanLog(ctx, log.DebugLevelApi, "updateFlavorInfo", "cloudlet", ckey)
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		info := edgeproto.CloudletInfo{}
		if !s.all.cloudletInfoApi.store.STMGet(stm, &ckey, &info) {
			log.SpanLog(ctx, log.DebugLevelApi, "updateFlavorInfo cloudletInfo not found", "cloudlet", ckey)
		}
		refs := edgeproto.CloudletNodeRefs{}
		// if no refs found, we'll clear the flavors
		s.all.cloudletNodeRefsApi.store.STMGet(stm, &ckey, &refs)
		log.SpanLog(ctx, log.DebugLevelApi, "updateFlavorInfo", "cloudlet", ckey, "refs", refs)
		nodeFlavors := resspec.NodeFlavors{}
		for _, key := range refs.Nodes {
			// note here we are reading from cache to avoid overloading
			// the STM. This is ok because if cloudlet membership changes,
			// the refs will change and trigger a rerun of the STM.
			buf := &edgeproto.Node{}
			if s.cache.Get(&key, buf) {
				err := nodeFlavors.AddNode(buf)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelApi, "updateFlavorInfo failed to add node flavor", "cloudlet", ckey, "node", key, "err", err)
				}
			} else {
				log.SpanLog(ctx, log.DebugLevelApi, "updateFlavorInfo node not found", "cloudlet", ckey, "node", key)
			}
		}
		info.Flavors = nodeFlavors.AsList()
		log.SpanLog(ctx, log.DebugLevelApi, "updateFlavorInfo flavors", "cloudlet", ckey, "flavors", info.Flavors)
		s.all.cloudletInfoApi.store.STMPut(stm, &info)
		return nil
	})
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "updateFlavorInfo failed", "cloudlet", ckey, "err", err)
	}
}
