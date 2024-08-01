// Copyright 2024 EdgeXR, Inc
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

package ccrm

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"os"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessvars"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/confignode"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"go.etcd.io/etcd/client/v3/concurrency"
	"gopkg.in/yaml.v2"
)

var (
	// TODO: This needs to be configurable
	DefaultPlatformFlavor = edgeproto.Flavor{
		Key:   cloudcommon.DefaultPlatformFlavorKey,
		Vcpus: 2,
		Ram:   4096,
		Disk:  20,
	}
)

// ApplyCloudlet implements a GRPC CloudletPlatform server method
func (s *CCRMHandler) ApplyCloudlet(in *edgeproto.Cloudlet, stream edgeproto.CloudletPlatformAPI_ApplyCloudletServer) error {
	ctx := stream.Context()
	log.SpanLog(ctx, log.DebugLevelApi, "ApplyCloudlet", "cloudlet", in)

	s.updateCloudletNodes(ctx, in)

	responseSender := edgeproto.NewCloudletInfoSendUpdater(ctx, stream, in.Key)

	var workFunc func(context.Context, *edgeproto.Cloudlet, platform.Platform, *edgeproto.CloudletInfoSendUpdater) error

	if in.State == edgeproto.TrackedState_CREATE_REQUESTED {
		workFunc = s.createCloudlet
	} else if in.State == edgeproto.TrackedState_DELETE_REQUESTED {
		workFunc = s.deleteCloudlet
	} else {
		if in.CrmOnEdge {
			// CRM will handle it
			return nil
		}
		return s.crmHandler.CloudletChanged(ctx, &in.Key, in, responseSender)
	}

	cloudletPlatform, found := s.newPlatform(in.PlatformType)
	if !found {
		return fmt.Errorf("ccrm %s got request for unknown platform %s for cloudlet %s", s.nodeMgr.MyNode.Key.Type, in.PlatformType, in.Key.GetKeyString())
	}
	err := workFunc(ctx, in, cloudletPlatform, responseSender)
	log.SpanLog(ctx, log.DebugLevelApi, "ccrm ApplyCloudlet done", "cloudlet", in, "err", err)
	return err
}

func (s *CCRMHandler) createCloudlet(ctx context.Context, in *edgeproto.Cloudlet, cloudletPlatform platform.Platform, sender *edgeproto.CloudletInfoSendUpdater) (reterr error) {
	log.SpanLog(ctx, log.DebugLevelApi, "create cloudlet", "cloudlet", in)
	accessKeys, err := accessvars.GetCRMAccessKeys(ctx, s.flags.Region, in, s.nodeMgr.VaultConfig)
	if err != nil {
		return err
	}
	pfConfig, err := s.getPlatformConfig(ctx, in, accessKeys)
	if err != nil {
		return err
	}

	pfFlavor := edgeproto.Flavor{}
	if in.Flavor.Name == cloudcommon.DefaultPlatformFlavorKey.Name {
		pfFlavor = DefaultPlatformFlavor
	} else {
		if !s.crmHandler.FlavorCache.Get(&in.Flavor, &pfFlavor) {
			return in.Flavor.NotFoundError()
		}
	}
	pfInitConfig := s.getPlatformInitConfig(in)

	caches := s.crmHandler.GetCaches()
	cloudletResourcesCreated, err := cloudletPlatform.CreateCloudlet(ctx, in, pfConfig, pfInitConfig, &pfFlavor, caches, sender.SendStatusIgnoreErr)
	defer func() {
		if reterr == nil {
			return
		}
		if cloudletResourcesCreated {
			undoErr := s.deleteCloudlet(ctx, in, cloudletPlatform, sender)
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "Undo cloudlet create failed", "cloudlet", in, "undoerr", undoErr)
			}
		}
	}()
	if err != nil {
		return err
	}
	if in.CrmOnEdge {
		// CRM will set up rootLB and capture resources
		return nil
	}

	log.SpanLog(ctx, log.DebugLevelApi, "ccrm setup new cloudlet", "cloudlet", in)
	// replicate here what CRM would have done to set up initial cloudlet state
	// Note that "cloudletPlatform" is initialized in CreateCloudlet, similar to
	// but not the same as platform.InitCommon(), so we need to get a different
	// copy of the platform object that has been initialized with InitCommon.
	pf, err := s.getCRMCloudletPlatform(ctx, &in.Key)
	if err != nil {
		if errors.Is(err, ErrPlatformNotFound) {
			return nil
		}
		return err
	}

	if err := pf.InitHAConditional(ctx, sender.SendStatusIgnoreErr); err != nil {
		return err
	}

	return sender.SendUpdate(func(info *edgeproto.CloudletInfo) error {
		info.CompatibilityVersion = cloudcommon.GetCRMCompatibilityVersion()
		info.ContainerVersion = in.ContainerVersion
		info.ControllerCacheReceived = true
		if cv, err := cloudcommon.GetDockerBaseImageVersion(); err == nil {
			info.ContainerVersion = cv
		}
		if err := s.crmHandler.GatherInitialCloudletInfo(ctx, in, pf, info, sender.SendStatusIgnoreErr); err != nil {
			return err
		}
		info.State = dme.CloudletState_CLOUDLET_STATE_READY
		if in.TrustPolicy == "" {
			info.TrustPolicyState = edgeproto.TrackedState_NOT_PRESENT
		} else {
			info.TrustPolicyState = edgeproto.TrackedState_READY
		}
		info.Fields = edgeproto.CloudletInfoAllFields
		return nil
	})
}

func (s *CCRMHandler) deleteCloudlet(ctx context.Context, in *edgeproto.Cloudlet, cloudletPlatform platform.Platform, sender *edgeproto.CloudletInfoSendUpdater) error {
	log.SpanLog(ctx, log.DebugLevelApi, "delete cloudlet", "cloudlet", in)
	accessKeys := &accessvars.CRMAccessKeys{}
	pfConfig, err := s.getPlatformConfig(ctx, in, accessKeys)
	if err != nil {
		return err
	}
	caches := s.crmHandler.GetCaches()
	pfInitConfig := s.getPlatformInitConfig(in)

	err = cloudletPlatform.DeleteCloudlet(ctx, in, pfConfig, pfInitConfig, caches, sender.SendStatusIgnoreErr)
	if err == nil {
		s.crmPlatforms.Delete(&in.Key)
	}
	return err
}

func (s *CCRMHandler) getPlatformConfig(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessKeys *accessvars.CRMAccessKeys) (*edgeproto.PlatformConfig, error) {
	pfConfig := edgeproto.PlatformConfig{}
	pfConfig.PlatformTag = s.flags.VersionTag
	pfConfig.TlsCertFile = s.nodeMgr.GetInternalTlsCertFile()
	pfConfig.TlsKeyFile = s.nodeMgr.GetInternalTlsKeyFile()
	pfConfig.TlsCaFile = s.nodeMgr.GetInternalTlsCAFile()
	pfConfig.UseVaultPki = s.nodeMgr.InternalPki.UseVaultPki
	pfConfig.ContainerRegistryPath = s.flags.CloudletRegistryPath
	pfConfig.CloudletVmImagePath = s.flags.CloudletVMImagePath
	pfConfig.EnvoyWithCurlImage = s.flags.EnvoyWithCurlImage
	pfConfig.NginxWithCurlImage = s.flags.NginxWithCurlImage
	pfConfig.TestMode = s.flags.TestMode
	pfConfig.EnvVar = make(map[string]string)
	for k, v := range cloudlet.EnvVar {
		pfConfig.EnvVar[k] = v
	}
	pfConfig.Region = s.flags.Region
	pfConfig.CommercialCerts = s.flags.CommercialCerts
	pfConfig.AppDnsRoot = s.flags.AppDNSRoot
	getCrmEnv(pfConfig.EnvVar)
	pfConfig.CrmAccessPrivateKey = accessKeys.PrivatePEM
	if cloudlet.PlatformHighAvailability {
		pfConfig.SecondaryCrmAccessPrivateKey = accessKeys.SecondaryPrivatePEM
	}
	pfConfig.NotifyCtrlAddrs = s.flags.ControllerPublicNotifyAddr
	pfConfig.AccessApiAddr = s.flags.ControllerPublicAccessApiAddr
	pfConfig.Span = log.SpanToString(ctx)
	pfConfig.DeploymentTag = s.nodeMgr.DeploymentTag
	pfConfig.ThanosRecvAddr = s.flags.ThanosRecvAddr
	pfConfig.AnsiblePublicAddr = s.flags.AnsiblePublicAddr

	return &pfConfig, nil
}

func (s *CCRMHandler) getPlatformInitConfig(cloudlet *edgeproto.Cloudlet) *platform.PlatformInitConfig {
	return &platform.PlatformInitConfig{
		AccessApi:      s.vaultClient.CloudletContext(cloudlet),
		CloudletSSHKey: s.cloudletSSHKey,
		SyncFactory:    regiondata.NewKVStoreSyncFactory(s.sync.GetKVStore(), s.nodeType, cloudlet.Key.GetKeyString()),
	}
}

func getCrmEnv(vars map[string]string) {
	for _, key := range []string{
		"JAEGER_ENDPOINT",
		"E2ETEST_TLS",
		"ES_SERVER_URLS",
	} {
		if val, ok := os.LookupEnv(key); ok {
			vars[key] = val
		}
	}
	if val, ok := os.LookupEnv("JAEGER_EXTERNAL_ENDPOINT"); ok {
		// JAEGER_ENDPOINT may point to internal DNS name in
		// kubernetes cluster, in which case CRM will need the
		// external endpoint.
		vars["JAEGER_ENDPOINT"] = val
	}
	if val, ok := os.LookupEnv("ES_SERVER_URLS_EXTERNAL"); ok {
		// ES_SERVER_URLS may point to the internal DNS name in
		// the kubernetes cluster, in which case CRM will need
		// the external endpoint.
		vars["ES_SERVER_URLS"] = val
	}
}

func (s *CCRMHandler) CreateCloudletNodeReq(ctx context.Context, node *edgeproto.CloudletNode) (string, error) {
	if s.ctrlConn == nil {
		return "", fmt.Errorf("create cloudlet node req, client not initialized yet")
	}
	client := edgeproto.NewCloudletNodeApiClient(s.ctrlConn)
	res, err := client.CreateCloudletNode(ctx, node)
	log.SpanLog(ctx, log.DebugLevelApi, "create cloudlet node req", "node", node, "err", err)
	if err != nil {
		return "", err
	}
	// Message is password
	return res.Message, nil
}

func (s *CCRMHandler) DeleteCloudletNodeReq(ctx context.Context, nodeKey *edgeproto.CloudletNodeKey) error {
	if s.ctrlConn == nil {
		return fmt.Errorf("delete cloudlet node req, client not initialized yet")
	}
	client := edgeproto.NewCloudletNodeApiClient(s.ctrlConn)
	node := edgeproto.CloudletNode{
		Key: *nodeKey,
	}
	_, err := client.DeleteCloudletNode(ctx, &node)
	log.SpanLog(ctx, log.DebugLevelApi, "delete cloudlet node req", "node", nodeKey, "err", err)
	return err
}

// update node attributes when node changes
func (s *CCRMHandler) cloudletNodeChanged(ctx context.Context, old *edgeproto.CloudletNode, in *edgeproto.CloudletNode) {
	baseAttributes := make(map[string]interface{})
	if in.NodeRole != cloudcommon.NodeRoleBase.String() {
		cloudlet := edgeproto.Cloudlet{}
		if !s.crmHandler.CloudletCache.Get(&in.Key.CloudletKey, &cloudlet) {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to get cloudlet to update cloudlet node", "node", in.Key)
			return
		}
		var err error
		baseAttributes, err = s.getCloudletPlatformAttributes(ctx, &cloudlet)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to compute cloudlet attributes for node", "node", in.Key, "err", err)
			return
		}
	}
	s.updateNodeAttributes(ctx, baseAttributes, in)
}

// update node attributes when cloudlet changes
func (s *CCRMHandler) updateCloudletNodes(ctx context.Context, in *edgeproto.Cloudlet) {
	baseAttributes, err := s.getCloudletPlatformAttributes(ctx, in)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to compute cloudlet platform attributes", "cloudlet", in, "err", err)
		return
	}
	nodeCache := &s.caches.CloudletNodeCache
	log.SpanLog(ctx, log.DebugLevelApi, "update cloudlet nodes", "cloudlet", in.Key)
	nodeCache.Mux.Lock()
	defer nodeCache.Mux.Unlock()
	for _, data := range nodeCache.Objs {
		node := data.Obj
		if node.NodeRole == cloudcommon.NodeRoleBase.String() {
			// no cloudlet attributes in node attributes
			continue
		}
		if !node.Key.CloudletKey.Matches(&in.Key) {
			continue
		}
		s.updateNodeAttributes(ctx, baseAttributes, node)
	}
}

func (s *CCRMHandler) getCloudletPlatformAttributes(ctx context.Context, in *edgeproto.Cloudlet) (map[string]interface{}, error) {
	pfConfig, err := s.getPlatformConfig(ctx, in, &accessvars.CRMAccessKeys{})
	if err != nil {
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "getPlatformConfig", "pfConfig", *pfConfig)
	auth, err := s.registryAuthAPI.GetRegistryAuth(ctx, s.flags.GetPlatformRegistryPath())
	if err != nil {
		return nil, err
	}
	return confignode.GetCloudletAttributes(ctx, in, pfConfig, auth)
}

func (s *CCRMHandler) updateNodeAttributes(ctx context.Context, baseAttributes map[string]interface{}, node *edgeproto.CloudletNode) {
	log.SpanLog(ctx, log.DebugLevelApi, "update node attributes cache", "node", node.Key)
	nodeAttributes := baseAttributes
	// add in node-specific attributes
	for k, v := range node.Attributes {
		nodeAttributes[k] = v
	}
	nodeAttributes["node_name"] = node.Key.Name
	nodeAttributes["node_type"] = node.NodeType
	nodeAttributes["node_role"] = node.NodeRole

	// record data
	data, err := yaml.Marshal(nodeAttributes)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to marshal node attributes", "node", node.Key, "err", err)
		return
	}
	checksum := fmt.Sprintf("%x", md5.Sum(data))
	log.SpanLog(ctx, log.DebugLevelApi, "computed node attributes checksum", "node", node.Key, "checksum", checksum)
	s.nodeAttributesCache.Update(node.Key, data, checksum)
}

func (s *CCRMHandler) vmResourceActionEnd(ctx context.Context, cloudletKey *edgeproto.CloudletKey) {
	// This is the equivalent to CRM's vmResourceActionEnd.
	// Unlike the CRM, multiple CCRM processes could spawn these in parallel.
	// We use a transaction to detect if another process wrote to the info,
	// we'll need to re-capture the snapshot to avoid a case where our
	// snapshot data is stale.
	// There's a bunch of drawbacks with just spawning a go thread:
	// - unrelated changes to info that aren't updating the resources will
	// trigger a rerun
	// - multiple threads/processes running in parallel may duplicate work
	// that could have been condensed into a single call to capture resources.
	//
	// Unfortunately, the alternative is to sync across multiple processes
	// which requires (essentially) a distributed lock, with a timeout in case
	// the holding process unexpectedly dies. Here we're being conservative
	// and choosing to be safer but less efficient.
	go func() {
		span, ctx := log.ChildSpan(ctx, log.DebugLevelApi, "capture cloudlet resource snapshot")
		defer span.Finish()

		var snapshot *edgeproto.InfraResourcesSnapshot
		var err error
		_, err = s.sync.GetKVStore().ApplySTM(ctx, func(stm concurrency.STM) error {
			info := edgeproto.CloudletInfo{}
			if !s.caches.CloudletInfoCache.Store.STMGet(stm, cloudletKey, &info) {
				return nil
			}
			pf, err := s.getCRMCloudletPlatform(ctx, cloudletKey)
			if err != nil {
				return err
			}
			snapshot, err = s.crmHandler.CaptureResourcesSnapshot(ctx, pf, cloudletKey)
			if err != nil {
				return err
			}
			if snapshot == nil {
				return nil
			}
			info.ResourcesSnapshot = *snapshot
			s.caches.CloudletInfoCache.Store.STMPut(stm, &info)
			return nil
		})
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to capture cloudlet resources", "cloudlet", cloudletKey, "err", err)
		}
		if snapshot != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "updated cloudlet resources", "cloudlet", cloudletKey, "snapshot", snapshot)
		}
	}()
}
