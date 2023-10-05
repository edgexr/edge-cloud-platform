package ccrm

import (
	"context"
	"crypto/md5"
	"fmt"
	"os"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessapi"
	"github.com/edgexr/edge-cloud-platform/pkg/accessvars"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/confignode"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
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

func (s *CCRMHandler) cloudletChanged(ctx context.Context, old *edgeproto.Cloudlet, in *edgeproto.Cloudlet) {
	log.SpanLog(ctx, log.DebugLevelApi, "cloudletChanged", "cloudlet", in)

	s.updateCloudletNodes(ctx, in)

	var ackState edgeproto.TrackedState
	var errState edgeproto.TrackedState
	var successState edgeproto.TrackedState
	var workFunc func(context.Context, *edgeproto.Cloudlet, platform.Platform, edgeproto.CacheUpdateCallback) error

	if in.OnboardingState == edgeproto.TrackedState_CREATE_REQUESTED {
		ackState = edgeproto.TrackedState_CREATING
		errState = edgeproto.TrackedState_CREATE_ERROR
		successState = edgeproto.TrackedState_READY
		workFunc = s.createCloudlet
	} else if in.OnboardingState == edgeproto.TrackedState_DELETE_REQUESTED {
		ackState = edgeproto.TrackedState_DELETING
		errState = edgeproto.TrackedState_DELETE_ERROR
		successState = edgeproto.TrackedState_DELETE_DONE
		workFunc = s.deleteCloudlet
	} else {
		// not for us to handle
		return
	}

	cloudletPlatform, found := s.caches.getPlatform(in.PlatformType)
	if !found {
		// ignore, some other CCRM should handle it
		log.SpanLog(ctx, log.DebugLevelApi, "cloudletChanged ignoring unknown platform", "platform", in.PlatformType)
		return
	}

	// Acknowledge request
	msg := edgeproto.CloudletOnboardingInfo{
		Key:             in.Key,
		OnboardingState: ackState,
	}
	s.caches.CloudletOnboardingInfoSend.Update(ctx, &msg)

	// do the work in a separate thread to not block the notify thread
	go func() {
		cspan, cctx := log.ChildSpan(ctx, log.DebugLevelApi, "ccrm-cloudletChanged")
		defer cspan.Finish()
		cb := s.getCloudletOnboardingInfoCallback(cctx, msg)

		err := workFunc(cctx, in, cloudletPlatform, cb)
		msg.Status = edgeproto.StatusInfo{}
		if err != nil {
			msg.OnboardingState = errState
			msg.Errors = []string{err.Error()}
		} else {
			msg.OnboardingState = successState
		}
		log.SpanLog(cctx, log.DebugLevelApi, "ccrm cloudletChanged done", "cloudlet", in, "result", msg)
		s.caches.CloudletOnboardingInfoSend.Update(ctx, &msg)
	}()
}

func (s *CCRMHandler) createCloudlet(ctx context.Context, in *edgeproto.Cloudlet, cloudletPlatform platform.Platform, cb edgeproto.CacheUpdateCallback) (reterr error) {
	accessKeys, err := accessvars.GetCRMAccessKeys(ctx, s.flags.Region, in, s.nodeMgr.VaultConfig)
	if err != nil {
		return err
	}
	pfConfig, err := s.getPlatformConfig(ctx, in, accessKeys)
	if err != nil {
		return err
	}

	if in.DeploymentLocal {
		// TODO: rather than starting up a CRM service per cloudlet
		// when platforms do not want on-site CRMs, we should instead
		// allow the CCRM to become a regional CRM that can handle
		// requests for different cloudlets.
		cb(edgeproto.UpdateTask, "Starting CRMServer")
		return process.StartCRMService(ctx, in, pfConfig, process.HARolePrimary, nil)
	}

	pfFlavor := edgeproto.Flavor{}
	if in.Flavor.Name == cloudcommon.DefaultPlatformFlavorKey.Name {
		pfFlavor = DefaultPlatformFlavor
	} else {
		if !s.caches.FlavorCache.Get(&in.Flavor, &pfFlavor) {
			return in.Flavor.NotFoundError()
		}
	}

	caches := s.caches.getPlatformCaches()
	accessApi := accessapi.NewVaultClient(in, s.nodeMgr.VaultConfig, s, s.flags.Region, s.flags.DnsZone)
	cloudletResourcesCreated, err := cloudletPlatform.CreateCloudlet(ctx, in, pfConfig, &pfFlavor, caches, accessApi, cb)
	defer func() {
		if reterr == nil {
			return
		}
		if cloudletResourcesCreated {
			undoErr := s.deleteCloudlet(ctx, in, cloudletPlatform, cb)
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "Undo cloudlet create failed", "cloudlet", in, "undoerr", undoErr)
			}
		}
	}()
	if err != nil {
		return err
	}
	return nil
}

func (s *CCRMHandler) deleteCloudlet(ctx context.Context, in *edgeproto.Cloudlet, cloudletPlatform platform.Platform, cb edgeproto.CacheUpdateCallback) error {

	if in.DeploymentLocal {
		cb(edgeproto.UpdateTask, "Stopping CRMServer")
		return process.StopCRMService(ctx, in, process.HARoleAll)
	}
	accessKeys := &accessvars.CRMAccessKeys{}
	pfConfig, err := s.getPlatformConfig(ctx, in, accessKeys)
	if err != nil {
		return err
	}
	caches := s.caches.getPlatformCaches()
	accessApi := accessapi.NewVaultClient(in, s.nodeMgr.VaultConfig, s, s.flags.Region, s.flags.DnsZone)

	return cloudletPlatform.DeleteCloudlet(ctx, in, pfConfig, caches, accessApi, cb)
}

func (s *CCRMHandler) getCloudletOnboardingInfoCallback(ctx context.Context, msg edgeproto.CloudletOnboardingInfo) func(updateType edgeproto.CacheUpdateType, value string) {
	return func(updateType edgeproto.CacheUpdateType, value string) {
		switch updateType {
		case edgeproto.UpdateTask:
			msg.Status.SetTask(value)
		case edgeproto.UpdateStep:
			msg.Status.SetStep(value)
		}
		s.caches.CloudletOnboardingInfoSend.Update(ctx, &msg)
	}
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
	pfConfig.InternalDomain = s.nodeMgr.InternalDomain

	return &pfConfig, nil
}

func getCrmEnv(vars map[string]string) {
	for _, key := range []string{
		"JAEGER_ENDPOINT",
		"E2ETEST_TLS",
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
}

func (s *CCRMHandler) GetCloudletManifest(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.CloudletManifest, error) {
	cloudlet := edgeproto.Cloudlet{}
	if !s.caches.CloudletCache.Get(key, &cloudlet) {
		return nil, key.NotFoundError()
	}
	cloudletPlatform, found := s.caches.getPlatform(cloudlet.PlatformType)
	if !found {
		// ignore, some other CCRM should handle it
		log.SpanLog(ctx, log.DebugLevelApi, "cloudletManifest ignoring unknown platform", "platform", cloudlet.PlatformType)
		return nil, nil
	}
	features := cloudletPlatform.GetFeatures()

	pfFlavor := edgeproto.Flavor{}
	if !features.IsVmPool {
		if cloudlet.Flavor.Name == "" && cloudlet.Flavor.Name != cloudcommon.DefaultPlatformFlavorKey.Name {
			if !s.caches.FlavorCache.Get(&cloudlet.Flavor, &pfFlavor) {
				return nil, cloudlet.Flavor.NotFoundError()
			}
		}
	}
	accessKeys, err := accessvars.GetCRMAccessKeys(ctx, s.flags.Region, &cloudlet, s.nodeMgr.VaultConfig)
	if err != nil {
		return nil, err
	}
	pfConfig, err := s.getPlatformConfig(ctx, &cloudlet, accessKeys)
	if err != nil {
		return nil, err
	}
	caches := s.caches.getPlatformCaches()
	accessApi := accessapi.NewVaultClient(&cloudlet, s.nodeMgr.VaultConfig, s, s.flags.Region, s.flags.DnsZone)

	manifest, err := cloudletPlatform.GetCloudletManifest(ctx, &cloudlet, pfConfig, accessApi, &pfFlavor, caches)
	if err != nil {
		return nil, err
	}

	reply := edgeproto.CloudletManifest{
		Manifest: manifest.Manifest,
	}
	return &reply, nil
}

func (s *CCRMHandler) GetRestrictedCloudletStatus(ctx context.Context, key *edgeproto.CloudletKey, send func(*edgeproto.StreamStatus) error) error {
	cloudlet := edgeproto.Cloudlet{}
	if !s.caches.CloudletCache.Get(key, &cloudlet) {
		return key.NotFoundError()
	}

	cloudletPlatform, found := s.caches.getPlatform(cloudlet.PlatformType)
	if !found {
		// ignore, some other CCRM should handle it
		log.SpanLog(ctx, log.DebugLevelApi, "cloudletManifest ignoring unknown platform", "platform", cloudlet.PlatformType)
		return nil
	}

	accessKeys, err := accessvars.GetCRMAccessKeys(ctx, s.flags.Region, &cloudlet, s.nodeMgr.VaultConfig)
	if err != nil {
		return err
	}
	pfConfig, err := s.getPlatformConfig(ctx, &cloudlet, accessKeys)
	if err != nil {
		return err
	}
	accessApi := accessapi.NewVaultClient(&cloudlet, s.nodeMgr.VaultConfig, s, s.flags.Region, s.flags.DnsZone)
	err = cloudletPlatform.GetRestrictedCloudletStatus(ctx, &cloudlet, pfConfig, accessApi, func(updateType edgeproto.CacheUpdateType, value string) {
		reply := &edgeproto.StreamStatus{
			CacheUpdateType: int32(updateType),
			Status:          value,
		}
		err := send(reply)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "GetRestrictedCloudletStatus failed to send reply", "reply", reply, "err", err)
		}
	})
	return err
}

func (s *CCRMHandler) CreateCloudletNodeReq(ctx context.Context, node *edgeproto.CloudletNode) (string, error) {
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
		if !s.caches.CloudletCache.Get(&in.Key.CloudletKey, &cloudlet) {
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
	return confignode.GetCloudletAttributes(ctx, in, pfConfig)
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
