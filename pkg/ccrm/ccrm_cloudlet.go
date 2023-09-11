package ccrm

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessapi"
	"github.com/edgexr/edge-cloud-platform/pkg/accessvars"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
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
	log.SpanLog(ctx, log.DebugLevelInfra, "cloudletChanged", "cloudlet", in)

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
		log.SpanLog(ctx, log.DebugLevelInfra, "cloudletChanged ignoring unknown platform", "platform", in.PlatformType)
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
	accessApi := accessapi.NewVaultClient(in, s.nodeMgr.VaultConfig, s.flags.Region, s.flags.DnsZone)
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
	accessApi := accessapi.NewVaultClient(in, s.nodeMgr.VaultConfig, s.flags.Region, s.flags.DnsZone)

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
	pfConfig.PlatformTag = cloudlet.ContainerVersion
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
	addrObjs := strings.Split(s.flags.ControllerNotifyAddr, ":")
	if len(addrObjs) != 2 {
		return nil, fmt.Errorf("unable to fetch notify addr of the controller")
	}
	accessAddrObjs := strings.Split(s.flags.ControllerAccessApiAddr, ":")
	if len(accessAddrObjs) != 2 {
		return nil, fmt.Errorf("unable to parse accessApi addr of the controller")
	}
	pfConfig.CrmAccessPrivateKey = accessKeys.PrivatePEM
	if cloudlet.PlatformHighAvailability {
		pfConfig.SecondaryCrmAccessPrivateKey = accessKeys.SecondaryPrivatePEM
	}
	pfConfig.NotifyCtrlAddrs = s.flags.ControllerPublicAddr + ":" + addrObjs[1]
	pfConfig.AccessApiAddr = s.flags.ControllerPublicAddr + ":" + accessAddrObjs[1]
	pfConfig.Span = log.SpanToString(ctx)
	pfConfig.ChefServerPath = s.flags.ChefServerPath
	pfConfig.ChefClientInterval = s.caches.SettingsCache.Singular().ChefClientInterval
	pfConfig.DeploymentTag = s.nodeMgr.DeploymentTag
	pfConfig.ThanosRecvAddr = s.flags.ThanosRecvAddr

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
}

func (s *CCRMHandler) GetCloudletManifest(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.CloudletManifest, error) {
	cloudlet := edgeproto.Cloudlet{}
	if !s.caches.CloudletCache.Get(key, &cloudlet) {
		return nil, key.NotFoundError()
	}
	cloudletPlatform, found := s.caches.getPlatform(cloudlet.PlatformType)
	if !found {
		// ignore, some other CCRM should handle it
		log.SpanLog(ctx, log.DebugLevelInfra, "cloudletManifest ignoring unknown platform", "platform", cloudlet.PlatformType)
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
	accessApi := accessapi.NewVaultClient(&cloudlet, s.nodeMgr.VaultConfig, s.flags.Region, s.flags.DnsZone)

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
		log.SpanLog(ctx, log.DebugLevelInfra, "cloudletManifest ignoring unknown platform", "platform", cloudlet.PlatformType)
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
	accessApi := accessapi.NewVaultClient(&cloudlet, s.nodeMgr.VaultConfig, s.flags.Region, s.flags.DnsZone)
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
