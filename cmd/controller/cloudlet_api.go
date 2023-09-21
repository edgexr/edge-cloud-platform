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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessvars"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	pfutils "github.com/edgexr/edge-cloud-platform/pkg/platform/utils"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/edgexr/edge-cloud-platform/pkg/vmspec"
	"github.com/gogo/protobuf/types"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type CloudletApi struct {
	all                 *AllApis
	sync                *Sync
	store               edgeproto.CloudletStore
	cache               *edgeproto.CloudletCache
	accessKeyServer     *node.AccessKeyServer
	dnsLabelStore       edgeproto.CloudletDnsLabelStore
	objectDnsLabelStore edgeproto.CloudletObjectDnsLabelStore
}

// Vault roles for all services
type VaultRoles struct {
	DmeRoleID    string `json:"dmeroleid"`
	DmeSecretID  string `json:"dmesecretid"`
	CRMRoleID    string `json:"crmroleid"`
	CRMSecretID  string `json:"crmsecretid"`
	CtrlRoleID   string `json:"controllerroleid"`
	CtrlSecretID string `json:"controllersecretid"`
}

// Transition states indicate states in which the CRM is still busy.
var CreateCloudletTransitions = map[dme.CloudletState]struct{}{}
var UpdateCloudletTransitions = map[dme.CloudletState]struct{}{
	dme.CloudletState_CLOUDLET_STATE_UPGRADE: struct{}{},
}

const (
	PlatformInitTimeout           = 20 * time.Minute
	DefaultResourceAlertThreshold = 80 // percentage
)

type updateCloudletCallback struct {
	in       *edgeproto.Cloudlet
	callback edgeproto.CloudletApi_CreateCloudletServer
}

func (s *updateCloudletCallback) cb(updateType edgeproto.CacheUpdateType, value string) {
	ctx := s.callback.Context()
	status := edgeproto.StatusInfo{}
	switch updateType {
	case edgeproto.UpdateTask:
		log.SpanLog(ctx, log.DebugLevelApi, "SetStatusTask", "key", s.in.Key, "taskName", value)
		status.SetTask(value)
		s.callback.Send(&edgeproto.Result{Message: status.ToString()})
	case edgeproto.UpdateStep:
		log.SpanLog(ctx, log.DebugLevelApi, "SetStatusStep", "key", s.in.Key, "stepName", value)
		status.SetStep(value)
		s.callback.Send(&edgeproto.Result{Message: status.ToString()})
	}
}

func ignoreCRMState(cctx *CallContext) bool {
	if cctx.Override == edgeproto.CRMOverride_IGNORE_CRM ||
		cctx.Override == edgeproto.CRMOverride_IGNORE_CRM_AND_TRANSIENT_STATE {
		return true
	}
	return false
}

func NewCloudletApi(sync *Sync, all *AllApis) *CloudletApi {
	cloudletApi := CloudletApi{}
	cloudletApi.all = all
	cloudletApi.sync = sync
	cloudletApi.store = edgeproto.NewCloudletStore(sync.store)
	cloudletApi.cache = nodeMgr.CloudletLookup.GetCloudletCache(node.NoRegion)
	sync.RegisterCache(cloudletApi.cache)
	cloudletApi.accessKeyServer = node.NewAccessKeyServer(cloudletApi.cache, nodeMgr.VaultAddr)
	return &cloudletApi
}

func (s *CloudletApi) Get(key *edgeproto.CloudletKey, buf *edgeproto.Cloudlet) bool {
	return s.cache.Get(key, buf)
}

func (s *CloudletApi) HasKey(key *edgeproto.CloudletKey) bool {
	return s.cache.HasKey(key)
}

func (s *CloudletApi) ReplaceErrorState(ctx context.Context, in *edgeproto.Cloudlet, newState edgeproto.TrackedState) {
	s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		inst := edgeproto.Cloudlet{}
		if !s.store.STMGet(stm, &in.Key, &inst) {
			// got deleted in the meantime
			return nil
		}

		if inst.State != edgeproto.TrackedState_CREATE_ERROR &&
			inst.State != edgeproto.TrackedState_DELETE_ERROR &&
			inst.State != edgeproto.TrackedState_UPDATE_ERROR {
			return nil
		}
		if newState == edgeproto.TrackedState_NOT_PRESENT {
			s.store.STMDel(stm, &in.Key)
			s.dnsLabelStore.STMDel(stm, inst.DnsLabel)
			s.all.cloudletRefsApi.store.STMDel(stm, &in.Key)
			s.all.clusterInstApi.deleteCloudletSingularCluster(stm, &in.Key, inst.SingleKubernetesClusterOwner)
		} else {
			inst.State = newState
			inst.Errors = nil
			s.store.STMPut(stm, &inst)
		}
		return nil
	})
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

func (s *CloudletApi) startCloudletStream(ctx context.Context, cctx *CallContext, key *edgeproto.CloudletKey, inCb edgeproto.CloudletApi_CreateCloudletServer) (*streamSend, edgeproto.CloudletApi_CreateCloudletServer, error) {
	streamSendObj, outCb, err := s.all.streamObjApi.startStream(ctx, cctx, key.StreamKey(), inCb)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to start Cloudlet stream", "err", err)
		return nil, inCb, err
	}
	return streamSendObj, outCb, err
}

func (s *CloudletApi) stopCloudletStream(ctx context.Context, cctx *CallContext, key *edgeproto.CloudletKey, streamSendObj *streamSend, objErr error, cleanupStream CleanupStreamAction) {
	if err := s.all.streamObjApi.stopStream(ctx, cctx, key.StreamKey(), streamSendObj, objErr, cleanupStream); err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to stop Cloudlet stream", "err", err)
	}
}

func (s *StreamObjApi) StreamCloudlet(key *edgeproto.CloudletKey, cb edgeproto.StreamObjApi_StreamCloudletServer) error {
	ctx := cb.Context()
	cloudlet := &edgeproto.Cloudlet{}
	// if cloudlet is absent, then stream the deletion status messages
	if !s.all.cloudletApi.cache.Get(key, cloudlet) ||
		cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_DIRECT_ACCESS ||
		(cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS && cloudlet.State != edgeproto.TrackedState_READY) {
		// If restricted scenario, then stream msgs only if either cloudlet obj was not created successfully or it is updating
		return s.StreamMsgs(ctx, key.StreamKey(), cb)
	}
	cloudletInfo := edgeproto.CloudletInfo{}
	if s.all.cloudletInfoApi.cache.Get(key, &cloudletInfo) {
		if cloudletInfo.State == dme.CloudletState_CLOUDLET_STATE_READY ||
			cloudletInfo.State == dme.CloudletState_CLOUDLET_STATE_ERRORS ||
			cloudletInfo.State == dme.CloudletState_CLOUDLET_STATE_OFFLINE {
			return nil
		}
	}
	features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
	if err != nil {
		return err
	}

	updatecb := updateCloudletCallback{cloudlet, cb}
	reqCtx, reqCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer reqCancel()

	client := rediscache.GetCCRMAPIClient(redisClient, features.NodeType)
	err = client.GetRestrictedCloudletStatus(reqCtx, key, func(status *edgeproto.StreamStatus) error {
		log.SpanLog(ctx, log.DebugLevelApi, "GetRestrictedCloudletStatus update", "cb", status)
		updatecb.cb(edgeproto.CacheUpdateType(status.CacheUpdateType), status.Status)
		return nil
	})
	if err != nil {
		return err
	}

	// Fetch cloudlet info status
	lastMsgId := 0
	done := make(chan bool, 1)
	failed := make(chan bool, 1)

	log.SpanLog(ctx, log.DebugLevelApi, "wait for cloudlet state", "key", key)

	checkState := func(key *edgeproto.CloudletKey) {
		cloudlet := edgeproto.Cloudlet{}
		if !s.all.cloudletApi.cache.Get(key, &cloudlet) {
			return
		}
		cloudletInfo := edgeproto.CloudletInfo{}
		if !s.all.cloudletInfoApi.cache.Get(key, &cloudletInfo) {
			return
		}

		curState := cloudletInfo.State

		if curState == dme.CloudletState_CLOUDLET_STATE_ERRORS ||
			curState == dme.CloudletState_CLOUDLET_STATE_OFFLINE {
			failed <- true
			return
		}

		if curState == dme.CloudletState_CLOUDLET_STATE_READY {
			done <- true
			return
		}
	}

	log.SpanLog(ctx, log.DebugLevelApi, "watch event for CloudletInfo")
	info := edgeproto.CloudletInfo{}
	cancel := s.all.cloudletInfoApi.cache.WatchKey(key, func(ctx context.Context) {
		if !s.all.cloudletInfoApi.cache.Get(key, &info) {
			return
		}
		for ii := lastMsgId; ii < len(info.Status.Msgs); ii++ {
			cb.Send(&edgeproto.Result{Message: info.Status.Msgs[ii]})
			lastMsgId++
		}
		checkState(key)
	})

	// After setting up watch, check current state,
	// as it may have already changed to target state
	checkState(key)

	select {
	case <-done:
		err = nil
		cb.Send(&edgeproto.Result{Message: "Cloudlet setup successfully"})
	case <-failed:
		if s.all.cloudletInfoApi.cache.Get(key, &info) {
			errs := strings.Join(info.Errors, ", ")
			err = fmt.Errorf("Encountered failures: %s", errs)
		} else {
			err = fmt.Errorf("Unknown failure")
		}
		cb.Send(&edgeproto.Result{Message: err.Error()})
	case <-time.After(PlatformInitTimeout):
		err = fmt.Errorf("Timed out waiting for cloudlet state to be Ready")
		cb.Send(&edgeproto.Result{Message: "platform bringup timed out"})
	}

	cancel()

	return err
}

func (s *CloudletApi) CreateCloudlet(in *edgeproto.Cloudlet, cb edgeproto.CloudletApi_CreateCloudletServer) error {
	if in.IpSupport == edgeproto.IpSupport_IP_SUPPORT_UNKNOWN {
		in.IpSupport = edgeproto.IpSupport_IP_SUPPORT_DYNAMIC
	}
	// TODO: support static IP assignment.
	if in.IpSupport != edgeproto.IpSupport_IP_SUPPORT_DYNAMIC {
		return errors.New("Only dynamic IPs are supported currently")
	}
	if in.IpSupport == edgeproto.IpSupport_IP_SUPPORT_STATIC {
		// TODO: Validate static ips
	} else {
		// dynamic
		if in.NumDynamicIps < 1 {
			return errors.New("Must specify at least one dynamic public IP available")
		}
	}
	if in.Location.Latitude == 0 && in.Location.Longitude == 0 {
		// user forgot to specify location
		return errors.New("location is missing; 0,0 is not a valid location")
	}

	// If notifysrvaddr is empty, set default value
	if in.NotifySrvAddr == "" {
		in.NotifySrvAddr = "127.0.0.1:0"
	}
	if in.SecondaryNotifySrvAddr == "" {
		in.SecondaryNotifySrvAddr = "127.0.0.1:0"
	}

	if in.ContainerVersion == "" {
		in.ContainerVersion = *versionTag
	}

	if in.DefaultResourceAlertThreshold == 0 {
		in.DefaultResourceAlertThreshold = DefaultResourceAlertThreshold
	}

	if in.DeploymentLocal {
		if in.AccessVars != nil {
			return errors.New("Access vars is not supported for local deployment")
		}
		if in.VmImageVersion != "" {
			return errors.New("VM Image version is not supported for local deployment")
		}
		if in.Deployment != "" {
			return errors.New("Deployment type is not supported for local deployment")
		}
		if in.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
			return errors.New("Infra access type private is not supported for local deployment")
		}
	} else {
		if in.Deployment == "" {
			in.Deployment = cloudcommon.DeploymentTypeDocker
		}
		if !cloudcommon.IsValidDeploymentType(in.Deployment, cloudcommon.ValidCloudletDeployments) {
			return fmt.Errorf("Invalid deployment, must be one of %v", cloudcommon.ValidCloudletDeployments)
		}
	}

	if in.GpuConfig.Driver.Name == "" {
		in.GpuConfig = edgeproto.GPUConfig{}
	}
	return s.createCloudletInternal(DefCallContext(), in, cb)
}

func caseInsensitiveContains(s, substr string) bool {
	s, substr = strings.ToUpper(s), strings.ToUpper(substr)
	return strings.Contains(s, substr)
}

func caseInsensitiveContainsTimedOut(s string) bool {
	return caseInsensitiveContains(s, "Timed out") || caseInsensitiveContains(s, "timedout")
}

func (s *CloudletApi) createCloudletInternal(cctx *CallContext, in *edgeproto.Cloudlet, inCb edgeproto.CloudletApi_CreateCloudletServer) (reterr error) {
	cctx.SetOverride(&in.CrmOverride)
	ctx := inCb.Context()

	if in.PlatformType == "" {
		return fmt.Errorf("Cloudlet platform type not specified")
	}
	features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, in.PlatformType)
	if err != nil {
		return fmt.Errorf("Failed to get features for platform: %s", err)
	}
	// EdgeboxOnly is set at MC for edgebox only operators.
	if in.EdgeboxOnly && !features.IsEdgebox && !features.IsMock {
		return fmt.Errorf("Cloudlet is restricted to edgebox or mock only platforms; %s is not an edgebox or mock platform", in.PlatformType)
	}

	if in.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS &&
		!features.IsVmPool && !features.IsPrebuiltKubernetesCluster {
		if in.InfraConfig.FlavorName == "" {
			return errors.New("Infra flavor name is required for private deployments")
		}
		if in.InfraConfig.ExternalNetworkName == "" {
			return errors.New("Infra external network is required for private deployments")
		}
	}
	if in.VmPool != "" {
		if !features.IsVmPool {
			return fmt.Errorf("Platform %s is not a VM Pool platform", in.PlatformType)
		}
		vmPoolKey := edgeproto.VMPoolKey{
			Name:         in.VmPool,
			Organization: in.Key.Organization,
		}
		if s.UsesVMPool(&vmPoolKey) {
			return errors.New("VM Pool with this name is already in use by some other Cloudlet")
		}
	} else {
		if features.IsVmPool {
			return fmt.Errorf("VM Pool platform %s requires a VmPool to be specified", in.PlatformType)
		}
	}
	if in.EnableDefaultServerlessCluster && !features.SupportsMultiTenantCluster {
		return fmt.Errorf("Serverless cluster not supported on %s", in.PlatformType)
	}
	if in.TrustPolicy != "" && !features.SupportsTrustPolicy {
		return fmt.Errorf("Trust Policy not supported on %s", in.PlatformType)
	}
	if in.PlatformHighAvailability {
		if in.Deployment == cloudcommon.DeploymentTypeDocker && !features.SupportsPlatformHighAvailabilityOnDocker {
			return fmt.Errorf("Platform High Availability not supported for docker on %s", in.PlatformType)
		} else if in.Deployment == cloudcommon.DeploymentTypeKubernetes && !features.SupportsPlatformHighAvailabilityOnK8S {
			return fmt.Errorf("Platform High Availability not supported for k8s on %s", in.PlatformType)
		}
	}
	if err := validateAllianceOrgs(ctx, in); err != nil {
		return err
	}

	cloudletKey := in.Key
	sendObj, cb, err := s.startCloudletStream(ctx, cctx, &cloudletKey, inCb)
	if err != nil {
		return err
	}
	defer func() {
		cleanupStream := NoCleanupStream
		if reterr != nil {
			// Cleanup stream if object is not present in etcd (due to undo)
			if !s.store.Get(ctx, &in.Key, nil) {
				cleanupStream = CleanupStream
			}
		}
		s.stopCloudletStream(ctx, cctx, &cloudletKey, sendObj, reterr, cleanupStream)
		if reterr == nil {
			RecordCloudletEvent(ctx, &in.Key, cloudcommon.CREATED, cloudcommon.InstanceUp)
		}
	}()

	if in.PhysicalName == "" {
		in.PhysicalName = in.Key.Name
		cb.Send(&edgeproto.Result{Message: "Setting physicalname to match cloudlet name"})
	}

	pfFlavor := edgeproto.Flavor{}
	if in.Flavor.Name == "" {
		in.Flavor = cloudcommon.DefaultPlatformFlavorKey
	}

	accessVars := make(map[string]string)
	if in.AccessVars != nil {
		accessVars = in.AccessVars
		in.AccessVars = nil
	}

	kafkaDetails := node.KafkaCreds{}
	if (in.KafkaUser != "") != (in.KafkaPassword != "") {
		return errors.New("Must specify both kafka username and password, or neither")
	} else if in.KafkaCluster == "" && in.KafkaUser != "" {
		return errors.New("Must specify a kafka cluster endpoint in addition to kafka credentials")
	}
	if in.KafkaCluster != "" {
		kafkaDetails.Endpoint = in.KafkaCluster
		kafkaDetails.Username = in.KafkaUser
		kafkaDetails.Password = in.KafkaPassword
		in.KafkaUser = ""
		in.KafkaPassword = ""
	}
	// store kafka details in Vault
	if kafkaDetails.Endpoint != "" {
		path := node.GetKafkaVaultPath(*region, in.Key.Name, in.Key.Organization)
		err = vault.PutData(vaultConfig, path, kafkaDetails)
		if err != nil {
			return fmt.Errorf("Unable to store kafka details: %s", err)
		}
	}
	defer func() {
		if reterr == nil {
			return
		}
		client, err := vaultConfig.Login()
		if err == nil {
			vault.DeleteKV(client, node.GetKafkaVaultPath(*region, in.Key.Name, in.Key.Organization))
		} else {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to login in to vault to delete kafka credentials", "err", err)
		}
	}()

	accessKey, err := node.GenerateAccessKey()
	if err != nil {
		return err
	}
	keys := accessvars.CRMAccessKeys{}
	keys.PublicPEM = accessKey.PublicPEM
	keys.PrivatePEM = accessKey.PrivatePEM
	in.CrmAccessPublicKey = accessKey.PublicPEM
	in.CrmAccessKeyUpgradeRequired = true

	if in.PlatformHighAvailability {
		secondaryAccessKey, err := node.GenerateAccessKey()
		if err != nil {
			return err
		}
		keys.SecondaryPublicPEM = secondaryAccessKey.PublicPEM
		keys.SecondaryPrivatePEM = secondaryAccessKey.PrivatePEM
		in.SecondaryCrmAccessPublicKey = secondaryAccessKey.PublicPEM
		in.SecondaryCrmAccessKeyUpgradeRequired = true
	}

	err = accessvars.SaveCRMAccessKeys(ctx, *region, in, nodeMgr.VaultConfig, &keys)
	if err != nil {
		return err
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := accessvars.DeleteCRMAccessKeys(ctx, *region, in, nodeMgr.VaultConfig)
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to undo save of crm access vars", "cloudlet", in.Key, "err", err)
		}
	}()

	if len(accessVars) > 0 {
		err = accessvars.ValidateAccessVars(accessVars, features.AccessVars)
		if err != nil {
			return err
		}
		err = accessvars.SaveCloudletAccessVars(ctx, *region, in, nodeMgr.VaultConfig, accessVars, features.AccessVars)
		if err != nil {
			return err
		}
		// NOTE: If accessvars is successfully stored then do not delete it on cleanup
		//       as it can be shared amongst other cloudlets
	}

	onboardingInfo := edgeproto.CloudletOnboardingInfo{
		Key: in.Key,
	}
	onboardingSub := rediscache.Subscribe(ctx, redisClient, &onboardingInfo)
	defer onboardingSub.Close()

	vmPool := edgeproto.VMPool{}
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if s.store.STMGet(stm, &in.Key, nil) {
			if !cctx.Undo {
				if in.State == edgeproto.TrackedState_CREATE_ERROR {
					cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Previous create failed, %v", in.Errors)})
					cb.Send(&edgeproto.Result{Message: "Use DeleteCloudlet to remove and try again"})
				}
				return in.Key.ExistsError()
			}
			in.Errors = nil
		}
		// this just makes sure features isn't being deleted before
		// we start using it.
		featuresCheck := edgeproto.PlatformFeatures{}
		featuresKey := edgeproto.PlatformFeaturesKey(in.PlatformType)
		if !s.all.platformFeaturesApi.store.STMGet(stm, &featuresKey, &featuresCheck) {
			return featuresKey.NotFoundError()
		}
		if featuresCheck.DeletePrepare {
			return featuresKey.BeingDeletedError()
		}
		if in.Flavor.Name != "" && in.Flavor.Name != cloudcommon.DefaultPlatformFlavorKey.Name {
			if !s.all.flavorApi.store.STMGet(stm, &in.Flavor, &pfFlavor) {
				return in.Flavor.NotFoundError()
			}
			if pfFlavor.DeletePrepare {
				return in.Flavor.BeingDeletedError()
			}
		}
		if in.VmPool != "" {
			vmPoolKey := edgeproto.VMPoolKey{
				Name:         in.VmPool,
				Organization: in.Key.Organization,
			}
			if !s.all.vmPoolApi.store.STMGet(stm, &vmPoolKey, &vmPool) {
				return vmPoolKey.NotFoundError()
			}
			if vmPool.DeletePrepare {
				return vmPoolKey.BeingDeletedError()
			}
		}
		if in.GpuConfig.Driver.Name != "" {
			if in.GpuConfig.Driver.Organization != "" && in.GpuConfig.Driver.Organization != in.Key.Organization {
				return fmt.Errorf("Can only use %s or '' org gpu drivers", in.Key.Organization)
			}
			gpuDriver := edgeproto.GPUDriver{}
			if !s.all.gpuDriverApi.store.STMGet(stm, &in.GpuConfig.Driver, &gpuDriver) {
				return in.GpuConfig.Driver.NotFoundError()
			}
			if gpuDriver.DeletePrepare {
				return in.GpuConfig.Driver.BeingDeletedError()
			}
			if gpuDriver.State == ChangeInProgress {
				return fmt.Errorf("GPU driver %s is busy", in.GpuConfig.Driver.String())
			}
			in.LicenseConfigStoragePath, err = cloudcommon.GetGPUDriverLicenseCloudletStoragePath(&gpuDriver.Key, *region, &in.Key)
			if err != nil {
				return err
			}
			// Check for md5sum to be empty so that the following is idempotent on multiple STM runs
			if in.GpuConfig.LicenseConfig != "" && in.GpuConfig.LicenseConfigMd5Sum == "" {
				storageClient, err := getGCSStorageClient(ctx, &gpuDriver)
				if err != nil {
					return err
				}
				defer storageClient.Close()

				cb.Send(&edgeproto.Result{Message: "Uploading the GPU driver license config to secure storage"})
				log.SpanLog(ctx, log.DebugLevelApi, "Uploading GPU driver license config to GCS", "driver key", gpuDriver.Key, "license path", in.LicenseConfigStoragePath)
				err = storageClient.UploadObject(ctx, in.LicenseConfigStoragePath, "", bytes.NewBufferString(in.GpuConfig.LicenseConfig))
				if err != nil {
					return fmt.Errorf("Failed to upload GPU driver license to %s, %v", in.LicenseConfigStoragePath, err)
				}
				// store the GCS path to license config
				in.GpuConfig.LicenseConfigMd5Sum = cloudcommon.Md5SumStr(in.GpuConfig.LicenseConfig)
				in.GpuConfig.LicenseConfig = cloudcommon.GetGPUDriverLicenseURL(gpuDriver.StorageBucketName, in.LicenseConfigStoragePath)
			}
		}
		if in.TrustPolicy != "" {
			policy := edgeproto.TrustPolicy{}
			policy.Key.Name = in.TrustPolicy
			policy.Key.Organization = in.Key.Organization
			if !s.all.trustPolicyApi.store.STMGet(stm, &policy.Key, &policy) {
				err := policy.Key.NotFoundError()
				return fmt.Errorf("%s", err.Error())
			}
			if policy.DeletePrepare {
				return policy.Key.BeingDeletedError()
			}
		}
		for _, rttKey := range in.ResTagMap {
			resTagTable := edgeproto.ResTagTable{}
			if !s.all.resTagTableApi.store.STMGet(stm, rttKey, &resTagTable) {
				return rttKey.NotFoundError()
			}
			if resTagTable.DeletePrepare {
				return rttKey.BeingDeletedError()
			}
		}

		err := in.Validate(edgeproto.CloudletAllFieldsMap)
		if err != nil {
			return err
		}
		resProps := features.ResourceQuotaProperties
		err = cloudcommon.ValidateCloudletResourceQuotas(ctx, resProps, nil, in.ResourceQuotas)
		if err != nil {
			return err
		}
		if err := s.setDnsLabel(stm, in); err != nil {
			return err
		}
		in.RootLbFqdn = getCloudletRootLBFQDN(in)
		if features.IsSingleKubernetesCluster {
			// create ClusterInst representation of Cloudlet
			err := s.all.clusterInstApi.createCloudletSingularCluster(stm, in, in.SingleKubernetesClusterOwner)
			if err != nil {
				return err
			}
		} else {
			if in.SingleKubernetesClusterOwner != "" {
				return fmt.Errorf("Single kubernetes cluster owner can only be set on a single cluster platform")
			}
		}

		in.CreatedAt = dme.TimeToTimestamp(time.Now())

		if ignoreCRMState(cctx) {
			in.OnboardingState = edgeproto.TrackedState_READY
			in.State = edgeproto.TrackedState_READY
		} else {
			in.OnboardingState = edgeproto.TrackedState_CREATE_REQUESTED
			in.State = edgeproto.TrackedState_CREATING
		}
		s.store.STMPut(stm, in)
		s.dnsLabelStore.STMPut(stm, in.DnsLabel)
		return nil
	})
	if err != nil {
		return err
	}

	defer func() {
		if reterr == nil {
			s.all.clusterInstApi.updateCloudletResourcesMetric(ctx, &in.Key)
		}
	}()

	if ignoreCRMState(cctx) {
		return nil
	}

	cloudletResourcesCreated := false
	defer func() {
		if reterr != nil {
			cb.Send(&edgeproto.Result{Message: reterr.Error()})
			cb.Send(&edgeproto.Result{Message: "Deleting Cloudlet due to failures"})
			log.SpanLog(ctx, log.DebugLevelInfo, "deleting cloudlet due to failures")
			undoErr := s.deleteCloudletInternal(cctx.WithUndo(), in, cb, cloudletResourcesCreated)
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "Undo create Cloudlet", "undoErr", undoErr)
			}
		}
	}()

	// CCRM will handle the state CREATE_REQUESTED.
	// It will send CloudletOnboardingInfo messages as it progresses,
	// and will start a CRM process.
	reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().CreateCloudletTimeout.TimeDuration())
	defer reqCancel()

	// Check for any error sent by the platform-specific onboarding.
	err = onboardingSub.WaitForMessage(reqCtx, func() (bool, error) {
		if onboardingInfo.OnboardingState == edgeproto.TrackedState_READY || onboardingInfo.OnboardingState == edgeproto.TrackedState_CREATE_ERROR {
			// done
			return true, nil
		}
		return false, nil
	})
	if err != nil && cctx.Override == edgeproto.CRMOverride_IGNORE_CRM_ERRORS {
		cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Create Cloudlet ignoring CRM failure: %s", err.Error())})
		s.ReplaceErrorState(ctx, in, edgeproto.TrackedState_READY)
		cb.Send(&edgeproto.Result{Message: "Created Cloudlet successfully"})
		return nil
	}
	if err != nil {
		return fmt.Errorf("Cloudlet onboarding failed: %s", err)
	}
	if onboardingInfo.OnboardingState == edgeproto.TrackedState_CREATE_ERROR {
		return errors.New(strings.Join(onboardingInfo.Errors, ", "))
	}
	cloudletResourcesCreated = true

	cloudlet := edgeproto.Cloudlet{}
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		saveCloudlet := false
		if !s.store.STMGet(stm, &in.Key, &cloudlet) {
			return in.Key.NotFoundError()
		}
		if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
			cloudlet.State = edgeproto.TrackedState_READY
			saveCloudlet = true
		}
		if in.ChefClientKey != nil {
			cloudlet.ChefClientKey = in.ChefClientKey
			saveCloudlet = true
		}
		if in.DeploymentLocal || features.CloudletServicesLocal {
			// Store controller address if crmserver is started locally
			cloudlet.HostController = *externalApiAddr
			saveCloudlet = true
		}
		if saveCloudlet {
			s.store.STMPut(stm, &cloudlet)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if in.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		cb.Send(&edgeproto.Result{
			Message: "Cloudlet configured successfully. Please run `GetCloudletManifest` to bringup Platform VM(s) for cloudlet services",
		})
		return nil
	}
	// Wait for CRM to connect to controller
	go func() {
		err := process.CrmServiceWait(in.Key)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to cleanup crm service", "err", err)
		}
	}()
	err = edgeproto.WaitForCloudletInfo(
		reqCtx, &in.Key,
		dme.CloudletState_CLOUDLET_STATE_READY,
		CreateCloudletTransitions, dme.CloudletState_CLOUDLET_STATE_ERRORS,
		"Created Cloudlet successfully", cb.Send,
		edgeproto.WithCrmMsgCh(sendObj.crmMsgCh))

	return err
}

func (s *CloudletApi) VerifyTrustPoliciesForAppInsts(ctx context.Context, app *edgeproto.App, appInsts map[edgeproto.AppInstKey]struct{}) error {
	TrustPolicies := make(map[edgeproto.PolicyKey]*edgeproto.TrustPolicy)
	s.all.trustPolicyApi.GetTrustPolicies(TrustPolicies)
	s.cache.Mux.Lock()
	trustedCloudlets := make(map[edgeproto.CloudletKey]*edgeproto.PolicyKey)
	for key, data := range s.cache.Objs {
		val := data.Obj
		if val.TrustPolicy != "" {
			pkey := edgeproto.PolicyKey{
				Organization: val.Key.Organization,
				Name:         val.TrustPolicy,
			}
			trustedCloudlets[key] = &pkey
		}

	}
	s.cache.Mux.Unlock()
	for akey := range appInsts {
		pkey, cloudletFound := trustedCloudlets[akey.CloudletKey]
		if cloudletFound {
			policy, policyFound := TrustPolicies[*pkey]
			if !policyFound {
				return fmt.Errorf("Unable to find trust policy in cache: %s", pkey.String())
			}
			err := s.all.appApi.CheckAppCompatibleWithTrustPolicy(ctx, &akey.CloudletKey, app, policy)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// updateTrustPolicyInternal updates the TrustPolicyState to TrackedState_UPDATE_REQUESTED
// and then waits for the update to complete.
func (s *CloudletApi) updateTrustPolicyInternal(ctx context.Context, ckey *edgeproto.CloudletKey, policyName string, cb edgeproto.CloudletApi_UpdateCloudletServer) error {
	log.SpanLog(ctx, log.DebugLevelApi, "updateTrustPolicyInternal", "policyName", policyName)

	err := cb.Send(&edgeproto.Result{
		Message: fmt.Sprintf("Doing TrustPolicy: %s Update for Cloudlet: %s", policyName, ckey.String()),
	})
	if err != nil {
		return err
	}
	cloudletInfo := edgeproto.CloudletInfo{}
	cloudlet := &edgeproto.Cloudlet{}
	var updateErr error
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, ckey, cloudlet) {
			return ckey.NotFoundError()
		}
		if !s.all.cloudletInfoApi.cache.Get(ckey, &cloudletInfo) {
			updateErr = fmt.Errorf("CloudletInfo not found for %s", ckey.String())
		} else {
			if cloudletInfo.State != dme.CloudletState_CLOUDLET_STATE_READY {
				updateErr = fmt.Errorf("Cannot modify trust policy for cloudlet in state: %s", cloudletInfo.State)
			}
		}
		if updateErr != nil {
			cloudlet.TrustPolicyState = edgeproto.TrackedState_UPDATE_ERROR
		} else {
			cloudlet.TrustPolicyState = edgeproto.TrackedState_UPDATE_REQUESTED
		}
		cloudlet.UpdatedAt = dme.TimeToTimestamp(time.Now())
		s.store.STMPut(stm, cloudlet)
		return nil
	})
	if err != nil {
		return err
	}
	if updateErr != nil {
		return updateErr
	}
	targetState := edgeproto.TrackedState_READY
	if policyName == "" {
		targetState = edgeproto.TrackedState_NOT_PRESENT
	}
	err = s.WaitForTrustPolicyState(ctx, ckey, targetState, edgeproto.TrackedState_UPDATE_ERROR, s.all.settingsApi.Get().UpdateTrustPolicyTimeout.TimeDuration())
	if err == nil {
		cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Successful TrustPolicy: %s Update for Cloudlet: %s", policyName, ckey.String())})
	} else if caseInsensitiveContainsTimedOut(err.Error()) {
		cb.Send(&edgeproto.Result{Message: fmt.Sprintf("In progress TrustPolicy: %s Update for Cloudlet: %s -- %v", policyName, ckey.String(), err.Error())})
	} else {
		cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Failed TrustPolicy: %s Update for Cloudlet: %s -- %v", policyName, ckey.String(), err.Error())})
	}
	return err
}

func (s *CloudletApi) UpdateCloudlet(in *edgeproto.Cloudlet, inCb edgeproto.CloudletApi_UpdateCloudletServer) (reterr error) {
	ctx := inCb.Context()
	cctx := DefCallContext()
	cctx.SetOverride(&in.CrmOverride)

	if err := validateAllianceOrgs(ctx, in); err != nil {
		return err
	}

	cloudletKey := in.Key
	sendObj, cb, err := s.startCloudletStream(ctx, cctx, &cloudletKey, inCb)
	if err != nil {
		return err
	}
	defer func() {
		s.stopCloudletStream(ctx, cctx, &cloudletKey, sendObj, reterr, NoCleanupStream)
	}()

	_ = updateCloudletCallback{in, cb}

	err = in.ValidateUpdateFields()
	if err != nil {
		return err
	}

	fmap := edgeproto.MakeFieldMap(in.Fields)
	if _, found := fmap[edgeproto.CloudletFieldNumDynamicIps]; found {
		staticSet := false
		if _, staticFound := fmap[edgeproto.CloudletFieldIpSupport]; staticFound {
			if in.IpSupport == edgeproto.IpSupport_IP_SUPPORT_STATIC {
				staticSet = true
			}
		}
		if in.NumDynamicIps < 1 && !staticSet {
			return errors.New("Cannot specify less than one dynamic IP unless Ip Support Static is specified")
		}
	}

	err = in.Validate(fmap)
	if err != nil {
		return err
	}

	cur := &edgeproto.Cloudlet{}
	if !s.cache.Get(&in.Key, cur) {
		return in.Key.NotFoundError()
	}
	features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cur.PlatformType)
	if err != nil {
		return fmt.Errorf("Failed to get features for platform: %s", err)
	}

	accessVars := make(map[string]string)
	if _, found := fmap[edgeproto.CloudletFieldAccessVars]; found {
		if in.DeploymentLocal {
			return errors.New("Access vars is not supported for local deployment")
		}
		accessVars = in.AccessVars
		in.AccessVars = nil
	}

	_, singleKubernetesClusterOwnerSet := fmap[edgeproto.CloudletFieldSingleKubernetesClusterOwner]
	if singleKubernetesClusterOwnerSet {
		// TODO: to support this, we need to use the ClusterRefs
		// to make sure no AppInsts exist, and then we need to delete
		// the current default single cluster and create a new one with
		// the new org.
		return fmt.Errorf("Changing the single kubernetes cluster owner is not supported yet")
	}

	_, kafkaClusterChanged := fmap[edgeproto.CloudletFieldKafkaCluster]
	_, kafkaUserChanged := fmap[edgeproto.CloudletFieldKafkaUser]
	_, kafkaPasswordChanged := fmap[edgeproto.CloudletFieldKafkaPassword]
	if kafkaClusterChanged && in.KafkaCluster == "" {
		in.KafkaCluster = ""
		in.KafkaUser = ""
		in.KafkaPassword = ""
		client, err := vaultConfig.Login()
		if err == nil {
			vault.DeleteKV(client, node.GetKafkaVaultPath(*region, in.Key.Name, in.Key.Organization))
		} else {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to login in to vault to delete kafka credentials", "err", err)
		}
	} else if kafkaClusterChanged || kafkaUserChanged || kafkaPasswordChanged {
		// get existing data
		kafkaCreds := node.KafkaCreds{}
		path := node.GetKafkaVaultPath(*region, in.Key.Name, in.Key.Organization)
		err := vault.GetData(vaultConfig, path, 0, &kafkaCreds)
		if kafkaClusterChanged {
			kafkaCreds.Endpoint = in.KafkaCluster
		}
		if kafkaUserChanged {
			kafkaCreds.Username = in.KafkaUser
		}
		if kafkaPasswordChanged {
			kafkaCreds.Password = in.KafkaPassword
		}
		if kafkaUserChanged != kafkaPasswordChanged {
			return errors.New("Must specify both kafka username and password, or neither")
		}
		// must specify either just a new endpoint, or everything
		if !kafkaClusterChanged && kafkaUserChanged {
			return errors.New("Please also specify endpoint when changing username and password")
		}
		// write back changes
		err = vault.PutData(vaultConfig, path, kafkaCreds)
		if err != nil {
			return fmt.Errorf("Unable to store kafka details: %s", err)
		}
	}
	in.KafkaUser = ""
	in.KafkaPassword = ""

	newLicenseConfig := ""
	if _, found := fmap[edgeproto.CloudletFieldGpuConfigLicenseConfig]; found {
		newLicenseConfig = in.GpuConfig.LicenseConfig
		in.GpuConfig.LicenseConfig = ""
	}

	crmUpdateReqd := false
	if _, found := fmap[edgeproto.CloudletFieldEnvVar]; found {
		if _, found := fmap[edgeproto.CloudletFieldMaintenanceState]; found {
			return errors.New("Cannot set envvars if maintenance state is set")
		}
		crmUpdateReqd = true
	}

	cloudletSpecificResources := features.ResourceQuotaProperties
	if err != nil {
		return err
	}
	if !ignoreCRMState(cctx) {
		if len(accessVars) > 0 {
			err = accessvars.UpdateCloudletAccessVars(ctx, *region, in, nodeMgr.VaultConfig, accessVars, features.AccessVars)
			if err != nil {
				return err
			}
		}
	}

	var newMaintenanceState dme.MaintenanceState
	maintenanceChanged := false
	_, privPolUpdateRequested := fmap[edgeproto.CloudletFieldTrustPolicy]

	var gpuDriver edgeproto.GPUDriver
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, cur) {
			return in.Key.NotFoundError()
		}
		cloudletInfo := edgeproto.CloudletInfo{}
		if !s.all.cloudletInfoApi.store.STMGet(stm, &in.Key, &cloudletInfo) {
			return fmt.Errorf("Missing cloudlet info: %v", in.Key)
		}
		cloudletRefs := edgeproto.CloudletRefs{}
		s.all.cloudletRefsApi.store.STMGet(stm, &in.Key, &cloudletRefs)
		if _, found := fmap[edgeproto.CloudletFieldResourceQuotas]; found {
			// get all cloudlet resources (platformVM, sharedRootLB, clusterVms, AppVMs, etc)
			allVmResources, _, _, err := s.all.clusterInstApi.getAllCloudletResources(ctx, stm, cur, &cloudletInfo, &cloudletRefs)
			if err != nil {
				return err
			}
			infraResInfo := make(map[string]edgeproto.InfraResource)
			for _, resInfo := range cloudletInfo.ResourcesSnapshot.Info {
				infraResInfo[resInfo.Name] = resInfo
			}

			allResInfo, err := s.all.cloudletApi.GetCloudletResourceInfo(ctx, stm, cur, allVmResources, infraResInfo)
			if err != nil {
				return err
			}
			err = cloudcommon.ValidateCloudletResourceQuotas(ctx, cloudletSpecificResources, allResInfo, in.ResourceQuotas)
			if err != nil {
				return err
			}
			crmUpdateReqd = true
		}
		if _, found := fmap[edgeproto.CloudletFieldGpuConfig]; found {
			if in.GpuConfig.Driver.Name == "" {
				// clear GPU config
				in.GpuConfig = edgeproto.GPUConfig{}
				in.LicenseConfigStoragePath = ""
				in.Fields = append(in.Fields, edgeproto.CloudletFieldGpuConfigDriverName)
				in.Fields = append(in.Fields, edgeproto.CloudletFieldGpuConfigDriverOrganization)
				in.Fields = append(in.Fields, edgeproto.CloudletFieldGpuConfigProperties)
				in.Fields = append(in.Fields, edgeproto.CloudletFieldLicenseConfigStoragePath)
			} else {
				if in.GpuConfig.Driver.Organization != "" && in.GpuConfig.Driver.Organization != in.Key.Organization {
					return fmt.Errorf("Can only use %s or '' org gpu drivers", in.Key.Organization)
				}
				if !s.all.gpuDriverApi.store.STMGet(stm, &in.GpuConfig.Driver, &gpuDriver) {
					return fmt.Errorf("GPU driver %s not found", in.GpuConfig.Driver.String())
				}
				if gpuDriver.DeletePrepare {
					return in.GpuConfig.Driver.BeingDeletedError()
				}
				if gpuDriver.State == ChangeInProgress {
					return fmt.Errorf("GPU driver %s is busy", in.GpuConfig.Driver.String())
				}
				in.LicenseConfigStoragePath, err = cloudcommon.GetGPUDriverLicenseCloudletStoragePath(&gpuDriver.Key, *region, &in.Key)
				if err != nil {
					return err
				}
				in.Fields = append(in.Fields, edgeproto.CloudletFieldLicenseConfigStoragePath)
			}
			crmUpdateReqd = true
		}

		if in.GpuConfig.Driver.Name != "" {
			if !s.all.gpuDriverApi.store.STMGet(stm, &in.GpuConfig.Driver, &gpuDriver) {
				return fmt.Errorf("GPU driver %s not found", in.GpuConfig.Driver.String())
			}
		}

		old := edgeproto.Cloudlet{}
		old.DeepCopyIn(cur)
		cur.CopyInFields(in)
		newMaintenanceState = cur.MaintenanceState
		if newMaintenanceState != old.MaintenanceState {
			maintenanceChanged = true
			// don't change maintenance here, we handle it below
			cur.MaintenanceState = old.MaintenanceState
		}
		if newMaintenanceState == dme.MaintenanceState_MAINTENANCE_START || newMaintenanceState == dme.MaintenanceState_MAINTENANCE_START_NO_FAILOVER {
			// return error when trying to put into maintenance but current state is not normal
			if old.MaintenanceState != dme.MaintenanceState_NORMAL_OPERATION {
				return fmt.Errorf("Cloudlet must be in NormalOperation before starting maintenance")
			}
		}
		if privPolUpdateRequested {
			if maintenanceChanged {
				return fmt.Errorf("Cannot change both maintenance state and trust policy at the same time")
			}
			if !ignoreCRM(cctx) {
				if cur.State != edgeproto.TrackedState_READY {
					return fmt.Errorf("Trust policy cannot be changed while cloudlet is not ready")
				}
			}
			if in.TrustPolicy != "" {
				if !features.SupportsTrustPolicy {
					return fmt.Errorf("Trust Policy not supported on %s", cur.PlatformType)
				}
				policy := edgeproto.TrustPolicy{}
				policy.Key.Name = in.TrustPolicy
				policy.Key.Organization = in.Key.Organization
				if !s.all.trustPolicyApi.store.STMGet(stm, &policy.Key, &policy) {
					return policy.Key.NotFoundError()
				}
				if policy.DeletePrepare {
					return policy.Key.BeingDeletedError()
				}
				if err := s.all.appInstApi.CheckCloudletAppinstsCompatibleWithTrustPolicy(ctx, &in.Key, &policy); err != nil {
					return err
				}
			}
		}
		if old.EnableDefaultServerlessCluster != cur.EnableDefaultServerlessCluster {
			if maintenanceChanged {
				return fmt.Errorf("Cannot change both enable default serverless cluster and maintenance state")
			}
			if cur.EnableDefaultServerlessCluster {
				if !features.SupportsMultiTenantCluster {
					return fmt.Errorf("Serverless cluster not supported on %s", cur.PlatformType)
				}
				go s.all.clusterInstApi.createDefaultMultiTenantCluster(ctx, cur.Key, features)
			} else {
				go s.all.clusterInstApi.deleteDefaultMultiTenantCluster(ctx, cur.Key)
			}
		}

		if crmUpdateReqd && !ignoreCRM(cctx) {
			cur.State = edgeproto.TrackedState_UPDATE_REQUESTED
		}
		if privPolUpdateRequested {
			if ignoreCRM(cctx) {
				if cur.TrustPolicy != "" {
					cur.TrustPolicyState = edgeproto.TrackedState_READY
				} else {
					cur.TrustPolicyState = edgeproto.TrackedState_NOT_PRESENT
				}
			}
		}
		cur.UpdatedAt = dme.TimeToTimestamp(time.Now())
		s.store.STMPut(stm, cur)
		return nil
	})

	if err != nil {
		return err
	}

	defer func() {
		if reterr != nil {
			dErr := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
				cloudlet := edgeproto.Cloudlet{}
				if !s.store.STMGet(stm, &in.Key, &cloudlet) {
					return in.Key.NotFoundError()
				}
				if cloudlet.State != edgeproto.TrackedState_UPDATE_ERROR {
					cloudlet.State = edgeproto.TrackedState_UPDATE_ERROR
					s.store.STMPut(stm, &cloudlet)
				}
				return nil
			})
			if dErr != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "Undo create cloudlet", "err", dErr)
			}
		}
	}()

	// Since state is set to UPDATE_REQUESTED, it is safe to do the following
	if _, found := fmap[edgeproto.CloudletFieldGpuConfigLicenseConfig]; found {
		if gpuDriver.Key.Name == "" {
			return fmt.Errorf("License config can only be updated if GPU config exists for the cloudlet")
		}
		storageClient, err := getGCSStorageClient(ctx, &gpuDriver)
		if err != nil {
			return err
		}
		defer storageClient.Close()
		newLicenseConfigMd5sum := ""
		if newLicenseConfig == "" {
			cb.Send(&edgeproto.Result{Message: "Deleting GPU driver license config from secure storage"})
			// Delete license config from GCS
			log.SpanLog(ctx, log.DebugLevelApi, "Deleting GPU driver license config from GCS", "driver key", gpuDriver.Key, "license path", cur.LicenseConfigStoragePath)
			err := storageClient.DeleteObject(ctx, cur.LicenseConfigStoragePath)
			if err != nil {
				return err
			}
			newLicenseConfigMd5sum = ""
		} else {
			cb.Send(&edgeproto.Result{Message: "Uploading the GPU driver license config to secure storage"})
			log.SpanLog(ctx, log.DebugLevelApi, "Uploading GPU driver license config to GCS", "driver key", gpuDriver.Key, "license path", cur.LicenseConfigStoragePath)
			err := storageClient.UploadObject(ctx, gpuDriver.LicenseConfigStoragePath, "", bytes.NewBufferString(newLicenseConfig))
			if err != nil {
				return fmt.Errorf("Failed to upload GPU driver license to %s, %v", cur.LicenseConfigStoragePath, err)
			}
			// store the GCS path to license config
			newLicenseConfigMd5sum = cloudcommon.Md5SumStr(newLicenseConfig)
			newLicenseConfig = cloudcommon.GetGPUDriverLicenseURL(gpuDriver.StorageBucketName, cur.LicenseConfigStoragePath)
		}
		err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			cl := edgeproto.Cloudlet{}
			if !s.store.STMGet(stm, &in.Key, &cl) {
				return in.Key.NotFoundError()
			}
			cl.GpuConfig.LicenseConfig = newLicenseConfig
			cl.GpuConfig.LicenseConfigMd5Sum = newLicenseConfigMd5sum
			s.store.STMPut(stm, &cl)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// after the cloudlet change is committed, if the location changed,
	// update app insts as well.
	s.UpdateAppInstLocations(ctx, in)

	if crmUpdateReqd && !ignoreCRM(cctx) {
		// Wait for cloudlet to finish upgrading
		reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().UpdateCloudletTimeout.TimeDuration())
		defer reqCancel()
		err = edgeproto.WaitForCloudletInfo(
			reqCtx, &in.Key,
			dme.CloudletState_CLOUDLET_STATE_READY,
			UpdateCloudletTransitions, dme.CloudletState_CLOUDLET_STATE_ERRORS,
			"Cloudlet updated successfully", cb.Send,
			edgeproto.WithCrmMsgCh(sendObj.crmMsgCh))
		return err
	}
	if privPolUpdateRequested && !ignoreCRM(cctx) {
		// Wait for policy to update
		err = s.updateTrustPolicyInternal(ctx, &in.Key, in.TrustPolicy, cb)
		if err != nil && caseInsensitiveContainsTimedOut(err.Error()) {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Update cloudlet is in progress: %s - %s Please use 'cloudlet show' to check current status", cloudletKey, err.Error())})
		}
		return err
	}

	// since default maintenance state is NORMAL_OPERATION, it is better to check
	// if the field is set before handling maintenance state
	if _, found := fmap[edgeproto.CloudletFieldMaintenanceState]; !found || !maintenanceChanged {
		cb.Send(&edgeproto.Result{Message: "Cloudlet updated successfully"})
		return nil
	}
	switch newMaintenanceState {
	case dme.MaintenanceState_NORMAL_OPERATION:
		log.SpanLog(ctx, log.DebugLevelApi, "Stop CRM maintenance")
		if !ignoreCRMState(cctx) {
			timeout := s.all.settingsApi.Get().CloudletMaintenanceTimeout.TimeDuration()
			err = s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_NORMAL_OPERATION_INIT)
			if err != nil {
				return err
			}
			cloudletInfo := edgeproto.CloudletInfo{}
			err = s.all.cloudletInfoApi.waitForMaintenanceState(ctx, &in.Key, dme.MaintenanceState_NORMAL_OPERATION, dme.MaintenanceState_CRM_ERROR, timeout, &cloudletInfo)
			if err != nil {
				return err
			}
			if cloudletInfo.MaintenanceState == dme.MaintenanceState_CRM_ERROR {
				return fmt.Errorf("CRM encountered some errors, aborting")
			}
		}
		err = s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_NORMAL_OPERATION)
		if err != nil {
			return err
		}
		cb.Send(&edgeproto.Result{Message: "Cloudlet is back to normal operation"})
	case dme.MaintenanceState_MAINTENANCE_START:
		// This is a state machine to transition into cloudlet
		// maintenance. Start by triggering AutoProv failovers.
		log.SpanLog(ctx, log.DebugLevelApi, "Start AutoProv failover")
		timeout := s.all.settingsApi.Get().CloudletMaintenanceTimeout.TimeDuration()
		err := cb.Send(&edgeproto.Result{
			Message: "Starting AutoProv failover",
		})
		if err != nil {
			return err
		}
		autoProvInfo := edgeproto.AutoProvInfo{}
		// first reset any old AutoProvInfo
		autoProvInfo = edgeproto.AutoProvInfo{
			Key:              in.Key,
			MaintenanceState: dme.MaintenanceState_NORMAL_OPERATION,
		}
		s.all.autoProvInfoApi.Update(ctx, &autoProvInfo, 0)

		err = s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_FAILOVER_REQUESTED)
		if err != nil {
			return err
		}
		err = s.all.autoProvInfoApi.waitForMaintenanceState(ctx, &in.Key, dme.MaintenanceState_FAILOVER_DONE, dme.MaintenanceState_FAILOVER_ERROR, timeout, &autoProvInfo)
		if err != nil {
			return err
		}
		for _, str := range autoProvInfo.Completed {
			res := edgeproto.Result{
				Message: str,
			}
			if err := cb.Send(&res); err != nil {
				return err
			}
		}
		for _, str := range autoProvInfo.Errors {
			res := edgeproto.Result{
				Message: str,
			}
			if err := cb.Send(&res); err != nil {
				return err
			}
		}
		if len(autoProvInfo.Errors) > 0 {
			undoErr := s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_NORMAL_OPERATION)
			log.SpanLog(ctx, log.DebugLevelApi, "AutoProv maintenance failures", "err", err, "undoErr", undoErr)
			return fmt.Errorf("AutoProv failover encountered some errors, aborting maintenance")
		}
		cb.Send(&edgeproto.Result{
			Message: "AutoProv failover completed",
		})

		log.SpanLog(ctx, log.DebugLevelApi, "AutoProv failover complete")

		// proceed to next state
		fallthrough
	case dme.MaintenanceState_MAINTENANCE_START_NO_FAILOVER:
		log.SpanLog(ctx, log.DebugLevelApi, "Start CRM maintenance")
		cb.Send(&edgeproto.Result{
			Message: "Starting CRM maintenance",
		})
		if !ignoreCRMState(cctx) {
			timeout := s.all.settingsApi.Get().CloudletMaintenanceTimeout.TimeDuration()
			// Tell CRM to go into maintenance mode
			err = s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_CRM_REQUESTED)
			if err != nil {
				return err
			}
			cloudletInfo := edgeproto.CloudletInfo{}
			err = s.all.cloudletInfoApi.waitForMaintenanceState(ctx, &in.Key, dme.MaintenanceState_CRM_UNDER_MAINTENANCE, dme.MaintenanceState_CRM_ERROR, timeout, &cloudletInfo)
			if err != nil {
				return err
			}
			if cloudletInfo.MaintenanceState == dme.MaintenanceState_CRM_ERROR {
				undoErr := s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_NORMAL_OPERATION)
				log.SpanLog(ctx, log.DebugLevelApi, "CRM maintenance failures", "err", err, "undoErr", undoErr)
				return fmt.Errorf("CRM encountered some errors, aborting maintenance")
			}
		}
		cb.Send(&edgeproto.Result{
			Message: "CRM maintenance started",
		})
		log.SpanLog(ctx, log.DebugLevelApi, "CRM maintenance started")
		// transition to maintenance
		err = s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_UNDER_MAINTENANCE)
		if err != nil {
			return err
		}
		cb.Send(&edgeproto.Result{
			Message: "Cloudlet is in maintenance",
		})
	}
	return nil
}

func (s *CloudletApi) setMaintenanceState(ctx context.Context, key *edgeproto.CloudletKey, state dme.MaintenanceState) error {
	changedState := false
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cur := &edgeproto.Cloudlet{}
		if !s.store.STMGet(stm, key, cur) {
			return key.NotFoundError()
		}
		if cur.MaintenanceState == state {
			return nil
		}
		changedState = true
		cur.MaintenanceState = state
		s.store.STMPut(stm, cur)
		return nil
	})

	msg := ""
	switch state {
	case dme.MaintenanceState_UNDER_MAINTENANCE:
		msg = "Cloudlet maintenance start"
	case dme.MaintenanceState_NORMAL_OPERATION:
		msg = "Cloudlet maintenance done"
	}
	if msg != "" && changedState {
		nodeMgr.Event(ctx, msg, key.Organization, key.GetTags(), nil, "maintenance-state", state.String())
	}
	return err
}

func (s *CloudletApi) DeleteCloudlet(in *edgeproto.Cloudlet, cb edgeproto.CloudletApi_DeleteCloudletServer) error {
	return s.deleteCloudletInternal(DefCallContext(), in, cb, true)
}

func (s *CloudletApi) deleteCloudletInternal(cctx *CallContext, in *edgeproto.Cloudlet, inCb edgeproto.CloudletApi_DeleteCloudletServer, cloudletResourcesCreated bool) (reterr error) {
	cctx.SetOverride(&in.CrmOverride)
	ctx := inCb.Context()

	cloudletKey := in.Key
	sendObj, cb, err := s.startCloudletStream(ctx, cctx, &cloudletKey, inCb)
	if err != nil {
		return err
	}
	defer func() {
		cleanupStream := NoCleanupStream
		if reterr == nil {
			// deletion is successful, cleanup stream
			cleanupStream = CleanupStream
		}
		s.stopCloudletStream(ctx, cctx, &cloudletKey, sendObj, reterr, cleanupStream)
		if reterr == nil {
			RecordCloudletEvent(ctx, &in.Key, cloudcommon.DELETED, cloudcommon.InstanceDown)
		}
	}()

	var dynInsts map[edgeproto.AppInstKey]struct{}
	var clDynInsts map[edgeproto.ClusterInstKey]struct{}

	var features *edgeproto.PlatformFeatures
	var prevState edgeproto.TrackedState
	var gpuDriver edgeproto.GPUDriver
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		dynInsts = make(map[edgeproto.AppInstKey]struct{})
		clDynInsts = make(map[edgeproto.ClusterInstKey]struct{})
		if !s.store.STMGet(stm, &in.Key, in) {
			return in.Key.NotFoundError()
		}
		if !ignoreCRMTransient(cctx) && in.DeletePrepare {
			return in.Key.BeingDeletedError()
		}
		features, err = s.all.platformFeaturesApi.GetCloudletFeatures(ctx, in.PlatformType)
		if err != nil {
			return fmt.Errorf("Failed to get features for platform: %s", err)
		}
		var defaultClustKey *edgeproto.ClusterInstKey
		if features.IsSingleKubernetesCluster {
			defaultClustKey = getDefaultClustKey(in.Key, in.SingleKubernetesClusterOwner)
		}
		refs := edgeproto.CloudletRefs{}
		if s.all.cloudletRefsApi.store.STMGet(stm, &in.Key, &refs) {
			err = s.all.clusterInstApi.deleteCloudletOk(stm, &refs, clDynInsts)
			if err != nil {
				return err
			}
		}
		if in.GpuConfig.Driver.Name != "" {
			if !s.all.gpuDriverApi.store.STMGet(stm, &in.GpuConfig.Driver, &gpuDriver) {
				return in.GpuConfig.Driver.NotFoundError()
			}
		}
		err = s.all.appInstApi.deleteCloudletOk(stm, &refs, defaultClustKey, dynInsts)
		if err != nil {
			return err
		}
		if err := validateDeleteState(cctx, "Cloudlet", in.State, in.Errors, cb.Send); err != nil {
			return err
		}
		prevState = in.State
		in.DeletePrepare = true
		// TODO: remove redundant DELETE_PREPARE state
		in.State = edgeproto.TrackedState_DELETE_PREPARE
		s.store.STMPut(stm, in)
		return nil
	})
	if err != nil {
		return err
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			if !s.store.STMGet(stm, &in.Key, in) {
				return in.Key.NotFoundError()
			}
			changed := false
			if in.State == edgeproto.TrackedState_DELETE_PREPARE {
				// restore previous state since we failed pre-delete actions
				in.State = prevState
				changed = true
			} else if in.State != edgeproto.TrackedState_DELETE_ERROR {
				// since deletion has failed, it will require manual intervention
				// and hence set state to error so that user can take appropriate
				// actions
				in.State = edgeproto.TrackedState_DELETE_ERROR
				changed = true
			}
			if in.DeletePrepare {
				in.DeletePrepare = false
				changed = true
			}
			if changed {
				s.store.STMPut(stm, in)
			}
			return nil
		})
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to undo delete prepare", "key", in.Key, "err", undoErr)
		}
	}()

	// for cascaded deletes of ClusterInst/AppInst, skip cloudlet
	// ready check because it's not ready - it's being deleted.
	cctx.SkipCloudletReadyCheck = true

	autoProvPolicies := s.all.autoProvPolicyApi.UsesCloudlet(&in.Key)
	if len(autoProvPolicies) > 0 {
		strs := []string{}
		for _, key := range autoProvPolicies {
			strs = append(strs, key.GetKeyString())
		}
		return fmt.Errorf("Cloudlet in use by AutoProvPolicy %s", strings.Join(strs, ", "))
	}
	cloudletPoolKeys := s.all.cloudletPoolApi.UsesCloudlet(&in.Key)
	if len(cloudletPoolKeys) > 0 {
		strs := []string{}
		for _, key := range cloudletPoolKeys {
			strs = append(strs, key.GetKeyString())
		}
		return fmt.Errorf("Cloudlet in use by CloudletPool %s", strings.Join(strs, ", "))
	}
	if networkKey := s.all.networkApi.UsesCloudlet(&in.Key); networkKey != nil {
		return fmt.Errorf("Cloudlet in use by Network %s", networkKey.GetKeyString())
	}
	// Delete dynamic instances while Cloudlet is still in database
	// and CRM is still up.
	err = s.all.appInstApi.AutoDeleteAppInsts(ctx, dynInsts, cctx.Override, cb)
	if err != nil {
		return err
	}
	if len(clDynInsts) > 0 {
		for key, _ := range clDynInsts {
			clInst := edgeproto.ClusterInst{Key: key}
			derr := s.all.clusterInstApi.deleteClusterInstInternal(cctx.Clone(), &clInst, cb)
			if derr != nil {
				log.SpanLog(ctx, log.DebugLevelApi,
					"Failed to delete dynamic ClusterInst",
					"key", key, "err", derr)
				return derr
			}
		}
	}

	if !ignoreCRMState(cctx) {
		// Subscribe to receive delete finished message
		deboardingInfo := edgeproto.CloudletOnboardingInfo{
			Key: in.Key,
		}
		deboardingSub := rediscache.Subscribe(ctx, redisClient, &deboardingInfo)
		defer deboardingSub.Close()

		// Set delete requested to trigger CCRM to run platform-specific delete
		err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			if !s.store.STMGet(stm, &in.Key, in) {
				return in.Key.NotFoundError()
			}
			in.OnboardingState = edgeproto.TrackedState_DELETE_REQUESTED
			s.store.STMPut(stm, in)
			return nil
		})
		if err != nil {
			return err
		}

		// Wait for result from CCRM
		reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().UpdateCloudletTimeout.TimeDuration())
		defer reqCancel()
		err = deboardingSub.WaitForMessage(reqCtx, func() (bool, error) {
			if deboardingInfo.OnboardingState == edgeproto.TrackedState_DELETE_DONE || deboardingInfo.OnboardingState == edgeproto.TrackedState_DELETE_ERROR {
				// done
				return true, nil
			}
			return false, nil
		})
		if err != nil {
			// if we are ignoring CRM errors, or if there were no resources created, proceed with deletion
			if cctx.Override == edgeproto.CRMOverride_IGNORE_CRM_ERRORS || !cloudletResourcesCreated {
				cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Delete Cloudlet ignoring CRM failure: %s", err.Error())})
				s.ReplaceErrorState(ctx, in, edgeproto.TrackedState_NOT_PRESENT)
				err = nil
			} else {
				return err
			}
		}
	}

	// Delete cloudlet from database
	updateCloudlet := edgeproto.Cloudlet{}
	err1 := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, &updateCloudlet) {
			return in.Key.NotFoundError()
		}
		if !cctx.Undo && err != nil {
			updateCloudlet.State = edgeproto.TrackedState_DELETE_ERROR
			s.store.STMPut(stm, &updateCloudlet)
			return nil
		}
		s.store.STMDel(stm, &in.Key)
		s.dnsLabelStore.STMDel(stm, updateCloudlet.DnsLabel)
		s.all.cloudletRefsApi.store.STMDel(stm, &in.Key)
		if features.IsSingleKubernetesCluster {
			s.all.clusterInstApi.deleteCloudletSingularCluster(stm, &in.Key, updateCloudlet.SingleKubernetesClusterOwner)
		}
		cb.Send(&edgeproto.Result{Message: "Deleted Cloudlet successfully"})
		return nil
	})
	if err1 != nil {
		return err1
	}

	if err != nil {
		return err
	}

	// also delete associated info
	// Note: don't delete cloudletinfo, that will get deleted once CRM
	// disconnects. Otherwise if admin deletes/recreates Cloudlet with
	// CRM connected the whole time, we will end up without cloudletInfo.
	// also delete dynamic instances
	if in.KafkaCluster != "" {
		client, err := vaultConfig.Login()
		if err == nil {
			vault.DeleteKV(client, node.GetKafkaVaultPath(*region, in.Key.Name, in.Key.Organization))
		} else {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to login in to vault to delete kafka credentials", "key", in.Key, "err", err)
		}
	}

	err = accessvars.DeleteCRMAccessKeys(ctx, *region, in, nodeMgr.VaultConfig)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Failed to delete accesskeys from Vault", "cloudlet", in.Key, "err", err)
	}

	if gpuDriver.Key.Name != "" && updateCloudlet.GpuConfig.LicenseConfig != "" {
		storageClient, err := getGCSStorageClient(ctx, &gpuDriver)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to get storage client", "bucket name", gpuDriver.StorageBucketName, "err", err)
		} else {
			defer storageClient.Close()
			// Delete license config from GCS
			cb.Send(&edgeproto.Result{Message: "Deleting GPU driver license config from secure storage"})
			log.SpanLog(ctx, log.DebugLevelApi, "Deleting GPU driver license config from GCS", "driver key", gpuDriver.Key, "license path", updateCloudlet.LicenseConfigStoragePath)
			err := storageClient.DeleteObject(ctx, updateCloudlet.LicenseConfigStoragePath)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "Failed to delete GPU driver license config from secure storage", "key", in.Key, "err", err)
			}
		}
	}

	s.all.cloudletInfoApi.cleanupCloudletInfo(ctx, in)
	s.all.autoProvInfoApi.Delete(ctx, &edgeproto.AutoProvInfo{Key: in.Key}, 0)
	s.all.alertApi.CleanupCloudletAlerts(ctx, &in.Key)
	return nil
}

func (s *CloudletApi) ShowCloudlet(in *edgeproto.Cloudlet, cb edgeproto.CloudletApi_ShowCloudletServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.Cloudlet) error {
		copy := *obj
		copy.ChefClientKey = make(map[string]string)
		err := cb.Send(&copy)
		return err
	})
	return err
}

func (s *CloudletApi) RemoveCloudletResMapping(ctx context.Context, in *edgeproto.CloudletResMap) (*edgeproto.Result, error) {
	var err error
	cl := edgeproto.Cloudlet{}
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, &cl) {
			return in.Key.NotFoundError()
		}

		for resource, _ := range in.Mapping {
			delete(cl.ResTagMap, resource)
		}
		s.store.STMPut(stm, &cl)
		return err
	})
	return &edgeproto.Result{}, err
}

func (s *CloudletApi) AddCloudletResMapping(ctx context.Context, in *edgeproto.CloudletResMap) (*edgeproto.Result, error) {
	var err error
	cl := edgeproto.Cloudlet{}
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, &in.Key, &cl) {
			return in.Key.NotFoundError()
		}
		if cl.DeletePrepare {
			return in.Key.BeingDeletedError()
		}
		if cl.ResTagMap == nil {
			cl.ResTagMap = make(map[string]*edgeproto.ResTagTableKey)
		}
		for resource, tblname := range in.Mapping {
			if valerr, ok := s.all.resTagTableApi.ValidateResName(ctx, resource); !ok {
				return valerr
			}
			resource = strings.ToLower(resource)
			var key edgeproto.ResTagTableKey
			key.Name = tblname
			key.Organization = in.Key.Organization
			tbl := edgeproto.ResTagTable{}
			if !s.all.resTagTableApi.store.STMGet(stm, &key, &tbl) {
				return key.NotFoundError()
			}
			if tbl.DeletePrepare {
				return key.BeingDeletedError()
			}
			cl.ResTagMap[resource] = &key
		}
		s.store.STMPut(stm, &cl)
		return err
	})
	return &edgeproto.Result{}, err
}

func (s *CloudletApi) UpdateAppInstLocations(ctx context.Context, in *edgeproto.Cloudlet) {
	fmap := edgeproto.MakeFieldMap(in.Fields)
	if _, found := fmap[edgeproto.CloudletFieldLocation]; !found {
		// no location fields updated
		return
	}

	// find all appinsts associated with the cloudlet
	keys := make([]edgeproto.AppInstKey, 0)
	s.all.appInstApi.cache.Mux.Lock()
	for _, data := range s.all.appInstApi.cache.Objs {
		inst := data.Obj
		if inst.Key.CloudletKey.Matches(&in.Key) {
			keys = append(keys, inst.Key)
		}
	}
	s.all.appInstApi.cache.Mux.Unlock()

	inst := edgeproto.AppInst{}
	for ii, _ := range keys {
		inst = *s.all.appInstApi.cache.Objs[keys[ii]].Obj
		inst.Fields = make([]string, 0)
		if _, found := fmap[edgeproto.CloudletFieldLocationLatitude]; found {
			inst.CloudletLoc.Latitude = in.Location.Latitude
			inst.Fields = append(inst.Fields, edgeproto.AppInstFieldCloudletLocLatitude)
		}
		if _, found := fmap[edgeproto.CloudletFieldLocationLongitude]; found {
			inst.CloudletLoc.Longitude = in.Location.Longitude
			inst.Fields = append(inst.Fields, edgeproto.AppInstFieldCloudletLocLongitude)
		}
		if len(inst.Fields) == 0 {
			break
		}

		err := s.all.appInstApi.updateAppInstStore(ctx, &inst)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Update AppInst Location",
				"inst", inst, "err", err)
		}
	}
}

func (s *CloudletApi) showCloudletsByKeys(keys map[edgeproto.CloudletKey]struct{}, cb func(obj *edgeproto.Cloudlet) error) error {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()

	for key, data := range s.cache.Objs {
		obj := data.Obj
		if _, found := keys[key]; !found {
			continue
		}
		err := cb(obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func validateAllianceOrgs(ctx context.Context, in *edgeproto.Cloudlet) error {
	// check for duplicate orgs
	// make sure can't add your own org
	orgs := make(map[string]struct{})
	for _, org := range in.AllianceOrgs {
		if org == in.Key.Organization {
			return fmt.Errorf("Cannot add cloudlet's own org %q as alliance org", org)
		}
		if _, ok := orgs[org]; ok {
			return fmt.Errorf("Duplicate alliance org %q specified", org)
		}
		orgs[org] = struct{}{}
	}
	return nil
}

func (s *CloudletApi) AddCloudletAllianceOrg(ctx context.Context, in *edgeproto.CloudletAllianceOrg) (*edgeproto.Result, error) {
	if in.Organization == "" {
		return &edgeproto.Result{}, fmt.Errorf("No alliance organization specified")
	}
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cl := edgeproto.Cloudlet{}
		if !s.store.STMGet(stm, &in.Key, &cl) {
			return in.Key.NotFoundError()
		}
		cl.AllianceOrgs = append(cl.AllianceOrgs, in.Organization)
		if err := validateAllianceOrgs(ctx, &cl); err != nil {
			return err
		}
		s.store.STMPut(stm, &cl)
		return nil
	})
	return &edgeproto.Result{}, err
}

func (s *CloudletApi) RemoveCloudletAllianceOrg(ctx context.Context, in *edgeproto.CloudletAllianceOrg) (*edgeproto.Result, error) {
	if in.Organization == "" {
		return &edgeproto.Result{}, fmt.Errorf("No alliance organization specified")
	}
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cl := edgeproto.Cloudlet{}
		if !s.store.STMGet(stm, &in.Key, &cl) {
			return in.Key.NotFoundError()
		}
		changed := false
		for ii, org := range cl.AllianceOrgs {
			if org != in.Organization {
				continue
			}
			cl.AllianceOrgs = append(cl.AllianceOrgs[:ii], cl.AllianceOrgs[ii+1:]...)
			changed = true
			break
		}
		if !changed {
			return nil
		}
		s.store.STMPut(stm, &cl)
		return nil
	})
	return &edgeproto.Result{}, err
}

func (s *CloudletApi) FindFlavorMatch(ctx context.Context, in *edgeproto.FlavorMatch) (*edgeproto.FlavorMatch, error) {

	cl := edgeproto.Cloudlet{}
	var spec *vmspec.VMCreationSpec
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {

		if !s.all.cloudletApi.store.STMGet(stm, &in.Key, &cl) {
			return in.Key.NotFoundError()
		}
		cli := edgeproto.CloudletInfo{}
		if !s.all.cloudletInfoApi.store.STMGet(stm, &in.Key, &cli) {
			return in.Key.NotFoundError()
		}
		mexFlavor := edgeproto.Flavor{}
		mexFlavor.Key.Name = in.FlavorName
		if !s.all.flavorApi.store.STMGet(stm, &mexFlavor.Key, &mexFlavor) {
			return in.Key.NotFoundError()
		}
		var verr error
		spec, verr = s.all.resTagTableApi.GetVMSpec(ctx, stm, mexFlavor, "", cl, cli)
		if verr != nil {
			return verr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	in.FlavorName = spec.FlavorName
	in.AvailabilityZone = spec.AvailabilityZone
	return in, nil
}

func RecordCloudletEvent(ctx context.Context, cloudletKey *edgeproto.CloudletKey, event cloudcommon.InstanceEvent, serverStatus string) {
	metric := edgeproto.Metric{}
	metric.Name = cloudcommon.CloudletEvent
	ts, _ := types.TimestampProto(time.Now())
	metric.Timestamp = *ts
	metric.AddStringVal("cloudletorg", cloudletKey.Organization)
	metric.AddTag("cloudlet", cloudletKey.Name)
	metric.AddStringVal("event", string(event))
	metric.AddStringVal("status", serverStatus)

	services.events.AddMetric(&metric)
}

func (s *CloudletApi) GetCloudletManifest(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.CloudletManifest, error) {
	cloudlet := &edgeproto.Cloudlet{}
	if !s.all.cloudletApi.cache.Get(key, cloudlet) {
		return nil, key.NotFoundError()
	}

	features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
	if err != nil {
		return &edgeproto.CloudletManifest{}, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client := rediscache.GetCCRMAPIClient(redisClient, features.NodeType)
	return client.GetCloudletManifest(reqCtx, key)
}

func (s *CloudletApi) UsesVMPool(vmPoolKey *edgeproto.VMPoolKey) bool {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for key, data := range s.cache.Objs {
		val := data.Obj
		cVMPoolKey := edgeproto.VMPoolKey{
			Organization: key.Organization,
			Name:         val.VmPool,
		}
		if vmPoolKey.Matches(&cVMPoolKey) {
			return true
		}
	}
	return false
}

func (s *CloudletApi) UsesPlatformFeatures(pfKey *edgeproto.PlatformFeaturesKey) (bool, []string) {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	cloudlets := []string{}
	inUse := false
	for _, data := range s.cache.Objs {
		val := data.Obj
		if string(*pfKey) == val.PlatformType {
			cloudlets = append(cloudlets, fmt.Sprintf("%s(%s)", val.Key.Name, val.Key.Organization))
			inUse = true
		}
	}
	return inUse, cloudlets
}

func (s *CloudletApi) UsesGPUDriver(driverKey *edgeproto.GPUDriverKey) (bool, []string) {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	cloudlets := []string{}
	inUse := false
	for _, data := range s.cache.Objs {
		val := data.Obj
		if driverKey.Matches(&val.GpuConfig.Driver) {
			cloudlets = append(cloudlets, val.Key.Name)
			inUse = true
		}
	}
	return inUse, cloudlets
}

func (s *CloudletApi) UsesFlavor(key *edgeproto.FlavorKey) *edgeproto.CloudletKey {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for k, data := range s.cache.Objs {
		val := data.Obj
		if val.Flavor.Matches(key) {
			return &k
		}
	}
	return nil
}

func (s *CloudletApi) UsesResTagTable(key *edgeproto.ResTagTableKey) *edgeproto.CloudletKey {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for ck, data := range s.cache.Objs {
		val := data.Obj
		for _, k := range val.ResTagMap {
			if k.Matches(key) {
				return &ck
			}
		}
	}
	return nil
}

func (s *CloudletApi) GetCloudletProps(ctx context.Context, in *edgeproto.CloudletProps) (*edgeproto.CloudletProps, error) {
	features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, in.PlatformType)
	if err != nil {
		return &edgeproto.CloudletProps{}, err
	}
	props := edgeproto.CloudletProps{
		PlatformType: features.PlatformType,
		Properties:   features.Properties,
	}
	return &props, nil
}

func (s *CloudletApi) RevokeAccessKey(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.Result, error) {
	cloudlet := edgeproto.Cloudlet{}
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, key, &cloudlet) {
			return key.NotFoundError()
		}
		cloudlet.CrmAccessPublicKey = ""
		s.store.STMPut(stm, &cloudlet)
		return nil
	})
	var vaultErr error
	if err == nil {
		vaultErr = accessvars.DeleteCRMAccessKeys(ctx, *region, &cloudlet, vaultConfig)
	}
	log.SpanLog(ctx, log.DebugLevelApi, "revoked crm access key", "CloudletKey", *key, "err", err, "vaultErr", vaultErr)
	return &edgeproto.Result{}, err
}

func (s *CloudletApi) GenerateAccessKey(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.Result, error) {
	res := edgeproto.Result{}
	cloudlet := edgeproto.Cloudlet{}
	var keyPair *node.KeyPair
	var err, vaultErr error
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		res.Message = ""
		if !s.store.STMGet(stm, key, &cloudlet) {
			return key.NotFoundError()
		}
		keyPair, err = node.GenerateAccessKey()
		if err != nil {
			return err
		}
		cloudlet.CrmAccessPublicKey = keyPair.PublicPEM
		cloudlet.CrmAccessKeyUpgradeRequired = false
		res.Message = keyPair.PrivatePEM
		s.store.STMPut(stm, &cloudlet)
		return nil
	})
	if err == nil {
		var accessKeys *accessvars.CRMAccessKeys
		accessKeys, vaultErr = accessvars.GetCRMAccessKeys(ctx, *region, &cloudlet, vaultConfig)
		if vaultErr == nil {
			accessKeys.PublicPEM = keyPair.PublicPEM
			accessKeys.PrivatePEM = keyPair.PrivatePEM
			vaultErr = accessvars.SaveCRMAccessKeys(ctx, *region, &cloudlet, vaultConfig, accessKeys)
		}
	}
	log.SpanLog(ctx, log.DebugLevelApi, "generated crm access key", "CloudletKey", *key, "err", err, "vaultErr", vaultErr)
	return &res, err
}

func (s *CloudletApi) UsesTrustPolicy(key *edgeproto.PolicyKey, stateMatch edgeproto.TrackedState) *edgeproto.CloudletKey {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for k, data := range s.cache.Objs {
		cloudlet := data.Obj
		if cloudlet.TrustPolicy == key.Name && cloudlet.Key.Organization == key.Organization {
			if stateMatch == edgeproto.TrackedState_TRACKED_STATE_UNKNOWN || stateMatch == cloudlet.State {
				return &k
			}
		}
	}
	return nil
}

func (s *CloudletApi) ValidateCloudletsUsingTrustPolicy(ctx context.Context, trustPolicy *edgeproto.TrustPolicy) error {
	log.SpanLog(ctx, log.DebugLevelApi, "ValidateCloudletsUsingTrustPolicy", "policy", trustPolicy)
	cloudletKeys := make(map[*edgeproto.CloudletKey]struct{})
	s.cache.Mux.Lock()
	for ck, data := range s.cache.Objs {
		val := data.Obj
		if ck.Organization != trustPolicy.Key.Organization || val.TrustPolicy != trustPolicy.Key.Name {
			continue
		}
		copyKey := edgeproto.CloudletKey{
			Organization: ck.Organization,
			Name:         ck.Name,
		}
		cloudletKeys[&copyKey] = struct{}{}
	}
	s.cache.Mux.Unlock()
	for k := range cloudletKeys {
		err := s.all.appInstApi.CheckCloudletAppinstsCompatibleWithTrustPolicy(ctx, k, trustPolicy)
		if err != nil {
			return fmt.Errorf("AppInst on cloudlet %s not compatible with trust policy - %s", strings.TrimSpace(k.String()), err.Error())
		}
	}
	return nil
}

func (s *CloudletApi) UpdateCloudletsUsingTrustPolicy(ctx context.Context, trustPolicy *edgeproto.TrustPolicy, cb edgeproto.TrustPolicyApi_CreateTrustPolicyServer) error {
	s.cache.Mux.Lock()
	type updateResult struct {
		errString string
	}

	updateResults := make(map[edgeproto.CloudletKey]chan updateResult)
	for k, data := range s.cache.Objs {
		val := data.Obj
		if k.Organization != trustPolicy.Key.Organization || val.TrustPolicy != trustPolicy.Key.Name {
			continue
		}

		updateResults[k] = make(chan updateResult)
		go func(k edgeproto.CloudletKey) {
			log.SpanLog(ctx, log.DebugLevelApi, "updating trust policy for cloudlet", "key", k)
			err := s.updateTrustPolicyInternal(ctx, &k, trustPolicy.Key.Name, cb)
			if err == nil {
				updateResults[k] <- updateResult{errString: ""}
			} else {
				updateResults[k] <- updateResult{errString: err.Error()}
			}
		}(k)
	}
	s.cache.Mux.Unlock()
	if len(updateResults) == 0 {
		log.SpanLog(ctx, log.DebugLevelApi, "no cloudlets matched", "key", trustPolicy.Key)
		cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Trust policy updated, no cloudlets affected")})
		return nil
	}

	numPassed := 0
	numFailed := 0
	numTotal := 0
	numInProgress := 0
	for k, r := range updateResults {
		numTotal++
		result := <-r
		log.SpanLog(ctx, log.DebugLevelApi, "cloudletUpdateResult ", "key", k, "error", result.errString)
		if result.errString == "" {
			numPassed++
		} else if caseInsensitiveContainsTimedOut(result.errString) {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Update cloudlet is in progress: %s - %s Please use 'cloudlet show' to check current status", k, result.errString)})
			numInProgress++
		} else {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Failed to update cloudlet: %s - %s", k, result.errString)})
			numFailed++
		}
	}
	cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Processed: %d Cloudlets.  Passed: %d InProgress: %d Failed: %d", numTotal, numPassed, numInProgress, numFailed)})
	if numPassed == 0 {
		if numInProgress == 0 {
			return fmt.Errorf("Failed to update trust policy on any cloudlets")
		}
		// If numInProgress is nonzero, there is still at least one cloudlet still doing the update which may eventually succeed.
		// If we return an error here, the UpdateTrustPolicy API itself will fail, and the trust policy in etcd will be reverted to the pre-update state.
		// This could cause an inconsistency, and so better to return nil error in this case. Fall through.
	}
	return nil
}

func (s *CloudletApi) WaitForTrustPolicyState(ctx context.Context, key *edgeproto.CloudletKey, targetState edgeproto.TrackedState, errorState edgeproto.TrackedState, timeout time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelApi, "WaitForTrustPolicyState", "target", targetState, "timeout", timeout)
	done := make(chan bool, 1)
	failed := make(chan bool, 1)
	cloudlet := edgeproto.Cloudlet{}
	check := func(ctx context.Context) {
		if !s.cache.Get(key, &cloudlet) {
			log.SpanLog(ctx, log.DebugLevelApi, "Error: WaitForTrustPolicyState cloudlet not found", "key", key)
			failed <- true
		}
		log.SpanLog(ctx, log.DebugLevelApi, "WaitForTrustPolicyState initial get from cache", "curState", cloudlet.TrustPolicyState, "targetState", targetState)
		if cloudlet.TrustPolicyState == targetState {
			done <- true
		} else if cloudlet.TrustPolicyState == errorState {
			failed <- true
		}
	}
	cancel := s.cache.WatchKey(key, check)
	check(ctx)
	var err error
	select {
	case <-done:
	case <-failed:
		err = fmt.Errorf("Error in updating Trust Policy")
	case <-time.After(timeout):
		err = fmt.Errorf("Timed out waiting for Trust Policy")
	}
	cancel()
	log.SpanLog(ctx, log.DebugLevelApi, "WaitForTrustPolicyState state done", "target", targetState, "curState", cloudlet.TrustPolicyState)
	return err
}

func (s *CloudletApi) GetCloudletResourceInfo(ctx context.Context, stm concurrency.STM, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) (map[string]edgeproto.InfraResource, error) {
	resQuotasInfo := make(map[string]edgeproto.InfraResource)
	for _, resQuota := range cloudlet.ResourceQuotas {
		resQuotasInfo[resQuota.Name] = edgeproto.InfraResource{
			Name:           resQuota.Name,
			Value:          resQuota.Value,
			AlertThreshold: resQuota.AlertThreshold,
		}
	}

	cloudletPlatform, err := pfutils.GetPlatform(ctx, cloudlet.PlatformType, nodeMgr.UpdateNodeProps)
	if err != nil {
		return nil, err
	}
	resInfo := make(map[string]edgeproto.InfraResource)
	for resName, resUnits := range cloudcommon.CommonCloudletResources {
		infraResMax := uint64(0)
		if infraRes, ok := infraResMap[resName]; ok {
			infraResMax = infraRes.InfraMaxValue
		}
		thresh := cloudlet.DefaultResourceAlertThreshold
		quotaMax := uint64(0)
		// look up quota if any
		if quota, found := resQuotasInfo[resName]; found {
			if quota.Value != 0 {
				quotaMax = quota.Value
			}
			if quota.AlertThreshold > 0 {
				// Set threshold values from Resource quotas
				thresh = quota.AlertThreshold
			}
		}
		resInfo[resName] = edgeproto.InfraResource{
			Name:           resName,
			Units:          resUnits,
			InfraMaxValue:  infraResMax,
			QuotaMaxValue:  quotaMax,
			AlertThreshold: thresh,
		}
	}

	for _, vmRes := range vmResources {
		if vmRes.VmFlavor != nil {
			ramInfo, ok := resInfo[cloudcommon.ResourceRamMb]
			if ok {
				ramInfo.Value += vmRes.VmFlavor.Ram
				resInfo[cloudcommon.ResourceRamMb] = ramInfo
			}
			vcpusInfo, ok := resInfo[cloudcommon.ResourceVcpus]
			if ok {
				vcpusInfo.Value += vmRes.VmFlavor.Vcpus
				resInfo[cloudcommon.ResourceVcpus] = vcpusInfo
			}
			diskInfo, ok := resInfo[cloudcommon.ResourceDiskGb]
			if ok {
				diskInfo.Value += vmRes.VmFlavor.Disk
				resInfo[cloudcommon.ResourceDiskGb] = diskInfo
			}
			if s.all.resTagTableApi.UsesGpu(ctx, stm, *vmRes.VmFlavor, *cloudlet) {
				gpusInfo, ok := resInfo[cloudcommon.ResourceGpus]
				if ok {
					gpusInfo.Value += 1
					resInfo[cloudcommon.ResourceGpus] = gpusInfo
				}
			}
			if cloudcommon.IsLBNode(vmRes.Type) || cloudcommon.IsPlatformNode(vmRes.Type) {
				externalIPInfo, ok := resInfo[cloudcommon.ResourceExternalIPs]
				if ok {
					externalIPInfo.Value += 1
					resInfo[cloudcommon.ResourceExternalIPs] = externalIPInfo
				}
			}
		}
	}
	addResInfo := cloudletPlatform.GetClusterAdditionalResources(ctx, cloudlet, vmResources, infraResMap)
	for k, v := range addResInfo {
		thresh := cloudlet.DefaultResourceAlertThreshold
		quotaMax := uint64(0)
		// look up quota if any
		if quota, found := resQuotasInfo[k]; found {
			if quota.Value != 0 {
				quotaMax = quota.Value
			}
			if quota.AlertThreshold > 0 {
				// Set threshold values from Resource quotas
				thresh = quota.AlertThreshold
			}
		}
		v.AlertThreshold = thresh
		v.QuotaMaxValue = quotaMax
		resInfo[k] = v
	}
	return resInfo, nil
}

// Get actual resource info used by the cloudlet
func (s *CloudletApi) GetResourceUsage(ctx context.Context, stm concurrency.STM, cloudlet *edgeproto.Cloudlet, infraResInfo []edgeproto.InfraResource, diffVmResources []edgeproto.VMResource, infraUsage bool) ([]edgeproto.InfraResource, error) {
	resQuotasInfo := make(map[string]edgeproto.InfraResource)
	for _, resQuota := range cloudlet.ResourceQuotas {
		resQuotasInfo[resQuota.Name] = edgeproto.InfraResource{
			Name:           resQuota.Name,
			Value:          resQuota.Value,
			AlertThreshold: resQuota.AlertThreshold,
		}
	}
	defaultAlertThresh := cloudlet.DefaultResourceAlertThreshold
	infraResInfoMap := make(map[string]edgeproto.InfraResource)
	for _, resInfo := range infraResInfo {
		thresh := defaultAlertThresh
		// look up quota if any
		if quota, found := resQuotasInfo[resInfo.Name]; found {
			if quota.Value > 0 {
				// Set max values from Resource quotas
				resInfo.QuotaMaxValue = quota.Value
			}
			if quota.AlertThreshold > 0 {
				// Set threshold values from Resource quotas
				thresh = quota.AlertThreshold
			}
		}
		if !infraUsage {
			resInfo.Value = 0
		}
		resInfo.AlertThreshold = thresh
		infraResInfoMap[resInfo.Name] = resInfo
	}
	diffResInfo, err := s.GetCloudletResourceInfo(ctx, stm, cloudlet, diffVmResources, infraResInfoMap)
	if err != nil {
		return nil, err
	}
	for resName, resInfo := range diffResInfo {
		if infraResInfo, ok := infraResInfoMap[resName]; ok {
			infraResInfo.Value += resInfo.Value
			infraResInfoMap[resName] = infraResInfo
		} else {
			infraResInfoMap[resName] = resInfo
		}
	}
	out := []edgeproto.InfraResource{}
	for _, val := range infraResInfoMap {
		out = append(out, val)
	}
	// sort keys for stable output order
	sort.Slice(out[:], func(i, j int) bool {
		return out[i].Name < out[j].Name
	})

	return out, nil
}

func (s *CloudletApi) GetCloudletResourceUsage(ctx context.Context, usage *edgeproto.CloudletResourceUsage) (*edgeproto.CloudletResourceUsage, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "GetCloudletResourceUsage", "key", usage.Key)
	cloudletResUsage := edgeproto.CloudletResourceUsage{}
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cloudlet := edgeproto.Cloudlet{}
		if !s.store.STMGet(stm, &usage.Key, &cloudlet) {
			return errors.New("Specified Cloudlet not found")
		}
		cloudletInfo := edgeproto.CloudletInfo{}
		if !s.all.cloudletInfoApi.store.STMGet(stm, &usage.Key, &cloudletInfo) {
			return fmt.Errorf("No resource information found for Cloudlet %s", usage.Key)
		}
		cloudletRefs := edgeproto.CloudletRefs{}
		s.all.cloudletRefsApi.store.STMGet(stm, &usage.Key, &cloudletRefs)
		allVmResources, diffVmResources, _, err := s.all.clusterInstApi.getAllCloudletResources(ctx, stm, &cloudlet, &cloudletInfo, &cloudletRefs)
		if err != nil {
			return err
		}
		cloudletResUsage.Key = usage.Key
		cloudletResUsage.InfraUsage = usage.InfraUsage
		cloudletResUsage.Info = cloudletInfo.ResourcesSnapshot.Info
		resInfo := []edgeproto.InfraResource{}
		if !usage.InfraUsage {
			resInfo, err = s.GetResourceUsage(ctx, stm, &cloudlet, cloudletInfo.ResourcesSnapshot.Info, allVmResources, usage.InfraUsage)
		} else {
			resInfo, err = s.GetResourceUsage(ctx, stm, &cloudlet, cloudletInfo.ResourcesSnapshot.Info, diffVmResources, usage.InfraUsage)
		}
		if err != nil {
			return err
		}
		cloudletResUsage.Info = resInfo
		return nil
	})
	return &cloudletResUsage, err
}

func GetPlatformVMsResources(ctx context.Context, cloudletInfo *edgeproto.CloudletInfo) ([]edgeproto.VMResource, error) {
	resources := []edgeproto.VMResource{}
	for _, vm := range cloudletInfo.ResourcesSnapshot.PlatformVms {
		if vm.InfraFlavor == "" {
			continue
		}
		for _, flavorInfo := range cloudletInfo.Flavors {
			if flavorInfo.Name == vm.InfraFlavor {
				resources = append(resources, edgeproto.VMResource{
					VmFlavor: flavorInfo,
					Type:     vm.Type,
				})
				break
			}
		}
	}
	return resources, nil
}

func (s *CloudletApi) GetCloudletResourceQuotaProps(ctx context.Context, in *edgeproto.CloudletResourceQuotaProps) (*edgeproto.CloudletResourceQuotaProps, error) {
	features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, in.PlatformType)
	if err != nil {
		return &edgeproto.CloudletResourceQuotaProps{}, err
	}
	props := edgeproto.CloudletResourceQuotaProps{
		PlatformType: features.PlatformType,
		Properties:   features.ResourceQuotaProperties,
	}
	return &props, nil
}

func (s *CloudletApi) ShowFlavorsForCloudlet(in *edgeproto.CloudletKey, cb edgeproto.CloudletApi_ShowFlavorsForCloudletServer) error {
	ctx := cb.Context()
	allMetaFlavors := make(map[edgeproto.FlavorKey]struct{})
	flavorCache := &s.all.flavorApi.cache
	flavorCache.GetAllKeys(ctx, func(k *edgeproto.FlavorKey, modRev int64) {
		allMetaFlavors[*k] = struct{}{}
	})
	cloudletKeys := make(map[edgeproto.CloudletKey]struct{})
	if in.ValidateKey() == nil {
		// only one cloudlet specified
		cloudletKeys[*in] = struct{}{}
	} else {
		// find all matching cloudlets
		s.cache.GetAllKeys(ctx, func(k *edgeproto.CloudletKey, modRef int64) {
			if k.Matches(in, edgeproto.MatchFilter()) {
				cloudletKeys[*k] = struct{}{}
			}
		})
	}
	flavors := make(map[edgeproto.FlavorKey]struct{})
	for cloudletKey, _ := range cloudletKeys {
		log.SpanLog(ctx, log.DebugLevelApi, "ShowFlavorsForCloudlet", "cloudletKey", cloudletKey)
		for flavor, _ := range allMetaFlavors {
			fm := edgeproto.FlavorMatch{
				Key:        cloudletKey,
				FlavorName: flavor.Name,
			}
			match, err := s.FindFlavorMatch(ctx, &fm)
			if err != nil {
				continue
			}
			flavors[flavor] = struct{}{}
			log.SpanLog(ctx, log.DebugLevelApi, "ShowFlavorsForCloudlet match", "metaflavor", flavor, "with", match.FlavorName, "on cloudlet", cloudletKey)
		}
	}
	// convert flavors to list so we can sort
	flavorsList := []edgeproto.FlavorKey{}
	for flavorKey, _ := range flavors {
		flavorsList = append(flavorsList, flavorKey)
	}
	sort.Slice(flavorsList, func(i, j int) bool {
		return flavorsList[i].GetKeyString() < flavorsList[j].GetKeyString()
	})
	for _, flavorKey := range flavorsList {
		err := cb.Send(&flavorKey)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *CloudletApi) GetOrganizationsOnCloudlet(in *edgeproto.CloudletKey, cb edgeproto.CloudletApi_GetOrganizationsOnCloudletServer) error {
	orgs := make(map[string]struct{})
	aiFilter := edgeproto.AppInst{}
	aiFilter.Key.CloudletKey = *in
	s.all.appInstApi.cache.Show(&aiFilter, func(appInst *edgeproto.AppInst) error {
		orgs[appInst.Key.Organization] = struct{}{}
		return nil
	})
	ciFilter := edgeproto.ClusterInst{}
	ciFilter.Key.CloudletKey = *in
	s.all.clusterInstApi.cache.Show(&ciFilter, func(clusterInst *edgeproto.ClusterInst) error {
		orgs[clusterInst.Key.ClusterKey.Organization] = struct{}{}
		return nil
	})
	for name, _ := range orgs {
		org := &edgeproto.Organization{
			Name: name,
		}
		err := cb.Send(org)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *CloudletApi) GetCloudletGPUDriverLicenseConfig(ctx context.Context, key *edgeproto.CloudletKey) (*edgeproto.Result, error) {
	cloudlet := edgeproto.Cloudlet{}
	if !s.store.Get(ctx, key, &cloudlet) {
		return &edgeproto.Result{}, key.NotFoundError()
	}
	if cloudlet.GpuConfig.Driver.Name == "" {
		return &edgeproto.Result{}, fmt.Errorf("Cloudlet is not associated with any GPU driver")
	}
	if cloudlet.LicenseConfigStoragePath == "" {
		return &edgeproto.Result{}, fmt.Errorf("Cloudlet license config storage path is empty")
	}
	return s.all.gpuDriverApi.GetGPUDriverLicenseConfig(ctx, &cloudlet.GpuConfig.Driver)
}
