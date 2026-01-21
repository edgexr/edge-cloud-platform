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

package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessapi"
	"github.com/edgexr/edge-cloud-platform/pkg/accessvars"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/edgexr/edge-cloud-platform/pkg/util/tasks"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/gogo/protobuf/types"
	"github.com/oklog/ulid/v2"
	"go.etcd.io/etcd/client/v3/concurrency"
)

const RedactedAccessVarValue = "***"

type CloudletApi struct {
	all                   *AllApis
	sync                  *regiondata.Sync
	store                 edgeproto.CloudletStore
	cache                 *edgeproto.CloudletCache
	accessKeyServer       *svcnode.AccessKeyServer
	dnsLabelStore         edgeproto.CloudletDnsLabelStore
	objectDnsLabelStore   edgeproto.CloudletObjectDnsLabelStore
	vaultClient           *accessapi.VaultClient
	defaultMTClustWorkers tasks.KeyWorkers
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

func NewCloudletApi(sync *regiondata.Sync, all *AllApis) *CloudletApi {
	cloudletApi := CloudletApi{}
	cloudletApi.all = all
	cloudletApi.sync = sync
	cloudletApi.store = edgeproto.NewCloudletStore(sync.GetKVStore())
	cloudletApi.cache = nodeMgr.CloudletLookup.GetCloudletCache(svcnode.NoRegion)
	cloudletApi.cache.Store = cloudletApi.store
	sync.RegisterCache(cloudletApi.cache)
	cloudletApi.accessKeyServer = svcnode.NewAccessKeyServer(cloudletApi.cache, nodeMgr.VaultAddr)
	cloudletApi.defaultMTClustWorkers.Init("UpdateMultiTenantCluster", cloudletApi.updateDefaultMultiTenantClusterWorker)
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
			s.all.cloudletIPsApi.cache.Store.STMDel(stm, &in.Key)
			s.all.clusterInstApi.deleteCloudletSingularCluster(stm, &in.Key, inst.SingleKubernetesClusterOwner)
		} else {
			inst.State = newState
			inst.Errors = nil
			s.store.STMPut(stm, &inst)
		}
		return nil
	})
}

func (s *CloudletApi) SetState(ctx context.Context, in *edgeproto.Cloudlet, newState edgeproto.TrackedState) {
	s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		inst := edgeproto.Cloudlet{}
		if !s.store.STMGet(stm, &in.Key, &inst) {
			// got deleted in the meantime
			return nil
		}
		if in.State == newState {
			return nil
		}
		in.State = newState
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

func (s *CloudletApi) startCloudletStream(ctx context.Context, cctx *CallContext, streamCb *CbWrapper, modRev int64) (*streamSend, error) {
	streamSendObj, err := s.all.streamObjApi.startStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to start Cloudlet stream", "err", err)
		return nil, err
	}
	return streamSendObj, err
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
	reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().CreateCloudletTimeout.TimeDuration())
	defer reqCancel()

	conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
	if err != nil {
		return err
	}
	api := edgeproto.NewCloudletPlatformAPIClient(conn)
	outStream, err := api.GetRestrictedCloudletStatus(reqCtx, key)
	if err != nil {
		return cloudcommon.GRPCErrorUnwrap(err)
	}
	err = cloudcommon.StreamRecv(ctx, outStream, func(status *edgeproto.StreamStatus) error {
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
		if !in.CrmOnEdge {
			return fmt.Errorf("deployment local is only for testing CRMs locally, must set CrmOnEdge to true")
		}
		if in.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
			return errors.New("infra access type restricted is not supported for local deployment")
		}
		if in.Deployment != "" && in.Deployment != cloudcommon.DeploymentTypeDocker {
			return fmt.Errorf("deployment type for local must be docker")
		}
	}
	if in.Deployment == "" {
		in.Deployment = cloudcommon.DeploymentTypeDocker
	}
	if !cloudcommon.IsValidDeploymentType(in.Deployment, cloudcommon.ValidCloudletDeployments) {
		return fmt.Errorf("Invalid deployment, must be one of %v", cloudcommon.ValidCloudletDeployments)
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
		if s.GetCloudletForVMPool(&vmPoolKey) != nil {
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
	if in.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		in.CrmOnEdge = true
	}
	if features.RequiresCrmOnEdge && !in.CrmOnEdge {
		in.CrmOnEdge = true
	}
	if features.RequiresCrmOffEdge && in.CrmOnEdge {
		return fmt.Errorf("platform %s requires CRM off edge site", features.PlatformType)
	}

	if in.PlatformHighAvailability {
		if !in.CrmOnEdge {
			return fmt.Errorf("Platform High Availability is only an option for CRM on Edge; when CRM runs centrally HA is automatically provided by horizontal scaling")
		}
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
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, cloudletKey.StreamKey(), inCb)

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
		in.AccessVars = redactAccessVars(accessVars)
	}

	kafkaDetails := svcnode.KafkaCreds{}
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
		path := svcnode.GetKafkaVaultPath(*region, in.Key.Name, in.Key.Organization)
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
			vault.DeleteKV(client, svcnode.GetKafkaVaultPath(*region, in.Key.Name, in.Key.Organization))
		} else {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to login in to vault to delete kafka credentials", "err", err)
		}
	}()

	accessKey, err := svcnode.GenerateAccessKey()
	if err != nil {
		return err
	}
	keys := accessvars.CRMAccessKeys{}
	keys.PublicPEM = accessKey.PublicPEM
	keys.PrivatePEM = accessKey.PrivatePEM
	in.CrmAccessPublicKey = accessKey.PublicPEM
	in.CrmAccessKeyUpgradeRequired = in.CrmOnEdge

	if in.PlatformHighAvailability {
		secondaryAccessKey, err := svcnode.GenerateAccessKey()
		if err != nil {
			return err
		}
		keys.SecondaryPublicPEM = secondaryAccessKey.PublicPEM
		keys.SecondaryPrivatePEM = secondaryAccessKey.PrivatePEM
		in.SecondaryCrmAccessPublicKey = secondaryAccessKey.PublicPEM
		in.SecondaryCrmAccessKeyUpgradeRequired = in.CrmOnEdge
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
		err = accessvars.ValidatePropVars(accessVars, features.AccessVars, "access")
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
	if len(in.EnvVar) > 0 {
		err = accessvars.ValidatePropVars(in.EnvVar, features.Properties, "env")
		if err != nil {
			return err
		}
	}

	vmPool := edgeproto.VMPool{}
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
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
		if zoneKey := in.GetZone(); zoneKey.IsSet() {
			zone := edgeproto.Zone{}
			if !s.all.zoneApi.store.STMGet(stm, zoneKey, &zone) {
				return zoneKey.NotFoundError()
			}
			if zone.DeletePrepare {
				return zoneKey.BeingDeletedError()
			}
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
				cb.Send(&edgeproto.Result{Message: "Validating GPU driver license config"})
				err := s.all.gpuDriverApi.validateLicenseConfig(ctx, in.GpuConfig.LicenseConfig, &in.GpuConfig.LicenseConfigMd5Sum)
				if err != nil {
					return err
				}
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
		err = ValidateCloudletResourceQuotas(ctx, resProps, nil, in.ResourceQuotas)
		if err != nil {
			return err
		}
		if err := s.setDnsLabel(stm, in); err != nil {
			return err
		}
		in.RootLbFqdn = getCloudletRootLBFQDN(in)
		in.StaticRootLbFqdn = in.RootLbFqdn
		if features.IsSingleKubernetesCluster {
			if in.EnableDefaultServerlessCluster {
				return errors.New("cannot enable default serverless cluster for single kubernetes cluster platform")
			}
			if in.SingleKubernetesNamespace != "" {
				if in.SingleKubernetesClusterOwner == "" {
					return errors.New("single kubernetes namespace requires specifying the single kubernetes cluster owner")
				}
				if err := util.ValidDNSName(in.SingleKubernetesNamespace); err != nil {
					return fmt.Errorf("invalid single kubernetes namespace: %s", err.Error())
				}
			}
			// create ClusterInst representation of Cloudlet
			err := s.all.clusterInstApi.createCloudletSingularCluster(stm, in, in.SingleKubernetesClusterOwner)
			if err != nil {
				return err
			}
		} else {
			if in.SingleKubernetesClusterOwner != "" {
				return fmt.Errorf("Single kubernetes cluster owner can only be set on a single cluster platform")
			}
			if in.SingleKubernetesNamespace != "" {
				return fmt.Errorf("Single kubernetes namespace can only be set on a single cluster platform")
			}
		}

		in.CreatedAt = dme.TimeToTimestamp(time.Now())
		in.ObjId = ulid.Make().String()

		if ignoreCRMState(cctx) {
			in.State = edgeproto.TrackedState_READY
		} else {
			in.State = edgeproto.TrackedState_CREATE_REQUESTED
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
			if in.Zone != "" {
				s.updateZoneLocation(ctx, in.Key.Organization, "", in.Zone)
			}
		}
	}()

	sendObj, err := s.startCloudletStream(ctx, cctx, streamCb, modRev)
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

	if ignoreCRMState(cctx) {
		return nil
	}

	cloudletResourcesCreated := false
	defer func() {
		if reterr != nil {
			cb.Send(&edgeproto.Result{Message: reterr.Error()})
			cb.Send(&edgeproto.Result{Message: "Deleting Cloudlet due to failures"})
			log.SpanLog(ctx, log.DebugLevelInfo, "deleting cloudlet due to failures")
			undoErr := s.deleteCloudletInternal(cctx.WithUndo().WithStream(sendObj), in, cb, cloudletResourcesCreated)
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "Undo create Cloudlet", "undoErr", undoErr)
			}
		}
	}()

	reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().CreateCloudletTimeout.TimeDuration())
	defer reqCancel()

	if in.InfraApiAccess != edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		// Connect to CCRM to onboard the cloudlet
		conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
		if err != nil {
			return err
		}
		cloudletResourcesCreated = true
		api := edgeproto.NewCloudletPlatformAPIClient(conn)
		in.State = edgeproto.TrackedState_CREATE_REQUESTED
		in.Fields = edgeproto.CloudletAllFields
		outStream, err := api.ApplyCloudlet(reqCtx, in)
		if err == nil {
			err = cloudcommon.StreamRecvWithStatus(ctx, outStream, cb.Send, func(info *edgeproto.CloudletInfo) error {
				s.all.cloudletInfoApi.UpdateRPC(ctx, info)
				return nil
			})
		}
		if err != nil && cctx.Override == edgeproto.CRMOverride_IGNORE_CRM_ERRORS {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Create Cloudlet ignoring CRM failure: %s", err.Error())})
			err = nil
		}
		if err != nil {
			return fmt.Errorf("Cloudlet onboarding failed: %s", cloudcommon.GRPCErrorUnwrap(err))
		}
	}

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
		if !in.CrmOnEdge {
			// CCRM has already fully onboarded cloudlet, no CRM to wait for
			cloudlet.State = edgeproto.TrackedState_READY
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
	successMsg := "Created Cloudlet successfully"
	if in.CrmOnEdge {
		// Wait for CRM to connect to controller
		go func() {
			err := process.CrmServiceWait(in.Key)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "failed to cleanup crm service", "err", err)
			}
		}()
		err = edgeproto.WaitForCloudletInfo(
			reqCtx, &in.Key, s.all.cloudletInfoApi.store,
			dme.CloudletState_CLOUDLET_STATE_READY,
			CreateCloudletTransitions, dme.CloudletState_CLOUDLET_STATE_ERRORS,
			successMsg, cb.Send, sendObj.crmMsgCh)
		if err != nil {
			return err
		}
	} else {
		cb.Send(&edgeproto.Result{
			Message: successMsg,
		})
	}
	return nil
}

func ValidateCloudletResourceQuotas(ctx context.Context, quotaProps []edgeproto.InfraResource, curRes map[string]*edgeproto.InfraResource, resourceQuotas []edgeproto.ResourceQuota) error {
	log.SpanLog(ctx, log.DebugLevelApi, "validate cloudlet resource quotas", "curResources", curRes, "quotas", resourceQuotas)
	resPropsMap := make(map[string]struct{})
	resPropsNames := []string{}
	for _, prop := range quotaProps {
		resKey := prop.ResKey()
		resPropsMap[resKey] = struct{}{}
		resPropsNames = append(resPropsNames, resKey)
	}
	for resName, _ := range cloudcommon.CommonCloudletResources {
		resPropsMap[resName] = struct{}{}
		resPropsNames = append(resPropsNames, resName)
	}
	sort.Strings(resPropsNames)
	for _, resQuota := range resourceQuotas {
		resKey := resQuota.ResKey()
		if _, ok := resPropsMap[resKey]; !ok {
			return fmt.Errorf("invalid quota for %s, valid quotas are for %s", resKey, strings.Join(resPropsNames, ", "))
		}
		if curRes == nil {
			continue
		}
		infraRes, ok := curRes[resKey]
		if !ok {
			continue
		}
		if infraRes.InfraMaxValue > 0 && resQuota.Value > infraRes.InfraMaxValue {
			return fmt.Errorf("resource quota for %s exceeded max supported value: %d", resKey, infraRes.InfraMaxValue)
		}
		// Note: not a failure if the currently used value exceeds the quota.
		// It just means no more resources can be consumed until the
		// current value drops below the quota.
		// Also, curRes has the current value as reported by the
		// infrastructure. But not all infras may report the current
		// usage.
	}
	return nil
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
		appInst := edgeproto.AppInst{}
		if !s.all.appInstApi.cache.Get(&akey, &appInst) {
			log.SpanLog(ctx, log.DebugLevelApi, "verify trust policies for app insts, app inst not found", "appInst", akey)
			continue
		}
		pkey, cloudletFound := trustedCloudlets[appInst.CloudletKey]
		if cloudletFound {
			policy, policyFound := TrustPolicies[*pkey]
			if !policyFound {
				return fmt.Errorf("Unable to find trust policy in cache: %s", pkey.String())
			}
			err := s.all.appApi.CheckAppCompatibleWithTrustPolicy(ctx, &appInst.CloudletKey, app, policy)
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

	reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().UpdateCloudletTimeout.TimeDuration())
	defer reqCancel()

	if cloudlet.CrmOnEdge {
		targetState := edgeproto.TrackedState_READY
		if policyName == "" {
			targetState = edgeproto.TrackedState_NOT_PRESENT
		}
		err = s.WaitForTrustPolicyState(reqCtx, ckey, targetState, edgeproto.TrackedState_UPDATE_ERROR, s.all.settingsApi.Get().UpdateTrustPolicyTimeout.TimeDuration())
		if err == nil {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Successful TrustPolicy: %s Update for Cloudlet: %s", policyName, ckey.String())})
		} else if caseInsensitiveContainsTimedOut(err.Error()) {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("In progress TrustPolicy: %s Update for Cloudlet: %s -- %v", policyName, ckey.String(), err.Error())})
		} else {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Failed TrustPolicy: %s Update for Cloudlet: %s -- %v", policyName, ckey.String(), err.Error())})
		}
		if err != nil {
			return err
		}
	} else {
		features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
		if err != nil {
			return err
		}
		conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
		if err != nil {
			return err
		}
		api := edgeproto.NewCloudletPlatformAPIClient(conn)

		cloudlet.Fields = []string{
			edgeproto.CloudletFieldTrustPolicyState,
			edgeproto.CloudletFieldTrustPolicy,
		}
		outStream, err := api.ApplyCloudlet(reqCtx, cloudlet)
		if err != nil {
			return cloudcommon.GRPCErrorUnwrap(err)
		}
		err = cloudcommon.StreamRecvWithStatus(ctx, outStream, cb.Send, func(info *edgeproto.CloudletInfo) error {
			s.all.cloudletInfoApi.UpdateRPC(ctx, info)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// once trust policy is updated, trust policy exceptions must now be updated
	s.all.trustPolicyExceptionApi.applyAllTPEsForCloudlet(ctx, cloudlet.Key)
	return nil
}

func (s *CloudletApi) UpdateCloudlet(in *edgeproto.Cloudlet, inCb edgeproto.CloudletApi_UpdateCloudletServer) (reterr error) {
	ctx := inCb.Context()
	cctx := DefCallContext()
	cctx.SetOverride(&in.CrmOverride)

	if err := validateAllianceOrgs(ctx, in); err != nil {
		return err
	}

	cloudletKey := in.Key
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, cloudletKey.StreamKey(), inCb)

	_ = updateCloudletCallback{in, cb}

	err := in.ValidateUpdateFields()
	if err != nil {
		return err
	}

	fmap := edgeproto.MakeFieldMap(in.Fields)
	if fmap.Has(edgeproto.CloudletFieldNumDynamicIps) {
		staticSet := false
		if fmap.Has(edgeproto.CloudletFieldIpSupport) {
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
	if fmap.HasOrHasChild(edgeproto.CloudletFieldAccessVars) {
		accessVars = in.AccessVars
	}

	singleKubernetesClusterOwnerSet := fmap.Has(edgeproto.CloudletFieldSingleKubernetesClusterOwner)
	if singleKubernetesClusterOwnerSet {
		// TODO: to support this, we need to use the ClusterRefs
		// to make sure no AppInsts exist, and then we need to delete
		// the current default single cluster and create a new one with
		// the new org.
		return fmt.Errorf("Changing the single kubernetes cluster owner is not supported yet")
	}

	kafkaClusterChanged := fmap.Has(edgeproto.CloudletFieldKafkaCluster)
	kafkaUserChanged := fmap.Has(edgeproto.CloudletFieldKafkaUser)
	kafkaPasswordChanged := fmap.Has(edgeproto.CloudletFieldKafkaPassword)
	if kafkaClusterChanged && in.KafkaCluster == "" {
		in.KafkaCluster = ""
		in.KafkaUser = ""
		in.KafkaPassword = ""
		client, err := vaultConfig.Login()
		if err == nil {
			vault.DeleteKV(client, svcnode.GetKafkaVaultPath(*region, in.Key.Name, in.Key.Organization))
		} else {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to login in to vault to delete kafka credentials", "err", err)
		}
	} else if kafkaClusterChanged || kafkaUserChanged || kafkaPasswordChanged {
		// get existing data
		kafkaCreds := svcnode.KafkaCreds{}
		path := svcnode.GetKafkaVaultPath(*region, in.Key.Name, in.Key.Organization)
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

	crmUpdateReqd := false
	if fmap.HasOrHasChild(edgeproto.CloudletFieldEnvVar) {
		if fmap.Has(edgeproto.CloudletFieldMaintenanceState) {
			return errors.New("Cannot set envvars if maintenance state is set")
		}
		crmUpdateReqd = true
	}

	cloudletSpecificResources := features.ResourceQuotaProperties
	if err != nil {
		return err
	}
	if fmap.HasOrHasChild(edgeproto.CloudletFieldAccessVars) {
		newVars, err := accessvars.UpdateCloudletAccessVars(ctx, *region, in, nodeMgr.VaultConfig, accessVars, features.AccessVars)
		if err != nil {
			return err
		}
		in.AccessVars = redactAccessVars(newVars)
	}

	var newMaintenanceState dme.MaintenanceState
	maintenanceChanged := false
	privPolUpdateRequested := fmap.Has(edgeproto.CloudletFieldTrustPolicy)
	updateDefaultMultiTenantCluster := false
	var diffFields *edgeproto.FieldMap

	var gpuDriver edgeproto.GPUDriver
	var oldZone string
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		updateDefaultMultiTenantCluster = false
		diffFields = edgeproto.NewFieldMap(nil)

		if !s.store.STMGet(stm, &in.Key, cur) {
			return in.Key.NotFoundError()
		}
		cloudletInfo := edgeproto.CloudletInfo{}
		if !s.all.cloudletInfoApi.store.STMGet(stm, &in.Key, &cloudletInfo) {
			return fmt.Errorf("Missing cloudlet info: %v", in.Key)
		}
		cloudletRefs := edgeproto.CloudletRefs{}
		s.all.cloudletRefsApi.store.STMGet(stm, &in.Key, &cloudletRefs)
		if fmap.HasOrHasChild(edgeproto.CloudletFieldResourceQuotas) {
			infraResInfo := make(map[string]*edgeproto.InfraResource)
			for _, resInfo := range cloudletInfo.ResourcesSnapshot.Info {
				infraResInfo[resInfo.ResKey()] = &resInfo
			}
			err = ValidateCloudletResourceQuotas(ctx, cloudletSpecificResources, infraResInfo, in.ResourceQuotas)
			if err != nil {
				return err
			}
			crmUpdateReqd = true
		}
		if fmap.HasOrHasChild(edgeproto.CloudletFieldGpuConfig) {
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
		if fmap.HasOrHasChild(edgeproto.CloudletFieldZone) && cur.Zone != in.Zone {
			oldZone = cur.Zone
			if zoneKey := in.GetZone(); zoneKey.IsSet() {
				zone := edgeproto.Zone{}
				if !s.all.zoneApi.store.STMGet(stm, zoneKey, &zone) {
					return zoneKey.NotFoundError()
				}
				if zone.DeletePrepare {
					return zoneKey.BeingDeletedError()
				}
			}
		}
		if in.GpuConfig.Driver.Name != "" {
			if !s.all.gpuDriverApi.store.STMGet(stm, &in.GpuConfig.Driver, &gpuDriver) {
				return fmt.Errorf("GPU driver %s not found", in.GpuConfig.Driver.String())
			}
		}

		old := edgeproto.Cloudlet{}
		old.DeepCopyIn(cur)
		cur.CopyInFields(in)
		diffFields = old.GetDiffFields(cur)

		if fmap.Has(edgeproto.CloudletFieldSingleKubernetesNamespace) {
			if !features.IsSingleKubernetesCluster {
				return fmt.Errorf("Single kubernetes namespace can only be set on a single cluster platform")
			}
			if cur.SingleKubernetesClusterOwner == "" {
				return errors.New("single kubernetes namespace requires specifying the single kubernetes cluster owner")
			}
			if cur.SingleKubernetesNamespace != "" {
				if err := util.ValidDNSName(in.SingleKubernetesNamespace); err != nil {
					return fmt.Errorf("invalid single kubernetes namespace %q: %s", in.SingleKubernetesNamespace, err.Error())
				}
			}
			defaultClustKey := cloudcommon.GetDefaultClustKey(in.Key, in.SingleKubernetesClusterOwner)
			clusterRefs := edgeproto.ClusterRefs{}
			if s.all.clusterRefsApi.store.STMGet(stm, defaultClustKey, &clusterRefs) {
				if len(clusterRefs.Apps) > 0 {
					return fmt.Errorf("cannot change single kubernetes namespace when app instances exist")
				}
			}
			// namespace is also copied onto default cluster
			clusterInst := edgeproto.ClusterInst{}
			if s.all.clusterInstApi.store.STMGet(stm, defaultClustKey, &clusterInst) {
				clusterInst.SingleKubernetesNamespace = in.SingleKubernetesNamespace
				s.all.clusterInstApi.store.STMPut(stm, &clusterInst)
			}
		}

		newMaintenanceState = cur.MaintenanceState
		if newMaintenanceState != old.MaintenanceState {
			maintenanceChanged = true
			// don't change maintenance here, we handle it below
			cur.MaintenanceState = old.MaintenanceState
			diffFields.Clear(edgeproto.CloudletFieldMaintenanceState)
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
			}
			updateDefaultMultiTenantCluster = true
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

	if updateDefaultMultiTenantCluster {
		s.defaultMTClustWorkers.NeedsWork(ctx, in.Key)
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

	sendObj, err := s.startCloudletStream(ctx, cctx, streamCb, modRev)
	if err != nil {
		return err
	}
	defer func() {
		s.stopCloudletStream(ctx, cctx, &cloudletKey, sendObj, reterr, NoCleanupStream)
	}()

	// Since state is set to UPDATE_REQUESTED, it is safe to do the following
	if fmap.HasOrHasChild(edgeproto.CloudletFieldGpuConfigLicenseConfig) {
		if gpuDriver.Key.Name == "" {
			return fmt.Errorf("License config can only be updated if GPU config exists for the cloudlet")
		}
		in.GpuConfig.LicenseConfigMd5Sum = ""
		if in.GpuConfig.LicenseConfig != "" {
			cb.Send(&edgeproto.Result{Message: "Validating GPU driver license config"})
			err := s.all.gpuDriverApi.validateLicenseConfig(ctx, in.GpuConfig.LicenseConfig, &in.GpuConfig.LicenseConfigMd5Sum)
			if err != nil {
				return err
			}
		}
		err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			cl := edgeproto.Cloudlet{}
			if !s.store.STMGet(stm, &in.Key, &cl) {
				return in.Key.NotFoundError()
			}
			cl.GpuConfig.LicenseConfig = in.GpuConfig.LicenseConfig
			cl.GpuConfig.LicenseConfigMd5Sum = in.GpuConfig.LicenseConfigMd5Sum
			s.store.STMPut(stm, &cl)
			return nil
		})
		if err != nil {
			return err
		}
	}

	reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().UpdateCloudletTimeout.TimeDuration())
	defer reqCancel()

	// after the cloudlet change is committed, if the location changed,
	// update app insts as well.
	s.UpdateAppInstLocations(ctx, in)

	successMsg := "Cloudlet updated successfully"
	if crmUpdateReqd && !ignoreCRM(cctx) && cur.CrmOnEdge {
		// Wait for cloudlet to finish upgrading
		err = edgeproto.WaitForCloudletInfo(
			reqCtx, &in.Key, s.all.cloudletInfoApi.store,
			dme.CloudletState_CLOUDLET_STATE_READY,
			UpdateCloudletTransitions, dme.CloudletState_CLOUDLET_STATE_ERRORS,
			successMsg, cb.Send, sendObj.crmMsgCh)
		return err
	} else if crmUpdateReqd && !ignoreCRM(cctx) {
		conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
		if err != nil {
			return err
		}
		api := edgeproto.NewCloudletPlatformAPIClient(conn)
		cur.Fields = diffFields.Fields()
		if crmUpdateReqd {
			cur.Fields = append(cur.Fields, edgeproto.CloudletFieldState)
		}
		outStream, err := api.ApplyCloudlet(reqCtx, cur)
		if err != nil {
			return cloudcommon.GRPCErrorUnwrap(err)
		}
		err = cloudcommon.StreamRecvWithStatus(ctx, outStream, cb.Send, func(info *edgeproto.CloudletInfo) error {
			s.all.cloudletInfoApi.UpdateRPC(ctx, info)
			return nil
		})
		if err == nil {
			cb.Send(&edgeproto.Result{
				Message: successMsg,
			})
		}
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

	if diffFields.Has(edgeproto.CloudletFieldZone) {
		s.updateZoneForCloudlet(ctx, &in.Key)
		s.updateZoneLocation(ctx, in.Key.Organization, oldZone, cur.Zone)
	}

	// since default maintenance state is NORMAL_OPERATION, it is better to check
	// if the field is set before handling maintenance state
	if !fmap.Has(edgeproto.CloudletFieldMaintenanceState) || !maintenanceChanged {
		cb.Send(&edgeproto.Result{Message: "Cloudlet updated successfully"})
		return nil
	}

	nodeType := features.NodeType

	switch newMaintenanceState {
	case dme.MaintenanceState_NORMAL_OPERATION:
		log.SpanLog(ctx, log.DebugLevelApi, "Stop CRM maintenance")
		if !ignoreCRMState(cctx) {
			timeout := s.all.settingsApi.Get().CloudletMaintenanceTimeout.TimeDuration()
			err = s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_NORMAL_OPERATION_INIT, reqCtx, nodeType)
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
		err = s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_NORMAL_OPERATION, reqCtx, nodeType)
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

		err = s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_FAILOVER_REQUESTED, reqCtx, nodeType)
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
			undoErr := s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_NORMAL_OPERATION, reqCtx, nodeType)
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
			err = s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_CRM_REQUESTED, reqCtx, nodeType)
			if err != nil {
				return err
			}
			cloudletInfo := edgeproto.CloudletInfo{}
			err = s.all.cloudletInfoApi.waitForMaintenanceState(ctx, &in.Key, dme.MaintenanceState_CRM_UNDER_MAINTENANCE, dme.MaintenanceState_CRM_ERROR, timeout, &cloudletInfo)
			if err != nil {
				return err
			}
			if cloudletInfo.MaintenanceState == dme.MaintenanceState_CRM_ERROR {
				undoErr := s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_NORMAL_OPERATION, reqCtx, nodeType)
				log.SpanLog(ctx, log.DebugLevelApi, "CRM maintenance failures", "err", err, "undoErr", undoErr)
				return fmt.Errorf("CRM encountered some errors, aborting maintenance")
			}
		}
		cb.Send(&edgeproto.Result{
			Message: "CRM maintenance started",
		})
		log.SpanLog(ctx, log.DebugLevelApi, "CRM maintenance started")
		// transition to maintenance
		err = s.setMaintenanceState(ctx, &in.Key, dme.MaintenanceState_UNDER_MAINTENANCE, reqCtx, nodeType)
		if err != nil {
			return err
		}
		cb.Send(&edgeproto.Result{
			Message: "Cloudlet is in maintenance",
		})
	}
	return nil
}

func (s *CloudletApi) setMaintenanceState(ctx context.Context, key *edgeproto.CloudletKey, state dme.MaintenanceState, reqCtx context.Context, nodeType string) error {
	changedState := false
	var cur *edgeproto.Cloudlet
	log.SpanLog(ctx, log.DebugLevelApi, "set cloudlet maintenance state", "cloudlet", key, "state", state)
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		cur = &edgeproto.Cloudlet{}
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
	if err != nil {
		return err
	}

	sendToCRM := false
	if state == dme.MaintenanceState_CRM_REQUESTED || state == dme.MaintenanceState_NORMAL_OPERATION_INIT {
		sendToCRM = true
	}
	if changedState && !cur.CrmOnEdge && sendToCRM {
		conn, err := services.platformServiceConnCache.GetConn(ctx, nodeType)
		if err != nil {
			return err
		}
		api := edgeproto.NewCloudletPlatformAPIClient(conn)

		cur.Fields = []string{edgeproto.CloudletFieldMaintenanceState}
		outStream, err := api.ApplyCloudlet(reqCtx, cur)
		if err != nil {
			return err
		}
		err = cloudcommon.StreamRecv(ctx, outStream, func(info *edgeproto.CloudletInfo) error {
			s.all.cloudletInfoApi.UpdateRPC(ctx, info)
			return nil
		})
		if err != nil {
			return err
		}
	}

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
	return nil
}

func (s *CloudletApi) DeleteCloudlet(in *edgeproto.Cloudlet, cb edgeproto.CloudletApi_DeleteCloudletServer) error {
	return s.deleteCloudletInternal(DefCallContext(), in, cb, true)
}

func (s *CloudletApi) deleteCloudletInternal(cctx *CallContext, in *edgeproto.Cloudlet, inCb edgeproto.CloudletApi_DeleteCloudletServer, cloudletResourcesCreated bool) (reterr error) {
	cctx.SetOverride(&in.CrmOverride)
	ctx := inCb.Context()

	cloudletKey := in.Key
	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, cloudletKey.StreamKey(), inCb)

	var dynInsts map[edgeproto.AppInstKey]struct{}
	var clDynInsts map[edgeproto.ClusterKey]struct{}

	var features *edgeproto.PlatformFeatures
	var prevState edgeproto.TrackedState
	var gpuDriver edgeproto.GPUDriver
	modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
		dynInsts = make(map[edgeproto.AppInstKey]struct{})
		clDynInsts = make(map[edgeproto.ClusterKey]struct{})
		if !s.store.STMGet(stm, &in.Key, in) {
			return in.Key.NotFoundError()
		}
		if !ignoreCRMTransient(cctx) && in.DeletePrepare {
			return in.Key.BeingDeletedError()
		}
		var err error
		features, err = s.all.platformFeaturesApi.GetCloudletFeatures(ctx, in.PlatformType)
		if err != nil {
			return fmt.Errorf("Failed to get features for platform: %s", err)
		}
		var defaultClustKey *edgeproto.ClusterKey
		if features.IsSingleKubernetesCluster {
			defaultClustKey = cloudcommon.GetDefaultClustKey(in.Key, in.SingleKubernetesClusterOwner)
		}
		refs := edgeproto.CloudletRefs{}
		if s.all.cloudletRefsApi.store.STMGet(stm, &in.Key, &refs) {
			err = s.all.clusterInstApi.deleteCloudletOk(stm, in, &refs, clDynInsts)
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

	sendObj, err := s.startCloudletStream(ctx, cctx, streamCb, modRev)
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

	// for cascaded deletes of ClusterInst/AppInst, skip cloudlet
	// ready check because it's not ready - it's being deleted.
	cctx.SkipCloudletReadyCheck = true

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

	ccrmDelete := func() error {
		// send delete to CCRM
		reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().UpdateCloudletTimeout.TimeDuration())
		defer reqCancel()
		conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
		if err != nil {
			return err
		}
		cloudletResourcesCreated = true
		api := edgeproto.NewCloudletPlatformAPIClient(conn)
		in.Fields = []string{edgeproto.CloudletFieldState}
		in.State = edgeproto.TrackedState_DELETE_REQUESTED
		s.SetState(ctx, in, edgeproto.TrackedState_DELETE_REQUESTED)
		outStream, err := api.ApplyCloudlet(reqCtx, in)
		if err != nil {
			return cloudcommon.GRPCErrorUnwrap(err)
		}
		err = cloudcommon.StreamRecvWithStatus(ctx, outStream, cb.Send, func(info *edgeproto.CloudletInfo) error {
			s.all.cloudletInfoApi.UpdateRPC(ctx, info)
			return nil
		})
		return err
	}
	if !ignoreCRMState(cctx) && in.InfraApiAccess != edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		err := ccrmDelete()
		if err != nil {
			// if we are ignoring CRM errors, or if there were no resources created, proceed with deletion.
			// If this was an undo, continue anyway. This allows
			// for us to clean up if the platform code hits an error
			// during platform.InitCommon(), which will happen in
			// ccrm.ApplyCloudlet() on both create and delete.
			if cctx.Override == edgeproto.CRMOverride_IGNORE_CRM_ERRORS || !cloudletResourcesCreated || cctx.Undo {
				cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Delete Cloudlet ignoring CRM failure: %s", err.Error())})
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
		s.all.cloudletIPsApi.cache.Store.STMDel(stm, &in.Key)
		if features.IsSingleKubernetesCluster {
			s.all.clusterInstApi.deleteCloudletSingularCluster(stm, &in.Key, updateCloudlet.SingleKubernetesClusterOwner)
		}
		return nil
	})
	if err1 != nil {
		return err1
	}
	cb.Send(&edgeproto.Result{Message: "Deleted Cloudlet successfully"})

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
			vault.DeleteKV(client, svcnode.GetKafkaVaultPath(*region, in.Key.Name, in.Key.Organization))
		} else {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to login in to vault to delete kafka credentials", "key", in.Key, "err", err)
		}
	}

	err = accessvars.DeleteCRMAccessKeys(ctx, *region, in, nodeMgr.VaultConfig)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Failed to delete accesskeys from Vault", "cloudlet", in.Key, "err", err)
	}

	s.all.cloudletInfoApi.cleanupCloudletInfo(ctx, in)
	s.all.autoProvInfoApi.Delete(ctx, &edgeproto.AutoProvInfo{Key: in.Key}, 0)
	s.all.alertApi.CleanupCloudletAlerts(ctx, &in.Key)
	s.all.cloudletNodeApi.cleanupNodes(ctx, &in.Key)
	return nil
}

func (s *CloudletApi) ShowCloudlet(in *edgeproto.Cloudlet, cb edgeproto.CloudletApi_ShowCloudletServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.Cloudlet) error {
		copy := *obj
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
	if !fmap.HasOrHasChild(edgeproto.CloudletFieldLocation) {
		// no location fields updated
		return
	}

	// find all appinsts associated with the cloudlet
	keys := make([]edgeproto.AppInstKey, 0)
	s.all.appInstApi.cache.Mux.Lock()
	for _, data := range s.all.appInstApi.cache.Objs {
		inst := data.Obj
		if inst.CloudletKey.Matches(&in.Key) {
			keys = append(keys, inst.Key)
		}
	}
	s.all.appInstApi.cache.Mux.Unlock()

	inst := edgeproto.AppInst{}
	for ii, _ := range keys {
		inst = *s.all.appInstApi.cache.Objs[keys[ii]].Obj
		inst.Fields = make([]string, 0)
		if fmap.Has(edgeproto.CloudletFieldLocationLatitude) {
			inst.CloudletLoc.Latitude = in.Location.Latitude
			inst.Fields = append(inst.Fields, edgeproto.AppInstFieldCloudletLocLatitude)
		}
		if fmap.Has(edgeproto.CloudletFieldLocationLongitude) {
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
	var spec *resspec.VMCreationSpec
	if !s.all.cloudletApi.cache.Get(&in.Key, &cl) {
		return nil, in.Key.NotFoundError()
	}
	cli := edgeproto.CloudletInfo{}
	if !s.all.cloudletInfoApi.cache.Get(&in.Key, &cli) {
		return nil, in.Key.NotFoundError()
	}
	mexFlavor := edgeproto.Flavor{}
	mexFlavor.Key.Name = in.FlavorName
	if !s.all.flavorApi.cache.Get(&mexFlavor.Key, &mexFlavor) {
		return nil, in.Key.NotFoundError()
	}
	// convert flavor to node resources requirement
	nr := mexFlavor.ToNodeResources()
	var verr error
	stm := edgeproto.NewOptionalSTM(nil)
	spec, verr = s.all.resTagTableApi.GetVMSpec(ctx, stm, nr, "", cl, cli)
	if verr != nil {
		return nil, fmt.Errorf("failed to find flavor match for %s, %s", in.Key.Name, verr)
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

	reqCtx, cancel := context.WithTimeout(ctx, s.all.settingsApi.Get().CcrmApiTimeout.TimeDuration())
	defer cancel()
	conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewCloudletPlatformAPIClient(conn)
	manifest, err := api.GetCloudletManifest(reqCtx, key)
	return manifest, cloudcommon.GRPCErrorUnwrap(err)
}

func (s *CloudletApi) GetCloudletForVMPool(vmPoolKey *edgeproto.VMPoolKey) *edgeproto.Cloudlet {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	for key, data := range s.cache.Objs {
		val := data.Obj
		cVMPoolKey := edgeproto.VMPoolKey{
			Organization: key.Organization,
			Name:         val.VmPool,
		}
		if vmPoolKey.Matches(&cVMPoolKey) {
			cloudlet := edgeproto.Cloudlet{}
			cloudlet.DeepCopyIn(val)
			return &cloudlet
		}
	}
	return nil
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

func (s *CloudletApi) CloudletsUsingResTagTable(key *edgeproto.ResTagTableKey) *edgeproto.CloudletKey {
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

func (s *CloudletApi) CloudletsUsingZone(zoneKey *edgeproto.ZoneKey) []string {
	s.cache.Mux.Lock()
	defer s.cache.Mux.Unlock()
	uses := []string{}
	for _, data := range s.cache.Objs {
		val := data.Obj
		if val.Key.Organization == zoneKey.Organization && val.Key.FederatedOrganization == zoneKey.FederatedOrganization && zoneKey.Name == val.Zone {
			uses = append(uses, val.Key.Name)
		}
	}
	return uses
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
	var keyPair *svcnode.KeyPair
	var err, vaultErr error
	err = s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		res.Message = ""
		if !s.store.STMGet(stm, key, &cloudlet) {
			return key.NotFoundError()
		}
		keyPair, err = svcnode.GenerateAccessKey()
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

// sumCloudletResources adds up resources from CloudletResources
func (s *CloudletApi) sumCloudletResources(ctx context.Context, stm *edgeproto.OptionalSTM, cloudlet *edgeproto.Cloudlet, cloudletInfo *edgeproto.CloudletInfo, features *edgeproto.PlatformFeatures, cloudletResources *CloudletResources) resspec.ResValMap {
	resVals := resspec.ResValMap{}
	// add in non-flavor resource values
	resVals.AddAllMult(cloudletResources.nonFlavorVals, 1)
	// sum resources from flavors
	if len(cloudletResources.flavors) > 0 {
		for _, flavor := range cloudletInfo.Flavors {
			count, ok := cloudletResources.flavors[flavor.Name]
			if !ok {
				continue
			}
			num := uint64(count)
			if features.ResourceCalcByFlavorCounts {
				resVals.AddFlavor(flavor.Name, num)
				continue
			}
			resVals.AddVcpus(flavor.Vcpus*num, 0)
			resVals.AddRam(flavor.Ram * num)
			resVals.AddDisk(flavor.Disk * num)
			resVals.AddGPUs(flavor.Gpus, uint32(num))
			// TODO: we need to figure out how to convert
			// platform-specific gpu annotations on flavors to
			// be able to match against platform-independent
			// resource definitions of gpus on OptResMaps.
			if s.all.resTagTableApi.UsesGpu(ctx, stm, *flavor, *cloudlet) {
				resVals.AddRes(cloudcommon.ResourceGpus, "", num, 0)
			}
		}
	}

	// set external IPs count
	externalIPs := cloudletResources.lbNodeCount + cloudletResources.platformNodeCount
	if externalIPs > 0 {
		resVals.AddRes(cloudcommon.ResourceExternalIPs, "", uint64(externalIPs), 0)
	}
	return resVals
}

// totalCloudletResources sums up the resources and adds in any
// additional cluster resources. This requires a network call.
func (s *CloudletApi) totalCloudletResources(ctx context.Context, stm *edgeproto.OptionalSTM, cloudlet *edgeproto.Cloudlet, cloudletInfo *edgeproto.CloudletInfo, cloudletResources *CloudletResources, options CloudletResCalcOptions) (resspec.ResValMap, error) {
	features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
	if err != nil {
		return nil, err
	}

	// sum and convert cloudlet resources to infra resources
	resVals := s.sumCloudletResources(ctx, stm, cloudlet, cloudletInfo, features, cloudletResources)

	// add in additional cluster resources
	reqCtx, cancel := context.WithTimeout(ctx, s.all.settingsApi.Get().CcrmApiTimeout.TimeDuration())
	defer cancel()
	conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
	if err != nil {
		return nil, err
	}
	api := edgeproto.NewCloudletPlatformAPIClient(conn)
	req := &edgeproto.ClusterResourcesReq{
		CloudletKey: &cloudlet.Key,
		VmResources: cloudletResources.vms,
	}
	if !options.skipAdditional {
		res, err := api.GetClusterAdditionalResources(reqCtx, req)
		if err != nil {
			return nil, cloudcommon.GRPCErrorUnwrap(err)
		}
		for k, v := range res.InfraResources {
			resVals.AddRes(k, v.Units, v.Value, 0)
		}
	}
	return resVals, nil
}

func (s *CloudletApi) GetCloudletResourceUsage(ctx context.Context, usage *edgeproto.CloudletResourceUsage) (*edgeproto.CloudletResourceUsage, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "GetCloudletResourceUsage", "key", usage.Key)
	// get used values
	stm := edgeproto.NewOptionalSTM(nil)
	resCalc := NewCloudletResCalc(s.all, stm, &usage.Key)
	if err := resCalc.InitDeps(ctx); err != nil {
		return nil, err
	}
	var usedVals resspec.ResValMap
	var err error
	if usage.InfraUsage {
		// used values as reported by infra platform
		usedVals = resspec.ResValMap{}
		for _, res := range resCalc.deps.cloudletInfo.ResourcesSnapshot.Info {
			usedVals.Add(resspec.FromInfraRes(&res))
		}
	} else {
		usedVals, err = resCalc.getUsedResVals(ctx)
		if err != nil {
			return nil, err
		}
	}
	// get max value limits
	limits := resCalc.getResourceLimits(ctx)

	if resCalc.deps.features.ResourceCalcByFlavorCounts {
		// calculate vcpus/mem/gpus from flavors, for display in UI
		flavors := map[string]*edgeproto.FlavorInfo{}
		for _, flavor := range resCalc.deps.cloudletInfo.Flavors {
			flavors[flavor.Name] = flavor
		}
		// convert used values
		for _, used := range usedVals {
			if used.ResourceType != cloudcommon.ResourceTypeFlavor {
				continue
			}
			flavor, ok := flavors[used.Name]
			if !ok {
				log.SpanLog(ctx, log.DebugLevelApi, "GetCloudletResourceUsage", "flavor not found for used", "name", used.Name)
				continue
			}
			usedVals.AddVcpus(flavor.Vcpus*used.Value.Whole, 0)
			usedVals.AddRam(flavor.Ram * used.Value.Whole)
			usedVals.AddDisk(flavor.Disk * used.Value.Whole)
			usedVals.AddGPUs(flavor.Gpus, uint32(used.Value.Whole))
		}
		// convert limits
		for _, limit := range limits {
			if limit.ResourceType != cloudcommon.ResourceTypeFlavor {
				continue
			}
			flavor, ok := flavors[limit.Name]
			if !ok {
				log.SpanLog(ctx, log.DebugLevelApi, "GetCloudletResourceUsage", "flavor not found for limit", "name", limit.Name)
				continue
			}
			limits.AddMax(cloudcommon.ResourceVcpus, "", "", flavor.Vcpus*limit.InfraMaxValue)
			limits.AddMax(cloudcommon.ResourceRamMb, "", cloudcommon.ResourceRamUnits, flavor.Ram*limit.InfraMaxValue)
			limits.AddMax(cloudcommon.ResourceDiskGb, "", cloudcommon.ResourceDiskUnits, flavor.Disk*limit.InfraMaxValue)
			for _, gpu := range flavor.Gpus {
				limits.AddMax(gpu.ModelId, cloudcommon.ResourceTypeGPU, "", uint64(limit.InfraMaxValue*uint64(gpu.Count)))
			}
		}
	}

	// convert usedVals and add in limits
	resInfo := []edgeproto.InfraResource{}
	for resName, resVal := range usedVals {
		infraRes := resVal.AsInfraRes()
		// add in limits
		if limit := limits[resName]; limit != nil {
			infraRes.QuotaMaxValue = limit.QuotaMaxValue
			infraRes.InfraMaxValue = limit.InfraMaxValue
			infraRes.AlertThreshold = limit.AlertThreshold
		}
		delete(limits, resName)
		resInfo = append(resInfo, *infraRes)
	}
	// add in limits for anything that wasn't in use
	for _, limit := range limits {
		res := edgeproto.InfraResource{
			Name:           limit.Name,
			Units:          limit.Units,
			InfraMaxValue:  limit.InfraMaxValue,
			QuotaMaxValue:  limit.QuotaMaxValue,
			AlertThreshold: limit.AlertThreshold,
			Type:           limit.ResourceType,
		}
		resInfo = append(resInfo, res)
	}
	sort.Slice(resInfo[:], func(i, j int) bool {
		return resInfo[i].ResKey() < resInfo[j].ResKey()
	})
	resourceScore := resCalc.calcResourceScoreFromUsed(usedVals)
	cloudletResUsage := edgeproto.CloudletResourceUsage{}
	cloudletResUsage.Key = usage.Key
	cloudletResUsage.InfraUsage = usage.InfraUsage
	cloudletResUsage.Info = resInfo
	cloudletResUsage.ResourceScore = resourceScore
	return &cloudletResUsage, err
}

func (s *CloudletApi) ShowCloudletResourceUsage(in *edgeproto.Cloudlet, cb edgeproto.CloudletApi_ShowCloudletResourceUsageServer) error {
	ctx := cb.Context()
	cloudletKeys := map[edgeproto.CloudletKey]struct{}{}
	err := s.cache.Show(in, func(obj *edgeproto.Cloudlet) error {
		cloudletKeys[obj.Key] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	usages := []*edgeproto.CloudletResourceUsage{}
	for key := range cloudletKeys {
		usageIn := &edgeproto.CloudletResourceUsage{
			Key: key,
		}
		usage, err := s.GetCloudletResourceUsage(ctx, usageIn)
		if err != nil {
			return fmt.Errorf("failed to get cloudlet resource usage for %s, %s", key.GetKeyString(), err)
		}
		usages = append(usages, usage)
	}
	sort.Slice(usages, func(i, j int) bool {
		return usages[i].Key.GetKeyString() < usages[j].Key.GetKeyString()
	})
	for _, usage := range usages {
		if err := cb.Send(usage); err != nil {
			return err
		}
	}
	return nil
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

func (s *CloudletApi) ShowFlavorsForZone(in *edgeproto.ZoneKey, cb edgeproto.CloudletApi_ShowFlavorsForZoneServer) error {
	ctx := cb.Context()
	allMetaFlavors := make(map[edgeproto.FlavorKey]struct{})
	flavorCache := &s.all.flavorApi.cache
	flavorCache.GetAllKeys(ctx, func(k *edgeproto.FlavorKey, modRev int64) {
		allMetaFlavors[*k] = struct{}{}
	})
	cloudletKeys := make(map[edgeproto.CloudletKey]struct{})
	// find all matching cloudlets
	filter := edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			Organization:          in.Organization,
			FederatedOrganization: in.FederatedOrganization,
		},
		Zone: in.Name,
	}
	s.cache.Show(&filter, func(cloudlet *edgeproto.Cloudlet) error {
		cloudletKeys[cloudlet.Key] = struct{}{}
		return nil
	})
	flavors := make(map[edgeproto.FlavorKey]struct{})
	for cloudletKey, _ := range cloudletKeys {
		log.SpanLog(ctx, log.DebugLevelApi, "ShowFlavorsForZone", "cloudletKey", cloudletKey)
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
			log.SpanLog(ctx, log.DebugLevelApi, "ShowFlavorsForZone match", "metaflavor", flavor, "with", match.FlavorName, "on cloudlet", cloudletKey)
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

func (s *CloudletApi) GetOrganizationsOnZone(in *edgeproto.ZoneKey, cb edgeproto.CloudletApi_GetOrganizationsOnZoneServer) error {
	orgs := make(map[string]struct{})
	aiFilter := edgeproto.AppInst{}
	aiFilter.ZoneKey = *in
	s.all.appInstApi.cache.Show(&aiFilter, func(appInst *edgeproto.AppInst) error {
		orgs[appInst.Key.Organization] = struct{}{}
		return nil
	})
	ciFilter := edgeproto.ClusterInst{}
	ciFilter.ZoneKey = *in
	s.all.clusterInstApi.cache.Show(&ciFilter, func(clusterInst *edgeproto.ClusterInst) error {
		orgs[clusterInst.Key.Organization] = struct{}{}
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

func (s *CloudletApi) updateDefaultMultiTenantClusterWorker(ctx context.Context, k interface{}) {
	key, ok := k.(edgeproto.CloudletKey)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelApi, "Unexpected failure, key not CloudletKey", "key", k)
		return
	}
	log.SetContextTags(ctx, key.GetTags())
	log.SpanLog(ctx, log.DebugLevelApi, "update default multi tenant cluster", "cloudlet", key)
	cloudlet := edgeproto.Cloudlet{}
	if !s.store.Get(ctx, &key, &cloudlet) {
		log.SpanLog(ctx, log.DebugLevelApi, "cloudlet not found", "cloudlet", key)
		return
	}
	features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to get features for cloudlet", "cloudlet", key, "err", err)
		return
	}
	if !features.SupportsMultiTenantCluster {
		log.SpanLog(ctx, log.DebugLevelApi, "cloudlet does not support multi-tenant clusters", "cloudlet", key, "platform", features.PlatformType)
		return
	}
	if cloudlet.EnableDefaultServerlessCluster {
		s.all.clusterInstApi.createDefaultMultiTenantCluster(ctx, key, features)
	} else {
		s.all.clusterInstApi.deleteDefaultMultiTenantCluster(ctx, key)
	}
}

func (s *CloudletApi) updateZoneForCloudlet(ctx context.Context, ckey *edgeproto.CloudletKey) {
	// when zone for cloudlet changes, update the zonekey on all appinsts and
	// clusterinsts for that cloudlet.
	aiFilter := edgeproto.AppInst{
		CloudletKey: *ckey,
	}
	aiKeys := []*edgeproto.AppInstKey{}
	s.all.appInstApi.cache.Show(&aiFilter, func(obj *edgeproto.AppInst) error {
		aiKeys = append(aiKeys, &obj.Key)
		return nil
	})
	log.SpanLog(ctx, log.DebugLevelApi, "update zone for appinsts", "cloudlet", ckey)
	for _, aikey := range aiKeys {
		err := s.all.appInstApi.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			ai := edgeproto.AppInst{}
			if !s.all.appInstApi.store.STMGet(stm, aikey, &ai) {
				return nil
			}
			if !ai.CloudletKey.Matches(ckey) {
				return nil
			}
			cloudlet := edgeproto.Cloudlet{}
			if !s.all.cloudletApi.store.STMGet(stm, ckey, &cloudlet) {
				return nil
			}
			zoneKey := cloudlet.GetZone()
			if ai.ZoneKey.Matches(zoneKey) {
				// no change
				return nil
			}
			ai.ZoneKey = *zoneKey
			s.all.appInstApi.store.STMPut(stm, &ai)
			return nil
		})
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to update zone for app inst", "appinst", aikey, "err", err)
		}
	}
	ciFilter := edgeproto.ClusterInst{
		CloudletKey: *ckey,
	}
	ciKeys := []*edgeproto.ClusterKey{}
	s.all.clusterInstApi.cache.Show(&ciFilter, func(obj *edgeproto.ClusterInst) error {
		ciKeys = append(ciKeys, &obj.Key)
		return nil
	})
	log.SpanLog(ctx, log.DebugLevelApi, "update zone for clusterinsts", "cloudlet", ckey)
	for _, cikey := range ciKeys {
		err := s.all.clusterInstApi.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			ci := edgeproto.ClusterInst{}
			if !s.all.clusterInstApi.store.STMGet(stm, cikey, &ci) {
				return nil
			}
			if !ci.CloudletKey.Matches(ckey) {
				return nil
			}
			cloudlet := edgeproto.Cloudlet{}
			if !s.all.cloudletApi.store.STMGet(stm, ckey, &cloudlet) {
				return nil
			}
			zoneKey := cloudlet.GetZone()
			if ci.ZoneKey.Matches(zoneKey) {
				// no change
				return nil
			}
			ci.ZoneKey = *zoneKey
			s.all.clusterInstApi.store.STMPut(stm, &ci)
			return nil
		})
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to update zone for cluster inst", "clusterinst", cikey, "err", err)
		}
	}
}

func (s *CloudletApi) updateZoneLocation(ctx context.Context, org string, oldZone, newZone string) {
	filter := edgeproto.Cloudlet{}
	filter.Key.Organization = org
	locations := map[edgeproto.ZoneKey][]dme.Loc{}
	// We need to potentially update two zones, the zone the cloudlet used to
	// be assigned to, and the new zone the cloudlet is now assigned
	err := s.cache.Show(&filter, func(cloudlet *edgeproto.Cloudlet) error {
		if cloudlet.Zone != "" && (cloudlet.Zone == oldZone || cloudlet.Zone == newZone) {
			zoneKey := cloudlet.GetZone()
			locations[*zoneKey] = append(locations[*zoneKey], cloudlet.Location)
		}
		return nil
	})
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to update zone location", "operator", org, "err", err)
	}
	for _, zoneName := range []string{oldZone, newZone} {
		zkey := edgeproto.ZoneKey{
			Name:         zoneName,
			Organization: org,
		}
		err := s.all.zoneApi.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			zone := edgeproto.Zone{}
			if !s.all.zoneApi.store.STMGet(stm, &zkey, &zone) {
				return nil
			}
			if zone.DeletePrepare {
				return nil
			}
			locs, ok := locations[zkey]
			if !ok {
				zone.Location = dme.Loc{}
			} else {
				var lat, long float64
				for _, loc := range locs {
					lat += loc.Latitude
					long += loc.Longitude
				}
				lat /= float64(len(locs))
				long /= float64(len(locs))
				zone.Location.Latitude = lat
				zone.Location.Longitude = long
			}
			s.all.zoneApi.store.STMPut(stm, &zone)
			return nil
		})
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to update zone location", "operator", org, "err", err)
		}
	}
}

func (s *CloudletApi) ChangeCloudletDNS(key *edgeproto.CloudletKey, inCb edgeproto.CloudletApi_ChangeCloudletDNSServer) (reterr error) {
	ctx := inCb.Context()
	cctx := DefCallContext()

	cloudlet := edgeproto.Cloudlet{}
	if !s.store.Get(ctx, key, &cloudlet) {
		return key.NotFoundError()
	}
	if !cloudlet.CrmOnEdge {
		return fmt.Errorf("unsupported - only cloudlets with crm on edge are currently supported")
	}

	if cloudlet.MaintenanceState != dme.MaintenanceState_UNDER_MAINTENANCE {
		return fmt.Errorf("maintenance mode is required to update DNS")
	}

	streamCb, cb := s.all.streamObjApi.newStream(ctx, cctx, key.StreamKey(), inCb)

	// Step 1 - update rootLb fqdn
	if cloudlet.RootLbFqdn == getCloudletRootLBFQDN(&cloudlet) {
		cb.Send(&edgeproto.Result{Message: "Cloudlet rootLB is already set correctly"})
		log.SpanLog(ctx, log.DebugLevelApi, "Current cloudlet fqdn already contains appDNSRoot suffix - nothing to do")
	} else {
		log.SpanLog(ctx, log.DebugLevelApi, "Update rootLB fqdn", "old", cloudlet.RootLbFqdn, "new", getCloudletRootLBFQDN(&cloudlet))
		cb.Send(&edgeproto.Result{Message: "Updating Cloudlet RootLb FQDN"})
		modRev, err := s.sync.ApplySTMWaitRev(ctx, func(stm concurrency.STM) error {
			if !s.store.STMGet(stm, key, &cloudlet) {
				// got deleted in the meantime
				return nil
			}
			// save old dns name for CCRM to update it
			cloudlet.AddAnnotation(cloudcommon.AnnotationPreviousDNSName, cloudlet.RootLbFqdn)
			cloudlet.RootLbFqdn = getCloudletRootLBFQDN(&cloudlet)
			cloudlet.State = edgeproto.TrackedState_UPDATE_REQUESTED
			cloudlet.UpdatedAt = dme.TimeToTimestamp(time.Now())
			s.store.STMPut(stm, &cloudlet)
			return nil
		})
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to update cloudlet fqdn in etcd", "err", err)
			return err
		}
		sendObj, err := s.startCloudletStream(ctx, cctx, streamCb, modRev)
		if err != nil {
			return err
		}
		defer func() {
			s.stopCloudletStream(ctx, cctx, key, sendObj, reterr, NoCleanupStream)
		}()

		// TODO - this right now only works for crm running on the cloudlet, add a handler api for ccrm case
		reqCtx, reqCancel := context.WithTimeout(ctx, s.all.settingsApi.Get().CreateCloudletTimeout.TimeDuration())
		defer reqCancel()
		successMsg := fmt.Sprintf("Cloudlet %s FQDN updated successfully", key.Name)
		if cloudlet.CrmOnEdge {
			// Wait for cloudlet to finish updating DNS entries
			err = edgeproto.WaitForCloudletInfo(
				reqCtx, key, s.all.cloudletInfoApi.store,
				dme.CloudletState_CLOUDLET_STATE_READY,
				UpdateCloudletTransitions, dme.CloudletState_CLOUDLET_STATE_ERRORS,
				successMsg, cb.Send, sendObj.crmMsgCh)
			if err != nil {
				// revert the fqdn back to the original state
				undoErr := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
					if !s.store.STMGet(stm, key, &cloudlet) {
						// got deleted in the meantime
						return nil
					}
					oldFqdn, ok := cloudlet.Annotations[cloudcommon.AnnotationPreviousDNSName]
					if !ok {
						log.SpanLog(ctx, log.DebugLevelApi, "no previous fqdn is set")
						return fmt.Errorf("no previous rootLB fqdn set for %s", cloudlet.Key.Name)
					}
					delete(cloudlet.Annotations, cloudcommon.AnnotationPreviousDNSName)
					cloudlet.RootLbFqdn = oldFqdn
					cloudlet.UpdatedAt = dme.TimeToTimestamp(time.Now())
					s.store.STMPut(stm, &cloudlet)
					return nil
				})
				if undoErr != nil {
					log.SpanLog(ctx, log.DebugLevelApi, "Failed to undo dns update", "key", key, "err", undoErr)
				}

				cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Failed to update cloudlet RootLB fqdn - %s", err.Error())})
				return err
			}
		}
	}
	// Step 2 - update all the clusterInst fqdns on this cloudlet
	ciFilter := edgeproto.ClusterInst{
		CloudletKey: *key,
	}
	clustersToUpdate := []edgeproto.ClusterInst{}
	s.all.clusterInstApi.cache.Show(&ciFilter, func(clusterInst *edgeproto.ClusterInst) error {
		log.SpanLog(ctx, log.DebugLevelApi, "Collecting clusters", "cluster", clusterInst.Key.Name)
		clustersToUpdate = append(clustersToUpdate, *clusterInst)
		return nil
	})
	cb.Send(&edgeproto.Result{Message: "Updating Cluster FQDNs"})
	for ii := range clustersToUpdate {
		err := s.all.clusterInstApi.updateRootLbFQDN(&clustersToUpdate[ii].Key, &cloudlet, inCb)
		if err != nil {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Failed to update Cluster(%s) FQDN - %s", clustersToUpdate[ii].Key.Name, err.Error())})
			return err
		}
	}

	// Step 3 - update all the appinst uris on this cluster
	aiFilter := edgeproto.AppInst{
		CloudletKey: *key,
	}
	appinstsToUpdate := []edgeproto.AppInst{}
	s.all.appInstApi.cache.Show(&aiFilter, func(appInst *edgeproto.AppInst) error {
		appinstsToUpdate = append(appinstsToUpdate, *appInst)
		return nil
	})
	cb.Send(&edgeproto.Result{Message: "Updating AppInst URIs"})
	for ii := range appinstsToUpdate {
		err := s.all.appInstApi.updateURI(&appinstsToUpdate[ii].Key, &cloudlet, inCb)
		if err != nil {
			cb.Send(&edgeproto.Result{Message: fmt.Sprintf("Failed to update AppInst(%s) URI - %s", appinstsToUpdate[ii].Key.Name, err.Error())})
		}
	}
	cb.Send(&edgeproto.Result{Message: "DNS Migration complete"})
	return nil
}

func redactAccessVars(accessVars map[string]string) map[string]string {
	vars := map[string]string{}
	for k := range accessVars {
		vars[k] = RedactedAccessVarValue
	}
	return vars
}

func canRunRefreshCerts(cloudlet *edgeproto.Cloudlet, features *edgeproto.PlatformFeatures) bool {
	// For CRM on edge, CRM runs cert refresh
	return !cloudlet.CrmOnEdge
}

func (s *CloudletApi) RefreshCerts(key *edgeproto.CloudletKey, cb edgeproto.CloudletApi_RefreshCertsServer) error {
	ctx := cb.Context()
	ptof := s.all.platformFeaturesApi.FeaturesByPlatform()

	filter := &edgeproto.Cloudlet{
		Key: *key,
	}
	cloudlets := []edgeproto.Cloudlet{}
	err := s.cache.Show(filter, func(obj *edgeproto.Cloudlet) error {
		features, ok := ptof[obj.PlatformType]
		if !ok {
			cb.Send(&edgeproto.Result{
				Message: fmt.Sprintf("%s: no features found", obj.Key.GetKeyString()),
			})
			return nil
		}
		if !canRunRefreshCerts(obj, &features) {
			cb.Send(&edgeproto.Result{
				Message: fmt.Sprintf("%s: skip CRM on edge", obj.Key.GetKeyString()),
			})
			return nil
		}
		cloudlets = append(cloudlets, *obj.Clone())
		return nil
	})
	if err != nil {
		return err
	}

	for ii := range cloudlets {
		cloudlet := &cloudlets[ii]
		features, ok := ptof[cloudlet.PlatformType]
		if !ok {
			// should not happen since we already looked it up once
			continue
		}
		conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
		if err != nil {
			cb.Send(&edgeproto.Result{
				Message: fmt.Sprintf("%s: no connection, %s", cloudlet.Key.GetKeyString(), err),
			})
			continue
		}
		api := edgeproto.NewCloudletPlatformAPIClient(conn)
		_, err = api.RefreshCerts(ctx, cloudlet)
		if err != nil {
			cb.Send(&edgeproto.Result{
				Message: fmt.Sprintf("%s: failed, %s", cloudlet.Key.GetKeyString(), err),
			})
		} else {
			cb.Send(&edgeproto.Result{
				Message: fmt.Sprintf("%s: done", cloudlet.Key.GetKeyString()),
			})
		}
	}
	return nil
}

func (s *CloudletApi) ShowCloudletGPUUsage(filter *edgeproto.Cloudlet, cb edgeproto.CloudletApi_ShowCloudletGPUUsageServer) error {
	ctx := cb.Context()
	cloudlets := []edgeproto.CloudletKey{}
	err := s.cache.Show(filter, func(obj *edgeproto.Cloudlet) error {
		cloudlets = append(cloudlets, obj.Key)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(cloudlets, func(i, j int) bool {
		return cloudlets[i].GetKeyString() < cloudlets[j].GetKeyString()
	})
	for _, ckey := range cloudlets {
		// get gpu usage information for cloudlet
		used := resspec.ResValMap{}
		limits := ResLimitMap{}
		gpuInfos := map[string]*edgeproto.GPUResource{}
		if err := s.addGPUsUsage(ctx, &ckey, used, limits, gpuInfos); err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to get gpu usage for cloudlet", "cloudlet", ckey, "err", err)
			continue
		}
		if len(gpuInfos) == 0 {
			continue
		}
		// build data to send back
		usages := []*edgeproto.GPUUsage{}
		for _, gpu := range gpuInfos {
			resKey := edgeproto.BuildResKey(cloudcommon.ResourceTypeGPU, gpu.ModelId)
			infraRes := &edgeproto.InfraResource{
				Name: gpu.ModelId,
				Type: cloudcommon.ResourceTypeGPU,
			}
			if res, ok := used[resKey]; ok {
				infraRes.Value = res.Value.Whole
			}
			if limit, ok := limits[resKey]; ok {
				infraRes.InfraMaxValue = limit.InfraMaxValue
				infraRes.QuotaMaxValue = limit.QuotaMaxValue
				infraRes.AlertThreshold = limit.AlertThreshold
			}
			gpu.Count = 0
			usage := &edgeproto.GPUUsage{
				Gpu:   gpu,
				Usage: infraRes,
			}
			usages = append(usages, usage)
		}
		sort.Slice(usages, func(i, j int) bool {
			return usages[i].Gpu.ModelId < usages[j].Gpu.ModelId
		})
		err := cb.Send(&edgeproto.CloudletGPUUsage{
			Key:  ckey,
			Gpus: usages,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *CloudletApi) addGPUsUsage(ctx context.Context, ckey *edgeproto.CloudletKey, used resspec.ResValMap, limits ResLimitMap, gpuInfos map[string]*edgeproto.GPUResource) error {
	stm := edgeproto.NewOptionalSTM(nil)
	resCalc := NewCloudletResCalc(s.all, stm, ckey)
	resCalc.options.skipLB = true
	resCalc.options.skipAdditional = true
	if err := resCalc.InitDeps(ctx); err != nil {
		return err
	}
	resCalc.addResourceLimits(ctx, limits)
	usedVals, err := resCalc.getUsedResVals(ctx)
	if err != nil {
		return err
	}
	if resCalc.deps.features.ResourceCalcByFlavorCounts {
		// gpus are not tracked individually, they are part of flavors.
		for _, flavor := range resCalc.deps.cloudletInfo.Flavors {
			resKey := edgeproto.BuildResKey(cloudcommon.ResourceTypeFlavor, flavor.Name)
			// extract used values
			flavorCount := usedVals.GetInt(resKey)
			if flavorCount > 0 {
				usedVals.AddGPUs(flavor.Gpus, uint32(flavorCount))
			}
			// extract limits
			if resLimit, ok := limits[resKey]; ok {
				for _, gpu := range flavor.Gpus {
					limits.AddMax(gpu.ModelId, cloudcommon.ResourceTypeGPU, "", uint64(resLimit.InfraMaxValue*uint64(gpu.Count)))
				}
			}
		}
	}
	used.AddAllMult(usedVals, 1)
	addCloudletGPUInfo(resCalc.deps.cloudletInfo, gpuInfos)
	return nil
}

// gets the information about which gpus are present in the cloudlet,
// ignoring the number of gpus. The returned map is keyed by the
// gpu modelID.
func addCloudletGPUInfo(info *edgeproto.CloudletInfo, gpus map[string]*edgeproto.GPUResource) {
	// on flavor-based cloudlets, gpu definitions come from the flavors
	for _, flavor := range info.Flavors {
		for _, gpu := range flavor.Gpus {
			gpus[gpu.ModelId] = gpu.Clone()
		}
	}
	// on kubernetes cloudlets, gpu definitions come from the nodes
	for _, pool := range info.NodePools {
		if pool.NodeResources == nil {
			continue
		}
		for _, gpu := range pool.NodeResources.Gpus {
			gpus[gpu.ModelId] = gpu.Clone()
		}
	}
}

func (s *CloudletApi) ShowCloudletManagedCluster(filter *edgeproto.CloudletManagedCluster, cb edgeproto.CloudletManagedClusterApi_ShowCloudletManagedClusterServer) error {
	ctx := cb.Context()

	if filter.CloudletKey.Organization == "" {
		return errors.New("cloudlet organization is required")
	}
	if filter.CloudletKey.Name == "" {
		return errors.New("cloudlet name is required")
	}
	cloudlet := edgeproto.Cloudlet{}
	if !s.all.cloudletApi.cache.Get(&filter.CloudletKey, &cloudlet) {
		return filter.CloudletKey.NotFoundError()
	}
	if cloudlet.CrmOnEdge {
		return errors.New("show cloudlet managed clusters is not supported for CRM on edge")
	}
	features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, cloudlet.PlatformType)
	if err != nil {
		return fmt.Errorf("failed to find platform features for cloudlet %s: %s", filter.CloudletKey.GetKeyString(), err)
	}
	if !features.SupportsCloudletManagedClusters {
		return fmt.Errorf("platform %s does not support cloudlet managed clusters", features.PlatformType)
	}
	conn, err := services.platformServiceConnCache.GetConn(ctx, features.NodeType)
	if err != nil {
		return err
	}
	api := edgeproto.NewCloudletPlatformAPIClient(conn)
	// Note that this returns all clusters that the cloudlet is aware of,
	// as it typically won't track which clusters were created by the
	// Edge Cloud platform vs created directly.
	outStream, err := api.GetCloudletManagedClusters(ctx, filter)
	if err == nil {
		err = cloudcommon.StreamRecv(ctx, outStream, func(obj *edgeproto.CloudletManagedCluster) error {
			return cb.Send(obj)
		})
	}
	if err != nil {
		return cloudcommon.GRPCErrorUnwrap(err)
	}
	return nil
}

func (s *CloudletApi) RegisterCloudletManagedCluster(in *edgeproto.CloudletManagedCluster, cb edgeproto.CloudletManagedClusterApi_RegisterCloudletManagedClusterServer) error {
	ctx := cb.Context()
	log.SpanLog(ctx, log.DebugLevelApi, "RegisterCloudletManagedCluster", "cluster", in)
	if in.Key.Id == "" && in.Key.Name == "" {
		return errors.New("cloudlet cluster id or name not specified")
	}
	if in.CloudletKey.Name == "" {
		return errors.New("cloudlet name must be specified")
	}
	if in.CloudletKey.Organization == "" {
		return errors.New("cloudlet organization must be specified")
	}
	// check if cluster already registered
	err := s.all.clusterInstApi.cache.Show(&edgeproto.ClusterInst{}, func(obj *edgeproto.ClusterInst) error {
		if obj.CloudletKey.Matches(&in.CloudletKey) {
			if obj.CloudletManagedClusterId == in.Key.Id {
				return fmt.Errorf("cluster with infra id %q already registered", in.Key.Id)
			}
			if obj.CloudletManagedClusterName == in.Key.Name {
				return errors.New("cluster with infra name %q already registered")
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	ci := &edgeproto.ClusterInst{}
	ci.Key = in.ClusterKey
	ci.CloudletKey = in.CloudletKey
	ci.CloudletManagedClusterId = in.Key.Id
	ci.CloudletManagedClusterName = in.Key.Name
	ci.Reservable = in.Reservable
	ci.MultiTenant = in.MultiTenant
	// for now only kubernetes supported
	ci.Deployment = cloudcommon.DeploymentTypeKubernetes
	// default cluster name to infra cluster name if not specified
	if ci.Key.Name == "" {
		ci.Key.Name = in.Key.Name
	}
	return s.all.clusterInstApi.CreateClusterInst(ci, cb)
}

func (s *CloudletApi) DeregisterCloudletManagedCluster(in *edgeproto.CloudletManagedCluster, cb edgeproto.CloudletManagedClusterApi_DeregisterCloudletManagedClusterServer) error {
	ctx := cb.Context()
	log.SpanLog(ctx, log.DebugLevelApi, "DeregisterCloudletManagedCluster", "cluster", in)
	ci := edgeproto.ClusterInst{}
	if in.ClusterKey.Name != "" && in.ClusterKey.Organization != "" {
		if !s.all.clusterInstApi.cache.Get(&in.ClusterKey, &ci) {
			return in.ClusterKey.NotFoundError()
		}
	} else if in.Key.Id != "" || in.Key.Name != "" {
		if in.CloudletKey.Name == "" {
			return errors.New("cloudlet name must be specified")
		}
		if in.CloudletKey.Organization == "" {
			return errors.New("cloudlet organization must be specified")
		}
		found := false
		err := s.all.clusterInstApi.cache.Show(&edgeproto.ClusterInst{}, func(obj *edgeproto.ClusterInst) error {
			if !obj.CloudletKey.Matches(&in.CloudletKey) {
				return nil
			}
			if obj.CloudletManagedClusterId == in.Key.Id || obj.CloudletManagedClusterName == in.Key.Name {
				ci.DeepCopyIn(obj)
				found = true
				return nil
			}
			return nil
		})
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("cloudlet managed cluster not found for infra name %q, infra id %q", in.Key.Name, in.Key.Id)
		}
	}
	return s.all.clusterInstApi.DeleteClusterInst(&ci, cb)
}
