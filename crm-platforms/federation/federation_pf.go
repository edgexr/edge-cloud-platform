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

package federation

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/mc/federation"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/redundancy"
	"github.com/edgexr/edge-cloud/cloudcommon"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
	yaml "github.com/mobiledgex/yaml/v2"
	v1 "k8s.io/api/core/v1"
)

const (
	AppDeploymentTimeout = 20 * time.Minute
)

// NOTE: This object is shared by all FRM-based cloudlets and hence it can't
//       hold fields just for a specific cloudlet
type FederationPlatform struct {
	fedClient *federation.FederationClient
	caches    *platform.Caches
	commonPf  *infracommon.CommonPlatform
}

// GetVersionProperties returns properties related to the platform version
func (f *FederationPlatform) GetVersionProperties() map[string]string {
	return map[string]string{}
}

// Get platform features
func (f *FederationPlatform) GetFeatures() *platform.Features {
	return &platform.Features{
		SupportsKubernetesOnly:        true,
		KubernetesRequiresWorkerNodes: true,
	}
}

// Get federation config for cloudlet
func (f *FederationPlatform) GetFederationConfig(ctx context.Context, cloudletKey *edgeproto.CloudletKey) (*edgeproto.FederationConfig, error) {
	cloudlet := edgeproto.Cloudlet{}
	if !f.caches.CloudletCache.Get(cloudletKey, &cloudlet) {
		return nil, fmt.Errorf("Cloudlet not found in cache %s", cloudletKey.String())
	}
	if cloudlet.FederationConfig.FederationName == "" {
		return nil, fmt.Errorf("Unable to find federation config for %s", cloudletKey.String())
	}
	return &cloudlet.FederationConfig, nil
}

// Init is called once during FRM startup.
func (f *FederationPlatform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	client, err := federation.NewClient(platformConfig.AccessApi)
	if err != nil {
		return err
	}
	f.fedClient = client
	f.caches = caches
	f.commonPf = &infracommon.CommonPlatform{
		PlatformConfig: platformConfig,
	}
	return nil
}

// InitHAConditional is optional init steps for the active unit, if applicable
func (f *FederationPlatform) InitHAConditional(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (f *FederationPlatform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "federation-1.0"
}

// Gather information about the cloudlet platform.
// This includes available resources, flavors, etc.
// Returns true if sync with controller is required
func (f *FederationPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return nil
}

// Create a Kubernetes Cluster on the cloudlet.
func (f *FederationPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	return nil
}

// Delete a Kuberentes Cluster on the cloudlet.
func (f *FederationPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Update the cluster
func (f *FederationPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Get resources used by the cloudlet
func (f *FederationPlatform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	return &edgeproto.InfraResourcesSnapshot{}, nil
}

// Get cluster additional resources used by the vms specific to the platform
func (f *FederationPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	return nil
}

// Get Cloudlet Resource Properties
func (f *FederationPlatform) GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletResourceQuotaProps")

	return &edgeproto.CloudletResourceQuotaProps{}, nil
}

// Get cluster additional resource metric
func (f *FederationPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

// Get resources used by the cluster
func (f *FederationPlatform) GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error) {
	return &edgeproto.InfraResources{}, nil
}

// TODO: Following will be removed once the partner operator
//       does the required changes
// XXX === Start of changes ===
const (
	AppArtifactIdKey        = "APP_ARTIFACT_ID"
	AppResourceProfileIdKey = "APP_RESOURCE_PROFILE_ID"
	AppManagementAPIVersion = "APP_MANAGEMENT_API_VERSION"

	DefaultAppArtifactId           = "ART-0001"
	DefaultAppResourceProfileId    = "c5.2xlarge"
	DefaultAppManagementAPIVersion = "v2"
)

// Federation config for App deployment
type AppFederationConfig struct {
	ArtifactId        string
	ResourceProfileId string
	ClientId          string
}

func GetAppFederationConfigs(ctx context.Context, appId string, fedAddr *string, cfgs []*edgeproto.ConfigFile) (*AppFederationConfig, error) {
	artifactId := DefaultAppArtifactId
	resourceProfileId := DefaultAppResourceProfileId
	appMgmtApiVers := DefaultAppManagementAPIVersion
	var appVars []v1.EnvVar
	for _, v := range cfgs {
		if v.Kind == edgeproto.AppConfigEnvYaml {
			err := yaml.Unmarshal([]byte(v.Config), &appVars)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cannot unmarshal app config env var",
					"appId", appId, "kind", v.Kind, "config", v.Config, "error", err)
				return nil, fmt.Errorf("cannot unmarshal app config env vars: %s,  %v", v.Config, err)
			}
			for _, appVar := range appVars {
				switch appVar.Name {
				case AppArtifactIdKey:
					artifactId = appVar.Value
				case AppResourceProfileIdKey:
					resourceProfileId = appVar.Value
				case AppManagementAPIVersion:
					appMgmtApiVers = appVar.Value
				}
			}
		}
	}

	if appMgmtApiVers != "" {
		urlParts, err := url.Parse(*fedAddr)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to parse federation addr", "addr", *fedAddr, "err", err)
			// ignore
		} else {
			urlParts.Path = "/" + appMgmtApiVers
			*fedAddr = urlParts.String()
			log.SpanLog(ctx, log.DebugLevelInfra, "new app mgmt federation addr", "newAddr", *fedAddr)
		}
	}

	outCfg := AppFederationConfig{
		ArtifactId:        artifactId,
		ResourceProfileId: resourceProfileId,
		ClientId:          "dummy",
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "app federation config", "appId", appId, "config", outCfg, "fedAddr", *fedAddr)
	return &outCfg, nil
}

// XXX === End of changes ===

// Create an appInst on a cluster
func (f *FederationPlatform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	if app.Deployment != cloudcommon.DeploymentTypeKubernetes {
		return fmt.Errorf("Only kubernetes based applications are supported on federation cloudlets")
	}
	fedConfig, err := f.GetFederationConfig(ctx, &appInst.ClusterInstKey().CloudletKey)
	if err != nil {
		return err
	}
	revision := log.SpanTraceID(ctx)
	appRegion := federation.AppRegion{
		Country:  fedConfig.ZoneCountryCode,
		Zone:     appInst.Key.ClusterInstKey.CloudletKey.Name,
		Operator: appInst.Key.ClusterInstKey.CloudletKey.FederatedOrganization,
	}
	appId := appInst.DnsLabel

	// TODO: These are hardcoded for now as the partner operator has not implemented
	//       the required functionality for this. For customization, fetch config from
	//       app.Configs
	appCfg, err := GetAppFederationConfigs(ctx, appId, &fedConfig.PartnerFederationAddr, app.Configs)
	if err != nil {
		return err
	}

	exposedIntfs := []federation.AppExposedInterface{}
	for _, port := range appInst.MappedPorts {
		proto, err := edgeproto.L4ProtoStr(port.Proto)
		if err != nil {
			return err
		}
		portStart := port.InternalPort
		portEnd := port.EndPort
		if portEnd == 0 {
			portEnd = portStart
		}
		for portVal := portStart; portVal <= portEnd; portVal++ {
			intf := federation.AppExposedInterface{
				InterfaceType: federation.AppInterfaceType_NETWORK,
				Port:          fmt.Sprintf("%d", portVal),
				Protocol:      strings.ToUpper(proto),
				Visibility:    federation.AppInterfaceVisibility_EXTERNAL,
			}
			exposedIntfs = append(exposedIntfs, intf)
		}
	}

	// App Onboarding
	updateCallback(edgeproto.UpdateTask, "Initiate application onboarding")
	appObReq := federation.AppOnboardingRequest{
		RequestId:           revision,
		LeadOperatorId:      appInst.Key.ClusterInstKey.CloudletKey.Organization,
		LeadFederationId:    fedConfig.SelfFederationId,
		PartnerFederationId: fedConfig.PartnerFederationId,
		AppId:               appId,
		AppType:             federation.AppType_SERVER,
		ArtifactId:          appCfg.ArtifactId,
		AppName:             app.Key.Name,
		Provisioning:        federation.AppProvisioningState_ENABLED,
		Regions:             []federation.AppRegion{appRegion},
		Specification: federation.AppSpec{
			ComponentDetails: []federation.AppComponentDetail{
				federation.AppComponentDetail{
					Components: []federation.AppComponent{
						federation.AppComponent{
							VirtualizationMode: federation.VirtualizationType_KUBERNETES,
							ComponentSource: federation.AppComponentSource{
								Repo:        cloudcommon.DeploymentTypeDocker,
								CodeArchive: "true",
								Path:        app.ImagePath,
							},
							ExposedInterfaces: exposedIntfs,
							ComputeResourceRequirements: federation.AppComputeResourceRequirement{
								ResourceProfileId: appCfg.ResourceProfileId,
							},
						},
					},
				},
			},
		},
	}
	err = f.fedClient.SendRequest(ctx, "POST",
		fedConfig.PartnerFederationAddr, fedConfig.FederationName,
		federation.APIKeyFromVault, federation.OperatorAppOnboardingAPI,
		&appObReq, nil)
	if err != nil {
		return err
	}

	// Wait for app to be onboarded
	updateCallback(edgeproto.UpdateTask, "Waiting for application to be onboarded")
	start := time.Now()
	appDeplStatusReq := federation.AppDeploymentStatusRequest{
		RequestId:           revision,
		AppId:               appId,
		Operator:            appInst.Key.ClusterInstKey.CloudletKey.FederatedOrganization,
		Country:             fedConfig.ZoneCountryCode,
		LeadFederationId:    fedConfig.SelfFederationId,
		PartnerFederationId: fedConfig.PartnerFederationId,
	}
	deplStatusReqArgs, err := cloudcommon.GetQueryArgsFromObj(appDeplStatusReq)
	if err != nil {
		return err
	}
	for {
		time.Sleep(10 * time.Second)

		// Fetch onboarding status
		appObStatusResp := federation.AppOnboardingStatusResponse{}
		err = f.fedClient.SendRequest(ctx, "GET",
			fedConfig.PartnerFederationAddr, fedConfig.FederationName,
			federation.APIKeyFromVault, federation.OperatorAppOnboardingAPI+"?"+deplStatusReqArgs,
			nil, &appObStatusResp)
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "App onboarding status received", "appId", appId, "response", appObStatusResp)
		if len(appObStatusResp.OnboardStatus) == 0 {
			return fmt.Errorf("Invalid response obj for status %v", appObStatusResp)
		}

		switch appObStatusResp.OnboardStatus[0].Status {
		case federation.OnboardingState_ONBOARDED:
			log.SpanLog(ctx, log.DebugLevelInfra, "App onboarded successfully", "appId", appId)
			break
		case federation.OnboardingState_PENDING:
			elapsed := time.Since(start)
			if elapsed >= AppDeploymentTimeout {
				// this should not happen and indicates that onboarding is stuck for some reason
				log.SpanLog(ctx, log.DebugLevelInfra, "App onboarding taking too long", "appId", appId, "elasped time", elapsed)
				return fmt.Errorf("App onboarding taking too long")
			}
			continue
		case federation.OnboardingState_FAILED:
			log.SpanLog(ctx, log.DebugLevelInfra, "App onboarding failed", "appId", appId)
			return fmt.Errorf("App onboarding failed")
		default:
			log.SpanLog(ctx, log.DebugLevelInfra, "Unexpected app onboarding status", "appId", appId, "status", appObStatusResp.OnboardStatus[0].Status)
			return fmt.Errorf("App onboarding unexpected status: %s", appObStatusResp.OnboardStatus[0].Status)
		}
		break
	}
	updateCallback(edgeproto.UpdateTask, "Application onboarded successfully")

	// App provisioning
	updateCallback(edgeproto.UpdateTask, "Initiate application provisioning")
	appProvReq := federation.AppProvisionRequest{
		RequestId:           revision,
		LeadOperatorId:      appInst.Key.ClusterInstKey.CloudletKey.Organization,
		LeadFederationId:    fedConfig.SelfFederationId,
		PartnerFederationId: fedConfig.PartnerFederationId,
		AppProvData: federation.AppProvisionData{
			AppId:    appId,
			Version:  app.Key.Version,
			Region:   appRegion,
			ClientId: appCfg.ClientId,
		},
	}
	err = f.fedClient.SendRequest(ctx, "POST",
		fedConfig.PartnerFederationAddr, fedConfig.FederationName,
		federation.APIKeyFromVault, federation.OperatorAppProvisionAPI,
		&appProvReq, nil)
	if err != nil {
		return err
	}

	// Wait for app provision status to be ready
	updateCallback(edgeproto.UpdateTask, "Waiting for application to be provisioned")
	start = time.Now()
	for {
		time.Sleep(10 * time.Second)

		// Fetch provisioning status
		appProvStatusResp := federation.AppProvisioningStatusResponse{}
		err = f.fedClient.SendRequest(ctx, "GET",
			fedConfig.PartnerFederationAddr, fedConfig.FederationName,
			federation.APIKeyFromVault, federation.OperatorAppProvisionStatusAPI+"?"+deplStatusReqArgs,
			nil, &appProvStatusResp)
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "App provisioning status received", "appId", appId, "response", appProvStatusResp)

		switch appProvStatusResp.Status {
		case federation.ProvisioningState_SUCCESS:
			updateCallback(edgeproto.UpdateTask, "Application provisioned successfully")
			if len(appProvStatusResp.AccessEndPoints.Microservices) == 0 {
				return fmt.Errorf("Unable to find any access endpoints for the provisioned app %s", appId)
			}
			ms := appProvStatusResp.AccessEndPoints.Microservices[0]
			if len(ms.HTTPBindings) == 0 {
				return fmt.Errorf("Unable to find any HTTP bindings for the provisioned app %s", appId)
			}

			if ms.HTTPBindings[0].Endpoint == "" || ms.HTTPBindings[0].Endpoint == "0.0.0.0" {
				return fmt.Errorf("Unable to find any endpoint IP for the provisioned app %s", appId)
			}
			updateCallback(edgeproto.UpdateTask, "Setting up DNS entry for app endpoint")
			fqdn := appInst.Uri
			externalAddr := ms.HTTPBindings[0].Endpoint
			log.SpanLog(ctx, log.DebugLevelInfra, "Setting up DNS entry for appinst", "appId", appId, "fqdn", fqdn, "externalAddr", externalAddr)
			err = f.commonPf.ActivateFQDNA(ctx, fqdn, externalAddr)
			if err != nil {
				return err
			}
			break
		case federation.ProvisioningState_PENDING:
			elapsed := time.Since(start)
			if elapsed >= AppDeploymentTimeout {
				// this should not happen and indicates that provisioning is stuck for some reason
				log.SpanLog(ctx, log.DebugLevelInfra, "App provisioning taking too long", "appId", appId, "elasped time", elapsed)
				return fmt.Errorf("App provisioning taking too long")
			}
			continue
		case federation.ProvisioningState_FAILED:
			log.SpanLog(ctx, log.DebugLevelInfra, "App provisioning failed", "appId", appId)
			return fmt.Errorf("App provisioning failed")
		default:
			log.SpanLog(ctx, log.DebugLevelInfra, "Unexpected app provisioning status", "appId", appId, "status", appProvStatusResp.Status)
			return fmt.Errorf("App provisioning unexpected status: %s", appProvStatusResp.Status)
		}
		break
	}
	return nil
}

// Delete an AppInst on a Cluster
func (f *FederationPlatform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	fedConfig, err := f.GetFederationConfig(ctx, &appInst.ClusterInstKey().CloudletKey)
	if err != nil {
		return err
	}
	revision := log.SpanTraceID(ctx)
	appId := appInst.DnsLabel
	appRegion := federation.AppRegion{
		Country:  fedConfig.ZoneCountryCode,
		Zone:     appInst.Key.ClusterInstKey.CloudletKey.Name,
		Operator: appInst.Key.ClusterInstKey.CloudletKey.FederatedOrganization,
	}

	// TODO: These are hardcoded for now as the partner operator has not implemented
	//       the required functionality for this. For customization, fetch config from
	//       app.Configs
	_, err = GetAppFederationConfigs(ctx, appId, &fedConfig.PartnerFederationAddr, app.Configs)
	if err != nil {
		return err
	}

	// App deprovisioning
	updateCallback(edgeproto.UpdateTask, "Initiate application deprovisioning")
	appDeprovReq := federation.AppDeprovisionRequest{
		RequestId:           revision,
		LeadFederationId:    fedConfig.SelfFederationId,
		PartnerFederationId: fedConfig.PartnerFederationId,
		AppDeprovData: federation.AppDeprovisionData{
			AppId:   appId,
			Version: app.Key.Version,
			Region:  appRegion,
		},
	}
	err = f.fedClient.SendRequest(ctx, "DELETE",
		fedConfig.PartnerFederationAddr, fedConfig.FederationName,
		federation.APIKeyFromVault, federation.OperatorAppProvisionAPI,
		&appDeprovReq, nil)
	if err != nil {
		return err
	}

	updateCallback(edgeproto.UpdateTask, "Waiting for application to be deprovisioned")
	// TODO: API to fetch deprovisioning status is yet to be implemented
	time.Sleep(1 * time.Minute)

	// App deboarding
	updateCallback(edgeproto.UpdateTask, "Initiate application deboarding")
	appDelReq := federation.AppDeboardingRequest{
		RequestId:           revision,
		AppId:               appId,
		Version:             app.Key.Version,
		LeadOperatorId:      appInst.Key.ClusterInstKey.CloudletKey.FederatedOrganization,
		LeadOperatorCountry: fedConfig.ZoneCountryCode,
		LeadFederationId:    fedConfig.SelfFederationId,
		PartnerFederationId: fedConfig.PartnerFederationId,
		Zone:                appInst.Key.ClusterInstKey.CloudletKey.Name,
	}
	delReq, err := cloudcommon.GetQueryArgsFromObj(appDelReq)
	if err != nil {
		return err
	}
	err = f.fedClient.SendRequest(ctx, "DELETE",
		fedConfig.PartnerFederationAddr, fedConfig.FederationName,
		federation.APIKeyFromVault, federation.OperatorAppOnboardingAPI+"?"+delReq,
		nil, nil)
	if err != nil {
		return err
	}

	updateCallback(edgeproto.UpdateTask, "Waiting for application to be deboarded")
	// TODO: API to fetch deboarding status is yet to be implemented
	time.Sleep(1 * time.Minute)

	updateCallback(edgeproto.UpdateTask, "Cleaning up DNS entry for app endpoint")
	log.SpanLog(ctx, log.DebugLevelInfra, "Cleaning up DNS for appinst", "appId", appId, "fqdn", appInst.Uri)
	err = f.commonPf.DeleteDNSRecords(ctx, appInst.Uri)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to cleanup DNS entry for app", "appId", appId, "fqdn", appInst.Uri, "err", err)
	}

	return nil
}

// Update an AppInst
func (f *FederationPlatform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Get AppInst runtime information
func (f *FederationPlatform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	return &edgeproto.AppInstRuntime{}, nil
}

// Get the client to manage the ClusterInst
func (f *FederationPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return nil, nil
}

// Get the client to manage the specified platform management node
func (f *FederationPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return nil, nil
}

// List the cloudlet management nodes used by this platform
func (f *FederationPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return nil, nil
}

// Get the command to pass to PlatformClient for the container command
func (f *FederationPlatform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return "", nil
}

// Get the console URL of the VM app
func (f *FederationPlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	return "", nil
}

// Set power state of the AppInst
func (f *FederationPlatform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Create Cloudlet returns cloudletResourcesCreated, error
func (f *FederationPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	// nothing to be done
	return false, nil
}

func (f *FederationPlatform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Delete Cloudlet
func (f *FederationPlatform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Save Cloudlet AccessVars
func (f *FederationPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Delete Cloudlet AccessVars
func (f *FederationPlatform) DeleteCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Sync data with controller
func (f *FederationPlatform) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	return nil
}

// Get Cloudlet Manifest Config
func (f *FederationPlatform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	return &edgeproto.CloudletManifest{}, nil
}

// Verify VM
func (f *FederationPlatform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	return nil
}

// Get Cloudlet Properties
func (f *FederationPlatform) GetCloudletProps(ctx context.Context) (*edgeproto.CloudletProps, error) {
	return &edgeproto.CloudletProps{}, nil
}

// Platform-sepcific access data lookup (only called from Controller context)
func (f *FederationPlatform) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	return nil, nil
}

// Update the cloudlet's Trust Policy
func (f *FederationPlatform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	return nil
}

//  Create and Update TrustPolicyException
func (f *FederationPlatform) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterInstKey *edgeproto.ClusterInstKey) error {
	return nil
}

// Delete TrustPolicyException
func (f *FederationPlatform) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterInstKey *edgeproto.ClusterInstKey) error {
	return nil
}

// Get restricted cloudlet create status
func (f *FederationPlatform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Get ssh clients of all root LBs
func (f *FederationPlatform) GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	return nil, nil
}

// Get RootLB Flavor
func (f *FederationPlatform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &edgeproto.Flavor{}, nil
}

func (k *FederationPlatform) ActiveChanged(ctx context.Context, platformActive bool) error {
	return nil
}

func (k *FederationPlatform) NameSanitize(name string) string {
	return name
}
