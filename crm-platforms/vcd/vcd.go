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

package vcd

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/edgexr/edge-cloud-infra/vmlayer"

	"github.com/vmware/go-vcloud-director/v2/govcd"

	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

type Refresh bool

var DoRefresh Refresh = true
var NoRefresh Refresh = false

// Note regarding govcd SDK:
// Most all types in govcd are arranged as a containerized type in govcd that compose Client and
// specific methods, with the business end of the type in types.go. example found in vdc.go:
//
//   type Vdc struct {
//  	  Vdc    *types.Vdc
//	  client *Client
//   }
//
// The method calls are accessed via the "outer" govcd.Vdc object utilizing the client object, and operate on
// the 'inner' types.Vdc object.
//
var vcdProviderVersion = "-0.1-alpha"
var VCDVdcCtxKey = "VCDVdcCtxKey"

type VcdPlatform struct {
	vmProperties *vmlayer.VMProperties
	vcdVars      map[string]string
	caches       *platform.Caches
	Creds        *VcdConfigParams
	TestMode     bool
	Verbose      bool
}

var DefaultClientRefreshInterval uint64 = 7 * 60 * 60 // 7 hours
var VCDOrgCtxKey = "VCDOrgCtxKey"

type VcdConfigParams struct {
	User                  string
	Password              string
	Org                   string
	VcdApiUrl             string
	VDC                   string
	Insecure              bool
	OauthSgwUrl           string
	OauthAgwUrl           string
	OauthClientId         string
	OauthClientSecret     string
	ClientTlsKey          string
	ClientTlsCert         string
	ClientRefreshInterval uint64
	TestToken             string
}

type VAppMap map[string]*govcd.VApp
type VMMap map[string]*govcd.VM
type NetMap map[string]*govcd.OrgVDCNetwork

func (v *VcdPlatform) InitProvider(ctx context.Context, caches *platform.Caches, stage vmlayer.ProviderInitStage, updateCallback edgeproto.CacheUpdateCallback) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider for Vcd", "stage", stage)
	v.Verbose = v.GetVcdVerbose()
	v.InitData(ctx, caches)

	switch stage {
	case vmlayer.ProviderInitPlatformStartCrmConditional:
		// note on CRM startup the Oauth Init is done in ActiveChanged
		var err error
		mexInternalNetRange, err = v.getMexInternalNetRange(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider NetRange failed", "stage", stage, "err", err)
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider", "mexInternalNetRange", mexInternalNetRange)

		log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider update isonet metadata", "stage", stage)
		err = v.UpdateLegacyIsoNetMetaData(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider UpdateLegacyIsoNetMetaData failed", "error", err)
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider DisableRuntimeLeases", "stage", stage)
		overrideLeaseDisable := v.GetLeaseOverride()
		if !overrideLeaseDisable {
			err := v.DisableOrgRuntimeLease(ctx, overrideLeaseDisable)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "InitProvider DisableOrgRuntimeLease failed", "stage", stage, "override", overrideLeaseDisable, "error", err)
				return err
			}
		}

	case vmlayer.ProviderInitCreateCloudletDirect:
		fallthrough
	case vmlayer.ProviderInitDeleteCloudlet:
		// update the token but no refresh needed
		if v.GetVcdOauthSgwUrl() != "" {
			err := v.UpdateOauthToken(ctx, v.Creds)
			if err != nil {
				return fmt.Errorf("UpdateOauthToken failed - %v", err)
			}
		}
	case vmlayer.ProviderInitPlatformStartShepherd:
		if v.GetVcdOauthSgwUrl() != "" {
			err := v.WaitForOauthTokenViaNotify(ctx, v.vmProperties.CommonPf.PlatformConfig.CloudletKey)
			if err != nil {
				return err
			}
		}
	}
	v.initDebug(v.vmProperties.CommonPf.PlatformConfig.NodeMgr, stage)
	return nil
}

func (v *VcdPlatform) ActiveChanged(ctx context.Context, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChanged")
	// update the oauth token and start refresh but do nothing else
	if v.GetVcdOauthSgwUrl() != "" {
		err := v.UpdateOauthToken(ctx, v.Creds)
		if err != nil {
			return fmt.Errorf("UpdateOauthToken failed - %v", err)
		}
		go v.RefreshOauthTokenPeriodic(ctx, v.Creds)
	}
	return nil
}

func (v *VcdPlatform) InitData(ctx context.Context, caches *platform.Caches) {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitData caches set")
	v.caches = caches
}

func (o *VcdPlatform) GetFeatures() *platform.Features {
	return &platform.Features{
		SupportsMultiTenantCluster:            true,
		SupportsSharedVolume:                  true,
		SupportsTrustPolicy:                   true,
		SupportsImageTypeOVF:                  true,
		SupportsAdditionalNetworks:            true,
		SupportsPlatformHighAvailabilityOnK8s: true,
	}
}

func (v *VcdPlatform) GetResourceID(ctx context.Context, resourceType vmlayer.ResourceType, resourceName string) (string, error) {

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return "", fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		fmt.Printf("GetVdc failed: %s\n", err.Error())
		return "", err
	}
	// VM, Subnet and SecGrp are the current potential values of Type
	// The only one we have so far is VMs, (subnets soon, and secGrps eventually)
	if resourceType == vmlayer.ResourceTypeVM {
		vm, err := v.FindVMByName(ctx, resourceName, vcdClient, vdc)
		if err != nil {
			return "", fmt.Errorf("resource %s not found", resourceName)
		}
		return vm.VM.ID, nil
	} else if resourceType == vmlayer.ResourceTypeSecurityGroup {
		// Get the security Group ID for default XXX
		return "1234", nil
	}
	return "", fmt.Errorf("GetResourceID not implemented for resource type: %s name %s", resourceType, resourceName)
}

// check server ready without cloudlets
//
// CheckServerReady
func (v VcdPlatform) CheckServerReady(ctx context.Context, client ssh.Client, serverName string) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "CheckServerReady", "serverName", serverName)
	detail, err := v.GetServerDetail(ctx, serverName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CheckServerReady GetServerDetail", "err", err)
		return err
	}
	out := ""
	if detail.Status == vmlayer.ServerActive {
		out, err = client.Output("systemctl status mobiledgex.service")
		log.SpanLog(ctx, log.DebugLevelInfra, "CheckServerReady Mobiledgex service status", "serverName", serverName, "out", out, "err", err)
		return nil
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "CheckServerReady Mobiledgex service status (recovered) ", "serverName", serverName, "out", out, "err", err)
		return fmt.Errorf("Server %s status: %s", serverName, detail.Status)
	}
}

// Retrieve our top level Org object. Tries to retrieve the org from context first, if the org is not
// in context then uses the APIs to retrieve it
func (v *VcdPlatform) GetOrg(ctx context.Context, vcdClient *govcd.VCDClient) (*govcd.Org, error) {
	// try to get from context first
	org, found := ctx.Value(VCDOrgCtxKey).(*govcd.Org)
	if found {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetOrg found org in context")
		return org, nil
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetOrg org not in context, doing API query")

	org, err := vcdClient.GetOrgByName(v.Creds.Org)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetOrgByName failed", "org", v.Creds.Org, "err", err)
		return nil, fmt.Errorf("GetOrgByName error %s", err.Error())
	}
	return org, nil
}

// GetVdcFromContext gets tries to get the VDC from context, otherwise it calls GetVdc to get via APIs
func (v *VcdPlatform) GetVdcFromContext(ctx context.Context, vcdClient *govcd.VCDClient) (*govcd.Vdc, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVdcFromContext")

	vdc, found := ctx.Value(VCDVdcCtxKey).(*govcd.Vdc)
	if found {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetVdc found vdc in context")
		return vdc, nil
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVdc vdc not in context, doing API query")
	return v.GetVdc(ctx, vcdClient)
}

// Retrieve our refreshed vdc object via APIs
func (v *VcdPlatform) GetVdc(ctx context.Context, vcdClient *govcd.VCDClient) (*govcd.Vdc, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVdc")

	org, err := v.GetOrg(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetVdc GetOrg return error", "vdc", v.Creds.VDC, "org", v.Creds.Org, "err", err)
		return nil, err
	}
	vdc, err := org.GetVDCByName(v.Creds.VDC, false)
	if err != nil {
		return nil, err
	}
	return vdc, err
}

func (v *VcdPlatform) GetConsoleUrl(ctx context.Context, serverName string) (string, error) {
	return "", fmt.Errorf("VM Console not supported for VCD")
}

func (v *VcdPlatform) ImportImage(ctx context.Context, folder, imageFile string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ImportImage", "imageFile", imageFile, "folder", folder)

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	// first delete anything that may be there for this image
	v.DeleteImage(ctx, folder, imageFile)
	// .ova's are the unit of upload to our catalog (but could be an ovf + vmdk)
	cat, err := v.GetCatalog(ctx, v.GetCatalogName(), vcdClient)
	if err != nil {
		return err
	}
	// ovaFile, itemName, description, uploadPieceSize xxx is folder appropriate for itemName?
	cat.UploadOvf(imageFile, folder+"-tmpl", "mex base iamge", 4*1024)
	return nil
}

// Assuming Vcd is more similar to Vsphere rather than vmPool or OpenStack
// alphanumeric plus -_. first char must be alpha, <= 255 chars.
func (v *VcdPlatform) NameSanitize(name string) string {
	r := strings.NewReplacer(
		" ", "",
		"&", "",
		",", "",
		"/", "_",
		"!", "")
	str := r.Replace(name)
	if str == "" {
		return str
	}
	if !unicode.IsLetter(rune(str[0])) {
		// first character must be alpha
		str = "a" + str
	}
	if len(str) > 255 {
		str = str[:254]
	}
	return str
}

// IdSanitize is NameSanitize plus removing "."
func (v *VcdPlatform) IdSanitize(name string) string {
	str := v.NameSanitize(name)
	str = strings.ReplaceAll(str, ".", "-")
	return str
}

func (v *VcdPlatform) GetServerDetail(ctx context.Context, serverName string) (*vmlayer.ServerDetail, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetail", "serverName", serverName)

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return nil, fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return nil, fmt.Errorf("GetVdcFailed - %v", err)
	}
	return v.GetServerDetailWithVdc(ctx, serverName, vdc, vcdClient)
}

func (v *VcdPlatform) GetVmStatus(ctx context.Context, vm *govcd.VM, refresh Refresh) (string, error) {
	if refresh == DoRefresh {
		return vm.GetStatus()
	} else {
		return types.VAppStatuses[vm.VM.Status], nil
	}
}
func (v *VcdPlatform) GetServerDetailWithVdc(ctx context.Context, serverName string, vdc *govcd.Vdc, vcdClient *govcd.VCDClient) (*vmlayer.ServerDetail, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetailWithVdc", "serverName", serverName)

	vm, err := v.FindVMByName(ctx, serverName, vcdClient, vdc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetail not found", "vmname", serverName)
		return nil, fmt.Errorf(vmlayer.ServerDoesNotExistError)
	}
	detail := vmlayer.ServerDetail{}
	detail.Name = vm.VM.Name
	detail.ID = vm.VM.ID
	vmStatus := types.VAppStatuses[vm.VM.Status]

	if vmStatus == "POWERED_ON" {
		detail.Status = vmlayer.ServerActive
	} else if vmStatus == "POWERED_OFF" {
		detail.Status = vmlayer.ServerShutoff
	} else {
		detail.Status = vmStatus
	}

	addresses, err := v.GetVMAddresses(ctx, vm, vcdClient, vdc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetail err getting VMAddresses for", "vmname", serverName, "err", err)
		return nil, err
	}
	detail.Addresses = addresses
	return &detail, nil
}

func (v *VcdPlatform) GetApiEndpointAddr(ctx context.Context) (string, error) {

	url := v.GetVcdUrl()
	log.SpanLog(ctx, log.DebugLevelInfra, "GetApiEndpointAddr", "Href", url)
	return url, nil
}

func (v *VcdPlatform) GetVappServerSuffix() string {
	return "-vapp"
}

// VCD does not yet actually support download/upload of images, but the common image suffix is provided here so it
// can be validated when this is implemented
func (v *VcdPlatform) GetCloudletImageSuffix(ctx context.Context) string {
	return ".qcow2"
}

func (v *VcdPlatform) GetCloudletManifest(ctx context.Context, name, cloudletImagePath string, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletManifest", "name", name, "imagePath", cloudletImagePath)
	return "", nil
}

func (v *VcdPlatform) GetSessionTokens(ctx context.Context, vaultConfig *vault.Config, account string) (map[string]string, error) {
	return nil, fmt.Errorf("GetSessionTokens not supported in VcdPlatform")
}

func (v *VcdPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("SaveCloudletAccessVars not implemented for vcd")
}

func (v *VcdPlatform) DisableOrgRuntimeLease(ctx context.Context, override bool) error {
	var err error
	log.SpanLog(ctx, log.DebugLevelInfra, "DisableOrgRuntimeLease", "override", override)

	vcdClient := v.GetVcdClientFromContext(ctx)

	if vcdClient == nil {
		// Too early for context
		vcdClient, err = v.GetClient(ctx, v.Creds)
		if err != nil {
			return fmt.Errorf("Failed to get VCD Client: %v", err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Obtained client directly continuing")
	}

	org, err := v.GetOrg(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DisableOrgRuntimeLease failed to retrive org", "error", err)
		return err
	}
	adminOrg, err := govcd.GetAdminOrgByName(vcdClient, org.Org.Name)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DisableOrgRuntimeLease failed to retrive adminOrg", "error", err)
		if override {
			log.SpanLog(ctx, log.DebugLevelInfra, "DisableOrgRuntimeLease failed to retrive adminOrg override on continuing with Org leases per VCD provider", "error", err)
			return nil
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "DisableOrgRuntimeLease failed to retrive adminOrg override off:  fatal", "error", err)
			return err
		}
	}
	adminOrg.AdminOrg.OrgSettings.OrgVAppLeaseSettings.DeploymentLeaseSeconds = TakeIntPointer(0)
	task, err := adminOrg.Update()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DisableOrgRuntimeLease org.Update failed", "error", err)
		return err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DisableOrgRuntimeLease wait org.Update failed", "error", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DisableOrgRuntimeLease disabled lease", "settings",
		adminOrg.AdminOrg.OrgSettings.OrgVAppLeaseSettings)
	return nil
}

func (v *VcdPlatform) InternalCloudletUpdatedCallback(ctx context.Context, old *edgeproto.CloudletInternal, new *edgeproto.CloudletInternal) {
	log.SpanLog(ctx, log.DebugLevelInfra, "InternalCloudletUpdatedCallback")

	token, ok := new.Props[vmlayer.CloudletAccessToken]
	if ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "stored new cloudlet access token")
		v.vmProperties.CloudletAccessToken = token
	}
	if token == "" {
		// if an empty token is received, this means CRM lost the token and so shepherd no longer has a valid token.
		// any futher API calls are blocked until a valid token is present.
		log.SpanLog(ctx, log.DebugLevelInfra, "Empty token received from CRM")

	}
}

func (v *VcdPlatform) GetGPUSetupStage(ctx context.Context) vmlayer.GPUSetupStage {
	return vmlayer.AppInstStage
}
