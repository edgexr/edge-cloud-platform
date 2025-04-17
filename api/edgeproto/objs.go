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

package edgeproto

import (
	"encoding/json"
	"errors"
	fmt "fmt"
	"net"
	"sort"
	"strconv"
	strings "strings"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	context "golang.org/x/net/context"
)

var AutoScaleMaxNodes uint32 = 10

var minPort uint32 = 1
var maxPort uint32 = 65535

const (
	AppConfigHelmYaml      = "helmCustomizationYaml"
	AppAccessCustomization = "appAccessCustomization"
	AppConfigEnvYaml       = "envVarsYaml"
	AppConfigPodArgs       = "podArgs"

	GPUDriverLicenseConfig = "license.conf"
	ForceImport            = "force-import"
)

var ValidConfigKinds = map[string]struct{}{
	AppConfigHelmYaml:      {},
	AppAccessCustomization: {},
	AppConfigEnvYaml:       {},
}

var ReservedPlatformPorts = map[string]string{
	"tcp:22":    "Platform inter-node SSH",
	"tcp:20800": "Kubernetes master join server",
	"udp:53":    "dns udp",
	"tcp:53":    "dns tcp",
}

// sort each slice by key
func (a *AllData) Sort() {
	sort.Slice(a.AppInstances[:], func(i, j int) bool {
		return a.AppInstances[i].Key.GetKeyString() < a.AppInstances[j].Key.GetKeyString()
	})
	sort.Slice(a.Apps[:], func(i, j int) bool {
		return a.Apps[i].Key.GetKeyString() < a.Apps[j].Key.GetKeyString()
	})
	sort.Slice(a.Zones[:], func(i, j int) bool {
		return a.Zones[i].Key.GetKeyString() < a.Zones[j].Key.GetKeyString()
	})
	sort.Slice(a.Cloudlets[:], func(i, j int) bool {
		return a.Cloudlets[i].Key.GetKeyString() < a.Cloudlets[j].Key.GetKeyString()
	})
	sort.Slice(a.OperatorCodes[:], func(i, j int) bool {
		return a.OperatorCodes[i].GetKey().GetKeyString() < a.OperatorCodes[j].GetKey().GetKeyString()
	})
	sort.Slice(a.ClusterInsts[:], func(i, j int) bool {
		return a.ClusterInsts[i].Key.GetKeyString() < a.ClusterInsts[j].Key.GetKeyString()
	})
	for ii := range a.ClusterInsts {
		sort.Slice(a.ClusterInsts[ii].Resources.Vms, func(i, j int) bool {
			return a.ClusterInsts[ii].Resources.Vms[i].Name < a.ClusterInsts[ii].Resources.Vms[j].Name
		})
	}
	sort.Slice(a.Flavors[:], func(i, j int) bool {
		return a.Flavors[i].Key.GetKeyString() < a.Flavors[j].Key.GetKeyString()
	})
	sort.Slice(a.CloudletInfos[:], func(i, j int) bool {
		return a.CloudletInfos[i].Key.GetKeyString() < a.CloudletInfos[j].Key.GetKeyString()
	})
	for i := range a.CloudletInfos {
		sort.Slice(a.CloudletInfos[i].ResourcesSnapshot.ClusterInsts[:], func(ii, jj int) bool {
			return a.CloudletInfos[i].ResourcesSnapshot.ClusterInsts[ii].GetKeyString() < a.CloudletInfos[i].ResourcesSnapshot.ClusterInsts[jj].GetKeyString()
		})
		sort.Slice(a.CloudletInfos[i].ResourcesSnapshot.VmAppInsts[:], func(ii, jj int) bool {
			return a.CloudletInfos[i].ResourcesSnapshot.VmAppInsts[ii].GetKeyString() < a.CloudletInfos[i].ResourcesSnapshot.VmAppInsts[jj].GetKeyString()
		})
	}
	sort.Slice(a.ZonePools[:], func(i, j int) bool {
		return a.ZonePools[i].Key.GetKeyString() < a.ZonePools[j].Key.GetKeyString()
	})
	sort.Slice(a.AutoScalePolicies[:], func(i, j int) bool {
		return a.AutoScalePolicies[i].Key.GetKeyString() < a.AutoScalePolicies[j].Key.GetKeyString()
	})
	sort.Slice(a.AutoProvPolicies[:], func(i, j int) bool {
		return a.AutoProvPolicies[i].Key.GetKeyString() < a.AutoProvPolicies[j].Key.GetKeyString()
	})
	sort.Slice(a.TrustPolicies[:], func(i, j int) bool {
		return a.TrustPolicies[i].Key.GetKeyString() < a.TrustPolicies[j].Key.GetKeyString()
	})
	sort.Slice(a.AutoProvPolicyZones[:], func(i, j int) bool {
		if a.AutoProvPolicyZones[i].Key.GetKeyString() == a.AutoProvPolicyZones[j].Key.GetKeyString() {
			return a.AutoProvPolicyZones[i].ZoneKey.GetKeyString() < a.AutoProvPolicyZones[j].ZoneKey.GetKeyString()
		}
		return a.AutoProvPolicyZones[i].Key.GetKeyString() < a.AutoProvPolicyZones[j].Key.GetKeyString()
	})
	sort.Slice(a.ResTagTables[:], func(i, j int) bool {
		return a.ResTagTables[i].Key.GetKeyString() < a.ResTagTables[j].Key.GetKeyString()
	})
	sort.Slice(a.AppInstRefs[:], func(i, j int) bool {
		return a.AppInstRefs[i].Key.GetKeyString() < a.AppInstRefs[j].Key.GetKeyString()
	})
	sort.Slice(a.ClusterRefs[:], func(i, j int) bool {
		return a.ClusterRefs[i].Key.GetKeyString() < a.ClusterRefs[j].Key.GetKeyString()
	})
	for i := range a.ClusterRefs {
		sort.Slice(a.ClusterRefs[i].Apps, func(ii, jj int) bool {
			return a.ClusterRefs[i].Apps[ii].GetKeyString() < a.ClusterRefs[i].Apps[jj].GetKeyString()
		})
	}
	sort.Slice(a.VmPools[:], func(i, j int) bool {
		return a.VmPools[i].Key.GetKeyString() < a.VmPools[j].Key.GetKeyString()
	})
	sort.Slice(a.FlowRateLimitSettings[:], func(i, j int) bool {
		return a.FlowRateLimitSettings[i].Key.GetKeyString() < a.FlowRateLimitSettings[j].Key.GetKeyString()
	})
	sort.Slice(a.MaxReqsRateLimitSettings[:], func(i, j int) bool {
		return a.MaxReqsRateLimitSettings[i].Key.GetKeyString() < a.MaxReqsRateLimitSettings[j].Key.GetKeyString()
	})
	sort.Slice(a.Networks[:], func(i, j int) bool {
		return a.Networks[i].Key.GetKeyString() < a.Networks[j].Key.GetKeyString()
	})
	sort.Slice(a.GpuDrivers[:], func(i, j int) bool {
		return a.GpuDrivers[i].Key.GetKeyString() < a.GpuDrivers[j].Key.GetKeyString()
	})
	for i := range a.PlatformFeatures {
		sort.Slice(a.PlatformFeatures[i].ResourceQuotaProperties, func(ii, jj int) bool {
			return a.PlatformFeatures[i].ResourceQuotaProperties[ii].Name < a.PlatformFeatures[i].ResourceQuotaProperties[jj].Name
		})
	}
	sort.Slice(a.PlatformFeatures, func(i, j int) bool {
		return a.PlatformFeatures[i].PlatformType < a.PlatformFeatures[j].PlatformType
	})
}

func (a *SvcNodeData) Sort() {
	sort.Slice(a.Nodes[:], func(i, j int) bool {
		// ignore name for sorting because it is ignored for comparison
		ikey := a.Nodes[i].Key
		ikey.Name = ""
		jkey := a.Nodes[j].Key
		jkey.Name = ""
		if ikey.GetKeyString() == jkey.GetKeyString() {
			// In e2e-tests, one controller creates the fake
			// cloudlet, so it loads the plugin, which adds in
			// the properties. Otherwise, they keys are the same.
			// For determinism, sort by the number of properties.
			return len(a.Nodes[i].Properties) < len(a.Nodes[j].Properties)
		}
		return ikey.GetKeyString() < jkey.GetKeyString()
	})
}

func (s *DeviceData) Sort() {
	sort.Slice(s.Devices, func(i, j int) bool {
		return s.Devices[i].GetKey().GetKeyString() < s.Devices[j].GetKey().GetKeyString()
	})
}

func (s *RateLimitSettingsData) Sort() {
	sort.Slice(s.Settings, func(i, j int) bool {
		return s.Settings[i].GetKey().GetKeyString() < s.Settings[j].GetKey().GetKeyString()
	})
}

// Validate functions to validate user input

func (key *OperatorCodeKey) ValidateKey() error {
	if key.GetKeyString() == "" {
		return errors.New("No code specified")
	}
	return nil
}

func (s *OperatorCode) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	if s.Organization == "" {
		return errors.New("No organization specified")
	}
	return nil
}

func (key *ClusterKey) ValidateKey() error {
	if !util.ValidKubernetesName(key.Name) {
		return errors.New("Invalid cluster name")
	}
	if !util.ValidName(key.Organization) {
		return errors.New("Invalid cluster organization")
	}
	return nil
}

func (s *ClusterInst) Validate(fmap objstore.FieldMap) error {
	return s.GetKey().ValidateKey()
}

func (key *FlavorKey) ValidateKey() error {
	if !util.ValidName(key.Name) {
		return errors.New("Invalid flavor name")
	}
	return nil
}

func (s *Flavor) Validate(fmap objstore.FieldMap) error {
	err := s.GetKey().ValidateKey()
	if err != nil {
		return err
	}
	if fmap.Has(FlavorFieldRam) && s.Ram == 0 {
		return errors.New("Ram cannot be 0")
	}
	if fmap.Has(FlavorFieldVcpus) && s.Vcpus == 0 {
		return errors.New("Vcpus cannot be 0")
	}
	if fmap.Has(FlavorFieldDisk) && s.Disk == 0 {
		return errors.New("Disk cannot be 0")
	}
	for _, gpu := range s.Gpus {
		if gpu.Count == 0 {
			return errors.New("flavor gpu count cannot be 0")
		}
		if gpu.ModelId == "" {
			return errors.New("flavor gpu model id cannot be empty")
		}
		if gpu.Memory == 0 {
			return errors.New("flavor gpu memory cannot be 0")
		}
	}

	return nil
}

func (key *AppKey) ValidateKey() error {
	if !util.ValidName(key.Name) {
		return errors.New("Invalid app name")
	}
	if !util.ValidName(key.Version) {
		return errors.New("Invalid app version")
	}
	if !util.ValidName(key.Organization) {
		return errors.New("Invalid app organization")
	}
	return nil
}

func validateCustomizationConfigs(configs []*ConfigFile) error {
	for _, cfg := range configs {
		if _, found := ValidConfigKinds[cfg.Kind]; !found {
			return fmt.Errorf("Invalid Config Kind - %s", cfg.Kind)
		}
	}
	return nil
}

func (s *App) Validate(fmap objstore.FieldMap) error {
	var err error
	if err = s.GetKey().ValidateKey(); err != nil {
		return err
	}
	if err = s.ValidateEnums(); err != nil {
		return err
	}
	if fmap.Has(AppFieldAccessPorts) {
		if s.AccessPorts != "" {
			_, err = ParseAppPorts(s.AccessPorts)
			if err != nil {
				return err
			}
		}
	}
	if s.AuthPublicKey != "" {
		_, err = util.ValidatePublicKey(s.AuthPublicKey)
		if err != nil {
			return err
		}
	}
	if s.TemplateDelimiter != "" {
		out := strings.Split(s.TemplateDelimiter, " ")
		if len(out) != 2 {
			return fmt.Errorf("invalid app template delimiter %s, valid format '<START-DELIM> <END-DELIM>'", s.TemplateDelimiter)
		}
	}
	if err = validateCustomizationConfigs(s.Configs); err != nil {
		return err
	}
	return nil
}

func (key PlatformFeaturesKey) ValidateKey() error {
	return nil
}

func (s *PlatformFeatures) Validate(fmap objstore.FieldMap) error {
	return nil
}

func (key *GPUDriverKey) ValidateKey() error {
	if key.Organization != "" && !util.ValidName(key.Organization) {
		return errors.New("Invalid organization name")
	}
	if key.Name == "" {
		return errors.New("Missing gpu driver name")
	}
	if !util.ValidName(key.Name) {
		return errors.New("Invalid gpu driver name")
	}
	return nil
}

func (g *GPUDriverBuild) ValidateName() error {
	if g.Name == "" {
		return errors.New("Missing gpu driver build name")
	}
	if g.Name == GPUDriverLicenseConfig {
		return fmt.Errorf("%s is a reserved name and hence cannot be used as a build name", g.Name)
	}
	if !util.ValidName(g.Name) {
		return fmt.Errorf("Invalid gpu driver build name: %s", g.Name)
	}
	return nil
}

func (g *GPUDriverBuild) Validate() error {
	if err := g.ValidateName(); err != nil {
		return err
	}
	if g.DriverPath == "" {
		return fmt.Errorf("Missing driverpath")
	}
	if g.Md5Sum == "" {
		return fmt.Errorf("Missing md5sum")
	}
	if _, err := util.ImagePathParse(g.DriverPath); err != nil {
		return fmt.Errorf("Invalid driver path(%q): %v", g.DriverPath, err)
	}
	if g.DriverPathCreds != "" {
		return fmt.Errorf("Driver path creds are no longer supported, for private storage upload to the artifact registry")
	}
	if g.OperatingSystem == OSType_LINUX && g.KernelVersion == "" {
		return fmt.Errorf("Kernel version is required for Linux build")
	}
	if err := g.ValidateEnums(); err != nil {
		return err
	}
	return nil
}

func (g *GPUDriverBuildMember) Validate() error {
	if err := g.GetKey().ValidateKey(); err != nil {
		return err
	}
	if err := g.Build.Validate(); err != nil {
		return err
	}
	return nil
}

func (g *GPUDriver) Validate(fmap objstore.FieldMap) error {
	if err := g.GetKey().ValidateKey(); err != nil {
		return err
	}
	if err := g.ValidateEnums(); err != nil {
		return err
	}
	buildNames := make(map[string]struct{})
	for _, build := range g.Builds {
		if err := build.Validate(); err != nil {
			return err
		}
		if _, ok := buildNames[build.Name]; ok {
			return fmt.Errorf("GPU driver build with name %s already exists", build.Name)
		}
		buildNames[build.Name] = struct{}{}
	}
	return nil
}

func (key GPUResourceKey) ValidateKey() error {
	if string(key) == "" {
		return errors.New("Empty product name")
	}
	return nil
}

func (key *CloudletKey) ValidateKey() error {
	if !util.ValidName(key.Organization) {
		return fmt.Errorf("Invalid cloudlet organization name %s", key.Organization)
	}
	if !util.ValidName(key.Name) {
		return errors.New("Invalid cloudlet name")
	}
	return nil
}

func (s *Cloudlet) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	if fmap.Has(CloudletFieldLocationLatitude) {
		if !util.IsLatitudeValid(s.Location.Latitude) {
			return errors.New("Invalid latitude value")
		}
	}
	if fmap.Has(CloudletFieldLocationLongitude) {
		if !util.IsLongitudeValid(s.Location.Longitude) {
			return errors.New("Invalid longitude value")
		}
	}
	if fmap.Has(CloudletFieldMaintenanceState) {
		if s.MaintenanceState != dme.MaintenanceState_NORMAL_OPERATION && s.MaintenanceState != dme.MaintenanceState_MAINTENANCE_START && s.MaintenanceState != dme.MaintenanceState_MAINTENANCE_START_NO_FAILOVER {
			return errors.New("Invalid maintenance state, only normal operation and maintenance start states are allowed")
		}
	}
	if s.VmImageVersion != "" {
		if err := util.ValidateImageVersion(s.VmImageVersion); err != nil {
			return err
		}
	}
	if err := s.ValidateEnums(); err != nil {
		return err
	}

	if fmap.Has(CloudletFieldDefaultResourceAlertThreshold) {
		if s.DefaultResourceAlertThreshold < 0 || s.DefaultResourceAlertThreshold > 100 {
			return fmt.Errorf("Invalid resource alert threshold %d specified, valid threshold is in the range of 0 to 100", s.DefaultResourceAlertThreshold)

		}
	}

	for _, resQuota := range s.ResourceQuotas {
		if resQuota.AlertThreshold < 0 || resQuota.AlertThreshold > 100 {
			return fmt.Errorf("Invalid resource quota alert threshold %d specified for %s, valid threshold is in the range of 0 to 100", resQuota.AlertThreshold, resQuota.ResKeyDesc())

		}
	}

	return nil
}

func (key *ZoneKey) ValidateKey() error {
	if !util.ValidName(key.Organization) {
		return fmt.Errorf("Invalid zone organization name %s", key.Organization)
	}
	if !util.ValidName(key.Name) {
		return errors.New("Invalid zone name")
	}
	return nil
}

func (s *Zone) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	return nil
}

func (s *CloudletInfo) Validate(fmap objstore.FieldMap) error {
	return nil
}

func (s *CloudletInternal) Validate(fmap objstore.FieldMap) error {
	return nil
}

func (s *CloudletManagedClusterKey) ValidateKey() error {
	return nil
}

func (s *CloudletManagedCluster) Validate(fmap objstore.FieldMap) error {
	return nil
}

func (s CloudletNodeKey) ValidateKey() error {
	// Cloudlet nodes are only created internally
	if s.Name == "" {
		return errors.New("Name must not be empty")
	}
	return s.CloudletKey.ValidateKey()
}

func (s *CloudletNode) Validate(fmap objstore.FieldMap) error {
	if err := s.Key.ValidateKey(); err != nil {
		return err
	}
	return nil
}

func (key *ZonePoolKey) ValidateKey() error {
	if !util.ValidName(key.Organization) {
		return errors.New("Invalid zone pool organization")
	}
	if !util.ValidName(key.Name) {
		return fmt.Errorf("Invalid zone pool name")
	}
	return nil
}

func (s *ZonePool) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	return nil
}

func (s *VM) ValidateName() error {
	if s.Name == "" {
		return errors.New("Missing VM name")
	}
	if !util.ValidName(s.Name) {
		return errors.New("Invalid VM name")
	}
	return nil
}

var invalidVMPoolIPs = map[string]struct{}{
	"0.0.0.0":   struct{}{},
	"127.0.0.1": struct{}{},
}

func (s *VM) Validate() error {
	if err := s.ValidateName(); err != nil {
		return err
	}
	if s.NetInfo.ExternalIp != "" {
		if net.ParseIP(s.NetInfo.ExternalIp) == nil {
			return fmt.Errorf("Invalid Address: %s", s.NetInfo.ExternalIp)
		}
		if _, ok := invalidVMPoolIPs[s.NetInfo.ExternalIp]; ok {
			return fmt.Errorf("Invalid Address: %s", s.NetInfo.ExternalIp)
		}
	}
	if s.NetInfo.InternalIp == "" {
		return fmt.Errorf("Missing internal IP for VM: %s", s.Name)
	}
	if net.ParseIP(s.NetInfo.InternalIp) == nil {
		return fmt.Errorf("Invalid Address: %s", s.NetInfo.InternalIp)
	}
	if _, ok := invalidVMPoolIPs[s.NetInfo.InternalIp]; ok {
		return fmt.Errorf("Invalid Address: %s", s.NetInfo.ExternalIp)
	}
	return nil
}

func (key *VMPoolKey) ValidateKey() error {
	if !util.ValidName(key.Organization) {
		return errors.New("Invalid organization name")
	}
	if !util.ValidName(key.Name) {
		return errors.New("Invalid VM pool name")
	}
	return nil
}

func (s *VMPool) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	if err := s.ValidateEnums(); err != nil {
		return err
	}
	externalIPMap := make(map[string]struct{})
	internalIPMap := make(map[string]struct{})
	for _, v := range s.Vms {
		if err := v.Validate(); err != nil {
			return err
		}
		if v.NetInfo.ExternalIp != "" {
			if _, ok := externalIPMap[v.NetInfo.ExternalIp]; ok {
				return fmt.Errorf("VM with same external IP %s already exists", v.NetInfo.ExternalIp)
			}
			externalIPMap[v.NetInfo.ExternalIp] = struct{}{}
		}
		if v.NetInfo.InternalIp != "" {
			if _, ok := internalIPMap[v.NetInfo.InternalIp]; ok {
				return fmt.Errorf("VM with same internal IP %s already exists", v.NetInfo.InternalIp)
			}
			internalIPMap[v.NetInfo.InternalIp] = struct{}{}
		}
		if v.State != VMState_VM_FREE && v.State != VMState_VM_FORCE_FREE {
			return errors.New("Invalid VM state, only VmForceFree state is allowed")
		}
	}
	return nil
}

func (s *VMPoolMember) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	if err := s.Vm.Validate(); err != nil {
		return err
	}
	return nil
}

func (s *VMPoolInfo) Validate(fmap objstore.FieldMap) error {
	return nil
}

func (key *ResTagTableKey) ValidateKey() error {
	if !util.ValidName(key.Name) {
		return errors.New("Invalid ResTagTable name")
	}
	return nil
}

func (s *ResTagTable) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	return nil
}

func (key *AppInstKey) ValidateKey() error {
	if !util.ValidName(key.Name) {
		return errors.New("Invalid app instance name")
	}
	if !util.ValidName(key.Organization) {
		return errors.New("Invalid app instance organization")
	}
	return nil
}

func (s *AppInst) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	if err := validateCustomizationConfigs(s.Configs); err != nil {
		return err
	}
	return nil
}

func (s *FedAppInstKey) ValidateKey() error {
	// key never comes from external input
	return nil
}

func (s *FedAppInst) Validate(fmap objstore.FieldMap) error {
	return nil
}

func (key *ControllerKey) ValidateKey() error {
	if key.Addr == "" {
		return errors.New("Invalid address")
	}
	return nil
}

func (s *Controller) Validate(fmap objstore.FieldMap) error {
	return s.GetKey().ValidateKey()
}

func (key *SvcNodeKey) ValidateKey() error {
	if key.Name == "" {
		return errors.New("Invalid node name")
	}
	return key.CloudletKey.ValidateKey()
}

func (s *SvcNode) Validate(fmap objstore.FieldMap) error {
	return s.GetKey().ValidateKey()
}

func (key *AlertKey) ValidateKey() error {
	if len(string(*key)) == 0 {
		return errors.New("Invalid empty string AlertKey")
	}
	return nil
}

func (s *Alert) Validate(fmap objstore.FieldMap) error {
	return s.GetKey().ValidateKey()
}

func (s *AppInstInfo) Validate(fmap objstore.FieldMap) error {
	return nil
}

func (s *ClusterInstInfo) Validate(fmap objstore.FieldMap) error {
	return nil
}

func (s *CloudletRefs) Validate(fmap objstore.FieldMap) error {
	return nil
}

func (s *ClusterRefs) Validate(fmap objstore.FieldMap) error {
	return nil
}

func (s *AppInstRefs) Validate(fmap objstore.FieldMap) error {
	return nil
}

func (key *PolicyKey) ValidateKey() error {
	if err := util.ValidObjName(key.Organization); err != nil {
		errstring := err.Error()
		// lowercase the first letter of the error message
		errstring = strings.ToLower(string(errstring[0])) + errstring[1:len(errstring)]
		return fmt.Errorf("Invalid organization, " + errstring)
	}
	if key.Name == "" {
		return errors.New("Policy name cannot be empty")
	}
	return nil
}

func (s *AppInstClientKey) ValidateKey() error {
	if s.AppInstKey.Matches(&AppInstKey{}) && s.UniqueId == "" && s.UniqueIdType == "" {
		return fmt.Errorf("At least one of the key fields must be non-empty %v", s)
	}
	return nil
}

func (s *AppInstClientKey) Validate(fmap objstore.FieldMap) error {
	return s.ValidateKey()
}

func (s *AutoScalePolicy) HasV0Config() bool {
	if s.ScaleUpCpuThresh > 0 || s.ScaleDownCpuThresh > 0 {
		return true
	}
	return false
}

func (s *AutoScalePolicy) HasV1Config() bool {
	if s.TargetCpu > 0 || s.TargetMem > 0 || s.TargetActiveConnections > 0 {
		return true
	}
	return false
}

const DefaultStabilizationWindowSec = 300

// Validate fields. Note that specified fields is ignored, so this function
// must be used only in the context when all fields are present (i.e. after
// CopyInFields for an update).
func (s *AutoScalePolicy) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	if s.MaxNodes > AutoScaleMaxNodes {
		return fmt.Errorf("Max nodes cannot exceed %d", AutoScaleMaxNodes)
	}
	if s.HasV0Config() && s.HasV1Config() {
		return errors.New("The new target cpu/mem/active-connections can only be used once the old cpu threshold settings have been disabled (set to 0)")
	}
	if s.HasV0Config() {
		if s.ScaleUpCpuThresh < 0 || s.ScaleUpCpuThresh > 100 {
			return errors.New("Scale up CPU threshold must be between 0 and 100")
		}
		if s.ScaleDownCpuThresh < 0 || s.ScaleDownCpuThresh > 100 {
			return errors.New("Scale down CPU threshold must be between 0 and 100")
		}
		if s.ScaleUpCpuThresh <= s.ScaleDownCpuThresh {
			return fmt.Errorf("Scale down cpu threshold must be less than scale up cpu threshold")
		}
	} else if !s.HasV1Config() {
		return fmt.Errorf("One of target cpu or target mem or target active connections must be specified")
	} else {
		// v1 config
		if s.StabilizationWindowSec == 0 {
			s.StabilizationWindowSec = DefaultStabilizationWindowSec
		}
		if s.TargetCpu < 0 || s.TargetCpu > 100 {
			return fmt.Errorf("Target cpu must be between 0 (disabled) and 100")
		}
		if s.TargetMem < 0 || s.TargetMem > 100 {
			return fmt.Errorf("Target mem must be between 0 (disabled) and 100")
		}
		maxActiveConnections := uint64(1e12)
		if s.TargetActiveConnections < 0 || s.TargetActiveConnections > maxActiveConnections {
			return fmt.Errorf("Target active connections must be between 0 (disabled) and %d", maxActiveConnections)
		}
	}
	if s.MaxNodes <= s.MinNodes {
		return fmt.Errorf("Max nodes must be greater than Min nodes")
	}
	return nil
}

func (s *AutoProvPolicy) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	if s.MinActiveInstances > s.MaxInstances && s.MaxInstances != 0 {
		return fmt.Errorf("Minimum active instances cannot be larger than Maximum Instances")
	}
	if s.MinActiveInstances == 0 && s.DeployClientCount == 0 {
		return fmt.Errorf("One of deploy client count and minimum active instances must be specified")
	}
	return nil
}

func (s *AutoProvInfo) Validate(fmap objstore.FieldMap) error {
	return nil
}

func ValidateSecurityRules(rules []SecurityRule) error {
	for _, r := range rules {
		if r.Protocol != "TCP" && r.Protocol != "UDP" && r.Protocol != "ICMP" {
			return fmt.Errorf("Protocol must be one of: (TCP,UDP,ICMP)")
		}
		if r.Protocol == "ICMP" {
			if r.PortRangeMin != 0 || r.PortRangeMax != 0 {
				return fmt.Errorf("Port range must be empty for ICMP")
			}
		} else {
			log.DebugLog(log.DebugLevelInfra, "ValidateSecurityRules()", "rule", r)
			if r.PortRangeMin < minPort || r.PortRangeMin > maxPort {
				return fmt.Errorf("Invalid min port: %d", r.PortRangeMin)
			}
			if r.PortRangeMax > maxPort {
				return fmt.Errorf("Invalid max port: %d", r.PortRangeMax)
			}
			if r.PortRangeMin > r.PortRangeMax {
				return fmt.Errorf("Min port range: %d cannot be higher than max: %d", r.PortRangeMin, r.PortRangeMax)
			}
		}
		_, _, err := net.ParseCIDR(r.RemoteCidr)
		if err != nil {
			return err
		}
	}
	return nil
}

// Always valid
func (s *DeviceReport) Validate(fmap objstore.FieldMap) error {
	return nil
}

func (key *DeviceKey) ValidateKey() error {
	if key.UniqueId == "" || key.UniqueIdType == "" {
		return errors.New("Device id cannot be empty")
	}
	return nil
}
func (s *Device) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	// TODO - we might want to validate timestamp in the future
	return nil
}

func (key *NetworkKey) ValidateKey() error {
	if err := key.CloudletKey.ValidateKey(); err != nil {
		return err
	}
	if !util.ValidName(key.Name) {
		return errors.New("Invalid network name")
	}
	return nil
}
func (s *Network) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	if s.ConnectionType == NetworkConnectionType_UNDEFINED {
		return errors.New("Invalid connection type")
	}
	for _, route := range s.Routes {
		_, _, err := net.ParseCIDR(route.DestinationCidr)
		if err != nil {
			return errors.New("Invalid route destination cidr")
		}
		ip := net.ParseIP(route.NextHopIp)
		if ip == nil {
			return errors.New("Invalid next hop")
		}
	}
	return nil
}

// AddTagFunc is used to collect tags and values
type AddTagFunc = func(key, value string)

// TagMap implements AddTagFunc
type TagMap map[string]string

func (s TagMap) AddTag(key, value string) {
	s[key] = value
}

func (m *Metric) AddTag(name string, val string) {
	tag := MetricTag{Name: name, Val: val}
	m.Tags = append(m.Tags, &tag)
}

func (m *Metric) AddKeyTags(key objstore.ObjKey) {
	for name, val := range key.GetTags() {
		m.AddTag(name, val)
	}
}

func (m *Metric) AddDoubleVal(name string, dval float64) {
	val := MetricVal{Name: name}
	val.Value = &MetricVal_Dval{Dval: dval}
	m.Vals = append(m.Vals, &val)
}

func (m *Metric) AddIntVal(name string, ival uint64) {
	val := MetricVal{Name: name}
	val.Value = &MetricVal_Ival{Ival: ival}
	m.Vals = append(m.Vals, &val)
}

func (m *Metric) AddBoolVal(name string, bval bool) {
	val := MetricVal{Name: name}
	val.Value = &MetricVal_Bval{Bval: bval}
	m.Vals = append(m.Vals, &val)
}

func (m *Metric) AddStringVal(name string, sval string) {
	val := MetricVal{Name: name}
	val.Value = &MetricVal_Sval{Sval: sval}
	m.Vals = append(m.Vals, &val)
}

func (m *MetricVal) MarshalJSON() ([]byte, error) {
	mv := MetricValJSONRaw{}
	val := map[string]interface{}{}

	// override default behavior of omitting value, otherwise
	// we can't tell what value type it is on unmarshal
	switch v := m.Value.(type) {
	case *MetricVal_Dval:
		val["dval"] = v.Dval
	case *MetricVal_Ival:
		val["ival"] = v.Ival
	case *MetricVal_Bval:
		val["bval"] = v.Bval
	case *MetricVal_Sval:
		val["sval"] = v.Sval
	default:
		return nil, fmt.Errorf("unhandled value type in MetricVal,%v", v)
	}
	mv.Name = m.Name
	valout, err := json.Marshal(val)
	if err != nil {
		return nil, err
	}
	mv.Value = valout
	return json.Marshal(mv)
}

type MetricValJSONRaw struct {
	Name  string `json:"name,omitempty"`
	Value json.RawMessage
}

func (m *MetricVal) UnmarshalJSON(b []byte) error {
	mv := MetricValJSONRaw{}
	err := json.Unmarshal(b, &mv)
	if err != nil {
		return err
	}
	m.Name = mv.Name
	if strings.HasPrefix(string(mv.Value), `{"dval"`) {
		m.Value = &MetricVal_Dval{}
	} else if strings.HasPrefix(string(mv.Value), `{"ival"`) {
		m.Value = &MetricVal_Ival{}
	} else if strings.HasPrefix(string(mv.Value), `{"bval"`) {
		m.Value = &MetricVal_Bval{}
	} else if strings.HasPrefix(string(mv.Value), `{"sval"`) {
		m.Value = &MetricVal_Sval{}
	} else {
		return fmt.Errorf("unmarshal MetricVal unable to determine value type from %s", string(mv.Value))
	}
	return json.Unmarshal(mv.Value, m.Value)
}

func GetLProto(s string) (dme.LProto, error) {
	s = strings.ToLower(s)
	switch s {
	case "tcp":
		return dme.LProto_L_PROTO_TCP, nil
	case "udp":
		return dme.LProto_L_PROTO_UDP, nil
	case "http":
		return dme.LProto_L_PROTO_HTTP, nil
	}
	return 0, fmt.Errorf("Unsupported protocol: %s", s)
}

func LProtoStr(proto dme.LProto) (string, error) {
	switch proto {
	case dme.LProto_L_PROTO_TCP:
		return "tcp", nil
	case dme.LProto_L_PROTO_UDP:
		return "udp", nil
	case dme.LProto_L_PROTO_HTTP:
		return "http", nil
	}
	return "", fmt.Errorf("Invalid proto %d", proto)
}

func L4ProtoStr(proto dme.LProto) (string, error) {
	switch proto {
	case dme.LProto_L_PROTO_TCP:
		return "tcp", nil
	case dme.LProto_L_PROTO_UDP:
		return "udp", nil
	case dme.LProto_L_PROTO_HTTP:
		return "http", nil
	}
	return "", fmt.Errorf("Invalid proto %d", proto)
}

func (s *InstPort) IsHTTP() bool {
	return s.Proto == dme.LProto_L_PROTO_HTTP
}

func (s *AppInst) UsesHTTP() bool {
	for _, p := range s.MappedPorts {
		if p.IsHTTP() {
			return true
		}
	}
	return false
}

func AppPortLookupKey(ap *InstPort) string {
	protoStr, _ := LProtoStr(ap.Proto)
	return fmt.Sprintf("%s%d", protoStr, ap.InternalPort)
}

// ProtoPortToString ensures consistent formatting
func ProtoPortToString(proto string, port int32) string {
	return fmt.Sprintf("%s:%d", strings.ToLower(proto), port)
}

func AppInternalPortToString(port *InstPort) (string, error) {
	lproto, err := LProtoStr(port.Proto)
	if err != nil {
		return "", err
	}
	return ProtoPortToString(lproto, port.InternalPort), nil
}

func ParseAppPorts(ports string) ([]InstPort, error) {
	appports := make([]InstPort, 0)
	if ports == "" {
		return appports, nil
	}

	portSpecs, err := util.ParsePorts(ports)
	if err != nil {
		return nil, err
	}

	var proto dme.LProto
	var baseport int64
	var endport int64

	for _, portSpec := range portSpecs {
		proto, err = GetLProto(portSpec.Proto)
		if err != nil {
			return nil, err
		}
		baseport, err = strconv.ParseInt(portSpec.Port, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("unable to convert port range base value")
		}
		endport, err = strconv.ParseInt(portSpec.EndPort, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("unable to convert port range end value")
		}

		// loop through to verify we are not using a platform reserved port
		lastPort := endport
		if lastPort == 0 {
			lastPort = baseport
		}
		for pnum := baseport; pnum <= lastPort; pnum++ {
			pstring := fmt.Sprintf("%s:%d", strings.ToLower(portSpec.Proto), pnum)
			desc, reserved := ReservedPlatformPorts[pstring]
			if reserved {
				return nil, fmt.Errorf("App cannot use port %s - reserved for %s", pstring, desc)
			}
		}

		p := InstPort{
			Proto:           proto,
			InternalPort:    int32(baseport),
			EndPort:         int32(endport),
			Tls:             portSpec.Tls,
			Nginx:           portSpec.Nginx,
			MaxPktSize:      portSpec.MaxPktSize,
			InternalVisOnly: portSpec.InternalVisOnly,
			Id:              portSpec.ID,
			PathPrefix:      portSpec.PathPrefix,
			ServiceName:     portSpec.ServiceName,
		}

		appports = append(appports, p)
	}
	return appports, nil
}

func DoPortsOverlap(a, b InstPort, skipHTTP bool) bool {
	// if platform uses ingress, all HTTP ports map to the
	// ingress controller so there is no conflict.
	// Otherwise, if ingress is not used, we treat HTTP ports
	// as if they are TCP ports.
	aProto := a.Proto
	bProto := b.Proto
	if a.Proto == dme.LProto_L_PROTO_HTTP {
		if skipHTTP {
			return false
		}
		aProto = dme.LProto_L_PROTO_TCP
	}
	if b.Proto == dme.LProto_L_PROTO_HTTP {
		if skipHTTP {
			return false
		}
		bProto = dme.LProto_L_PROTO_TCP
	}
	lastPortA := a.EndPort
	if lastPortA == 0 {
		lastPortA = a.InternalPort
	}
	lastPortB := b.EndPort
	if lastPortB == 0 {
		lastPortB = b.InternalPort
	}
	if aProto != bProto ||
		a.InternalPort > lastPortB ||
		lastPortA < b.InternalPort {
		// no overlap
		return false
	}
	return true
}

func CmpSortDebugReply(a DebugReply, b DebugReply) bool {
	// e2e tests ignore Name for comparison, so name cannot
	// be used to sort.
	aKey := a.Node
	aKey.Name = ""
	bKey := b.Node
	bKey.Name = ""
	return aKey.GetKeyString() < bKey.GetKeyString()
}

func CmpSortFlavorInfo(a *FlavorInfo, b *FlavorInfo) bool {
	return a.Name < b.Name
}

func IgnoreTaggedFields(taglist string) []cmp.Option {
	opts := []cmp.Option{}
	opts = append(opts, IgnoreAppFields(taglist))
	opts = append(opts, IgnoreAppInstFields(taglist))
	opts = append(opts, IgnoreAppInstInfoFields(taglist))
	opts = append(opts, IgnoreClusterInstFields(taglist))
	opts = append(opts, IgnoreClusterInstInfoFields(taglist))
	opts = append(opts, IgnoreCloudletFields(taglist))
	opts = append(opts, IgnoreCloudletInfoFields(taglist))
	opts = append(opts, IgnoreSvcNodeFields(taglist))
	return opts
}

func CmpSortSlices() []cmp.Option {
	opts := []cmp.Option{}
	opts = append(opts, cmpopts.SortSlices(CmpSortApp))
	opts = append(opts, cmpopts.SortSlices(CmpSortAppInst))
	opts = append(opts, cmpopts.SortSlices(CmpSortZone))
	opts = append(opts, cmpopts.SortSlices(CmpSortCloudlet))
	opts = append(opts, cmpopts.SortSlices(CmpSortOperatorCode))
	opts = append(opts, cmpopts.SortSlices(CmpSortClusterInst))
	opts = append(opts, cmpopts.SortSlices(CmpSortFlavor))
	opts = append(opts, cmpopts.SortSlices(CmpSortCloudletInfo))
	opts = append(opts, cmpopts.SortSlices(CmpSortFlavorInfo))
	opts = append(opts, cmpopts.SortSlices(CmpSortAppInstInfo))
	opts = append(opts, cmpopts.SortSlices(CmpSortClusterInstInfo))
	opts = append(opts, cmpopts.SortSlices(CmpSortSvcNode))
	opts = append(opts, cmpopts.SortSlices(CmpSortZonePool))
	opts = append(opts, cmpopts.SortSlices(CmpSortZonePoolMember))
	opts = append(opts, cmpopts.SortSlices(CmpSortAutoScalePolicy))
	opts = append(opts, cmpopts.SortSlices(CmpSortResTagTable))
	opts = append(opts, cmpopts.SortSlices(CmpSortAppInstRefs))
	opts = append(opts, cmpopts.SortSlices(CmpSortClusterRefs))
	return opts
}

var OrganizationPlatos = "platos"
var OrganizationEdgeCloud = "edgecloudorg"
var OrganizationEdgeCloudOld = "openXedge"
var OrganizationEdgeCloudOlder = "MobiledgeX"
var OrganizationEdgeBox = "EdgeBox"

func IsEdgeCloudOrg(s string) bool {
	// support backwards compatibility for old name
	return s == OrganizationEdgeCloud || s == OrganizationEdgeCloudOld || s == OrganizationEdgeCloudOlder
}

func IsEdgeCloudOrgLC(s string) bool {
	s = strings.ToLower(s)
	// support backwards compatibility for old name
	return s == strings.ToLower(OrganizationEdgeCloud) || s == strings.ToLower(OrganizationEdgeCloudOld) || s == strings.ToLower(OrganizationEdgeCloudOlder)
}

func GetOrg(obj interface{}) string {
	switch v := obj.(type) {
	case *OperatorCode:
		return v.Organization
	case *Cloudlet:
		return v.Key.Organization
	case *ClusterInst:
		return v.Key.Organization
	case *App:
		return v.Key.Organization
	case *AppInst:
		return v.Key.Organization
	default:
		return OrganizationEdgeCloud
	}
}

func GetTags(obj interface{}) map[string]string {
	switch v := obj.(type) {
	case objstore.Obj:
		return v.GetObjKey().GetTags()
	case objstore.ObjKey:
		return v.GetTags()
	default:
		return map[string]string{}
	}
}

func (c *ClusterInstCache) UsesOrg(org string) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for _, cd := range c.Objs {
		val := cd.Obj
		if val.Key.Organization == org || val.CloudletKey.Organization == org || (val.Reservable && val.ReservedBy == org) {
			return true
		}
	}
	return false
}

func (c *CloudletInfoCache) WaitForCloudletState(ctx context.Context, key *CloudletKey, targetState dme.CloudletState, timeout time.Duration) error {
	curState := dme.CloudletState_CLOUDLET_STATE_UNKNOWN
	done := make(chan bool, 1)

	checkState := func(key *CloudletKey) {
		info := CloudletInfo{}
		if c.Get(key, &info) {
			curState = info.State
		}
		if curState == targetState {
			done <- true
		}
	}

	cancel := c.WatchKey(key, func(ctx context.Context) {
		checkState(key)
	})
	defer cancel()

	// After setting up watch, check current state,
	// as it may have already changed to target state.
	checkState(key)

	select {
	case <-done:
	case <-time.After(timeout):
		return fmt.Errorf("Timed out; expected state %s buf is %s",
			dme.CloudletState_CamelName[int32(targetState)],
			dme.CloudletState_CamelName[int32(curState)])
	}
	return nil
}

func (s *App) GetAutoProvPolicies() map[string]struct{} {
	policies := make(map[string]struct{})
	if s.AutoProvPolicy != "" {
		policies[s.AutoProvPolicy] = struct{}{}
	}
	for _, name := range s.AutoProvPolicies {
		policies[name] = struct{}{}
	}
	return policies
}

func (s *App) GetAutoProvPolicys() map[PolicyKey]struct{} {
	policies := make(map[PolicyKey]struct{})
	if s.AutoProvPolicy != "" {
		key := PolicyKey{
			Name:         s.AutoProvPolicy,
			Organization: s.Key.Organization,
		}
		policies[key] = struct{}{}
	}
	for _, name := range s.AutoProvPolicies {
		key := PolicyKey{
			Name:         name,
			Organization: s.Key.Organization,
		}
		policies[key] = struct{}{}
	}
	return policies
}

func (s *AutoProvPolicy) GetZoneKeys() map[ZoneKey]struct{} {
	keys := make(map[ZoneKey]struct{})
	for _, key := range s.Zones {
		keys[*key] = struct{}{}
	}
	return keys
}

func (s *ZonePool) GetZoneKeys() map[ZoneKey]struct{} {
	keys := make(map[ZoneKey]struct{})
	for _, key := range s.Zones {
		keys[*key] = struct{}{}
	}
	return keys
}

func (s *ZoneKey) IsSet() bool {
	return s.Name != "" || s.Organization != "" || s.FederatedOrganization != ""
}

func (s *Cloudlet) GetZone() *ZoneKey {
	if s.Zone == "" {
		return &ZoneKey{}
	}
	key := ZoneKey{
		Name:                  s.Zone,
		Organization:          s.Key.Organization,
		FederatedOrganization: s.Key.FederatedOrganization,
	}
	return &key
}

func (s *AppInst) GetClusterKey() *ClusterKey {
	return &s.ClusterKey
}

// For backwards compatibility with the old virtual cluster name,
// gets the virtual cluster if it's an older AppInst, or the real
// cluster if no virtual or newer AppInst
func (s *AppInst) VClusterKey() ClusterKey {
	if s.VirtualClusterKey.Name != "" {
		return s.VirtualClusterKey
	}
	return s.ClusterKey
}

func (r *InfraResources) UpdateResources(inRes *InfraResources) (updated bool) {
	if inRes == nil || len(inRes.Vms) == 0 {
		return false
	}
	if len(r.Vms) != len(inRes.Vms) {
		return true
	}
	vmStatusMap := make(map[string]string)
	for _, vmInfo := range r.Vms {
		vmStatusMap[vmInfo.Name] = vmInfo.Status
	}
	for _, vmInfo := range inRes.Vms {
		status, ok := vmStatusMap[vmInfo.Name]
		if !ok {
			return true
		}
		if status != vmInfo.Status {
			return true
		}
	}
	return false
}

func (key *AlertPolicyKey) ValidateKey() error {
	if !util.ValidName(key.Name) {
		return errors.New("Invalid alert policy name")
	}
	if !util.ValidName(key.Organization) {
		return errors.New("Invalid alert policy organization")
	}
	return nil
}

func (a *AlertPolicy) Validate(fmap objstore.FieldMap) error {
	if err := a.GetKey().ValidateKey(); err != nil {
		return err
	}
	// Since active connections and other metrics are part
	// of different instances of Prometheus, disallow mixing them
	if a.ActiveConnLimit != 0 {
		if a.CpuUtilizationLimit != 0 || a.MemUtilizationLimit != 0 || a.DiskUtilizationLimit != 0 {
			return errors.New("Active Connection Alerts should not include any other triggers")
		}
	}
	// at least one of the values for alert should be set
	if a.ActiveConnLimit == 0 && a.CpuUtilizationLimit == 0 &&
		a.MemUtilizationLimit == 0 && a.DiskUtilizationLimit == 0 {
		return errors.New("At least one of the measurements for alert should be set")
	}
	// check CPU to be within 0-100 percent
	if a.CpuUtilizationLimit > 100 {
		return errors.New("Cpu utilization limit is percent. Valid values 1-100%")
	}
	// check Memory to be within 0-100 percent
	if a.MemUtilizationLimit > 100 {
		return errors.New("Memory utilization limit is percent. Valid values 1-100%")
	}
	// check Disk to be within 0-100 percent
	if a.DiskUtilizationLimit > 100 {
		return errors.New("Disk utilization limit is percent. Valid values 1-100%")
	}
	// reasonable max trigger time check - should not be >24h
	if a.TriggerTime > Duration(72*time.Hour) {
		return errors.New("Trigger duration should not exceed 72 hours")
	}
	return nil
}

// Check if AlertPolicies are different between two apps
func (app *App) AppAlertPoliciesDifferent(other *App) bool {
	alertsDiff := false
	if len(app.AlertPolicies) != len(other.AlertPolicies) {
		alertsDiff = true
	} else {
		oldAlerts := make(map[string]struct{})
		for _, alert := range app.AlertPolicies {
			oldAlerts[alert] = struct{}{}
		}
		for _, alert := range other.AlertPolicies {
			if _, found := oldAlerts[alert]; !found {
				alertsDiff = true
				break
			}
		}
	}
	return alertsDiff
}

func (s *TrustPolicy) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelInfra, "ValidateSecurityRules()", "TrustPolicy:", s.GetKey().Name)
	return ValidateSecurityRules(s.OutboundSecurityRules)
}

func (key *TrustPolicyExceptionKey) ValidateKey() error {
	if err := key.AppKey.ValidateKey(); err != nil {
		errstring := err.Error()
		return fmt.Errorf("Invalid AppKey in TrustPolicyExceptionKey, " + errstring)
	}
	if err := key.ZonePoolKey.ValidateKey(); err != nil {
		errstring := err.Error()
		return fmt.Errorf("Invalid ZonePoolKey in TrustPolicyExceptionKey, " + errstring)
	}
	if key.Name == "" {
		return fmt.Errorf("TrustPolicyException name cannot be empty")
	}
	return nil
}

func (s *TrustPolicyException) Validate(fmap objstore.FieldMap) error {
	if err := s.GetKey().ValidateKey(); err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelInfra, "ValidateSecurityRules()", "TrustPolicyException:", s.GetKey().Name)
	if len(s.OutboundSecurityRules) == 0 {
		return fmt.Errorf("Security rules must be specified")
	}
	return ValidateSecurityRules(s.OutboundSecurityRules)
}

func (s *TPEInstanceKey) ValidateKey() error {
	return nil
}

func (s *TPEInstanceState) Validate(fmap objstore.FieldMap) error {
	return nil
}

func fixupSecurityRules(ctx context.Context, rules []SecurityRule) {
	// port range max is optional, set it to min if min is present but not max
	for i, o := range rules {
		if o.PortRangeMax == 0 {
			log.SpanLog(ctx, log.DebugLevelApi, "Setting PortRangeMax equal to min", "PortRangeMin", o.PortRangeMin)
			rules[i].PortRangeMax = o.PortRangeMin
		}
		rules[i].Protocol = strings.ToUpper(o.Protocol)
	}
}
func (s *TrustPolicy) FixupSecurityRules(ctx context.Context) {
	fixupSecurityRules(ctx, s.OutboundSecurityRules)
}

func (s *TrustPolicyException) FixupSecurityRules(ctx context.Context) {
	fixupSecurityRules(ctx, s.OutboundSecurityRules)
}

func (s *App) FixupSecurityRules(ctx context.Context) {
	fixupSecurityRules(ctx, s.RequiredOutboundConnections)
}

// AllSelector registers selected strings, or all if none specified.
type AllSelector map[string]struct{}

func (s AllSelector) Select(str string) {
	s[str] = struct{}{}
}

func (s AllSelector) Has(str string) bool {
	if len(s) == 0 {
		// none selected, select all
		return true
	}
	_, found := s[str]
	return found
}

func (s AllSelector) HasExplicit(str string) bool {
	_, found := s[str]
	return found
}

// For tracking App + Zone
type AppZoneKeyPair struct {
	AppKey  AppKey
	ZoneKey ZoneKey
}

func (s *AppInst) GetTags() map[string]string {
	tags := make(map[string]string)
	s.AddTags(tags)
	return tags
}

func (s *AppInst) AddTags(tags map[string]string) {
	s.Key.AddTags(tags)
	s.AppKey.AddTags(tags)
	s.ClusterKey.AddTags(tags)
	s.CloudletKey.AddTags(tags)
	s.ZoneKey.AddTags(tags)
}

func (s *ClusterInst) GetTags() map[string]string {
	tags := make(map[string]string)
	s.AddTags(tags)
	return tags
}

func (s *ClusterInst) AddTags(tags map[string]string) {
	s.Key.AddTags(tags)
	s.CloudletKey.AddTags(tags)
	s.ZoneKey.AddTags(tags)
}

func (s *AppInst) AddAnnotationNoClobber(key, val string) bool {
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	if _, ok := s.Annotations[key]; ok {
		return false
	}
	s.Annotations[key] = val
	return true
}

func (s *ClusterInst) AddAnnotationNoClobber(key, val string) bool {
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	if _, ok := s.Annotations[key]; ok {
		return false
	}
	s.Annotations[key] = val
	return true
}

func (s *Cloudlet) AddAnnotationNoClobber(key, val string) bool {
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	if _, ok := s.Annotations[key]; ok {
		return false
	}
	s.Annotations[key] = val
	return true
}

func (s *AppInst) AddAnnotation(key, val string) bool {
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	s.Annotations[key] = val
	return true
}

func (s *ClusterInst) AddAnnotation(key, val string) bool {
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	s.Annotations[key] = val
	return true
}

func (s *Cloudlet) AddAnnotation(key, val string) bool {
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	s.Annotations[key] = val
	return true
}

type OrgName string

func (s OrgName) Matches(o OrgName) bool {
	// organization names are case insensitive
	return strings.EqualFold(string(s), string(o))
}

func (s *ClusterInst) IsCloudletManaged() bool {
	return s.CloudletManagedClusterId != "" || s.CloudletManagedClusterName != ""
}
