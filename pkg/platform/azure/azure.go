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

package azure

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/managedk8s"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
)

const AzureMaxResourceGroupNameLen int = 80

type AzurePlatform struct {
	properties *infracommon.InfraProperties
	accessVars map[string]string
	creds      *azidentity.DefaultAzureCredential
}

type AZName struct {
	LocalizedValue string
	Value          string
}

type AZLimit struct {
	CurrentValue string
	Limit        string
	LocalName    string
	Name         AZName
}

type AZFlavor struct {
	Disk  int
	Name  string
	RAM   int
	VCPUs int
}

func NewPlatform() platform.Platform {
	return &managedk8s.ManagedK8sPlatform{
		Provider: &AzurePlatform{},
	}
}

func (o *AzurePlatform) Init(accessVars map[string]string, properties *infracommon.InfraProperties, commonPf *infracommon.CommonPlatform, caches *platform.Caches) error {
	o.accessVars = accessVars
	o.properties = properties
	return nil
}

func (o *AzurePlatform) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:                  platform.PlatformTypeAzure,
		SupportsMultiTenantCluster:    true,
		SupportsKubernetesOnly:        true,
		KubernetesRequiresWorkerNodes: true,
		IpAllocatedPerService:         true,
		ManagesK8SControlNodes:        true,
		AccessVars:                    AccessVarProps,
		Properties:                    azureProps,
		ResourceQuotaProperties:       cloudcommon.CommonResourceQuotaProps,
		RequiresCrmOffEdge:            true,
	}
}

func (a *AzurePlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	location := a.GetAzureLocation()
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo", "location", location, "resourceGroup", a.accessVars[AZURE_RESOURCE_GROUP])
	if err := a.Login(ctx); err != nil {
		return err
	}
	subscriptionID := a.accessVars[AZURE_SUBSCRIPTION_ID]
	clientFactory, err := armcompute.NewClientFactory(subscriptionID, a.creds, nil)
	if err != nil {
		return err
	}

	usagePager := clientFactory.NewUsageClient().NewListPager(location, nil)
	for usagePager.More() {
		page, err := usagePager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, v := range page.Value {
			if v.CurrentValue == nil || v.Limit == nil || v.Name == nil || v.Name.LocalizedValue == nil {
				continue
			}
			if *v.Name.LocalizedValue == "Total Regional vCPUs" {
				vcpus := uint64(*v.Limit)
				info.OsMaxVcores = uint64(vcpus)
				info.OsMaxRam = uint64(4 * vcpus)
				info.OsMaxVolGb = uint64(500 * vcpus)
				break
			}
		}
		if info.OsMaxVcores > 0 {
			break
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "got limits", "location", location, "vcpus", info.OsMaxVcores)

	// We will not support all Azure flavors, only selected ones:
	// https://azure.microsoft.com/en-in/pricing/details/virtual-machines/series/
	skuPager := clientFactory.NewResourceSKUsClient().NewListPager(&armcompute.ResourceSKUsClientListOptions{
		Filter: to.Ptr("location eq '" + location + "'"),
	})
	for skuPager.More() {
		page, err := skuPager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, v := range page.Value {
			if v.ResourceType == nil || v.Name == nil || v.Family == nil {
				continue
			}
			if *v.ResourceType != "virtualMachines" {
				continue
			}
			fmt.Printf("name: %s, family: %s\n", *v.Name, *v.Family)
			// we only allow standard DSv3 sizes and NC GPUs
			// newer v4/v5 DS sizes have no local storage by default.
			if *v.Family != "standardDSv3Family" && *v.Family != "standardAv2Family" && !strings.HasPrefix(*v.Name, "Standard_NC") && !strings.HasPrefix(*v.Name, "Standard_NV") {
				continue
			}
			if *v.Family == "standardNVSv2Family" {
				// seems to be retired, no info about it
				continue
			}

			flavor := &edgeproto.FlavorInfo{
				Name: *v.Name,
			}
			for _, cap := range v.Capabilities {
				if cap.Name == nil || cap.Value == nil {
					continue
				}
				if *cap.Name == "vCPUs" {
					num, err := strconv.ParseUint(*cap.Value, 10, 64)
					if err != nil {
						return fmt.Errorf("failed to parse %s value %s for flavor %s, %s", *cap.Name, *cap.Value, *v.Name, err)
					}
					flavor.Vcpus = num
				}
				if *cap.Name == "MemoryGB" {
					num, err := strconv.ParseFloat(*cap.Value, 64)
					if err != nil {
						return fmt.Errorf("failed to parse %s value %s for flavor %s, %s", *cap.Name, *cap.Value, *v.Name, err)
					}
					flavor.Ram = uint64(1024 * num)
				}
				if *cap.Name == "MaxResourceVolumeMB" {
					num, err := strconv.ParseUint(*cap.Value, 10, 64)
					if err != nil {
						return fmt.Errorf("failed to parse %s value %s for flavor %s, %s", *cap.Name, *cap.Value, *v.Name, err)
					}
					flavor.Disk = uint64(num / 1023)
				}
				if *cap.Name == "GPUs" {
					num, err := strconv.ParseUint(*cap.Value, 10, 64)
					if err != nil {
						return fmt.Errorf("failed to parse %s value %s for flavor %s, %s", *cap.Name, *cap.Value, *v.Name, err)
					}
					// See https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/overview?tabs=breakdownseries%2Cgeneralsizelist%2Ccomputesizelist%2Cmemorysizelist%2Cstoragesizelist%2Cgpusizelist%2Cfpgasizelist%2Chpcsizelist#gpu-accelerated
					modelID := "unknown-gpu"
					memory := uint64(0)
					vendor := ""
					if *v.Family == "standardNCSv3Family" {
						modelID = "NVIDIA-K80"
						vendor = cloudcommon.GPUVendorNVIDIA
						memory = 24
					} else if *v.Family == "Standard NCASv3_T4 Family" {
						modelID = "NVIDIA-T4"
						vendor = cloudcommon.GPUVendorNVIDIA
						memory = 16
					} else if *v.Family == "StandardNCADSA100v4Family" {
						modelID = "NVIDIA-A100"
						vendor = cloudcommon.GPUVendorNVIDIA
						memory = 94
					} else if *v.Family == "StandardNCadsH100v5Family" || *v.Family == "standardNDSH100v5Family" {
						modelID = "NVIDIA-H100"
						vendor = cloudcommon.GPUVendorNVIDIA
						memory = 94
					} else if *v.Family == "standardNVSv3Family" {
						modelID = "NVIDIA-M60"
						vendor = cloudcommon.GPUVendorNVIDIA
						memory = 16
					} else if *v.Family == "standardNVSv4Family" {
						modelID = "AMD-MI25"
						vendor = cloudcommon.GPUVendorAMD
						memory = 16
					} else if *v.Family == "StandardNVADSA10v5Family" {
						modelID = "NVIDIA-A10"
						vendor = cloudcommon.GPUVendorNVIDIA
						memory = 24
					} else if *v.Family == "StandardNVadsV710v5Family" {
						vendor = cloudcommon.GPUVendorAMD
						switch *v.Name {
						case "Standard_NV4ads_V710_v5":
							modelID = "AMD-V710-6Q" // 1/6
							memory = 4
						case "Standard_NV8ads_V710_v5":
							modelID = "AMD-V710-3Q" // 1/3
							memory = 8
						case "Standard_NV12ads_V710_v5":
							modelID = "AMD-V710-2Q" // 1/2
							memory = 12
						case "Standard_NV24ads_V710_v5":
							fallthrough
						case "Standard_NV28adms_V710_v5":
							modelID = "AMD-V710"
							memory = 24
						}
					}
					flavor.Gpus = []*edgeproto.GPUResource{{
						ModelId: modelID,
						Vendor:  vendor,
						Count:   uint32(num),
						Memory:  memory,
					}}
				}
				// There is no indication of how much GPU VRAM is available,
				// nor what type of GPU.
			}
			info.Flavors = append(info.Flavors, flavor)
		}
		sort.Slice(info.Flavors, func(i, j int) bool {
			fi := info.Flavors[i]
			fj := info.Flavors[j]
			if fi.Vcpus == fj.Vcpus {
				return fi.Ram < fj.Ram
			}
			return fi.Vcpus < fj.Vcpus
		})
		for _, flavor := range info.Flavors {
			gpu := ""
			if len(flavor.Gpus) > 0 {
				gpu = flavor.Gpus[0].ModelId
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "got flavor", "name", flavor.Name, "vcpus", flavor.Vcpus, "ramMB", flavor.Ram, "diskGB", flavor.Disk, "gpu", gpu, "propmap", flavor.PropMap)
		}
	}
	return nil
}

func (a *AzurePlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (a *AzurePlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (a *AzurePlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

// Login logs into azure
func (a *AzurePlatform) Login(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "doing azure login")
	clientID := a.accessVars[AZURE_CLIENT_ID]
	clientSecret := a.accessVars[AZURE_CLIENT_SECRET]
	tenantID := a.accessVars[AZURE_TENANT_ID]
	subscriptionID := a.accessVars[AZURE_SUBSCRIPTION_ID]
	resourceGroup := a.accessVars[AZURE_RESOURCE_GROUP]
	if clientID == "" {
		return fmt.Errorf("missing %s", AZURE_CLIENT_ID)
	}
	if clientSecret == "" {
		return fmt.Errorf("missing %s", AZURE_CLIENT_SECRET)
	}
	if tenantID == "" {
		return fmt.Errorf("missing tenant ID")
	}
	if subscriptionID == "" {
		return fmt.Errorf("missing subscription ID")
	}
	if resourceGroup == "" {
		return fmt.Errorf("missing resource group name")
	}
	// only way to pass in service principal credentials is via env vars.
	os.Setenv("AZURE_TENANT_ID", tenantID)
	os.Setenv("AZURE_CLIENT_ID", clientID)
	os.Setenv("AZURE_CLIENT_SECRET", clientSecret)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return err
	}
	a.creds = cred
	return nil
}

func (a *AzurePlatform) NameSanitize(clusterName string) string {
	// azure will create a "node resource group" which will append the
	// clustername to the resource group name plus several other characters:
	// MC_clustername_rgname_region.
	clusterName = strings.NewReplacer(".", "").Replace(clusterName)
	if len(clusterName) > AzureMaxResourceGroupNameLen {
		clusterName = clusterName[:AzureMaxResourceGroupNameLen]
	}
	return clusterName
}

func (a *AzurePlatform) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return nil, nil
}
