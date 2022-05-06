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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/codeskyblue/go-sh"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

const AzureMaxResourceGroupNameLen int = 80

type AzurePlatform struct {
	properties *infracommon.InfraProperties
	accessVars map[string]string
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

func (o *AzurePlatform) GetFeatures() *platform.Features {
	return &platform.Features{
		SupportsMultiTenantCluster:    true,
		SupportsKubernetesOnly:        true,
		KubernetesRequiresWorkerNodes: true,
		IPAllocatedPerService:         true,
	}
}

func (a *AzurePlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo")
	if err := a.Login(ctx); err != nil {
		return err
	}

	var limits []AZLimit
	out, err := infracommon.Sh(a.accessVars).Command("az", "vm", "list-usage", "--location", a.GetAzureLocation(), sh.Dir("/tmp")).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("cannot get limits from azure, %s, %s", out, err.Error())
		return err
	}
	err = json.Unmarshal(out, &limits)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return err
	}
	for _, l := range limits {
		if l.LocalName == "Total Regional vCPUs" {
			vcpus, err := strconv.Atoi(l.Limit)
			if err != nil {
				err = fmt.Errorf("failed to parse azure output, %s", err.Error())
				return err
			}
			info.OsMaxVcores = uint64(vcpus)
			info.OsMaxRam = uint64(4 * vcpus)
			info.OsMaxVolGb = uint64(500 * vcpus)
			break
		}
	}

	/*
	* We will not support all Azure flavors, only selected ones:
	* https://azure.microsoft.com/en-in/pricing/details/virtual-machines/series/
	 */
	var vmsizes []AZFlavor
	out, err = infracommon.Sh(a.accessVars).Command("az", "vm", "list-sizes",
		"--location", a.GetAzureLocation(),
		"--query", "[].{"+
			"Name:name,"+
			"VCPUs:numberOfCores,"+
			"RAM:memoryInMb, Disk:resourceDiskSizeInMb"+
			"}[?starts_with(Name,'Standard_DS')]|[?ends_with(Name,'v2')]",
		sh.Dir("/tmp")).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("cannot get vm-sizes from azure, %s, %s", out, err.Error())
		return err
	}
	err = json.Unmarshal(out, &vmsizes)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return err
	}
	for _, f := range vmsizes {
		info.Flavors = append(
			info.Flavors,
			&edgeproto.FlavorInfo{
				Name:  f.Name,
				Vcpus: uint64(f.VCPUs),
				Ram:   uint64(f.RAM),
				Disk:  uint64(f.Disk),
			},
		)
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
	user := a.GetAzureUser()
	pass := a.GetAzurePass()
	if user == "" || pass == "" {
		return fmt.Errorf("Missing azure credentials")
	}
	out, err := infracommon.Sh(a.accessVars).Command("az", "login", "--username", user, "--password", pass).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Login Failed: %s %v", out, err)
	}
	return nil
}

func (a *AzurePlatform) GetResourceGroupForCluster(clusterName string) string {
	return clusterName
}

func (a *AzurePlatform) NameSanitize(clusterName string) string {
	// azure will create a "node resource group" which will append the
	// clustername to the resource group name plus several other characters:
	// MC_clustername_rgname_region.
	clusterName = strings.NewReplacer(".", "").Replace(clusterName)
	regionNameLen := len(a.GetAzureLocation())
	fixedPartLen := 5 // "MC_" and 2 underscores
	allowedLenForcluster := (AzureMaxResourceGroupNameLen - fixedPartLen - regionNameLen) / 2
	if len(clusterName) > allowedLenForcluster {
		clusterName = clusterName[:allowedLenForcluster]
	}
	return clusterName
}

func (a *AzurePlatform) SetProperties(props *infracommon.InfraProperties) error {
	a.properties = props
	return nil
}

func (a *AzurePlatform) GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	return nil, nil
}
