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
	"strings"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

const NotFound = "could not be found"

// CreateResourceGroup creates azure resource group
func (a *AzurePlatform) CreateResourceGroup(ctx context.Context, group, location string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateResourceGroup", "group", group, "location", location)
	out, err := infracommon.Sh(a.accessVars).Command("az", "group", "create", "-l", location, "-n", group).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in CreateResourceGroup", "out", string(out), "err", err)
		return fmt.Errorf("Error in CreateResourceGroup: %s - %v", string(out), err)
	}
	return nil
}

// CreateClusterPrerequisites executes CreateResourceGroup to create a resource group
func (a *AzurePlatform) CreateClusterPrerequisites(ctx context.Context, clusterName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateClusterPrerequisites", "clusterName", clusterName)
	rg := a.GetResourceGroupForCluster(clusterName)
	err := a.CreateResourceGroup(ctx, rg, a.GetAzureLocation())
	if err != nil {
		return err
	}
	return nil
}

// RunClusterCreateCommand creates a kubernetes cluster on azure
func (a *AzurePlatform) RunClusterCreateCommand(ctx context.Context, clusterName string, numNodes uint32, flavor string) error {
	rg := a.GetResourceGroupForCluster(clusterName)
	log.SpanLog(ctx, log.DebugLevelInfra, "RunClusterCreateCommand", "clusterName", clusterName, "rgName", rg)
	numNodesStr := fmt.Sprintf("%d", numNodes)
	out, err := infracommon.Sh(a.accessVars).Command("az", "aks", "create", "--resource-group", rg,
		"--name", clusterName, "--generate-ssh-keys",
		"--node-vm-size", flavor,
		"--node-count", numNodesStr).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in aks create", "out", string(out), "err", err)
		return fmt.Errorf("Error in aks create: %s - %v", string(out), err)
	}
	return nil
}

// RunClusterDeleteCommand removes the kubernetes cluster on azure
func (a *AzurePlatform) RunClusterDeleteCommand(ctx context.Context, clusterName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RunClusterDeleteCommand", "clusterName", clusterName)
	rg := a.GetResourceGroupForCluster(clusterName)
	out, err := infracommon.Sh(a.accessVars).Command("az", "group", "delete", "--name", rg, "--yes", "--no-wait").CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), NotFound) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Cluster already gone", "out", out, "err", err)
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in aks delete", "out", string(out), "err", err)
		return fmt.Errorf("Error in aks delete: %s - %v", string(out), err)
	}
	return nil
}

// GetCredentials retrieves kubeconfig credentials from azure for the cluster just created
func (a *AzurePlatform) GetCredentials(ctx context.Context, clusterName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCredentials", "clusterName", clusterName)
	rg := a.GetResourceGroupForCluster(clusterName)
	out, err := infracommon.Sh(a.accessVars).Command("az", "aks", "get-credentials", "--resource-group", rg, "--name", clusterName).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in Azure GetCredentials", "out", string(out), "err", err)
		return fmt.Errorf("Error in GetCredentials: %s - %v", string(out), err)
	}
	return nil
}

func (a *AzurePlatform) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	return []edgeproto.InfraResource{}, nil
}

// called by controller, make sure it doesn't make any calls to infra API
func (a *AzurePlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	return nil
}

func (a *AzurePlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

func (a *AzurePlatform) GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error) {
	return &edgeproto.CloudletResourceQuotaProps{}, nil
}
