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
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v6"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
)

const NotFound = "could not be found"

func (a *AzurePlatform) getManagedClusterClient(ctx context.Context) (*armcontainerservice.ManagedClustersClient, error) {
	subscriptionID := a.accessVars[AZURE_SUBSCRIPTION_ID]
	containerserviceClientFactory, err := armcontainerservice.NewClientFactory(subscriptionID, a.creds, nil)
	if err != nil {
		return nil, err
	}
	managedClustersClient := containerserviceClientFactory.NewManagedClustersClient()
	return managedClustersClient, nil
}

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
	// Optionally create resource group if it doesn't exist.
	// For now we require that it already exists.
	return nil
}

// RunClusterCreateCommand creates a kubernetes cluster on azure
func (a *AzurePlatform) RunClusterCreateCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (map[string]string, error) {
	return a.createOrUpdateCluster(ctx, clusterName, clusterInst, "create")
}

func (a *AzurePlatform) createOrUpdateCluster(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst, action string) (map[string]string, error) {
	resourceGroup := a.accessVars[AZURE_RESOURCE_GROUP]
	log.SpanLog(ctx, log.DebugLevelInfra, "Create or Update Cluster", "action", action, "clusterName", clusterName, "resourceGroup", resourceGroup)
	managedClustersClient, err := a.getManagedClusterClient(ctx)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	pool := clusterInst.NodePools[0]

	managedCluster := armcontainerservice.ManagedCluster{
		Location: to.Ptr(a.GetAzureLocation()),
		Properties: &armcontainerservice.ManagedClusterProperties{
			KubernetesVersion: nil,
			AgentPoolProfiles: []*armcontainerservice.ManagedClusterAgentPoolProfile{{
				Name:   to.Ptr("agentpool"),
				Count:  to.Ptr[int32](int32(pool.NumNodes)),
				VMSize: to.Ptr(pool.NodeResources.InfraNodeFlavor),
				OSType: to.Ptr(armcontainerservice.OSTypeLinux),
				Type:   to.Ptr(armcontainerservice.AgentPoolTypeVirtualMachineScaleSets),
				Mode:   to.Ptr(armcontainerservice.AgentPoolModeSystem),
			}},
			ServicePrincipalProfile: &armcontainerservice.ManagedClusterServicePrincipalProfile{
				ClientID: to.Ptr(a.accessVars[AZURE_CLIENT_ID]),
				Secret:   to.Ptr(a.accessVars[AZURE_CLIENT_SECRET]),
			},
			EnableRBAC: to.Ptr[bool](true),
			DNSPrefix:  to.Ptr(clusterName),
		},
	}
	if clusterInst.KubernetesVersion != "" {
		managedCluster.Properties.KubernetesVersion = &clusterInst.KubernetesVersion
	}
	pollerResp, err := managedClustersClient.BeginCreateOrUpdate(ctx, resourceGroup, clusterName, managedCluster, nil)
	if err != nil {
		if azerr, ok := err.(*azcore.ResponseError); ok {
			return nil, fmt.Errorf("failed to %s cluster (%s), %s", action, azerr.ErrorCode, azerr.Error())
		}
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "cluster create or update in progress", "action", action, "cluster", clusterName)
	_, err = pollerResp.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{
		Frequency: 15 * time.Second,
	})
	log.SpanLog(ctx, log.DebugLevelInfra, "cluster "+action+" finished", "cluster", clusterName, "took", time.Since(start).String(), "err", err)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (a *AzurePlatform) RunClusterUpdateCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (map[string]string, error) {
	return a.createOrUpdateCluster(ctx, clusterName, clusterInst, "update")
}

// RunClusterDeleteCommand removes the kubernetes cluster on azure
func (a *AzurePlatform) RunClusterDeleteCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) error {
	resourceGroup := a.accessVars[AZURE_RESOURCE_GROUP]
	log.SpanLog(ctx, log.DebugLevelInfra, "Delete Cluster", "clusterName", clusterName, "resourceGroup", resourceGroup)
	managedClustersClient, err := a.getManagedClusterClient(ctx)
	if err != nil {
		return err
	}
	start := time.Now()

	pollerResp, err := managedClustersClient.BeginDelete(ctx, resourceGroup, clusterName, nil)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "cluster delete in progress", "cluster", clusterName)
	_, err = pollerResp.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{
		Frequency: 15 * time.Second,
	})
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "cluster delete finished", "cluster", clusterName, "took", time.Since(start).String())
	return nil
}

// GetCredentials retrieves kubeconfig credentials from azure for the cluster just created
func (a *AzurePlatform) GetCredentials(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) ([]byte, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCredentials", "clusterName", clusterName)
	resourceGroup := a.accessVars[AZURE_RESOURCE_GROUP]
	managedClustersClient, err := a.getManagedClusterClient(ctx)
	if err != nil {
		return nil, err
	}
	creds, err := managedClustersClient.ListClusterAdminCredentials(ctx, resourceGroup, clusterName, nil)
	if err != nil {
		return nil, err
	}
	if len(creds.Kubeconfigs) == 0 {
		return nil, errors.New("no kubeconfig credentials found for cluster " + clusterName)
	}
	// Note: although comments for azure sdk code say the data is
	// base64 encoded, the actual values from Azure are not.
	return creds.Kubeconfigs[0].Value, nil
}

func (a *AzurePlatform) GetClusterAddonInfo(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (*k8smgmt.ClusterAddonInfo, error) {
	info := k8smgmt.ClusterAddonInfo{}
	// The external traffic policy local is required for
	// external traffic to be able to reach the ingress
	info.IngressNginxOps = []k8smgmt.IngressNginxOp{
		k8smgmt.WithIngressNginxWaitForExternalIP(),
		k8smgmt.WithIngressNginxHelmSetCmd("--set controller.service.externalTrafficPolicy=Local"),
	}
	return &info, nil
}

func (a *AzurePlatform) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	return []edgeproto.InfraResource{}, nil
}

// called by controller, make sure it doesn't make any calls to infra API
func (a *AzurePlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource {
	return nil
}

func (a *AzurePlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

func (v *AzurePlatform) GetAllClusters(ctx context.Context) ([]*edgeproto.CloudletManagedCluster, error) {
	return nil, errors.New("not supported")
}

func (v *AzurePlatform) RegisterCluster(ctx context.Context, clusterName string, in *edgeproto.ClusterInst) (map[string]string, error) {
	return nil, errors.New("not supported")
}
