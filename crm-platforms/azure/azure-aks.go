package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/log"
)

const NotFound = "could not be found"

// CreateResourceGroup creates azure resource group
func (a *AzurePlatform) CreateResourceGroup(ctx context.Context, group, location string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateResourceGroup", "group", group, "location", location)
	out, err := sh.Command("az", "group", "create", "-l", location, "-n", group).CombinedOutput()
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
	out, err := sh.Command("az", "aks", "create", "--resource-group", rg,
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
	out, err := sh.Command("az", "group", "delete", "--name", rg, "--yes", "--no-wait").CombinedOutput()
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
	out, err := sh.Command("az", "aks", "get-credentials", "--resource-group", rg, "--name", clusterName).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in Azure GetCredentials", "out", string(out), "err", err)
		return fmt.Errorf("Error in GetCredentials: %s - %v", string(out), err)
	}
	return nil
}
