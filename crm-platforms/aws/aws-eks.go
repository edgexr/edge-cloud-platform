package aws

import (
	"context"
	"fmt"

	"github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/log"
)

// CreateClusterPrerequisites does nothing for now, but for outpost may need to create a vpc
func (a *AWSPlatform) CreateClusterPrerequisites(ctx context.Context, clusterName string) error {
	return nil
}

// RunClusterCreateCommand creates a kubernetes cluster on AWS
func (a *AWSPlatform) RunClusterCreateCommand(ctx context.Context, clusterName string, numNodes uint32, flavor string) error {
	log.DebugLog(log.DebugLevelInfra, "RunClusterCreateCommand", "clusterName", clusterName, "numNodes:", numNodes, "NodeFlavor", flavor)
	// Can not create a managed cluster if numNodes is 0
	var out []byte
	var err error
	region := a.GetAwsRegion()
	if numNodes == 0 {
		out, err = sh.Command("eksctl", "create", "--region", region, "cluster", "--name", clusterName, "--node-type", flavor, "--nodes", fmt.Sprintf("%d", numNodes)).CombinedOutput()
	} else {
		out, err = sh.Command("eksctl", "create", "--region", region, "cluster", "--name", clusterName, "--node-type", flavor, "--nodes", fmt.Sprintf("%d", numNodes), "--managed").CombinedOutput()
	}
	if err != nil {
		log.DebugLog(log.DebugLevelInfra, "Create eks cluster failed", "clusterName", clusterName, "out", string(out), "err", err)
		return fmt.Errorf("Create eks cluster failed: %s - %v", string(out), err)
	}
	return nil
}

// RunClusterDeleteCommand removes the kubernetes cluster on AWS
func (a *AWSPlatform) RunClusterDeleteCommand(ctx context.Context, clusterName string) error {
	log.DebugLog(log.DebugLevelInfra, "RunClusterDeleteCommand", "clusterName:", clusterName)
	out, err := sh.Command("eksctl", "delete", "cluster", "--name", clusterName).CombinedOutput()
	if err != nil {
		log.DebugLog(log.DebugLevelInfra, "Delete eks cluster failed", "clusterName", clusterName, "out", string(out), "err", err)
		return fmt.Errorf("Delete eks cluster failed: %s - %v", string(out), err)
	}
	return nil
}

// GetCredentials retrieves kubeconfig credentials from AWS
func (a *AWSPlatform) GetCredentials(ctx context.Context, clusterName string) error {
	log.DebugLog(log.DebugLevelInfra, "GetCredentials", "clusterName:", clusterName)
	out, err := sh.Command("eksctl", "utils", "write-kubeconfig", clusterName).CombinedOutput()
	if err != nil {
		log.DebugLog(log.DebugLevelInfra, "Error in write-kubeconfig", "out", string(out), "err", err)
		return fmt.Errorf("Error in write-kubeconfig: %s - %v", string(out), err)
	}
	return nil
}
