package gcp

import (
	"context"
	"fmt"

	"github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/log"
)

// SetProject sets the project in gcloud config
func (g *GCPPlatform) SetProject(ctx context.Context, project string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetProject", "project", project)
	out, err := sh.Command("gcloud", "config", "set", "project", project).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in SetProject", "out", string(out), "err", err)
		return fmt.Errorf("Error in SetProject: %s - %v", string(out), err)
	}
	return nil
}

// SetZone sets the zone in gcloud config
func (g *GCPPlatform) SetZone(ctx context.Context, zone string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetZone", "zone", zone)
	out, err := sh.Command("gcloud", "config", "set", "compute/zone", zone).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in SetZone", "zone", zone, "out", string(out), "err", err)
		return fmt.Errorf("Error in SetZone: %s - %v", string(out), err)
	}
	return nil
}

// CreateClusterPrerequisites currently does nothing
func (a *GCPPlatform) CreateClusterPrerequisites(ctx context.Context, clusterName string) error {
	return nil
}

// RunClusterCreateCommand creates a kubernetes cluster on gcloud
func (g *GCPPlatform) RunClusterCreateCommand(ctx context.Context, clusterName string, numNodes uint32, flavor string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RunClusterCreateCommand", "clusterName", clusterName)
	numNodesStr := fmt.Sprintf("%d", numNodes)
	out, err := sh.Command("gcloud", "container", "clusters", "create", "--num-nodes="+numNodesStr, "--machine-type="+flavor, clusterName).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in cluster create", "out", string(out), "err", err)
		return fmt.Errorf("Error in cluster create: %s - %v", string(out), err)
	}
	return nil
}

// RunClusterDeleteCommand removes kubernetes cluster on gcloud
func (g *GCPPlatform) RunClusterDeleteCommand(ctx context.Context, clusterName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RunClusterDeleteCommand", "clusterName", clusterName)
	out, err := sh.Command("gcloud", "container", "clusters", "delete", "--quiet", clusterName).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in cluster delete", "out", string(out), "err", err)
		return fmt.Errorf("Error in cluster delete: %s - %v", string(out), err)
	}
	return nil
}

// GetCredentials retrieves kubeconfig credentials from gcloud.
func (g *GCPPlatform) GetCredentials(ctx context.Context, clusterName string) error {
	out, err := sh.Command("gcloud", "container", "clusters", "get-credentials", clusterName).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in GetCredentials", "out", string(out), "err", err)
		return fmt.Errorf("Error in GetCredential: %s - %v", string(out), err)
	}
	return nil
}
