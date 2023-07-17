package k8sop

import (
	"context"
	"fmt"

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	ssh "github.com/edgexr/golang-ssh"
)

func (s *K8sOperator) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PerformUpgrades", "cloudletState", cloudletState)
	return nil
}

func (s *K8sOperator) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest not supported", "cloudletName", cloudlet.Key.Name)
	return nil, fmt.Errorf("GetCloudletManifest not supported for managed k8s provider")
}

func (s *K8sOperator) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "VerifyVMs nothing to do")
	return nil
}

func (s *K8sOperator) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletInfraResources")
	// TODO
	return &edgeproto.InfraResourcesSnapshot{}, nil
}

func (s *K8sOperator) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateCloudlet", "cloudlet", cloudlet)
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		updateCallback(edgeproto.UpdateTask, "Please continue to set up cloudlet-operator manually")
		return false, nil
	}
	return false, fmt.Errorf("Create of single kubernetes cluster from controller is not supported yet, use restricted access for manual setup")
}

func (s *K8sOperator) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *K8sOperator) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	log.DebugLog(log.DebugLevelInfra, "update ManagedK8sPlatform TrustPolicy", "policy", TrustPolicy)
	return fmt.Errorf("UpdateTrustPolicy not supported on managed k8s platform: %s", s.Type)
}
func (s *K8sOperator) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterInstKey *edgeproto.ClusterInstKey) error {
	return fmt.Errorf("UpdateTrustPolicyException TODO")
}

func (s *K8sOperator) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterInstKey *edgeproto.ClusterInstKey) error {
	return fmt.Errorf("DeleteTrustPolicyException TODO")
}

func (s *K8sOperator) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudlet", "cloudlet", cloudlet)
	return nil
}

func (s *K8sOperator) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *K8sOperator) GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	return nil, nil
}

func (s *K8sOperator) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return nil, nil
}

func (s *K8sOperator) ActiveChanged(ctx context.Context, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChanged")
	return nil
}
